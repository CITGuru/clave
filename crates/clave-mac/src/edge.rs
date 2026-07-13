#![cfg(target_os = "macos")]
#![allow(deprecated)]

use std::collections::HashSet;
use std::os::raw::c_void;
use std::ptr::null;
use std::sync::Arc;
use std::time::Duration;

use cocoa::base::{id, nil, NO, YES};
use cocoa::foundation::{NSAutoreleasePool, NSPoint, NSRect, NSSize, NSString, NSUInteger};
use objc::{class, msg_send, sel, sel_impl};

use clave_core::{recompute_frames_themed, BorderCfg, RectPx, WindowGeom, ZoneRegistry};
use clave_platform::{Rgba, WindowId};

use crate::platform::TrackedWindows;

type CFTypeRef = *const c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct CgPoint {
    x: f64,
    y: f64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CgSize {
    width: f64,
    height: f64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CgRect {
    origin: CgPoint,
    size: CgSize,
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFArrayGetCount(array: CFTypeRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CFTypeRef, idx: isize) -> *const c_void;
    fn CFDictionaryGetValueIfPresent(
        dict: CFTypeRef,
        key: *const c_void,
        value: *mut *const c_void,
    ) -> u8;
    fn CFNumberGetValue(number: CFTypeRef, the_type: isize, value_ptr: *mut c_void) -> u8;
    fn CFRelease(cf: CFTypeRef);
}

#[allow(non_upper_case_globals)]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    static kCGWindowNumber: CFTypeRef;
    static kCGWindowOwnerPID: CFTypeRef;
    static kCGWindowBounds: CFTypeRef;
    static kCGWindowLayer: CFTypeRef;
    fn CGWindowListCopyWindowInfo(option: u32, relative_to_window: u32) -> CFTypeRef;
    fn CGRectMakeWithDictionaryRepresentation(dict: CFTypeRef, rect: *mut CgRect) -> u8;
}

#[link(name = "QuartzCore", kind = "framework")]
extern "C" {}

const CF_NUMBER_SINT64: isize = 4;
const WINDOW_LIST_OPTION: u32 = (1 << 0) | (1 << 4);
const NULL_WINDOW_ID: u32 = 0;

unsafe fn dict_i64(dict: CFTypeRef, key: CFTypeRef) -> Option<i64> {
    let mut val: *const c_void = null();
    if CFDictionaryGetValueIfPresent(dict, key, &mut val) == 0 || val.is_null() {
        return None;
    }
    let mut out: i64 = 0;
    if CFNumberGetValue(val, CF_NUMBER_SINT64, &mut out as *mut i64 as *mut c_void) == 0 {
        return None;
    }
    Some(out)
}

unsafe fn dict_rect(dict: CFTypeRef, key: CFTypeRef) -> Option<CgRect> {
    let mut val: *const c_void = null();
    if CFDictionaryGetValueIfPresent(dict, key, &mut val) == 0 || val.is_null() {
        return None;
    }
    let mut r = CgRect {
        origin: CgPoint { x: 0.0, y: 0.0 },
        size: CgSize {
            width: 0.0,
            height: 0.0,
        },
    };
    if CGRectMakeWithDictionaryRepresentation(val, &mut r) == 0 {
        return None;
    }
    Some(r)
}

struct ScreenSpace {
    min_x: f64,
    min_y: f64,
    width: f64,
    height: f64,
    primary_height: f64,
}

unsafe fn screen_space() -> ScreenSpace {
    let screens: id = msg_send![class!(NSScreen), screens];
    let count: NSUInteger = msg_send![screens, count];
    let (mut min_x, mut min_y) = (f64::MAX, f64::MAX);
    let (mut max_x, mut max_y) = (f64::MIN, f64::MIN);
    let mut primary_height = 0.0;
    for i in 0..count {
        let scr: id = msg_send![screens, objectAtIndex: i];
        let f: NSRect = msg_send![scr, frame];
        min_x = min_x.min(f.origin.x);
        min_y = min_y.min(f.origin.y);
        max_x = max_x.max(f.origin.x + f.size.width);
        max_y = max_y.max(f.origin.y + f.size.height);
        if f.origin.x == 0.0 && f.origin.y == 0.0 {
            primary_height = f.size.height;
        }
    }
    if count == 0 {
        return ScreenSpace {
            min_x: 0.0,
            min_y: 0.0,
            width: 0.0,
            height: 0.0,
            primary_height: 0.0,
        };
    }
    if primary_height == 0.0 {
        primary_height = max_y - min_y;
    }
    ScreenSpace {
        min_x,
        min_y,
        width: max_x - min_x,
        height: max_y - min_y,
        primary_height,
    }
}

pub fn run_clave_edge(
    zones: Arc<ZoneRegistry>,
    tracked: TrackedWindows,
    cfg_of: impl Fn() -> BorderCfg,
) -> ! {
    let poll = std::env::var("CLAVE_EDGE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .unwrap_or(100);
    let visible_in_capture = std::env::var("CLAVE_EDGE_CAPTURE").as_deref() == Ok("1");
    let debug = std::env::var("CLAVE_EDGE_DEBUG").as_deref() == Ok("1");
    let own_pid = std::process::id();

    unsafe {
        let app: id = msg_send![class!(NSApplication), sharedApplication];
        let _: () = msg_send![app, setActivationPolicy: 1i64];

        let space = screen_space();
        let frame = NSRect::new(
            NSPoint::new(space.min_x, space.min_y),
            NSSize::new(space.width, space.height),
        );

        let window: id = msg_send![class!(NSWindow), alloc];
        let window: id = msg_send![window,
            initWithContentRect: frame
            styleMask: 0u64
            backing: 2u64
            defer: NO];
        let _: () = msg_send![window, setOpaque: NO];
        let clear: id = msg_send![class!(NSColor), clearColor];
        let _: () = msg_send![window, setBackgroundColor: clear];
        let _: () = msg_send![window, setIgnoresMouseEvents: YES];
        let _: () = msg_send![window, setHasShadow: NO];
        let _: () = msg_send![window, setLevel: 3i64];
        let _: () = msg_send![window, setCollectionBehavior: (1u64 | (1 << 4) | (1 << 6))];
        let _: () = msg_send![window, setSharingType: if visible_in_capture { 1u64 } else { 0u64 }];

        let content: id = msg_send![window, contentView];
        let _: () = msg_send![content, setWantsLayer: YES];
        let root_layer: id = msg_send![content, layer];

        let _: () = msg_send![app, finishLaunching];
        let _: () = msg_send![window, orderFrontRegardless];

        let run_loop_mode = NSString::alloc(nil).init_str("kCFRunLoopDefaultMode");
        let _: () = msg_send![run_loop_mode, retain];

        loop {
            let pool: id = NSAutoreleasePool::new(nil);

            let distant_past: id = msg_send![class!(NSDate), distantPast];
            loop {
                let event: id = msg_send![app,
                    nextEventMatchingMask: u64::MAX
                    untilDate: distant_past
                    inMode: run_loop_mode
                    dequeue: YES];
                if event == nil {
                    break;
                }
                let _: () = msg_send![app, sendEvent: event];
            }

            let cfg = cfg_of();
            let segments = compute_segments(&zones, &tracked, &cfg, own_pid, &space, debug);
            paint(root_layer, &segments);

            let _: () = msg_send![pool, drain];
            std::thread::sleep(Duration::from_millis(poll));
        }
    }
}

/// How many on-screen windows belong to work apps.
///
/// A screen capture only concerns the enclave when work content is actually on the screen — a
/// screenshot of a purely personal desktop is never instrumented (doc 01). "Running" is not enough:
/// a minimised or hidden work app has nothing to capture, so this counts real, non-degenerate
/// windows at layer 0, exactly as the overlay does when deciding what to frame.
pub fn work_windows_on_screen(zones: &ZoneRegistry) -> usize {
    let supervised: HashSet<u32> = zones.supervised_pids().into_iter().collect();
    if supervised.is_empty() {
        return 0;
    }
    // SAFETY: CGWindowList returns a +1 CFArray of CFDictionaries; every read below goes through
    // the same null- and type-checked helpers the overlay uses, and the array is released after.
    unsafe {
        let info = CGWindowListCopyWindowInfo(WINDOW_LIST_OPTION, NULL_WINDOW_ID);
        if info.is_null() {
            return 0;
        }
        let mut count = 0usize;
        for i in 0..CFArrayGetCount(info) {
            let dict = CFArrayGetValueAtIndex(info, i);
            if dict.is_null() || dict_i64(dict, kCGWindowLayer).unwrap_or(1) != 0 {
                continue;
            }
            let owner = dict_i64(dict, kCGWindowOwnerPID).unwrap_or(0) as u32;
            if !supervised.contains(&owner) {
                continue;
            }
            let Some(bounds) = dict_rect(dict, kCGWindowBounds) else {
                continue;
            };
            if bounds.size.width >= 1.0 && bounds.size.height >= 1.0 {
                count += 1;
            }
        }
        CFRelease(info);
        count
    }
}

unsafe fn compute_segments(
    zones: &ZoneRegistry,
    tracked: &TrackedWindows,
    cfg: &BorderCfg,
    own_pid: u32,
    space: &ScreenSpace,
    debug: bool,
) -> Vec<(NSRect, Rgba)> {
    let supervised: HashSet<u32> = zones.supervised_pids().into_iter().collect();
    let tracked_colors: std::collections::HashMap<WindowId, Rgba> =
        tracked.lock().expect("overlay lock poisoned").clone();
    if debug {
        eprintln!(
            "clave-edge: tick supervised={:?} tracked={}",
            supervised,
            tracked_colors.len()
        );
    }
    if supervised.is_empty() && tracked_colors.is_empty() {
        return Vec::new();
    }

    let info = CGWindowListCopyWindowInfo(WINDOW_LIST_OPTION, NULL_WINDOW_ID);
    if info.is_null() {
        return Vec::new();
    }

    let mut windows: Vec<WindowGeom> = Vec::new();
    let mut work: Vec<WindowId> = Vec::new();
    let count = CFArrayGetCount(info);
    for i in 0..count {
        let dict = CFArrayGetValueAtIndex(info, i);
        if dict.is_null() {
            continue;
        }
        if dict_i64(dict, kCGWindowLayer).unwrap_or(1) != 0 {
            continue;
        }
        let owner = dict_i64(dict, kCGWindowOwnerPID).unwrap_or(0) as u32;
        if owner == own_pid {
            continue;
        }
        let number = dict_i64(dict, kCGWindowNumber).unwrap_or(0) as u64;
        let Some(bounds) = dict_rect(dict, kCGWindowBounds) else {
            continue;
        };
        if bounds.size.width < 1.0 || bounds.size.height < 1.0 {
            continue;
        }
        let rect = RectPx::new(
            bounds.origin.x.round() as i32,
            bounds.origin.y.round() as i32,
            bounds.size.width.round() as i32,
            bounds.size.height.round() as i32,
        );
        let id = WindowId(number);
        windows.push(WindowGeom::new(id, rect));
        if supervised.contains(&owner) || tracked_colors.contains_key(&id) {
            work.push(id);
        }
    }
    CFRelease(info);

    if debug {
        eprintln!(
            "clave-edge: supervised_pids={:?} windows={} work_windows={}",
            supervised,
            windows.len(),
            work.len()
        );
    }

    let frames = recompute_frames_themed(&windows, &work, cfg, &tracked_colors);
    let mut segments = Vec::new();
    for frame in frames {
        for s in frame.segments {
            let local_x = s.x as f64 - space.min_x;
            let local_y = (space.primary_height - (s.y as f64 + s.h as f64)) - space.min_y;
            let rect = NSRect::new(
                NSPoint::new(local_x, local_y),
                NSSize::new(s.w as f64, s.h as f64),
            );
            segments.push((rect, frame.color));
        }
    }
    if debug && !segments.is_empty() {
        eprintln!("clave-edge: painting {} segments", segments.len());
    }
    segments
}

unsafe fn paint(root_layer: id, segments: &[(NSRect, Rgba)]) {
    let _: () = msg_send![class!(CATransaction), begin];
    let _: () = msg_send![class!(CATransaction), setDisableActions: YES];
    let _: () = msg_send![root_layer, setSublayers: nil];
    let mut colors: std::collections::HashMap<[u8; 4], id> = std::collections::HashMap::new();
    for (rect, color) in segments {
        let key = [color.r, color.g, color.b, color.a];
        let cg_color = match colors.get(&key) {
            Some(c) => *c,
            None => {
                let ns_color: id = msg_send![class!(NSColor),
                    colorWithSRGBRed: color.r as f64 / 255.0
                    green: color.g as f64 / 255.0
                    blue: color.b as f64 / 255.0
                    alpha: color.a as f64 / 255.0];
                let cg: id = msg_send![ns_color, CGColor];
                colors.insert(key, cg);
                cg
            }
        };
        let layer: id = msg_send![class!(CALayer), layer];
        let _: () = msg_send![layer, setFrame: *rect];
        let _: () = msg_send![layer, setBackgroundColor: cg_color];
        let _: () = msg_send![root_layer, addSublayer: layer];
    }
    let _: () = msg_send![class!(CATransaction), commit];
}
