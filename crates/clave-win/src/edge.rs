//! The Clave Edge overlay on Windows (doc 09 §3.3).
//!
//! A poll-based, click-through layered window frames every on-screen work window with a colored
//! border, reusing the portable geometry in `clave-core` (`recompute_frames_themed`) so macOS and
//! Windows draw identical frames. This is a UI affordance, never a control — its enforcement
//! posture is `DevelopmentOnly`: it makes the work zone visible but cannot stop anything.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use clave_core::{recompute_frames_themed, BorderCfg, RectPx, WindowGeom, ZoneRegistry};
use clave_platform::WindowId;

use windows::core::w;
use windows::Win32::Foundation::{BOOL, COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, SIZE, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, SelectObject, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, BLENDFUNCTION, DIB_RGB_COLORS, HBITMAP, HDC, HGDIOBJ,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, EnumWindows, GetSystemMetrics, GetWindowRect,
    GetWindowThreadProcessId, IsIconic, IsWindowVisible, PeekMessageW, RegisterClassW, ShowWindow,
    TranslateMessage, UpdateLayeredWindow, MSG, PM_REMOVE, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
    SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SW_SHOWNOACTIVATE, ULW_ALPHA, WNDCLASSW, WS_EX_LAYERED,
    WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
};

// AC_SRC_OVER / AC_SRC_ALPHA from `wingdi.h`; used as the BLENDFUNCTION op/format bytes.
const AC_SRC_OVER: u8 = 0x00;
const AC_SRC_ALPHA: u8 = 0x01;

const DEFAULT_POLL_MS: u64 = 150;

/// Draws the Clave Edge until the process exits. Reads the live border config each tick via
/// `cfg_of`. Returns `Err` only if the overlay window can't be created, letting the daemon log
/// and carry on without it.
pub fn run_clave_edge(
    zones: Arc<ZoneRegistry>,
    cfg_of: impl Fn() -> BorderCfg,
) -> std::io::Result<()> {
    let poll = std::env::var("CLAVE_EDGE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .unwrap_or(DEFAULT_POLL_MS);
    let own_pid = std::process::id();

    let mut surface = unsafe { Surface::create() }?;

    loop {
        pump_messages();

        let cfg = cfg_of();
        let frames = compute_frames(&zones, &cfg, own_pid, surface.origin());
        unsafe { surface.paint(&frames) };

        std::thread::sleep(Duration::from_millis(poll));
    }
}

/// The virtual-screen-sized layered window plus its 32-bit BGRA back buffer.
struct Surface {
    hwnd: HWND,
    mem_dc: HDC,
    dib: HBITMAP,
    bits: *mut u8,
    origin: (i32, i32),
    size: (i32, i32),
}

impl Surface {
    unsafe fn create() -> std::io::Result<Self> {
        let instance = GetModuleHandleW(None)
            .map_err(|e| std::io::Error::other(format!("GetModuleHandle: {e}")))?;
        let class_name = w!("ClaveEdgeOverlay");

        let wc = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: instance.into(),
            lpszClassName: class_name,
            ..Default::default()
        };
        // A zero return means the class is already registered from a prior run — harmless.
        RegisterClassW(&wc);

        let (vx, vy) = (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
        );
        let (vw, vh) = (
            GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1),
            GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1),
        );

        let hwnd = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            class_name,
            w!("Clave Edge"),
            WS_POPUP,
            vx,
            vy,
            vw,
            vh,
            None,
            None,
            instance,
            None,
        )
        .map_err(|e| std::io::Error::other(format!("CreateWindowEx: {e}")))?;

        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);

        let mem_dc = CreateCompatibleDC(None);
        // Top-down 32-bit DIB (negative height) so row 0 is the top of the screen.
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: vw,
                biHeight: -vh,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
        let dib = CreateDIBSection(mem_dc, &info, DIB_RGB_COLORS, &mut bits, None, 0)
            .map_err(|e| std::io::Error::other(format!("CreateDIBSection: {e}")))?;
        SelectObject(mem_dc, HGDIOBJ(dib.0));

        Ok(Self {
            hwnd,
            mem_dc,
            dib,
            bits: bits as *mut u8,
            origin: (vx, vy),
            size: (vw, vh),
        })
    }

    fn origin(&self) -> (i32, i32) {
        self.origin
    }

    /// Clears the back buffer, fills each border segment as premultiplied BGRA, and blits it to
    /// the layered window in one alpha-composited update.
    unsafe fn paint(&mut self, frames: &[clave_core::Frame]) {
        let (w, h) = self.size;
        let stride = (w * 4) as isize;
        std::ptr::write_bytes(self.bits, 0, (w * h * 4) as usize);

        for frame in frames {
            let c = frame.color;
            // Premultiply so AC_SRC_ALPHA composites the border at its configured opacity.
            let a = c.a as u32;
            let b = (c.b as u32 * a / 255) as u8;
            let g = (c.g as u32 * a / 255) as u8;
            let r = (c.r as u32 * a / 255) as u8;
            for seg in &frame.segments {
                self.fill(seg, [b, g, r, c.a], stride, w, h);
            }
        }

        let pt_src = POINT { x: 0, y: 0 };
        let pt_dst = POINT {
            x: self.origin.0,
            y: self.origin.1,
        };
        let size = SIZE { cx: w, cy: h };
        let blend = BLENDFUNCTION {
            BlendOp: AC_SRC_OVER,
            BlendFlags: 0,
            SourceConstantAlpha: 255,
            AlphaFormat: AC_SRC_ALPHA,
        };
        let _ = UpdateLayeredWindow(
            self.hwnd,
            HDC::default(),
            Some(&pt_dst),
            Some(&size),
            self.mem_dc,
            Some(&pt_src),
            COLORREF(0),
            Some(&blend),
            ULW_ALPHA,
        );
    }

    /// Fills one screen-space rectangle into the back buffer, clipped to its bounds.
    unsafe fn fill(&self, seg: &RectPx, bgra: [u8; 4], stride: isize, w: i32, h: i32) {
        let x0 = (seg.x - self.origin.0).max(0);
        let y0 = (seg.y - self.origin.1).max(0);
        let x1 = (seg.x - self.origin.0 + seg.w).min(w);
        let y1 = (seg.y - self.origin.1 + seg.h).min(h);
        for y in y0..y1 {
            let row = self.bits.offset(y as isize * stride);
            for x in x0..x1 {
                let px = row.offset(x as isize * 4);
                std::ptr::copy_nonoverlapping(bgra.as_ptr(), px, 4);
            }
        }
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteObject(HGDIOBJ(self.dib.0));
            let _ = DeleteDC(self.mem_dc);
        }
    }
}

extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
}

fn pump_messages() {
    let mut msg = MSG::default();
    unsafe {
        while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// Enumerates on-screen top-level windows and asks the shared core to lay out border frames for
/// the ones owned by a supervised (work) process.
fn compute_frames(
    zones: &ZoneRegistry,
    cfg: &BorderCfg,
    own_pid: u32,
    _origin: (i32, i32),
) -> Vec<clave_core::Frame> {
    let supervised: std::collections::HashSet<u32> = zones.supervised_pids().into_iter().collect();
    if supervised.is_empty() {
        return Vec::new();
    }

    let mut windows: Vec<WindowGeom> = Vec::new();
    let mut work: Vec<WindowId> = Vec::new();
    for hwnd in top_level_windows() {
        let (Some(pid), Some(rect)) = (window_pid(hwnd), window_rect(hwnd)) else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        let id = WindowId(hwnd.0 as u64);
        windows.push(WindowGeom::new(id, rect));
        if supervised.contains(&pid) {
            work.push(id);
        }
    }
    if work.is_empty() {
        return Vec::new();
    }
    recompute_frames_themed(&windows, &work, cfg, &HashMap::new())
}

fn top_level_windows() -> Vec<HWND> {
    let mut out: Vec<HWND> = Vec::new();
    unsafe {
        let _ = EnumWindows(Some(enum_proc), LPARAM(&mut out as *mut Vec<HWND> as isize));
    }
    out
}

extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    unsafe {
        if IsWindowVisible(hwnd).as_bool() && !IsIconic(hwnd).as_bool() {
            let out = &mut *(lparam.0 as *mut Vec<HWND>);
            out.push(hwnd);
        }
    }
    true.into()
}

fn window_pid(hwnd: HWND) -> Option<u32> {
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    (pid != 0).then_some(pid)
}

fn window_rect(hwnd: HWND) -> Option<RectPx> {
    let mut r = RECT::default();
    unsafe { GetWindowRect(hwnd, &mut r).ok()? };
    let (w, h) = (r.right - r.left, r.bottom - r.top);
    (w >= 1 && h >= 1).then_some(RectPx::new(r.left, r.top, w, h))
}
