//! Windows input-isolation watch (doc 06 §2).
//!
//! A `WH_KEYBOARD_LL` hook flags **injected** keystrokes (`LLKHF_INJECTED`) that land while a
//! supervised work window owns the foreground — the signal of a synthetic-input tool driving a
//! work app. It reports (audits) but does not block: the hard control is a signed keyboard filter
//! driver, so the honest posture is `DevelopmentOnly`, visibility only.

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clave_core::ZoneRegistry;

use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetForegroundWindow, GetMessageW, GetWindowThreadProcessId,
    SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, HC_ACTION, KBDLLHOOKSTRUCT,
    LLKHF_INJECTED, MSG, WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
};

/// Minimum gap between reports so a held or scripted key burst audits once, not per keystroke.
const REPORT_THROTTLE: Duration = Duration::from_millis(1000);

type InjectedFn = Box<dyn Fn(u32) + Send + Sync>;

struct Guard {
    zones: Arc<ZoneRegistry>,
    on_injected: InjectedFn,
}

// A low-level hook proc has no user-context parameter, so the guard state lives in a process
// global set once when the watch starts.
static GUARD: OnceLock<Guard> = OnceLock::new();
static LAST_REPORT_MS: AtomicI64 = AtomicI64::new(0);

/// Installs the keyboard hook and pumps its message loop until the process exits. `on_injected`
/// is called with the focused work pid when injected input is seen over it.
pub fn run_input_guard(
    zones: Arc<ZoneRegistry>,
    on_injected: impl Fn(u32) + Send + Sync + 'static,
) -> std::io::Result<()> {
    if GUARD
        .set(Guard {
            zones,
            on_injected: Box::new(on_injected),
        })
        .is_err()
    {
        return Err(std::io::Error::other("input guard already installed"));
    }

    unsafe {
        let hmod = GetModuleHandleW(None)
            .map_err(|e| std::io::Error::other(format!("GetModuleHandle: {e}")))?;
        let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), HINSTANCE(hmod.0), 0)
            .map_err(|e| std::io::Error::other(format!("SetWindowsHookExW: {e}")))?;

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let _ = UnhookWindowsHookEx(hook);
    }
    Ok(())
}

unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 {
        let msg = wparam.0 as u32;
        if msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN {
            let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
            if kb.flags.0 & LLKHF_INJECTED.0 != 0 {
                report_if_over_work();
            }
        }
    }
    CallNextHookEx(None, code, wparam, lparam)
}

fn report_if_over_work() {
    let Some(guard) = GUARD.get() else {
        return;
    };
    let Some(pid) = foreground_pid() else {
        return;
    };
    if !guard.zones.supervised_pids().contains(&pid) {
        return;
    }
    if throttled() {
        return;
    }
    (guard.on_injected)(pid);
}

fn throttled() -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let last = LAST_REPORT_MS.load(Ordering::Relaxed);
    if now - last < REPORT_THROTTLE.as_millis() as i64 {
        return true;
    }
    LAST_REPORT_MS.store(now, Ordering::Relaxed);
    false
}

fn foreground_pid() -> Option<u32> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        (pid != 0).then_some(pid)
    }
}
