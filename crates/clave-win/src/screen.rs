//! Screen-capture exclusion on Windows (doc 07 §2).
//!
//! `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` is a real hard control — the DWM omits the
//! window from screenshots and recordings — but Windows only lets a process set it on **its own**
//! top-level windows (a cross-process call fails with `ERROR_ACCESS_DENIED`). So the daemon cannot
//! protect a third-party work window from the outside; delivery needs the in-process shim (doc 07
//! §2). This primitive is what that shim calls; the `Screen` capability stays `Unavailable` until
//! the shim ships, rather than reporting a protection the daemon cannot actually apply.

#![allow(unsafe_code)]

use clave_platform::{PResult, PlatformError};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE};

/// Excludes a top-level window from screen capture. Succeeds only for a window owned by the
/// calling process; a foreign `hwnd` returns the OS `ERROR_ACCESS_DENIED`.
pub fn exclude_from_capture(hwnd: isize) -> PResult<()> {
    unsafe {
        SetWindowDisplayAffinity(HWND(hwnd as *mut core::ffi::c_void), WDA_EXCLUDEFROMCAPTURE)
            .map_err(|e| PlatformError::Io(e.message()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::w;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WS_OVERLAPPED,
    };

    #[test]
    fn excludes_a_window_this_process_owns() {
        unsafe {
            // A predefined "STATIC" class gives us a real top-level window with no registration.
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!("clave-capture-test"),
                WS_OVERLAPPED,
                0,
                0,
                10,
                10,
                None,
                None,
                None,
                None,
            )
            .expect("create test window");

            let result = exclude_from_capture(hwnd.0 as isize);
            let _ = DestroyWindow(hwnd);
            result.expect("a process may exclude its own window from capture");
        }
    }
}
