//! The `#[no_mangle]` boundary between the signed `ClaveDaemonHost` macOS app
//! (`crates/clave-mac/macos/ClaveDaemonHost`) and `clave-daemon`'s mac startup
//! (`clave_daemon::mac_main::run_macos`).
//!
//! This exists as its own crate — not a module inside `clave-daemon` — because `clave-daemon`
//! carries `#![forbid(unsafe_code)]` and `#[no_mangle]` itself trips that lint (unmangled exported
//! symbols are an unsafe-code category: the linker gives no guarantee against a colliding symbol
//! from elsewhere). Keeping the FFI export here, not there, means the policy-brain-adjacent
//! `clave-daemon` code keeps its forbid; this crate is the one, tiny, intentional OS-adapter
//! boundary that needs it — the same split `clave-mac` already draws between its safe core and its
//! `unsafe extern "C"` C ABI.

#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn clave_daemon_run() {
    clave_daemon::mac_main::run_macos();
}
