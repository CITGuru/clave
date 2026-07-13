//! The `#[no_mangle]` boundary the signed `ClaveDaemonHost` app links to reach the daemon.
//!
//! Its own crate, not a module in `clave-daemon`: that crate carries `#![forbid(unsafe_code)]`, and
//! `#[no_mangle]` trips it. Keeping the export here confines the unsafety to an OS-adapter boundary,
//! as `clave-mac` already does for its C ABI.

#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn clave_daemon_run() {
    clave_daemon::mac_main::run_macos(clave_daemon::mac_main::Profile::SignedHost);
}
