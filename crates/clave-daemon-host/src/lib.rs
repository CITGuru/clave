#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn clave_daemon_run() {
    clave_daemon::mac_main::run_macos(clave_daemon::mac_main::Profile::SignedHost);
}

/// # Safety
/// `pusher`, if `Some`, must be a valid C function pointer that accepts `(ptr, len)` describing
/// `len` readable bytes and remains callable for the lifetime of the process.
#[cfg(target_os = "macos")]
#[no_mangle]
pub unsafe extern "C" fn clave_daemon_set_policy_pusher(
    pusher: Option<unsafe extern "C" fn(*const u8, usize) -> bool>,
) {
    let Some(pusher) = pusher else {
        return;
    };
    clave_daemon::mac_main::register_policy_publisher(std::sync::Arc::new(move |bytes: &[u8]| {
        unsafe { pusher(bytes.as_ptr(), bytes.len()) }
    }));
}
