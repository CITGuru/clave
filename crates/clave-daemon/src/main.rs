fn main() {
    println!("clave-daemon — IPC proto v{}", clave_ipc::PROTO_VERSION);

    #[cfg(target_os = "macos")]
    clave_daemon::mac_main::run_macos(clave_daemon::mac_main::Profile::Dev);

    #[cfg(target_os = "windows")]
    clave_daemon::win_main::run_windows();

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    println!("no OS platform adapter for this target yet; run `cargo test` for daemon logic.");
}
