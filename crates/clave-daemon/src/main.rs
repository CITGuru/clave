fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("enroll") {
        if let Err(e) = clave_daemon::run_enroll_cli(&args[2..]) {
            eprintln!("clave-daemon enroll: {e}");
            std::process::exit(1);
        }
        return;
    }

    println!("clave-daemon — IPC proto v{}", clave_ipc::PROTO_VERSION);

    #[cfg(target_os = "macos")]
    clave_daemon::mac_main::run_macos(clave_daemon::mac_main::Profile::Dev);

    #[cfg(target_os = "windows")]
    clave_daemon::win_main::run_windows();

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    println!("no OS platform adapter for this target yet; run `cargo test` for daemon logic.");
}
