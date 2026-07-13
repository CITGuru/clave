fn main() {
    println!("clave-daemon — IPC proto v{}", clave_ipc::PROTO_VERSION);

    #[cfg(target_os = "macos")]
    clave_daemon::mac_main::run_macos();

    #[cfg(not(target_os = "macos"))]
    report_platform();
}

/// Windows: construct the real adapter and print its enforcement posture. The launcher IPC server
/// is Unix-only (the named-pipe transport is a future scaffold), so this reports and exits.
#[cfg(target_os = "windows")]
fn report_platform() {
    use clave_platform::Platform;
    use std::sync::Arc;

    // The process-notify driver feeds this zone mirror over the IOCTL channel in production.
    let zones = Arc::new(clave_core::ZoneRegistry::new());
    let platform = clave_win::WindowsPlatform::new(zones);
    let report = platform.enforcement_report();

    println!("platform: Windows adapter (clave-win)");
    print!("{report}");
    if !report.is_production_ready() {
        println!(
            "lab build: not production-ready — a capability reaches `enforced` only with\n\
             Microsoft-signed drivers on a Secure-Boot machine."
        );
    }
}

/// No OS adapter is linked for other targets yet.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn report_platform() {
    println!("no OS platform adapter for this target yet; run `cargo test` for daemon logic.");
}
