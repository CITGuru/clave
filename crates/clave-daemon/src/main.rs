//! Entry point: selects this target's OS [`Platform`](clave_platform::Platform) adapter and
//! surfaces its enforcement posture.
//!
//! A *full* run additionally needs enrollment — a provisioned encrypted volume, the pinned gateway
//! key, and the audit spool — which the daemon library wires up; the daemon *logic* is exercised by
//! `cargo test -p clave-daemon` against the `clave-testkit` mock platform.

fn main() {
    println!("clave-daemon — IPC proto v{}", clave_ipc::PROTO_VERSION);
    report_platform();
}

/// macOS: construct the real adapter and print what it actually enforces vs what is a
/// development-only stand-in or unavailable.
#[cfg(target_os = "macos")]
fn report_platform() {
    use clave_platform::Platform;
    use std::sync::Arc;

    // The ES System Extension feeds this zone mirror over XPC in production (deferred).
    let zones = Arc::new(clave_core::ZoneRegistry::new());
    let platform = clave_mac::MacPlatform::new(zones);
    let report = platform.enforcement_report();

    println!("platform: macOS adapter (clave-mac)");
    print!("{report}");
    if !report.is_production_ready() {
        println!(
            "lab build: not production-ready — a capability reaches `enforced` only on a stock,\n\
             entitled, SIP-enabled Mac."
        );
    }
}

/// Windows: construct the real adapter and print its enforcement posture.
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
