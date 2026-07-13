//! Drives the real clipboard guard against the real macOS pasteboard.
//!
//! Unit tests cover the state machine; this exercises the AppKit half — `changeCount`, the declared
//! UTIs, `frontmostApplication`, and `clearContents` — end to end:
//!
//! 1. treat the current frontmost app as a work app (join it to the zone),
//! 2. copy a secret while it is in front  → the guard tags it as a work payload,
//! 3. drop it from the zone               → the frontmost app is now "personal",
//! 4. the guard must clear the pasteboard → the secret is gone.
//!
//! ```sh
//! cargo run -p clave-mac --example clipboard_live
//! ```

use clave_core::{JoinReason, ZoneRegistry};
use clave_platform::{Decision, ProcId, Zone};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

/// Long enough for the guard's 200 ms poll to observe each step.
const SETTLE: Duration = Duration::from_millis(700);
const SECRET: &str = "quarterly-revenue-projection-CONFIDENTIAL";

fn pbcopy(text: &str) {
    let mut c = Command::new("pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("pbcopy");
    use std::io::Write;
    c.stdin
        .take()
        .expect("stdin")
        .write_all(text.as_bytes())
        .expect("write");
    c.wait().expect("pbcopy");
}

fn pbpaste() -> String {
    let out = Command::new("pbpaste").output().expect("pbpaste");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn proc_id(pid: u32) -> ProcId {
    let mut token = [0u32; 8];
    token[5] = pid;
    ProcId::macos(token)
}

fn main() {
    let Some(pid) = clave_mac::frontmost_app_pid() else {
        eprintln!("no frontmost app (run this with a GUI session)");
        std::process::exit(1);
    };
    println!("frontmost app pid {pid} — treating it as a work app");

    let zones = Arc::new(ZoneRegistry::new());
    zones.join(proc_id(pid), JoinReason::Launcher);

    // The restrictive default (doc 05 §1): nothing leaves the enclave.
    std::thread::spawn({
        let zones = Arc::clone(&zones);
        move || {
            clave_mac::run_clipboard_guard(zones, |src, dst, _fmt| match (src, dst) {
                (Zone::Work, Zone::Personal) => Decision::Deny,
                _ => Decision::Allow,
            })
        }
    });

    println!("copying a secret from the work app...");
    pbcopy(SECRET);
    std::thread::sleep(SETTLE);
    assert_eq!(
        pbpaste(),
        SECRET,
        "a work app must still be able to use its own clipboard"
    );
    println!("  clipboard holds the secret (work→work is untouched)");

    println!("switching to a personal app...");
    zones.leave(&proc_id(pid));
    std::thread::sleep(SETTLE);

    let after = pbpaste();
    if after.contains(SECRET) {
        eprintln!("FAIL: the secret survived the switch to a personal app");
        std::process::exit(1);
    }
    println!("  clipboard cleared — the secret did not cross the boundary");
    println!("\nOK");
}
