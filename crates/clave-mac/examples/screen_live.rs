use clave_core::{JoinReason, ZoneRegistry};
use clave_mac::{CaptureWatch, Capturer};
use clave_platform::ProcId;
use std::process::Command;
use std::sync::Arc;

fn proc_id(pid: u32) -> ProcId {
    let mut token = [0u32; 8];
    token[5] = pid;
    ProcId::macos(token)
}

fn screenshot_and_sample() -> Vec<Capturer> {
    let out = std::env::temp_dir().join("clave-screen-live.png");
    let mut child = Command::new("/usr/sbin/screencapture")
        .arg("-x")
        .arg(&out)
        .spawn()
        .expect("screencapture");

    let mut seen = Vec::new();
    for _ in 0..200 {
        seen = clave_mac::running_capture_tools();
        if !seen.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let _ = child.wait();
    let _ = std::fs::remove_file(&out);
    seen
}

fn main() {
    let zones = Arc::new(ZoneRegistry::new());

    let Some(front) = clave_mac::frontmost_app_pid() else {
        eprintln!("no frontmost app (run this with a GUI session)");
        std::process::exit(1);
    };
    zones.join(proc_id(front), JoinReason::Launcher);
    println!("treating frontmost app (pid {front}) as a work app with a window on screen");

    let work_on_screen = clave_mac::work_windows_on_screen(&zones);
    println!("work windows on screen: {work_on_screen}");
    assert!(
        work_on_screen > 0,
        "the frontmost app should have a visible window"
    );

    println!("taking a real screenshot...");
    let running = screenshot_and_sample();
    if running.is_empty() {
        eprintln!("FAIL: the screenshot was never observed (it out-ran the sampler)");
        std::process::exit(1);
    }
    println!("  observed capture tooling: {running:?}");

    let mut watch = CaptureWatch::new();
    let reported = watch.observe(&running, true);
    assert!(
        !reported.is_empty(),
        "a capture over work content must be reported"
    );
    println!("  reported over work content: {reported:?}");

    assert!(
        watch.observe(&running, true).is_empty(),
        "the same capture must not be reported twice"
    );
    println!("  and not re-reported on the next poll");

    let mut watch = CaptureWatch::new();
    assert!(
        watch.observe(&running, false).is_empty(),
        "a screenshot of a personal desktop must never be instrumented"
    );
    println!("  a screenshot with no work window on screen is ignored");

    println!("\nOK");
}
