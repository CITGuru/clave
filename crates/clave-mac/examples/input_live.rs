//! Enumerate real keyboard event taps on this machine via `CGGetEventTapList`.
//!
//! Prints the pids holding a keyboard tap and their executables. If you have a text expander,
//! clipboard manager, or hotkey tool running (or grant this session Input Monitoring and run a
//! recorder), it shows up here — proving the OS enumeration works end to end.
//!
//! ```sh
//! cargo run -p clave-mac --example input_live
//! ```
fn main() {
    let pids = clave_mac::raw_keyboard_taps();
    println!("processes holding a keyboard event tap: {}", pids.len());
    for pid in pids {
        let comm = std::process::Command::new("ps")
            .args(["-o", "comm=", "-p", &pid.to_string()])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        println!("  pid {pid:<7} {comm}");
    }
    println!("\nOK (CGGetEventTapList returned without error)");
}
