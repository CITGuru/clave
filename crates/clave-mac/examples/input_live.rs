#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("input_live requires macOS");
}

#[cfg(target_os = "macos")]
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
