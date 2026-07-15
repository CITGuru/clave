fn main() {
    // WinFSP only supports delay-loading; emit the link flags so the DLL is resolved at runtime.
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();

    // Place the vendored WinDivert runtime next to the built binary so the network split-tunnel
    // loads `WinDivert.dll` (and the `.sys` it opens) straight from `cargo run` without a separate
    // download. x64 only; other targets simply run without the control.
    #[cfg(windows)]
    copy_windivert();
}

#[cfg(windows)]
fn copy_windivert() {
    use std::path::PathBuf;

    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64") {
        return;
    }

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor = manifest.join("vendor/windivert/x64");

    // OUT_DIR is <target>/<profile>/build/<pkg>-<hash>/out; three levels up is the profile dir the
    // daemon binary is emitted into.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let Some(profile_dir) = out_dir.ancestors().nth(3) else {
        return;
    };

    for file in ["WinDivert.dll", "WinDivert64.sys"] {
        let from = vendor.join(file);
        println!("cargo:rerun-if-changed={}", from.display());
        let _ = std::fs::copy(&from, profile_dir.join(file));
    }
}
