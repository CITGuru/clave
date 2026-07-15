fn main() {
    // WinFsp only supports delay-loading; emit the link flags on the binary so `winfsp-x64.dll` is
    // resolved at first use (via `winfsp_init`) rather than required at process load.
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();
}
