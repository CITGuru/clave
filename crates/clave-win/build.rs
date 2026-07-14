fn main() {
    // WinFSP only supports delay-loading; emit the link flags so the DLL is resolved at runtime.
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();
}
