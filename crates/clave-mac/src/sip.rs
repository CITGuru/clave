#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipStatus {
    Enabled,
    Disabled,
    Unknown,
}

impl SipStatus {
    pub fn detect() -> Self {
        #[cfg(target_os = "macos")]
        {
            extern "C" {
                fn csr_get_active_config(config: *mut u32) -> std::os::raw::c_int;
            }
            let mut config: u32 = 0;
            let rc = unsafe { csr_get_active_config(&mut config) };
            match (rc, config) {
                (0, 0) => SipStatus::Enabled,
                (0, _) => SipStatus::Disabled,
                _ => SipStatus::Unknown,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            SipStatus::Unknown
        }
    }

    pub fn is_disabled(self) -> bool {
        matches!(self, SipStatus::Disabled)
    }
}

impl std::fmt::Display for SipStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SipStatus::Enabled => "enabled",
            SipStatus::Disabled => "disabled",
            SipStatus::Unknown => "unknown",
        })
    }
}
