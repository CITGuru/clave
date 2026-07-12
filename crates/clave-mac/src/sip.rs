//! Runtime System Integrity Protection (SIP) detection. SIP state decides whether the macOS dev
//! enforcement path (an unsigned ES/NE on a lab Mac) can run at all — it never promotes a capability
//! to `Enforced`. [`MacPlatform::apply_sip_posture`] turns a detected [`SipStatus`] into the
//! `DevelopmentOnly` / `Unavailable` distinction.

/// The machine's System Integrity Protection posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipStatus {
    /// SIP is fully enabled — the stock, shippable posture (`csrutil status: enabled`).
    Enabled,
    /// SIP is (at least partially) disabled — a lab Mac (doc 14 §2.3).
    Disabled,
    /// Could not be determined (the query SPI was unavailable / not macOS).
    Unknown,
}

impl SipStatus {
    /// Query the live SIP configuration.
    ///
    /// On macOS this calls `csr_get_active_config`, an unprivileged System Private Interface in
    /// libSystem: a zero active config means SIP is fully enabled; any relaxed bit means it is
    /// disabled. Off macOS (or if the SPI is unavailable) it reports [`SipStatus::Unknown`].
    pub fn detect() -> Self {
        #[cfg(target_os = "macos")]
        {
            extern "C" {
                fn csr_get_active_config(config: *mut u32) -> std::os::raw::c_int;
            }
            let mut config: u32 = 0;
            // SAFETY: FFI to a libSystem SPI that writes a single `u32` through the pointer we own.
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

    /// Whether SIP is known to be (at least partially) disabled — the lab condition under which the
    /// unsigned dev ES/NE path can run.
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
