//! Per-capability enforcement posture.
//!
//! Every Clave control runs in one of three postures, and the product must be honest about which:
//! a `DevelopmentOnly` stand-in (a mock, launcher-seeded membership, a SIP-disabled lab Mac, a
//! test-signed driver, a local-only profile) is **not** the same as a production-`Enforced`
//! control on a stock OS. Encoding this in the type system lets a production CI gate fail — or the
//! product refuse to claim a control — the moment any capability is only a dev fallback, the
//! same way the audit schema makes personal data unrepresentable.

use serde::{Deserialize, Serialize};

/// The OS-backed controls a [`Platform`](crate::Platform) provides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// Zone membership / process supervision.
    ProcessSupervision,
    /// Encrypted Clave Disk mount + gate.
    Volume,
    /// Clipboard / data-transfer DLP.
    Clipboard,
    /// Network split-tunnel.
    Network,
    /// Screen-capture protection.
    Screen,
    /// Clave Edge overlay.
    Overlay,
    /// Input isolation / anti-keylogging.
    Input,
}

impl Capability {
    /// How many capabilities there are.
    pub const COUNT: usize = 7;

    /// Every capability, for exhaustive iteration and reporting.
    pub const ALL: [Capability; Self::COUNT] = [
        Capability::ProcessSupervision,
        Capability::Volume,
        Capability::Clipboard,
        Capability::Network,
        Capability::Screen,
        Capability::Overlay,
        Capability::Input,
    ];

    /// Human-readable name for product surfaces and logs.
    pub fn name(self) -> &'static str {
        match self {
            Capability::ProcessSupervision => "process supervision",
            Capability::Volume => "encrypted volume",
            Capability::Clipboard => "clipboard DLP",
            Capability::Network => "network split-tunnel",
            Capability::Screen => "screen-capture protection",
            Capability::Overlay => "Clave Edge overlay",
            Capability::Input => "input isolation",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// How a [`Capability`] is currently enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnforcementStatus {
    /// Production-grade: running on a stock OS with the required approval / signing / entitlement
    /// (SIP & Secure Boot on; notarized / Microsoft-signed). The only shippable state.
    Enforced,
    /// Working, but through a development shortcut — a mock, launcher-seeded membership, a
    /// test-signed driver, a SIP- or Secure-Boot-disabled lab machine, or a local-only profile.
    /// Fine for demos and CI; **never** a production posture.
    DevelopmentOnly,
    /// Not operating at all: the entitlement, driver, TCC grant, or OS primitive is missing.
    Unavailable,
}

impl EnforcementStatus {
    /// Whether this is the production-grade posture.
    pub fn is_enforced(self) -> bool {
        matches!(self, EnforcementStatus::Enforced)
    }
}

impl std::fmt::Display for EnforcementStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EnforcementStatus::Enforced => "enforced",
            EnforcementStatus::DevelopmentOnly => "development-only",
            EnforcementStatus::Unavailable => "unavailable",
        };
        f.write_str(s)
    }
}

/// The enforcement posture of every [`Capability`] — the honest, surfaceable summary of what this
/// build actually enforces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementReport {
    entries: [(Capability, EnforcementStatus); Capability::COUNT],
}

impl EnforcementReport {
    /// Build a report by asking `status` for each capability.
    pub fn from_fn(status: impl Fn(Capability) -> EnforcementStatus) -> Self {
        Self {
            entries: Capability::ALL.map(|cap| (cap, status(cap))),
        }
    }

    /// The status of one capability.
    pub fn status(&self, cap: Capability) -> EnforcementStatus {
        self.entries
            .iter()
            .find(|(c, _)| *c == cap)
            .map(|(_, s)| *s)
            .unwrap_or(EnforcementStatus::Unavailable)
    }

    /// All `(capability, status)` pairs, in [`Capability::ALL`] order.
    pub fn entries(&self) -> &[(Capability, EnforcementStatus)] {
        &self.entries
    }

    /// Capabilities that are **not** production-`Enforced` — the reasons a build is a lab build.
    /// Each carries its status so the caller can tell a `DevelopmentOnly` stand-in
    /// from a missing (`Unavailable`) primitive.
    pub fn production_blockers(&self) -> Vec<(Capability, EnforcementStatus)> {
        self.entries
            .iter()
            .copied()
            .filter(|(_, s)| !s.is_enforced())
            .collect()
    }

    /// True only when *every* capability is production-`Enforced` (release rule).
    pub fn is_production_ready(&self) -> bool {
        self.entries.iter().all(|(_, s)| s.is_enforced())
    }

    /// `Ok` if production-ready, else `Err(blockers)`. A production CI gate should call this and
    /// fail the build on `Err`, so a dev-only fallback can never ship silently.
    pub fn require_production(&self) -> Result<(), Vec<(Capability, EnforcementStatus)>> {
        let blockers = self.production_blockers();
        if blockers.is_empty() {
            Ok(())
        } else {
            Err(blockers)
        }
    }
}

impl std::fmt::Display for EnforcementReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "enforcement: {}",
            if self.is_production_ready() {
                "production-ready"
            } else {
                "lab build"
            }
        )?;
        for (cap, status) in &self.entries {
            writeln!(f, "  - {cap}: {status}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_development_only_is_not_production_ready() {
        let r = EnforcementReport::from_fn(|_| EnforcementStatus::DevelopmentOnly);
        assert!(!r.is_production_ready());
        assert_eq!(r.production_blockers().len(), Capability::COUNT);
        assert!(r.require_production().is_err());
    }

    #[test]
    fn all_enforced_is_production_ready() {
        let r = EnforcementReport::from_fn(|_| EnforcementStatus::Enforced);
        assert!(r.is_production_ready());
        assert!(r.production_blockers().is_empty());
        assert!(r.require_production().is_ok());
    }

    #[test]
    fn a_single_non_enforced_capability_blocks_production() {
        let r = EnforcementReport::from_fn(|cap| match cap {
            Capability::Network => EnforcementStatus::Unavailable,
            _ => EnforcementStatus::Enforced,
        });
        assert!(!r.is_production_ready());
        assert_eq!(
            r.require_production().unwrap_err(),
            vec![(Capability::Network, EnforcementStatus::Unavailable)]
        );
        assert_eq!(
            r.status(Capability::Network),
            EnforcementStatus::Unavailable
        );
        assert_eq!(r.status(Capability::Volume), EnforcementStatus::Enforced);
    }

    #[test]
    fn display_lists_each_capability() {
        let r = EnforcementReport::from_fn(|_| EnforcementStatus::DevelopmentOnly);
        let s = format!("{r}");
        assert!(s.contains("lab build"));
        assert!(s.contains("network split-tunnel: development-only"));
    }
}
