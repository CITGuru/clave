use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    ProcessSupervision,
    Volume,
    Clipboard,
    Network,
    Screen,
    Overlay,
    Input,
}

impl Capability {
    pub const COUNT: usize = 7;

    pub const ALL: [Capability; Self::COUNT] = [
        Capability::ProcessSupervision,
        Capability::Volume,
        Capability::Clipboard,
        Capability::Network,
        Capability::Screen,
        Capability::Overlay,
        Capability::Input,
    ];

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnforcementStatus {
    Enforced,
    DevelopmentOnly,
    Unavailable,
}

impl EnforcementStatus {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementReport {
    entries: [(Capability, EnforcementStatus); Capability::COUNT],
}

impl EnforcementReport {
    pub fn from_fn(status: impl Fn(Capability) -> EnforcementStatus) -> Self {
        Self {
            entries: Capability::ALL.map(|cap| (cap, status(cap))),
        }
    }

    pub fn status(&self, cap: Capability) -> EnforcementStatus {
        self.entries
            .iter()
            .find(|(c, _)| *c == cap)
            .map(|(_, s)| *s)
            .unwrap_or(EnforcementStatus::Unavailable)
    }

    pub fn entries(&self) -> &[(Capability, EnforcementStatus)] {
        &self.entries
    }

    pub fn production_blockers(&self) -> Vec<(Capability, EnforcementStatus)> {
        self.entries
            .iter()
            .copied()
            .filter(|(_, s)| !s.is_enforced())
            .collect()
    }

    pub fn is_production_ready(&self) -> bool {
        self.entries.iter().all(|(_, s)| s.is_enforced())
    }

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
