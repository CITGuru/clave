//! The policy model. A [`PolicyBundle`] is the signed, versioned unit the gateway delivers and the
//! daemon caches; the entry point that combines its sub-decisions is [`crate::decide::decide`].

use clave_platform::{ClipFormat, Decision, Rgba, Zone};
use serde::{Deserialize, Serialize};

use crate::app::AppPolicy;
use crate::overlay::BorderCfg;

/// Seconds since the Unix epoch. Time is always passed in to the decision functions so every
/// decision stays deterministic and replayable for audit.
pub type UnixTime = u64;

/// The signed policy unit. (Signature/tenant fields live in `clave-proto` to keep the core free of
/// crypto deps.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Monotonic; a bundle below the last-applied version is rejected (rollback protection).
    pub version: u64,
    /// Expiry. After this instant every decision fails closed (see [`crate::decide::decide`]).
    pub not_after: UnixTime,
    pub clipboard: ClipboardPolicy,
    pub network: NetworkPolicy,
    pub files: FilePolicy,
    /// Which binaries may run as supervised work apps.
    pub apps: AppPolicy,
    /// Clave Edge appearance. Purely cosmetic, so it never fails closed.
    #[serde(default)]
    pub overlay: OverlayPolicy,
}

impl PolicyBundle {
    /// The conservative bundle used before the first gateway sync, and the fallback if a delivered
    /// bundle fails to verify: blocks all cross-zone transfer and out-of-enclave work writes.
    /// `not_after` is "never" so the default itself does not expire.
    pub fn restrictive_default() -> Self {
        Self {
            version: 0,
            not_after: UnixTime::MAX,
            clipboard: ClipboardPolicy {
                work_to_personal_allow: Vec::new(),
                personal_to_work_sanitize: Vec::new(),
            },
            network: NetworkPolicy {
                blocked_hosts: Vec::new(),
                static_egress_ip: None,
            },
            files: FilePolicy {
                allow_save_outside_enclave: false,
                work_data_roots: Vec::new(),
                cow_roots: Vec::new(),
            },
            // No allow-listed apps by default: only the launcher and inheritance supervise.
            apps: AppPolicy::empty(),
            overlay: OverlayPolicy::default(),
        }
    }
}

/// The Clave Edge appearance (brand color, thickness), themable per tenant. A UI affordance only,
/// so it has a permissive, non-fail-closed default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayPolicy {
    /// Frame color. Defaults to [`Rgba::CLAVE_EDGE`] (calm blue).
    #[serde(default = "default_edge_color")]
    pub color: Rgba,
    /// Ring width in points. `0` hides the edge.
    #[serde(default = "default_edge_thickness")]
    pub thickness: u32,
}

fn default_edge_color() -> Rgba {
    Rgba::CLAVE_EDGE
}
fn default_edge_thickness() -> u32 {
    3
}

impl Default for OverlayPolicy {
    fn default() -> Self {
        OverlayPolicy {
            color: default_edge_color(),
            thickness: default_edge_thickness(),
        }
    }
}

impl OverlayPolicy {
    /// The portable [`BorderCfg`] the overlay geometry/drawer consumes.
    pub fn border_cfg(&self) -> BorderCfg {
        BorderCfg {
            thickness: self.thickness as i32,
            color: self.color,
        }
    }
}

/// Clipboard / drag-drop matrix policy. The cross-zone rows are configurable per format;
/// the same-zone rows are fixed in [`crate::decide::clip_decision`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardPolicy {
    /// Formats permitted to move work → personal. Anything not listed is denied.
    pub work_to_personal_allow: Vec<ClipFormat>,
    /// Formats sanitized on personal → work (strip active content). Anything not listed passes.
    pub personal_to_work_sanitize: Vec<ClipFormat>,
}

impl ClipboardPolicy {
    /// work → personal: allow only explicitly permitted formats.
    pub fn work_to_personal(&self, fmt: ClipFormat) -> Decision {
        if self.work_to_personal_allow.contains(&fmt) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    /// personal → work: sanitize listed formats, otherwise allow.
    pub fn personal_to_work(&self, fmt: ClipFormat) -> Decision {
        if self.personal_to_work_sanitize.contains(&fmt) {
            Decision::Sanitize
        } else {
            Decision::Allow
        }
    }
}

/// Network egress policy for **work** flows. (Personal flows are never consulted — they
/// always route direct and unseen.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Work-egress denylist. Matched by normalized host (case-fold + trailing-dot strip); host
    /// globbing/subdomain matching is a still-deferred extension.
    pub blocked_hosts: Vec<String>,
    /// The corporate static egress IP advertised for SaaS conditional access; informational
    /// at the core layer (the tunnel enforces it).
    pub static_egress_ip: Option<String>,
}

impl NetworkPolicy {
    pub fn is_blocked(&self, host: &str) -> bool {
        let host = normalize_host(host);
        self.blocked_hosts.iter().any(|h| normalize_host(h) == host)
    }
}

/// Normalize a DNS name for denylist comparison: DNS is case-insensitive and a trailing FQDN dot is
/// insignificant, so `Evil.Example` and `evil.example.` both match a stored `evil.example`.
/// Subdomain globbing and raw-IP connections are out of scope — the tunnel is the authoritative
/// egress control.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// File-save policy for supervised processes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePolicy {
    /// If false (the safe default), a supervised process may not write work data outside the
    /// encrypted volume. The kernel minifilter / ES `AUTH_OPEN` is the authoritative enforcer.
    pub allow_save_outside_enclave: bool,
    /// Path prefixes whose contents are work data, redirected into the Clave Disk
    /// ([`PathClass::WorkData`](crate::PathClass)).
    pub work_data_roots: Vec<String>,
    /// System path prefixes needing copy-on-write so the base system is never mutated
    /// ([`PathClass::SystemCow`](crate::PathClass)).
    pub cow_roots: Vec<String>,
}

/// A zone pair, handy for exhaustive iteration in tests and policy tooling.
pub const ZONE_PAIRS: [(Zone, Zone); 4] = [
    (Zone::Work, Zone::Work),
    (Zone::Work, Zone::Personal),
    (Zone::Personal, Zone::Work),
    (Zone::Personal, Zone::Personal),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn net(blocked: &[&str]) -> NetworkPolicy {
        NetworkPolicy {
            blocked_hosts: blocked.iter().map(|s| s.to_string()).collect(),
            static_egress_ip: None,
        }
    }

    #[test]
    fn denylist_matches_exact_host() {
        let p = net(&["evil.example"]);
        assert!(p.is_blocked("evil.example"));
        assert!(!p.is_blocked("good.example"));
    }

    #[test]
    fn denylist_is_case_insensitive() {
        // DNS is case-insensitive; a byte-exact match let `Evil.Example` slip past.
        let p = net(&["evil.example"]);
        assert!(p.is_blocked("Evil.Example"));
        assert!(p.is_blocked("EVIL.EXAMPLE"));
        // ...and a mixed-case stored entry still matches a lowercase query.
        assert!(net(&["EVIL.example"]).is_blocked("evil.example"));
    }

    #[test]
    fn denylist_ignores_trailing_dot_fqdn() {
        // `evil.example.` (fully-qualified, root-labelled) is the same name as `evil.example`.
        assert!(net(&["evil.example"]).is_blocked("evil.example."));
        assert!(net(&["evil.example."]).is_blocked("evil.example"));
    }

    #[test]
    fn denylist_does_not_match_subdomains() {
        // Documents the deferred limit: subdomain globbing is not yet implemented, so a child
        // label is not blocked by a parent entry.
        assert!(!net(&["evil.example"]).is_blocked("sub.evil.example"));
    }

    #[test]
    fn overlay_policy_defaults_to_clave_edge() {
        let p = PolicyBundle::restrictive_default();
        assert_eq!(p.overlay, OverlayPolicy::default());
        let cfg = p.overlay.border_cfg();
        assert_eq!(cfg.color, Rgba::CLAVE_EDGE);
        assert_eq!(cfg.thickness, 3);
    }

    #[test]
    fn overlay_policy_is_themable_via_border_cfg() {
        let overlay = OverlayPolicy {
            color: Rgba {
                r: 0xFF,
                g: 0x00,
                b: 0x00,
                a: 0xFF,
            },
            thickness: 6,
        };
        let cfg = overlay.border_cfg();
        assert_eq!(cfg.thickness, 6);
        assert_eq!(cfg.color.r, 0xFF);
    }

    #[test]
    fn overlay_policy_missing_in_json_falls_back_to_default() {
        // Older bundles won't carry an `overlay` field; `#[serde(default)]` must fill it in.
        let json = r#"{
            "version": 1,
            "not_after": 9999999999,
            "clipboard": { "work_to_personal_allow": [], "personal_to_work_sanitize": [] },
            "network": { "blocked_hosts": [], "static_egress_ip": null },
            "files": { "allow_save_outside_enclave": false, "work_data_roots": [], "cow_roots": [] },
            "apps": { "allow": [] }
        }"#;
        let p: PolicyBundle = serde_json::from_str(json).expect("parse legacy bundle");
        assert_eq!(p.overlay, OverlayPolicy::default());
    }
}
