//! The policy model.
//!
//! A [`PolicyBundle`] is the signed, versioned unit the gateway delivers and the daemon
//! caches inside the encrypted volume. Here we model the data and the *sub-decisions*; the
//! single entry point that combines them is [`crate::decide::decide`].
//!
//! Phase 1 implements the clipboard / network / file sub-policies. Screen, input, and app
//! allow-listing slot in the same way and are added in later milestones.

use clave_platform::{ClipFormat, Decision, Zone};
use serde::{Deserialize, Serialize};

use crate::app::AppPolicy;

/// Seconds since the Unix epoch. Time is always *passed in* to the decision functions —
/// the core never reads an ambient clock, which keeps every decision deterministic and
/// replayable for audit.
pub type UnixTime = u64;

/// The signed policy unit. (Signature/tenant fields are added with `clave-proto`; omitted
/// here so the core stays free of crypto deps for Phase 1.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Monotonic; the daemon rejects a bundle whose version is below the last applied
    /// (rollback protection).
    pub version: u64,
    /// Expiry. After this instant every decision fails closed (see [`crate::decide::decide`]).
    pub not_after: UnixTime,
    pub clipboard: ClipboardPolicy,
    pub network: NetworkPolicy,
    pub files: FilePolicy,
    /// Which binaries may run as supervised work apps.
    pub apps: AppPolicy,
}

impl PolicyBundle {
    /// The conservative bundle used before the first successful gateway sync, and the safe
    /// fallback if a delivered bundle fails to parse/verify. Blocks all cross-zone transfer
    /// and all out-of-enclave work writes. `not_after` is "never" so the default itself does
    /// not expire (a device that has *never* synced is still protected, just restricted).
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
        }
    }
}

/// Clipboard / drag-drop matrix policy. The cross-zone rows are configurable per format;
/// the same-zone rows are fixed in [`crate::decide::clip_decision`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardPolicy {
    /// Formats permitted to move **work → personal**. Anything not listed is denied
    /// (default-deny exfil).
    pub work_to_personal_allow: Vec<ClipFormat>,
    /// Formats that must be **sanitized** on **personal → work** (e.g. strip active content
    /// to prevent paste-based injection into work apps). Anything not listed is allowed
    /// as-is.
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

/// Normalize a DNS name for denylist comparison. DNS is case-insensitive, and a trailing dot (the
/// FQDN root label) is not significant — so `Evil.Example` and `evil.example.` must both match a
/// stored `evil.example`. Without this the byte-exact match was trivially bypassable.
///
/// Two limits remain and are intentional here: subdomain/glob matching (`*.evil.example`) is a
/// separate deferred feature, and a connection made to a **raw IP** is not caught by a *name*
/// denylist at all. The authoritative egress control is the tunnel, not this list.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// File-save policy for supervised processes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePolicy {
    /// If false (the safe default), a supervised process may not create/write work data
    /// outside the encrypted volume. The kernel minifilter / ES `AUTH_OPEN` is the
    /// authoritative enforcer; this flag is the policy the core hands it.
    pub allow_save_outside_enclave: bool,
    /// Path prefixes whose contents are **work data**: a supervised app's access there is
    /// redirected into the Clave Disk ([`PathClass::WorkData`](crate::PathClass)).
    pub work_data_roots: Vec<String>,
    /// System path prefixes a supervised app writes to that need **copy-on-write** so the base
    /// system is never mutated ([`PathClass::SystemCow`](crate::PathClass)).
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
}
