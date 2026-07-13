use clave_platform::{ClipFormat, Decision, Rgba, Zone};
use serde::{Deserialize, Serialize};

use crate::app::AppPolicy;
use crate::overlay::BorderCfg;

pub type UnixTime = u64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub version: u64,
    pub not_after: UnixTime,
    pub clipboard: ClipboardPolicy,
    pub network: NetworkPolicy,
    pub files: FilePolicy,
    pub apps: AppPolicy,
    #[serde(default)]
    pub overlay: OverlayPolicy,
    #[serde(default)]
    pub screen: ScreenPolicy,
    #[serde(default)]
    pub input: InputPolicy,
}

impl PolicyBundle {
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
            apps: AppPolicy::empty(),
            overlay: OverlayPolicy::default(),
            screen: ScreenPolicy::default(),
            input: InputPolicy::default(),
        }
    }
}

/// What may read the keyboard while a work app has focus.
///
/// Kept separate from [`ScreenPolicy`] even though the shape matches: an admin may well sanction a
/// meeting app to capture the screen while never sanctioning anything to read keystrokes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputPolicy {
    /// What to do when a non-work process holds a keyboard event tap while a work app is focused.
    #[serde(default = "default_on_tap")]
    pub on_tap: Decision,
    /// Tools permitted to tap the keyboard even under a work app — a text expander or hotkey
    /// launcher the company sanctions. Matched against the process's executable name.
    #[serde(default)]
    pub allowed_tappers: Vec<String>,
}

impl Default for InputPolicy {
    fn default() -> Self {
        Self {
            on_tap: default_on_tap(),
            allowed_tappers: Vec::new(),
        }
    }
}

impl InputPolicy {
    pub fn is_allowed_tapper(&self, exe: &str) -> bool {
        self.allowed_tappers.iter().any(|a| a == exe)
    }
}

/// Deny by default: nothing outside the enclave reads work keystrokes. macOS cannot *enforce* this
/// (doc 06 §3.1 — no shippable kernel input filter); the denial is still the decision, and an
/// unenforceable one is audited.
fn default_on_tap() -> Decision {
    Decision::Deny
}

/// What may capture the screen while work windows are on it.
///
/// A capture is only ever a *work* concern when work content is actually visible — a screenshot of
/// a personal desktop is none of our business (doc 01: personal resources are never instrumented).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenPolicy {
    /// What to do when a non-work process captures the screen while work windows are visible.
    #[serde(default = "default_on_capture")]
    pub on_capture: Decision,
    /// Capture tools permitted even over work content — e.g. the sanctioned meeting app that
    /// employees are expected to screen-share from. Matched against the process's executable name.
    #[serde(default)]
    pub allowed_capturers: Vec<String>,
}

impl Default for ScreenPolicy {
    fn default() -> Self {
        Self {
            on_capture: default_on_capture(),
            allowed_capturers: Vec::new(),
        }
    }
}

impl ScreenPolicy {
    /// Whether `exe` (a process's executable name) is a sanctioned capture tool.
    pub fn is_allowed_capturer(&self, exe: &str) -> bool {
        self.allowed_capturers.iter().any(|a| a == exe)
    }
}

/// Deny by default: work content is not screenshot-able. macOS cannot always *enforce* this
/// (doc 07 §3.4) — the decision is still the decision, and an unenforceable denial is audited.
fn default_on_capture() -> Decision {
    Decision::Deny
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayPolicy {
    #[serde(default = "default_edge_color")]
    pub color: Rgba,
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
    pub fn border_cfg(&self) -> BorderCfg {
        BorderCfg {
            thickness: self.thickness as i32,
            color: self.color,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardPolicy {
    pub work_to_personal_allow: Vec<ClipFormat>,
    pub personal_to_work_sanitize: Vec<ClipFormat>,
}

impl ClipboardPolicy {
    pub fn work_to_personal(&self, fmt: ClipFormat) -> Decision {
        if self.work_to_personal_allow.contains(&fmt) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    pub fn personal_to_work(&self, fmt: ClipFormat) -> Decision {
        if self.personal_to_work_sanitize.contains(&fmt) {
            Decision::Sanitize
        } else {
            Decision::Allow
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub blocked_hosts: Vec<String>,
    pub static_egress_ip: Option<String>,
}

impl NetworkPolicy {
    pub fn is_blocked(&self, host: &str) -> bool {
        let host = normalize_host(host);
        self.blocked_hosts.iter().any(|h| normalize_host(h) == host)
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePolicy {
    pub allow_save_outside_enclave: bool,
    pub work_data_roots: Vec<String>,
    pub cow_roots: Vec<String>,
}

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
        let p = net(&["evil.example"]);
        assert!(p.is_blocked("Evil.Example"));
        assert!(p.is_blocked("EVIL.EXAMPLE"));
        assert!(net(&["EVIL.example"]).is_blocked("evil.example"));
    }

    #[test]
    fn denylist_ignores_trailing_dot_fqdn() {
        assert!(net(&["evil.example"]).is_blocked("evil.example."));
        assert!(net(&["evil.example."]).is_blocked("evil.example"));
    }

    #[test]
    fn denylist_does_not_match_subdomains() {
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
