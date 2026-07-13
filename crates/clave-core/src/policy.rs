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
        }
    }
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
