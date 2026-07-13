#![forbid(unsafe_code)]

mod authz;
mod model;

pub use authz::{
    accept_invitation, authorize_enrollment, authorize_login, can, min_role, AdminAction,
    DenyReason, EnrollmentDecision, InviteError, LoginDecision,
};
pub use model::{AuthMethod, Invitation, Membership, MembershipStatus, Role, SsoMode, Workspace};

use serde::{Deserialize, Serialize};

pub type UnixTime = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmailAddr(String);

impl EmailAddr {
    pub fn parse(raw: &str) -> Option<EmailAddr> {
        let s = raw.trim().to_ascii_lowercase();
        if s.contains(char::is_whitespace) {
            return None;
        }
        let (local, domain) = s.split_once('@')?;
        if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
            return None;
        }
        Some(EmailAddr(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn domain(&self) -> &str {
        self.0.split_once('@').map(|(_, d)| d).unwrap_or("")
    }
}

impl std::fmt::Display for EmailAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
