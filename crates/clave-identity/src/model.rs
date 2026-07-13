use serde::{Deserialize, Serialize};

use crate::{EmailAddr, UnixTime, UserId, WorkspaceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Member,
    Admin,
    Owner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipStatus {
    Invited,
    Active,
    Suspended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsoMode {
    Optional,
    Required,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    EmailCode,
    Password,
    Sso { verified: bool },
}

impl AuthMethod {
    pub fn is_verified_sso(self) -> bool {
        matches!(self, AuthMethod::Sso { verified: true })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub allowed_domains: Vec<String>,
    pub sso: SsoMode,
}

impl Workspace {
    pub fn domain_allowed(&self, email: &EmailAddr) -> bool {
        if self.allowed_domains.is_empty() {
            return true;
        }
        let d = email.domain();
        self.allowed_domains
            .iter()
            .any(|allowed| allowed.trim().eq_ignore_ascii_case(d))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub workspace: WorkspaceId,
    pub user: UserId,
    pub role: Role,
    pub status: MembershipStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub workspace: WorkspaceId,
    pub email: EmailAddr,
    pub role: Role,
    pub expires_at: UnixTime,
    pub accepted: bool,
}
