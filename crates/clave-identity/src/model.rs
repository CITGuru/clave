//! The identity value types the gateway hydrates from Postgres and hands to [`crate::authz`].
//!
//! These are plain data — no methods that touch the network or clock — so the authorization
//! decisions over them stay pure and exhaustively testable.

use serde::{Deserialize, Serialize};

use crate::{EmailAddr, UnixTime, UserId, WorkspaceId};

/// A member's role within a workspace. Ordered by privilege so authorization can be a single
/// comparison: the declaration order makes `Member < Admin < Owner`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Member,
    Admin,
    Owner,
}

/// Lifecycle of a [`Membership`]. Only `Active` is admitted; `Suspended` is the SCIM/admin
/// deprovision state and `Invited` means an invitation exists but is not yet accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipStatus {
    Invited,
    Active,
    Suspended,
}

/// Whether a workspace merely *offers* SSO or *requires* it. `Required` rejects password /
/// magic-link sign-ins — only a verified IdP assertion is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsoMode {
    Optional,
    Required,
}

/// How a human proved their identity at the IdP (WorkOS) before this crate decides admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// Email magic-link / one-time code (WorkOS Magic Auth).
    EmailCode,
    /// Password (WorkOS AuthKit).
    Password,
    /// Federated SSO via the workspace's IdP connection (Okta/Entra/Google). `verified` records
    /// whether the provider actually validated the assertion *for this workspace*.
    Sso { verified: bool },
}

impl AuthMethod {
    /// True only for an SSO sign-in whose assertion the provider verified.
    pub fn is_verified_sso(self) -> bool {
        matches!(self, AuthMethod::Sso { verified: true })
    }
}

/// A workspace == one tenant/customer org.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    /// Verified email domains (e.g. `["acme.com"]`). Empty ⇒ pure invite-only: admission is gated
    /// solely by an explicit membership/invitation, with no domain constraint.
    pub allowed_domains: Vec<String>,
    /// Whether SSO is optional or mandatory for this workspace.
    pub sso: SsoMode,
}

impl Workspace {
    /// Does `email`'s domain satisfy this workspace's domain policy? Always `true` when no domains
    /// are configured (invite-only). Comparison is case-insensitive and tolerant of stray
    /// whitespace in the configured list.
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

/// A user's standing in a workspace — the authoritative "invited to the workspace" record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub workspace: WorkspaceId,
    pub user: UserId,
    pub role: Role,
    pub status: MembershipStatus,
}

/// A pending invitation to a workspace, addressed to an email that may not yet have an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub workspace: WorkspaceId,
    pub email: EmailAddr,
    pub role: Role,
    /// Invitations expire (fail-closed): after this instant [`crate::accept_invitation`] refuses.
    pub expires_at: UnixTime,
    pub accepted: bool,
}
