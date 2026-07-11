//! The fail-closed authorization decisions.
//!
//! Every function here is pure and deterministic: given the workspace, the membership, and (for
//! invitations) the current time, it returns admit-or-deny with an explainable reason. The only
//! path to "admit" is an `Active` member who clears the workspace's domain and SSO policy — every
//! other input falls closed.

use crate::{
    AuthMethod, EmailAddr, Invitation, Membership, MembershipStatus, Role, SsoMode, UnixTime,
    UserId, Workspace, WorkspaceId,
};

/// Why an identity request was refused. Every variant means **no access was granted**; the caller
/// returns the restrictive outcome. Mirrors `clave_core::Reason` for explainable audit/UX.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// Not an active member of this workspace (never invited, or the invite is unaccepted).
    NotAMember,
    /// A membership exists but is suspended (e.g. SCIM/admin deprovision).
    Suspended,
    /// The email's domain is not on the workspace's verified-domain allowlist.
    DomainNotAllowed,
    /// The workspace requires SSO and the sign-in did not present a verified SSO assertion.
    SsoRequired,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DenyReason::NotAMember => "not an active member of this workspace",
            DenyReason::Suspended => "membership is suspended",
            DenyReason::DomainNotAllowed => "email domain is not allowed for this workspace",
            DenyReason::SsoRequired => "this workspace requires SSO sign-in",
        };
        f.write_str(s)
    }
}

/// Outcome of an admin-console sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginDecision {
    /// Sign-in permitted; the session carries this role.
    Allow { role: Role },
    Deny(DenyReason),
}

impl LoginDecision {
    /// Whether sign-in was permitted.
    pub fn is_allowed(self) -> bool {
        matches!(self, LoginDecision::Allow { .. })
    }
}

/// Outcome of a device enrollment request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentDecision {
    /// Enrollment may proceed: the device will be bound to this workspace (tenant) and the
    /// enrolling user holds this role. Only after `Allow` does the gateway issue the device
    /// certificate, the wrapped volume key, and the signed policy bundle.
    Allow { workspace: WorkspaceId, role: Role },
    Deny(DenyReason),
}

impl EnrollmentDecision {
    /// Whether enrollment was permitted.
    pub fn is_allowed(self) -> bool {
        matches!(self, EnrollmentDecision::Allow { .. })
    }
}

/// The single admission gate shared by login and enrollment: resolve a membership to the role it
/// grants, or the reason it does not. The lone "admit" path in the whole crate.
fn active_member_role(
    workspace: &Workspace,
    membership: Option<&Membership>,
) -> Result<Role, DenyReason> {
    match membership {
        Some(m) if m.workspace == workspace.id => match m.status {
            MembershipStatus::Active => Ok(m.role),
            MembershipStatus::Suspended => Err(DenyReason::Suspended),
            MembershipStatus::Invited => Err(DenyReason::NotAMember),
        },
        _ => Err(DenyReason::NotAMember),
    }
}

/// Decide an admin-console sign-in. The IdP (WorkOS) has already proven `email`/`method`; this
/// applies the workspace's domain + SSO policy and the authoritative membership gate.
pub fn authorize_login(
    email: &EmailAddr,
    method: AuthMethod,
    workspace: &Workspace,
    membership: Option<&Membership>,
) -> LoginDecision {
    // Work-email domain policy (defense in depth: enforced even for an existing member).
    if !workspace.domain_allowed(email) {
        return LoginDecision::Deny(DenyReason::DomainNotAllowed);
    }
    // SSO mandate.
    if workspace.sso == SsoMode::Required && !method.is_verified_sso() {
        return LoginDecision::Deny(DenyReason::SsoRequired);
    }
    match active_member_role(workspace, membership) {
        Ok(role) => LoginDecision::Allow { role },
        Err(reason) => LoginDecision::Deny(reason),
    }
}

/// Decide a device enrollment. Identity/freshness were established by the device-code flow at the
/// IdP; this checks the enrolling user is an active member of the target workspace.
pub fn authorize_enrollment(
    workspace: &Workspace,
    membership: Option<&Membership>,
) -> EnrollmentDecision {
    match active_member_role(workspace, membership) {
        Ok(role) => EnrollmentDecision::Allow {
            workspace: workspace.id,
            role,
        },
        Err(reason) => EnrollmentDecision::Deny(reason),
    }
}

/// Why an invitation could not be accepted. Every variant leaves the user a non-member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteError {
    /// The invitation address does not match the authenticated email.
    EmailMismatch,
    /// The invitation was already accepted.
    AlreadyAccepted,
    /// The invitation has expired (`now > expires_at`).
    Expired,
    /// Domain or SSO policy was not satisfied; carries the underlying reason.
    Rejected(DenyReason),
}

impl std::fmt::Display for InviteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InviteError::EmailMismatch => f.write_str("invitation is for a different email"),
            InviteError::AlreadyAccepted => f.write_str("invitation already accepted"),
            InviteError::Expired => f.write_str("invitation has expired"),
            InviteError::Rejected(r) => write!(f, "invitation rejected: {r}"),
        }
    }
}

impl std::error::Error for InviteError {}

/// Accept an invitation for the authenticated `user`/`email`, producing the `Active` [`Membership`]
/// the gateway then persists. Fail-closed: email must match, the invite must be unexpired and
/// unaccepted, and the workspace's domain + SSO policy must hold.
///
/// `user` is supplied by the caller because minting a [`UserId`] is the database's job, not the
/// pure core's — the gateway has already resolved the authenticated human to a row.
pub fn accept_invitation(
    user: UserId,
    email: &EmailAddr,
    method: AuthMethod,
    workspace: &Workspace,
    invitation: &Invitation,
    now: UnixTime,
) -> Result<Membership, InviteError> {
    if &invitation.email != email {
        return Err(InviteError::EmailMismatch);
    }
    if invitation.accepted {
        return Err(InviteError::AlreadyAccepted);
    }
    if now > invitation.expires_at {
        return Err(InviteError::Expired);
    }
    if !workspace.domain_allowed(email) {
        return Err(InviteError::Rejected(DenyReason::DomainNotAllowed));
    }
    if workspace.sso == SsoMode::Required && !method.is_verified_sso() {
        return Err(InviteError::Rejected(DenyReason::SsoRequired));
    }
    Ok(Membership {
        workspace: workspace.id,
        user,
        role: invitation.role,
        status: MembershipStatus::Active,
    })
}

/// A privileged control-plane action whose authorization depends on the actor's [`Role`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminAction {
    /// Enroll a new device under one's own account.
    EnrollDevice,
    /// Invite members or revoke invitations.
    ManageMembers,
    /// Change another member's role.
    ChangeRoles,
    /// Edit and publish the workspace's policy bundle.
    ManagePolicy,
    /// Configure the SSO / SCIM connection.
    ManageSso,
    /// Lock or wipe an enrolled device.
    ControlDevice,
    /// Read the audit log.
    ViewAudit,
    /// Delete the workspace or transfer ownership.
    AdministerWorkspace,
}

/// The least-privileged [`Role`] permitted to perform `action`. Authorization is monotonic:
/// any role `>= min_role(action)` may act.
pub fn min_role(action: AdminAction) -> Role {
    use AdminAction::*;
    match action {
        EnrollDevice => Role::Member,
        ManageMembers | ChangeRoles | ManagePolicy | ManageSso | ControlDevice | ViewAudit => {
            Role::Admin
        }
        AdministerWorkspace => Role::Owner,
    }
}

/// Whether `role` may perform `action`. Monotonic in role: `Owner ⊇ Admin ⊇ Member`.
pub fn can(role: Role, action: AdminAction) -> bool {
    role >= min_role(action)
}
