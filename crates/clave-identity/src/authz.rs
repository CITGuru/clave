use crate::{
    AuthMethod, EmailAddr, Invitation, Membership, MembershipStatus, Role, SsoMode, UnixTime,
    UserId, Workspace, WorkspaceId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    NotAMember,
    Suspended,
    DomainNotAllowed,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginDecision {
    Allow { role: Role },
    Deny(DenyReason),
}

impl LoginDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, LoginDecision::Allow { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentDecision {
    Allow { workspace: WorkspaceId, role: Role },
    Deny(DenyReason),
}

impl EnrollmentDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, EnrollmentDecision::Allow { .. })
    }
}

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

pub fn authorize_login(
    email: &EmailAddr,
    method: AuthMethod,
    workspace: &Workspace,
    membership: Option<&Membership>,
) -> LoginDecision {
    if !workspace.domain_allowed(email) {
        return LoginDecision::Deny(DenyReason::DomainNotAllowed);
    }
    if workspace.sso == SsoMode::Required && !method.is_verified_sso() {
        return LoginDecision::Deny(DenyReason::SsoRequired);
    }
    match active_member_role(workspace, membership) {
        Ok(role) => LoginDecision::Allow { role },
        Err(reason) => LoginDecision::Deny(reason),
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteError {
    EmailMismatch,
    AlreadyAccepted,
    Expired,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminAction {
    EnrollDevice,
    ManageMembers,
    ChangeRoles,
    ManagePolicy,
    ManageSso,
    ControlDevice,
    ViewAudit,
    AdministerWorkspace,
}

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

pub fn can(role: Role, action: AdminAction) -> bool {
    role >= min_role(action)
}
