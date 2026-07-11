//! Worked examples for the identity authorization brain.

use clave_identity::{
    accept_invitation, authorize_enrollment, authorize_login, can, AdminAction, AuthMethod,
    DenyReason, EmailAddr, EnrollmentDecision, Invitation, InviteError, LoginDecision, Membership,
    MembershipStatus, Role, SsoMode, UserId, Workspace, WorkspaceId,
};

fn email(s: &str) -> EmailAddr {
    EmailAddr::parse(s).expect("valid email")
}

fn workspace(domains: &[&str], sso: SsoMode) -> Workspace {
    Workspace {
        id: WorkspaceId(1),
        allowed_domains: domains.iter().map(|d| d.to_string()).collect(),
        sso,
    }
}

fn member(ws: &Workspace, role: Role, status: MembershipStatus) -> Membership {
    Membership {
        workspace: ws.id,
        user: UserId(7),
        role,
        status,
    }
}

#[test]
fn active_member_logs_in_with_their_role() {
    let ws = workspace(&[], SsoMode::Optional);
    let m = member(&ws, Role::Admin, MembershipStatus::Active);
    assert_eq!(
        authorize_login(&email("ceo@acme.com"), AuthMethod::Password, &ws, Some(&m)),
        LoginDecision::Allow { role: Role::Admin }
    );
}

#[test]
fn non_member_is_denied() {
    let ws = workspace(&[], SsoMode::Optional);
    assert_eq!(
        authorize_login(&email("stranger@evil.com"), AuthMethod::EmailCode, &ws, None),
        LoginDecision::Deny(DenyReason::NotAMember)
    );
}

#[test]
fn suspended_member_is_denied() {
    let ws = workspace(&[], SsoMode::Optional);
    let m = member(&ws, Role::Owner, MembershipStatus::Suspended);
    assert_eq!(
        authorize_login(&email("ex@acme.com"), AuthMethod::Password, &ws, Some(&m)),
        LoginDecision::Deny(DenyReason::Suspended)
    );
}

#[test]
fn invited_but_unaccepted_cannot_log_in() {
    let ws = workspace(&[], SsoMode::Optional);
    let m = member(&ws, Role::Member, MembershipStatus::Invited);
    assert_eq!(
        authorize_login(&email("new@acme.com"), AuthMethod::EmailCode, &ws, Some(&m)),
        LoginDecision::Deny(DenyReason::NotAMember)
    );
}

#[test]
fn wrong_domain_is_denied_even_for_a_member() {
    let ws = workspace(&["acme.com"], SsoMode::Optional);
    let m = member(&ws, Role::Admin, MembershipStatus::Active);
    assert_eq!(
        authorize_login(&email("user@gmail.com"), AuthMethod::Password, &ws, Some(&m)),
        LoginDecision::Deny(DenyReason::DomainNotAllowed)
    );
}

#[test]
fn allowed_domain_matches_case_insensitively() {
    let ws = workspace(&["Acme.COM"], SsoMode::Optional);
    let m = member(&ws, Role::Member, MembershipStatus::Active);
    assert!(authorize_login(&email("User@ACME.com"), AuthMethod::Password, &ws, Some(&m)).is_allowed());
}

#[test]
fn sso_required_blocks_password_login() {
    let ws = workspace(&[], SsoMode::Required);
    let m = member(&ws, Role::Admin, MembershipStatus::Active);
    assert_eq!(
        authorize_login(&email("ceo@acme.com"), AuthMethod::Password, &ws, Some(&m)),
        LoginDecision::Deny(DenyReason::SsoRequired)
    );
}

#[test]
fn sso_required_admits_verified_sso() {
    let ws = workspace(&[], SsoMode::Required);
    let m = member(&ws, Role::Admin, MembershipStatus::Active);
    assert_eq!(
        authorize_login(
            &email("ceo@acme.com"),
            AuthMethod::Sso { verified: true },
            &ws,
            Some(&m)
        ),
        LoginDecision::Allow { role: Role::Admin }
    );
}

#[test]
fn active_member_may_enroll_a_device() {
    let ws = workspace(&[], SsoMode::Optional);
    let m = member(&ws, Role::Member, MembershipStatus::Active);
    assert_eq!(
        authorize_enrollment(&ws, Some(&m)),
        EnrollmentDecision::Allow {
            workspace: ws.id,
            role: Role::Member
        }
    );
}

#[test]
fn suspended_member_cannot_enroll() {
    let ws = workspace(&[], SsoMode::Optional);
    let m = member(&ws, Role::Member, MembershipStatus::Suspended);
    assert_eq!(
        authorize_enrollment(&ws, Some(&m)),
        EnrollmentDecision::Deny(DenyReason::Suspended)
    );
}

fn invite(ws: &Workspace, to: &str, role: Role, expires_at: u64) -> Invitation {
    Invitation {
        workspace: ws.id,
        email: email(to),
        role,
        expires_at,
        accepted: false,
    }
}

#[test]
fn accepting_a_valid_invitation_creates_an_active_membership() {
    let ws = workspace(&["acme.com"], SsoMode::Optional);
    let inv = invite(&ws, "new@acme.com", Role::Admin, 1_000);
    let got = accept_invitation(
        UserId(42),
        &email("New@Acme.com"),
        AuthMethod::EmailCode,
        &ws,
        &inv,
        500,
    )
    .expect("accepted");
    assert_eq!(
        got,
        Membership {
            workspace: ws.id,
            user: UserId(42),
            role: Role::Admin,
            status: MembershipStatus::Active,
        }
    );
}

#[test]
fn expired_invitation_is_rejected() {
    let ws = workspace(&[], SsoMode::Optional);
    let inv = invite(&ws, "late@acme.com", Role::Member, 1_000);
    assert_eq!(
        accept_invitation(UserId(1), &email("late@acme.com"), AuthMethod::EmailCode, &ws, &inv, 1_001),
        Err(InviteError::Expired)
    );
}

#[test]
fn invitation_for_another_email_is_rejected() {
    let ws = workspace(&[], SsoMode::Optional);
    let inv = invite(&ws, "intended@acme.com", Role::Member, 1_000);
    assert_eq!(
        accept_invitation(UserId(1), &email("someone@acme.com"), AuthMethod::EmailCode, &ws, &inv, 500),
        Err(InviteError::EmailMismatch)
    );
}

#[test]
fn already_accepted_invitation_is_rejected() {
    let ws = workspace(&[], SsoMode::Optional);
    let mut inv = invite(&ws, "dup@acme.com", Role::Member, 1_000);
    inv.accepted = true;
    assert_eq!(
        accept_invitation(UserId(1), &email("dup@acme.com"), AuthMethod::EmailCode, &ws, &inv, 500),
        Err(InviteError::AlreadyAccepted)
    );
}

#[test]
fn role_permissions() {
    assert!(can(Role::Member, AdminAction::EnrollDevice));
    assert!(!can(Role::Member, AdminAction::ManagePolicy));
    assert!(!can(Role::Member, AdminAction::ViewAudit));

    assert!(can(Role::Admin, AdminAction::ManagePolicy));
    assert!(can(Role::Admin, AdminAction::ViewAudit));
    assert!(can(Role::Admin, AdminAction::ControlDevice));
    assert!(!can(Role::Admin, AdminAction::AdministerWorkspace));

    assert!(can(Role::Owner, AdminAction::AdministerWorkspace));
}

#[test]
fn email_parsing_normalizes_and_validates() {
    assert_eq!(email("  CEO@Acme.COM ").as_str(), "ceo@acme.com");
    assert_eq!(email("a@b.co").domain(), "b.co");
    assert!(EmailAddr::parse("no-at-sign").is_none());
    assert!(EmailAddr::parse("@acme.com").is_none());
    assert!(EmailAddr::parse("user@nodot").is_none());
    assert!(EmailAddr::parse("two@@acme.com").is_none());
    assert!(EmailAddr::parse("user name@acme.com").is_none());
}
