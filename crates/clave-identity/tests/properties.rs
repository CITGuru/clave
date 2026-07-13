use clave_identity::{
    accept_invitation, authorize_enrollment, authorize_login, can, AdminAction, AuthMethod,
    DenyReason, EmailAddr, Invitation, InviteError, LoginDecision, Membership, MembershipStatus,
    Role, SsoMode, UserId, Workspace, WorkspaceId,
};
use proptest::prelude::*;
use proptest::string::string_regex;

fn re(pat: &str) -> impl Strategy<Value = String> {
    string_regex(pat).unwrap()
}

fn email_strat() -> impl Strategy<Value = EmailAddr> {
    (re("[a-z]{1,8}"), re("[a-z]{1,8}"), re("[a-z]{2,4}")).prop_map(|(l, d, t)| {
        EmailAddr::parse(&format!("{l}@{d}.{t}")).expect("regex builds valid email")
    })
}

fn role_strat() -> impl Strategy<Value = Role> {
    prop_oneof![Just(Role::Member), Just(Role::Admin), Just(Role::Owner)]
}

fn method_strat() -> impl Strategy<Value = AuthMethod> {
    prop_oneof![
        Just(AuthMethod::EmailCode),
        Just(AuthMethod::Password),
        Just(AuthMethod::Sso { verified: true }),
        Just(AuthMethod::Sso { verified: false }),
    ]
}

fn non_sso_method_strat() -> impl Strategy<Value = AuthMethod> {
    prop_oneof![
        Just(AuthMethod::EmailCode),
        Just(AuthMethod::Password),
        Just(AuthMethod::Sso { verified: false }),
    ]
}

fn workspace_strat() -> impl Strategy<Value = Workspace> {
    (
        any::<u64>(),
        prop::collection::vec(re("[a-z]{1,8}\\.[a-z]{2,4}"), 0..3),
        prop_oneof![Just(SsoMode::Optional), Just(SsoMode::Required)],
    )
        .prop_map(|(id, allowed_domains, sso)| Workspace {
            id: WorkspaceId(id),
            allowed_domains,
            sso,
        })
}

fn member_in(ws: &Workspace, role: Role, status: MembershipStatus) -> Membership {
    Membership {
        workspace: ws.id,
        user: UserId(1),
        role,
        status,
    }
}

proptest! {
    #[test]
    fn non_member_is_never_admitted(
        e in email_strat(), m in method_strat(), ws in workspace_strat(),
    ) {
        prop_assert!(!authorize_login(&e, m, &ws, None).is_allowed());
        prop_assert!(!authorize_enrollment(&ws, None).is_allowed());
    }

    #[test]
    fn suspended_member_is_never_admitted(
        e in email_strat(), m in method_strat(), ws in workspace_strat(), role in role_strat(),
    ) {
        let member = member_in(&ws, role, MembershipStatus::Suspended);
        prop_assert!(!authorize_login(&e, m, &ws, Some(&member)).is_allowed());
        prop_assert!(!authorize_enrollment(&ws, Some(&member)).is_allowed());
    }

    #[test]
    fn active_member_of_open_workspace_always_logs_in(
        e in email_strat(), m in method_strat(), id in any::<u64>(), role in role_strat(),
    ) {
        let ws = Workspace { id: WorkspaceId(id), allowed_domains: vec![], sso: SsoMode::Optional };
        let member = member_in(&ws, role, MembershipStatus::Active);
        prop_assert_eq!(authorize_login(&e, m, &ws, Some(&member)), LoginDecision::Allow { role });
    }

    #[test]
    fn sso_required_blocks_non_sso(
        e in email_strat(), m in non_sso_method_strat(), id in any::<u64>(), role in role_strat(),
    ) {
        let ws = Workspace { id: WorkspaceId(id), allowed_domains: vec![], sso: SsoMode::Required };
        let member = member_in(&ws, role, MembershipStatus::Active);
        prop_assert_eq!(
            authorize_login(&e, m, &ws, Some(&member)),
            LoginDecision::Deny(DenyReason::SsoRequired)
        );
    }

    #[test]
    fn domain_match_is_case_insensitive(local in re("[a-z]{1,8}"), dom in re("[a-z]{1,8}\\.[a-z]{2,4}")) {
        let e = EmailAddr::parse(&format!("{local}@{dom}")).unwrap();
        let ws = Workspace {
            id: WorkspaceId(1),
            allowed_domains: vec![dom.to_ascii_uppercase()],
            sso: SsoMode::Optional,
        };
        prop_assert!(ws.domain_allowed(&e));
    }

    #[test]
    fn expired_invitation_never_accepts(
        e in email_strat(),
        m in method_strat(),
        ws in workspace_strat(),
        role in role_strat(),
        expires_at in 0u64..1_000_000_000,
        delta in 1u64..1_000_000,
    ) {
        let inv = Invitation { workspace: ws.id, email: e.clone(), role, expires_at, accepted: false };
        let now = expires_at + delta;
        prop_assert_eq!(
            accept_invitation(UserId(1), &e, m, &ws, &inv, now),
            Err(InviteError::Expired)
        );
    }

    #[test]
    fn valid_invitation_yields_active_membership(
        e in email_strat(), id in any::<u64>(), role in role_strat(),
        expires_at in 1u64..1_000_000, before in 0u64..1,
    ) {
        let ws = Workspace { id: WorkspaceId(id), allowed_domains: vec![], sso: SsoMode::Optional };
        let inv = Invitation { workspace: ws.id, email: e.clone(), role, expires_at, accepted: false };
        let now = expires_at - 1 + before;
        let got = accept_invitation(UserId(9), &e, AuthMethod::EmailCode, &ws, &inv, now);
        prop_assert_eq!(
            got,
            Ok(Membership { workspace: ws.id, user: UserId(9), role, status: MembershipStatus::Active })
        );
    }

    #[test]
    fn authorization_is_monotonic_in_role(action in prop_oneof![
        Just(AdminAction::EnrollDevice),
        Just(AdminAction::ManageMembers),
        Just(AdminAction::ChangeRoles),
        Just(AdminAction::ManagePolicy),
        Just(AdminAction::ManageSso),
        Just(AdminAction::ControlDevice),
        Just(AdminAction::ViewAudit),
        Just(AdminAction::AdministerWorkspace),
    ]) {
        if can(Role::Member, action) {
            prop_assert!(can(Role::Admin, action) && can(Role::Owner, action));
        }
        if can(Role::Admin, action) {
            prop_assert!(can(Role::Owner, action));
        }
    }
}
