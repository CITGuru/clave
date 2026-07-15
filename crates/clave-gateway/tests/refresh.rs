use std::sync::Arc;

use clave_gateway::{
    AuthMethod, EmailAddr, Gateway, GatewayError, MemStore, Membership, MembershipStatus,
    MockIdentityProvider, Role, Session, SsoMode, UserId, VerifiedUser, Workspace, WorkspaceId,
};

const WS: WorkspaceId = WorkspaceId(100);

fn verified() -> VerifiedUser {
    VerifiedUser {
        email: EmailAddr::parse("ceo@acme.com").unwrap(),
        idp_user_id: "u1".to_string(),
        workspace: WS,
        method: AuthMethod::Password,
        access_token: "access".to_string(),
        refresh_token: "rotated".to_string(),
    }
}

fn setup(status: MembershipStatus) -> (Arc<MemStore>, Gateway<MockIdentityProvider, Arc<MemStore>>) {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(Workspace {
        id: WS,
        allowed_domains: vec!["acme.com".to_string()],
        sso: SsoMode::Optional,
    });
    store.seed_membership(Membership {
        workspace: WS,
        user: UserId(1),
        role: Role::Admin,
        status,
    });
    let gw = Gateway::new(MockIdentityProvider::new(verified(), "d"), store.clone());
    (store, gw)
}

fn expired_session() -> Session {
    Session {
        user: UserId(1),
        workspace: WS,
        role: Role::Admin,
        expires_at: 500,
        refresh_token: "old-refresh".to_string(),
    }
}

#[tokio::test]
async fn an_expired_session_refreshes_with_a_new_expiry_and_token() {
    let (_store, gw) = setup(MembershipStatus::Active);
    let refreshed = gw
        .refresh_session(&expired_session(), 1_000, 3_600)
        .await
        .expect("refresh succeeds");
    assert_eq!(refreshed.expires_at, 1_000 + 3_600);
    assert_eq!(refreshed.role, Role::Admin);
    assert_eq!(refreshed.user, UserId(1));
    assert_eq!(refreshed.refresh_token, "rotated");
}

#[tokio::test]
async fn a_suspended_member_cannot_refresh() {
    let (_store, gw) = setup(MembershipStatus::Suspended);
    assert!(matches!(
        gw.refresh_session(&expired_session(), 1_000, 3_600).await,
        Err(GatewayError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn a_session_without_a_refresh_token_cannot_refresh() {
    let (_store, gw) = setup(MembershipStatus::Active);
    let mut session = expired_session();
    session.refresh_token = String::new();
    assert!(matches!(
        gw.refresh_session(&session, 1_000, 3_600).await,
        Err(GatewayError::Idp(_))
    ));
}
