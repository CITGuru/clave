use std::sync::Arc;

use clave_gateway::{
    AuthMethod, DeviceId, DeviceStatus, EmailAddr, Gateway, GatewayError, MemStore, Membership,
    MembershipStatus, MockIdentityProvider, RequestContext, Role, SsoMode, Store, UserId,
    VerifiedUser, Workspace, WorkspaceId,
};

const WS: WorkspaceId = WorkspaceId(100);

fn workspace() -> Workspace {
    Workspace {
        id: WS,
        allowed_domains: vec!["acme.com".to_string()],
        sso: SsoMode::Optional,
    }
}

fn active(user: u64, role: Role) -> Membership {
    Membership {
        workspace: WS,
        user: UserId(user),
        role,
        status: MembershipStatus::Active,
    }
}

fn ctx(user: u64, role: Role) -> RequestContext {
    RequestContext {
        user: UserId(user),
        workspace: WS,
        role,
    }
}

fn gateway(store: Arc<MemStore>) -> Gateway<MockIdentityProvider, Arc<MemStore>> {
    let vu = VerifiedUser {
        email: EmailAddr::parse("admin@acme.com").unwrap(),
        idp_user_id: "u1".to_string(),
        workspace: WS,
        method: AuthMethod::Password,
        access_token: "a".to_string(),
        refresh_token: "r".to_string(),
    };
    Gateway::new(MockIdentityProvider::new(vu, "approved-device"), store)
}

fn seeded() -> (Arc<MemStore>, Gateway<MockIdentityProvider, Arc<MemStore>>) {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace());
    store.seed_membership(active(1, Role::Admin));
    let gw = gateway(store.clone());
    (store, gw)
}

#[tokio::test]
async fn admin_invites_and_lists_members() {
    let (store, gw) = seeded();
    store.upsert_user(&EmailAddr::parse("dev@acme.com").unwrap(), "u2").await.unwrap();
    store.seed_membership(active(2, Role::Member));

    let inv = gw
        .invite_member(&ctx(1, Role::Admin), "new@acme.com", Role::Member, 9_999)
        .await
        .expect("invite");
    assert_eq!(inv.role, Role::Member);
    assert_eq!(gw.list_invitations(&ctx(1, Role::Admin)).await.unwrap().len(), 1);

    let members = gw.list_members(&ctx(1, Role::Admin)).await.unwrap();
    assert_eq!(members.len(), 2);
}

#[tokio::test]
async fn a_plain_member_cannot_reach_the_admin_surface() {
    let (_store, gw) = seeded();
    let err = gw.list_members(&ctx(9, Role::Member)).await.unwrap_err();
    assert!(matches!(err, GatewayError::Forbidden(_)));
}

#[tokio::test]
async fn change_role_refuses_to_grant_above_your_own() {
    let (store, gw) = seeded();
    store.seed_membership(active(2, Role::Member));

    gw.change_role(&ctx(1, Role::Admin), UserId(2), Role::Admin)
        .await
        .expect("admin can promote to admin");

    let err = gw
        .change_role(&ctx(1, Role::Admin), UserId(2), Role::Owner)
        .await
        .unwrap_err();
    assert!(matches!(err, GatewayError::Forbidden(_)));
}

#[tokio::test]
async fn suspend_then_restore_flips_membership_status() {
    let (store, gw) = seeded();
    store.seed_membership(active(2, Role::Member));

    gw.suspend_member(&ctx(1, Role::Admin), UserId(2)).await.unwrap();
    let m = store.membership(WS, UserId(2)).await.unwrap().unwrap();
    assert_eq!(m.status, MembershipStatus::Suspended);

    gw.restore_member(&ctx(1, Role::Admin), UserId(2)).await.unwrap();
    let m = store.membership(WS, UserId(2)).await.unwrap().unwrap();
    assert_eq!(m.status, MembershipStatus::Active);
}

#[tokio::test]
async fn admin_lists_locks_and_wipes_a_device() {
    let (store, gw) = seeded();
    store.record_device(WS, UserId(1), &[0xAB; 32]).await.unwrap();

    let devices = gw.list_devices(&ctx(1, Role::Admin)).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].status, DeviceStatus::Active);
    let id = devices[0].id;

    gw.lock_device(&ctx(1, Role::Admin), id).await.unwrap();
    assert_eq!(
        gw.list_devices(&ctx(1, Role::Admin)).await.unwrap()[0].status,
        DeviceStatus::Locked
    );

    gw.wipe_device(&ctx(1, Role::Admin), id).await.unwrap();
    assert_eq!(
        gw.list_devices(&ctx(1, Role::Admin)).await.unwrap()[0].status,
        DeviceStatus::Wiped
    );
}

#[tokio::test]
async fn controlling_an_unknown_device_is_not_found() {
    let (_store, gw) = seeded();
    let err = gw
        .lock_device(&ctx(1, Role::Admin), DeviceId(4242))
        .await
        .unwrap_err();
    assert!(matches!(err, GatewayError::NotFound(_)));
}

#[tokio::test]
async fn a_member_cannot_control_devices() {
    let (store, gw) = seeded();
    store.record_device(WS, UserId(1), &[0xAB; 32]).await.unwrap();
    let id = gw.list_devices(&ctx(1, Role::Admin)).await.unwrap()[0].id;

    let err = gw.lock_device(&ctx(2, Role::Member), id).await.unwrap_err();
    assert!(matches!(err, GatewayError::Forbidden(_)));
}
