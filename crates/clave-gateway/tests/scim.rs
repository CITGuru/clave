use std::sync::Arc;

use clave_gateway::{
    AuthMethod, EmailAddr, Gateway, MemStore, Membership, MembershipDelta, MembershipStatus,
    MockIdentityProvider, Role, ScimEvent, SsoMode, Store, UserId, VerifiedUser, Workspace,
    WorkspaceId,
};

const WS: WorkspaceId = WorkspaceId(100);

fn setup() -> (Arc<MemStore>, Gateway<MockIdentityProvider, Arc<MemStore>>) {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(Workspace {
        id: WS,
        allowed_domains: vec![],
        sso: SsoMode::Optional,
    });
    let vu = VerifiedUser {
        email: EmailAddr::parse("admin@acme.com").unwrap(),
        idp_user_id: "u1".to_string(),
        workspace: WS,
        method: AuthMethod::Password,
        access_token: "a".to_string(),
        refresh_token: "r".to_string(),
    };
    let gw = Gateway::new(MockIdentityProvider::new(vu, "d"), store.clone());
    (store, gw)
}

async fn seed_member(store: &MemStore, email: &str) -> UserId {
    let e = EmailAddr::parse(email).unwrap();
    let user = store.upsert_user(&e, "idp").await.unwrap();
    store
        .put_membership(&Membership {
            workspace: WS,
            user,
            role: Role::Member,
            status: MembershipStatus::Active,
        })
        .await
        .unwrap();
    user
}

fn deactivate(email: &str) -> ScimEvent {
    ScimEvent::UserDeactivated {
        workspace: WS,
        email: EmailAddr::parse(email).unwrap(),
    }
}

fn activate(email: &str) -> ScimEvent {
    ScimEvent::UserActivated {
        workspace: WS,
        email: EmailAddr::parse(email).unwrap(),
    }
}

#[tokio::test]
async fn deprovision_suspends_then_reprovision_restores() {
    let (store, gw) = setup();
    let user = seed_member(&store, "dev@acme.com").await;

    let delta = gw
        .apply_directory_event(deactivate("dev@acme.com"))
        .await
        .unwrap();
    assert_eq!(delta, MembershipDelta::Suspended { user });
    assert_eq!(
        store.membership(WS, user).await.unwrap().unwrap().status,
        MembershipStatus::Suspended
    );

    let delta = gw
        .apply_directory_event(activate("dev@acme.com"))
        .await
        .unwrap();
    assert_eq!(delta, MembershipDelta::Restored { user });
    assert_eq!(
        store.membership(WS, user).await.unwrap().unwrap().status,
        MembershipStatus::Active
    );
}

#[tokio::test]
async fn an_event_for_an_unknown_member_changes_nothing() {
    let (_store, gw) = setup();
    let delta = gw
        .apply_directory_event(deactivate("stranger@acme.com"))
        .await
        .unwrap();
    assert_eq!(delta, MembershipDelta::Unchanged);
}

#[tokio::test]
async fn deactivating_an_already_suspended_member_is_a_no_op() {
    let (store, gw) = setup();
    seed_member(&store, "dev@acme.com").await;
    gw.apply_directory_event(deactivate("dev@acme.com"))
        .await
        .unwrap();

    let delta = gw
        .apply_directory_event(deactivate("dev@acme.com"))
        .await
        .unwrap();
    assert_eq!(delta, MembershipDelta::Unchanged);
}
