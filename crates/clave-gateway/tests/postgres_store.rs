#![cfg(feature = "postgres")]

use std::time::{SystemTime, UNIX_EPOCH};

use clave_gateway::{
    EmailAddr, Invitation, Membership, MembershipStatus, PgStore, Role, SsoMode, Store, Workspace,
    WorkspaceId,
};

async fn connect() -> Option<PgStore> {
    let url = std::env::var("CLAVE_TEST_DATABASE_URL").ok()?;
    let store = PgStore::connect(&url)
        .await
        .expect("connect to CLAVE_TEST_DATABASE_URL");
    store.migrate().await.expect("run migrations");
    Some(store)
}

fn unique_suffix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[tokio::test]
async fn pg_store_round_trips_the_whole_identity_surface() {
    let Some(store) = connect().await else {
        eprintln!("skipping pg_store test: set CLAVE_TEST_DATABASE_URL to run it");
        return;
    };

    let n = unique_suffix();
    let ws_id = WorkspaceId(n);
    let member_email = EmailAddr::parse(&format!("dev+{n}@acme.com")).unwrap();
    let invitee_email = EmailAddr::parse(&format!("invitee+{n}@acme.com")).unwrap();

    store
        .upsert_workspace(&Workspace {
            id: ws_id,
            allowed_domains: vec!["acme.com".into()],
            sso: SsoMode::Required,
        })
        .await
        .unwrap();
    let ws = store
        .workspace(ws_id)
        .await
        .unwrap()
        .expect("workspace exists");
    assert_eq!(ws.allowed_domains, vec!["acme.com".to_string()]);
    assert_eq!(ws.sso, SsoMode::Required);
    assert!(store
        .workspace(WorkspaceId(n ^ 0xdead))
        .await
        .unwrap()
        .is_none());

    let user = store
        .upsert_user(&member_email, "idp_user_1")
        .await
        .unwrap();
    assert_eq!(
        store
            .upsert_user(&member_email, "idp_user_1")
            .await
            .unwrap(),
        user
    );
    assert!(store.membership(ws_id, user).await.unwrap().is_none());
    store
        .put_membership(&Membership {
            workspace: ws_id,
            user,
            role: Role::Admin,
            status: MembershipStatus::Active,
        })
        .await
        .unwrap();
    let m = store
        .membership(ws_id, user)
        .await
        .unwrap()
        .expect("membership");
    assert_eq!(m.role, Role::Admin);
    assert_eq!(m.status, MembershipStatus::Active);
    store
        .put_membership(&Membership {
            status: MembershipStatus::Suspended,
            ..m
        })
        .await
        .unwrap();
    assert_eq!(
        store.membership(ws_id, user).await.unwrap().unwrap().status,
        MembershipStatus::Suspended
    );

    store
        .upsert_invitation(&Invitation {
            workspace: ws_id,
            email: invitee_email.clone(),
            role: Role::Member,
            expires_at: 10_000_000,
            accepted: false,
        })
        .await
        .unwrap();
    let inv = store
        .invitation(ws_id, &invitee_email)
        .await
        .unwrap()
        .expect("invitation");
    assert_eq!(inv.role, Role::Member);
    assert!(!inv.accepted);
    store
        .mark_invitation_accepted(ws_id, &invitee_email)
        .await
        .unwrap();
    assert!(
        store
            .invitation(ws_id, &invitee_email)
            .await
            .unwrap()
            .unwrap()
            .accepted
    );

    let d1 = store.record_device(ws_id, user, &[9u8; 32]).await.unwrap();
    let d1_again = store.record_device(ws_id, user, &[9u8; 32]).await.unwrap();
    assert_eq!(d1, d1_again, "re-enrolling the same key must be idempotent");
    let d2 = store.record_device(ws_id, user, &[7u8; 32]).await.unwrap();
    assert_ne!(d1, d2, "a different key must be a distinct device");
}
