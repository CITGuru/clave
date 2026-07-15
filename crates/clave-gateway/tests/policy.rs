use std::sync::Arc;

use clave_gateway::{
    AuthMethod, EmailAddr, Gateway, GatewayCommand, GatewayError, GatewaySigningKey,
    GatewayVerifier, MemPolicyIssuer, MemStore, MockIdentityProvider, PolicyBundle, RequestContext,
    Role, SsoMode, TenantId, UserId, VerifiedUser, Workspace, WorkspaceId,
};

const WS: WorkspaceId = WorkspaceId(100);
const TENANT: TenantId = TenantId(1);

fn ctx(role: Role) -> RequestContext {
    RequestContext {
        user: UserId(1),
        workspace: WS,
        role,
    }
}

fn setup() -> (Gateway<MockIdentityProvider, Arc<MemStore>>, [u8; 32]) {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(Workspace {
        id: WS,
        allowed_domains: vec![],
        sso: SsoMode::Optional,
    });
    let signer = GatewaySigningKey::from_seed(TENANT, [0x5A; 32]);
    let pinned = signer.public_key();
    let issuer = Arc::new(MemPolicyIssuer::new(signer));
    let vu = VerifiedUser {
        email: EmailAddr::parse("admin@acme.com").unwrap(),
        idp_user_id: "u1".to_string(),
        workspace: WS,
        method: AuthMethod::Password,
        access_token: "a".to_string(),
        refresh_token: "r".to_string(),
    };
    let gw = Gateway::new(MockIdentityProvider::new(vu, "d"), store).with_policy_issuer(issuer);
    (gw, pinned)
}

#[tokio::test]
async fn authoring_bumps_the_version_monotonically() {
    let (gw, _pin) = setup();
    let c = ctx(Role::Admin);

    let b1 = gw
        .author_policy(&c, PolicyBundle::restrictive_default())
        .await
        .unwrap();
    assert_eq!(b1.version, 1);
    let b2 = gw
        .author_policy(&c, PolicyBundle::restrictive_default())
        .await
        .unwrap();
    assert_eq!(b2.version, 2);

    assert_eq!(gw.policy_versions(&c).await.unwrap(), vec![1, 2]);
    assert_eq!(gw.get_policy(&c).await.unwrap().unwrap().version, 2);
}

#[tokio::test]
async fn reissue_signs_the_current_policy_and_a_pinned_verifier_accepts_it() {
    let (gw, pin) = setup();
    let c = ctx(Role::Admin);
    gw.author_policy(&c, PolicyBundle::restrictive_default())
        .await
        .unwrap();

    let signed = gw.reissue_policy(&c, 1_000).await.unwrap();
    let mut verifier = GatewayVerifier::new(TENANT, pin).unwrap();
    match verifier.verify(&signed, 1_000).unwrap() {
        GatewayCommand::UpdatePolicy(b) => assert_eq!(b.version, 1),
        other => panic!("expected UpdatePolicy, got {other:?}"),
    }

    let signed2 = gw.reissue_policy(&c, 1_000).await.unwrap();
    assert!(
        verifier.verify(&signed2, 1_000).is_ok(),
        "a fresh reissue carries a higher envelope counter"
    );
    assert!(
        verifier.verify(&signed, 1_000).is_err(),
        "replaying the first reissue is rejected"
    );
}

#[tokio::test]
async fn a_member_cannot_author_or_reissue_policy() {
    let (gw, _pin) = setup();
    let c = ctx(Role::Member);
    assert!(matches!(
        gw.author_policy(&c, PolicyBundle::restrictive_default()).await,
        Err(GatewayError::Forbidden(_))
    ));
    assert!(matches!(
        gw.reissue_policy(&c, 1_000).await,
        Err(GatewayError::Forbidden(_))
    ));
}

#[tokio::test]
async fn reissue_without_a_policy_is_not_found() {
    let (gw, _pin) = setup();
    assert!(matches!(
        gw.reissue_policy(&ctx(Role::Admin), 1_000).await,
        Err(GatewayError::NotFound(_))
    ));
}
