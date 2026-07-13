use std::sync::Arc;

use clave_gateway::{
    AuthMethod, DenyReason, EmailAddr, EnrollmentCompletion, EnrollmentOutcome, Gateway,
    GatewayCommand, GatewayError, GatewaySigningKey, GatewayVerifier, Invitation, MemPolicyIssuer,
    MemStore, MemVolumeKeyService, Membership, MembershipStatus, MockIdentityProvider,
    PolicyBundle, Role, SealedVolumeKeyService, Session, SsoMode, TenantId, UserId, VerifiedUser,
    Workspace, WorkspaceId,
};
use clave_volume::{
    open_dek, ContainerId, Dek, DeviceSealingKey, Kek, SealedDek, WrappedDek, DEK_LEN,
    WRAPPED_DEK_LEN,
};

const WS: WorkspaceId = WorkspaceId(100);
const TTL: u64 = 3_600;

fn email(s: &str) -> EmailAddr {
    EmailAddr::parse(s).unwrap()
}

fn workspace(domains: &[&str], sso: SsoMode) -> Workspace {
    Workspace {
        id: WS,
        allowed_domains: domains.iter().map(|d| d.to_string()).collect(),
        sso,
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

fn verified(email_str: &str, method: AuthMethod) -> VerifiedUser {
    VerifiedUser {
        email: email(email_str),
        idp_user_id: "user_workos_1".to_string(),
        workspace: WS,
        method,
        access_token: "access.jwt".to_string(),
        refresh_token: "refresh.tok".to_string(),
    }
}

fn gateway(
    user: VerifiedUser,
    store: Arc<MemStore>,
) -> Gateway<MockIdentityProvider, Arc<MemStore>> {
    Gateway::new(MockIdentityProvider::new(user, "approved-device"), store)
}

#[tokio::test]
async fn active_member_logs_in_and_session_carries_the_refresh_token() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&["acme.com"], SsoMode::Optional));
    store.seed_membership(active(1, Role::Admin));
    let gw = gateway(
        verified("ceo@acme.com", AuthMethod::Password),
        store.clone(),
    );

    let session = gw
        .console_login("code", 1_000, TTL)
        .await
        .expect("login ok");
    assert_eq!(session.user, UserId(1));
    assert_eq!(session.role, Role::Admin);
    assert_eq!(session.expires_at, 1_000 + TTL);
    assert_eq!(session.refresh_token, "refresh.tok");
}

#[tokio::test]
async fn login_accepts_a_pending_invitation_on_first_sign_in() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&["acme.com"], SsoMode::Optional));
    store.seed_invitation(Invitation {
        workspace: WS,
        email: email("new@acme.com"),
        role: Role::Member,
        expires_at: 10_000,
        accepted: false,
    });
    let gw = gateway(
        verified("new@acme.com", AuthMethod::EmailCode),
        store.clone(),
    );

    let session = gw
        .console_login("code", 1_000, TTL)
        .await
        .expect("login ok");
    assert_eq!(session.role, Role::Member);

    let ctx = gw
        .authorize_request(&session, 1_500)
        .await
        .expect("authorized");
    assert_eq!(ctx.role, Role::Member);
}

#[tokio::test]
async fn uninvited_user_is_rejected() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    let gw = gateway(
        verified("stranger@evil.com", AuthMethod::EmailCode),
        store.clone(),
    );

    let err = gw.console_login("code", 1_000, TTL).await.unwrap_err();
    assert_eq!(err, GatewayError::Unauthorized(DenyReason::NotAMember));
}

#[tokio::test]
async fn sso_required_workspace_rejects_password_login() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Required));
    store.seed_membership(active(1, Role::Admin));
    let gw = gateway(
        verified("ceo@acme.com", AuthMethod::Password),
        store.clone(),
    );

    let err = gw.console_login("code", 1_000, TTL).await.unwrap_err();
    assert_eq!(err, GatewayError::Unauthorized(DenyReason::SsoRequired));
}

#[tokio::test]
async fn suspension_locks_a_user_out_on_the_very_next_request() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    store.seed_membership(active(1, Role::Admin));
    let gw = gateway(
        verified("ceo@acme.com", AuthMethod::Password),
        store.clone(),
    );

    let session = gw
        .console_login("code", 1_000, TTL)
        .await
        .expect("login ok");
    assert!(gw.authorize_request(&session, 1_100).await.is_ok());

    store.seed_membership(Membership {
        status: MembershipStatus::Suspended,
        ..active(1, Role::Admin)
    });
    let err = gw.authorize_request(&session, 1_200).await.unwrap_err();
    assert_eq!(err, GatewayError::Unauthorized(DenyReason::Suspended));
}

#[tokio::test]
async fn expired_session_is_invalid() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    store.seed_membership(active(1, Role::Member));
    let gw = gateway(
        verified("user@acme.com", AuthMethod::EmailCode),
        store.clone(),
    );

    let session = Session {
        user: UserId(1),
        workspace: WS,
        role: Role::Member,
        expires_at: 2_000,
        refresh_token: "r".to_string(),
    };
    assert_eq!(
        gw.authorize_request(&session, 2_001).await.unwrap_err(),
        GatewayError::SessionInvalid
    );
}

#[tokio::test]
async fn device_enrollment_approves_an_active_member() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    store.seed_membership(active(1, Role::Member));
    let gw = gateway(
        verified("dev@acme.com", AuthMethod::Sso { verified: true }),
        store.clone(),
    );

    let auth = gw.begin_enrollment(WS).await.expect("begin");
    assert_eq!(
        gw.poll_enrollment(WS, "not-yet").await.unwrap(),
        EnrollmentOutcome::Pending
    );
    assert_eq!(
        gw.poll_enrollment(WS, &auth.device_code).await.unwrap(),
        EnrollmentOutcome::Approved {
            user: UserId(1),
            role: Role::Member
        }
    );
}

#[tokio::test]
async fn device_enrollment_rejects_a_non_member() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    let gw = gateway(
        verified("stranger@evil.com", AuthMethod::Sso { verified: true }),
        store.clone(),
    );

    let auth = gw.begin_enrollment(WS).await.expect("begin");
    assert_eq!(
        gw.poll_enrollment(WS, &auth.device_code).await.unwrap_err(),
        GatewayError::Unauthorized(DenyReason::NotAMember)
    );
}

#[tokio::test]
async fn completing_enrollment_registers_the_device_and_is_idempotent() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    store.seed_membership(active(1, Role::Member));
    let gw = gateway(
        verified("dev@acme.com", AuthMethod::Sso { verified: true }),
        store.clone(),
    );
    let auth = gw.begin_enrollment(WS).await.expect("begin");
    let pubkey = [9u8; 32];

    assert_eq!(
        gw.complete_enrollment(WS, "not-yet", &pubkey, None, 1_000)
            .await
            .unwrap(),
        EnrollmentCompletion::Pending
    );

    let first = gw
        .complete_enrollment(WS, &auth.device_code, &pubkey, None, 1_000)
        .await
        .unwrap();
    let device = match first {
        EnrollmentCompletion::Approved {
            device,
            user,
            role,
            policy,
            volume_key,
        } => {
            assert_eq!(user, UserId(1));
            assert_eq!(role, Role::Member);
            assert!(policy.is_none(), "no issuer ⇒ no signed bundle");
            assert!(
                volume_key.is_none(),
                "no key service ⇒ no wrapped volume key"
            );
            device
        }
        EnrollmentCompletion::Pending => panic!("expected approval"),
    };

    let again = gw
        .complete_enrollment(WS, &auth.device_code, &pubkey, None, 1_000)
        .await
        .unwrap();
    assert_eq!(
        again,
        EnrollmentCompletion::Approved {
            device,
            user: UserId(1),
            role: Role::Member,
            policy: None,
            volume_key: None,
        }
    );

    let other = gw
        .complete_enrollment(WS, &auth.device_code, &[7u8; 32], None, 1_000)
        .await
        .unwrap();
    assert!(matches!(other, EnrollmentCompletion::Approved { device: d, .. } if d != device));
}

#[tokio::test]
async fn completing_enrollment_rejects_a_non_member() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    let gw = gateway(
        verified("stranger@evil.com", AuthMethod::Sso { verified: true }),
        store.clone(),
    );
    let auth = gw.begin_enrollment(WS).await.expect("begin");
    assert_eq!(
        gw.complete_enrollment(WS, &auth.device_code, &[1u8; 32], None, 1_000)
            .await
            .unwrap_err(),
        GatewayError::Unauthorized(DenyReason::NotAMember)
    );
}

#[tokio::test]
async fn enrollment_issues_a_verifiable_signed_initial_policy() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    store.seed_membership(active(1, Role::Member));

    let issuer = Arc::new(MemPolicyIssuer::new(GatewaySigningKey::from_seed(
        TenantId(1),
        [0x5A; 32],
    )));
    let mut bundle = PolicyBundle::restrictive_default();
    bundle.version = 7;
    issuer.set_policy(WS, bundle.clone());
    let pinned = issuer.public_key();

    let gw = Gateway::new(
        MockIdentityProvider::new(
            verified("dev@acme.com", AuthMethod::Sso { verified: true }),
            "approved-device",
        ),
        store.clone(),
    )
    .with_policy_issuer(issuer.clone());

    let auth = gw.begin_enrollment(WS).await.expect("begin");
    let now = 5_000;
    let signed = match gw
        .complete_enrollment(WS, &auth.device_code, &[3u8; 32], None, now)
        .await
        .unwrap()
    {
        EnrollmentCompletion::Approved {
            policy: Some(p),
            role: Role::Member,
            ..
        } => p,
        other => panic!("expected approval carrying a signed policy, got {other:?}"),
    };

    let mut verifier = GatewayVerifier::new(TenantId(1), pinned).unwrap();
    match verifier.verify(&signed, now).unwrap() {
        GatewayCommand::UpdatePolicy(got) => assert_eq!(*got, bundle),
        other => panic!("expected UpdatePolicy, got {other:?}"),
    }

    let wrong_key = GatewaySigningKey::from_seed(TenantId(1), [0x01; 32]).public_key();
    let mut wrong = GatewayVerifier::new(TenantId(1), wrong_key).unwrap();
    assert!(
        wrong.verify(&signed, now).is_err(),
        "a forged/unpinned key must not verify the bundle"
    );
}

#[tokio::test]
async fn enrollment_issues_a_wrapped_volume_key_only_the_device_can_open() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    store.seed_membership(active(1, Role::Member));

    let escrowed_dek = [0xDE; DEK_LEN];
    let container = ContainerId(0xC1A5_ED15);
    let keys = Arc::new(MemVolumeKeyService::new());
    keys.set_container(WS, container, escrowed_dek);
    let device_kek = [0x11; 32];

    let gw = Gateway::new(
        MockIdentityProvider::new(
            verified("dev@acme.com", AuthMethod::Sso { verified: true }),
            "approved-device",
        ),
        store.clone(),
    )
    .with_volume_key_service(keys.clone());

    let auth = gw.begin_enrollment(WS).await.expect("begin");
    let wrapped_key = match gw
        .complete_enrollment(WS, &auth.device_code, &[3u8; 32], Some(&device_kek), 1_000)
        .await
        .unwrap()
    {
        EnrollmentCompletion::Approved {
            volume_key: Some(vk),
            ..
        } => vk,
        other => panic!("expected approval carrying a wrapped volume key, got {other:?}"),
    };
    assert_eq!(wrapped_key.container, container.0);
    assert_eq!(wrapped_key.wrapped_dek.len(), WRAPPED_DEK_LEN);

    let bytes: [u8; WRAPPED_DEK_LEN] = wrapped_key.wrapped_dek.clone().try_into().unwrap();
    let wrapped = WrappedDek::from_bytes(bytes);
    let recovered = Kek::from_bytes(device_kek)
        .unwrap(&wrapped)
        .expect("the device KEK unwraps its volume key");
    assert!(
        Kek::from_bytes([0x22; 32]).unwrap(&wrapped).is_err(),
        "a different KEK must not unwrap the volume key"
    );

    let probe = Kek::from_bytes([0x77; 32]);
    assert_eq!(
        probe.wrap(&recovered).as_bytes(),
        probe.wrap(&Dek::from_bytes(escrowed_dek)).as_bytes(),
        "the device recovered exactly the escrowed Clave Disk DEK"
    );

    let none = gw
        .complete_enrollment(WS, &auth.device_code, &[3u8; 32], None, 1_000)
        .await
        .unwrap();
    assert!(matches!(
        none,
        EnrollmentCompletion::Approved {
            volume_key: None,
            ..
        }
    ));
}

#[tokio::test]
async fn enrollment_seals_the_volume_key_to_the_device_public_key() {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(workspace(&[], SsoMode::Optional));
    store.seed_membership(active(1, Role::Member));

    let escrowed = [0xDE; DEK_LEN];
    let container = ContainerId(0xBEEF);
    let keys = Arc::new(SealedVolumeKeyService::new());
    keys.set_container(WS, container, escrowed);
    let device = DeviceSealingKey::generate();

    let gw = Gateway::new(
        MockIdentityProvider::new(
            verified("dev@acme.com", AuthMethod::Sso { verified: true }),
            "approved-device",
        ),
        store.clone(),
    )
    .with_volume_key_service(keys.clone());

    let auth = gw.begin_enrollment(WS).await.expect("begin");
    let vk = match gw
        .complete_enrollment(
            WS,
            &auth.device_code,
            &[3u8; 32],
            Some(&device.public_key()),
            1_000,
        )
        .await
        .unwrap()
    {
        EnrollmentCompletion::Approved {
            volume_key: Some(vk),
            ..
        } => vk,
        other => panic!("expected a sealed volume key, got {other:?}"),
    };
    assert_eq!(vk.container, container.0);

    let ephemeral_pub = vk
        .ephemeral_pub
        .expect("sealed delivery carries an ephemeral pub");
    let bytes: [u8; WRAPPED_DEK_LEN] = vk.wrapped_dek.try_into().unwrap();
    let dek = open_dek(
        &device,
        &SealedDek {
            ephemeral_pub,
            wrapped: WrappedDek::from_bytes(bytes),
        },
    )
    .expect("the device's hardware key opens its sealed volume key");
    let probe = Kek::from_bytes([0x77; 32]);
    assert_eq!(
        probe.wrap(&dek).as_bytes(),
        probe.wrap(&Dek::from_bytes(escrowed)).as_bytes(),
        "the device recovered exactly the escrowed Clave Disk DEK"
    );
}
