use std::sync::{Arc, Mutex};

use clave_core::{AuditAction, PolicyBundle, ZoneRegistry};
use clave_daemon::Daemon;
use clave_gateway::{
    AuthMethod, EnrollmentCompletion, Gateway, IngestError, MemStore, MockIdentityProvider, Role,
    SsoMode, VerifiedUser,
};
use clave_identity::{EmailAddr, Membership, MembershipStatus, UserId, Workspace, WorkspaceId};
use clave_net::LoopbackTunnel;
use clave_proto::{
    AuditError, AuditSpool, ControlReason, DeviceSigningKey, GatewayCommand, GatewaySigningKey,
    GatewayVerifier, TenantId,
};
use clave_testkit::MockPlatform;
use clave_volume::{ClaveVolume, ContainerId, ContainerMeta, Dek, Kek, MemBacking, MemKeyStore};

const WS: WorkspaceId = WorkspaceId(100);
const TENANT: TenantId = TenantId(1);
const CONTAINER: ContainerId = ContainerId(0xC1A5_ED15);

fn gateway() -> Gateway<MockIdentityProvider, Arc<MemStore>> {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(Workspace {
        id: WS,
        allowed_domains: vec![],
        sso: SsoMode::Optional,
    });
    store.seed_membership(Membership {
        workspace: WS,
        user: UserId(1),
        role: Role::Member,
        status: MembershipStatus::Active,
    });
    let user = VerifiedUser {
        email: EmailAddr::parse("dev@acme.com").unwrap(),
        idp_user_id: "user_1".into(),
        workspace: WS,
        method: AuthMethod::Sso { verified: true },
        access_token: "a".into(),
        refresh_token: "r".into(),
    };
    Gateway::new(MockIdentityProvider::new(user, "approved-device"), store)
}

fn daemon(tenant_signer: &GatewaySigningKey) -> (Arc<Daemon>, Arc<AuditSpool>) {
    let platform = MockPlatform::new();
    let zones: Arc<ZoneRegistry> = Arc::clone(&platform.zones);
    let spool = Arc::new(AuditSpool::new());

    let keystore = Arc::new(MemKeyStore::new());
    keystore.provision(
        CONTAINER,
        Kek::from_bytes([0x4B; 32]),
        &Dek::from_bytes([0xDE; 64]),
    );
    let volume = ClaveVolume::new(
        ContainerMeta::new(CONTAINER),
        keystore,
        Arc::new(MemBacking::zeroed(64)),
        zones.clone(),
    );

    let verifier = GatewayVerifier::new(TENANT, tenant_signer.public_key()).unwrap();
    let daemon = Arc::new(Daemon::new(
        zones,
        Box::new(platform),
        spool.clone(),
        PolicyBundle::restrictive_default(),
        Box::new(LoopbackTunnel::new(0x5A)),
        Arc::new(Mutex::new(volume)),
        verifier,
    ));
    (daemon, spool)
}

async fn enroll(
    gw: &Gateway<MockIdentityProvider, Arc<MemStore>>,
    device_key: &DeviceSigningKey,
) -> clave_gateway::DeviceId {
    let auth = gw.begin_enrollment(WS).await.expect("begin enrollment");
    match gw
        .complete_enrollment(WS, &auth.device_code, &device_key.public_key(), None, 1_000)
        .await
        .expect("complete enrollment")
    {
        EnrollmentCompletion::Approved { device, .. } => device,
        EnrollmentCompletion::Pending => panic!("enrollment should be approved"),
    }
}

#[tokio::test]
async fn a_gateway_wipe_is_obeyed_and_the_resulting_audit_verifies_at_the_gateway() {
    let gw = gateway();
    let tenant = GatewaySigningKey::from_seed(TENANT, [0x6A; 32]);
    let device_key = DeviceSigningKey::from_seed([0xD0; 32]);

    let device = enroll(&gw, &device_key).await;
    assert_eq!(
        gw.audit().high_water(device),
        Some(1),
        "chain opened at seq 1"
    );

    let (daemon, spool) = daemon(&tenant);
    daemon.unlock_volume(1).unwrap();
    let wipe = tenant.sign(
        1,
        100,
        GatewayCommand::Wipe {
            container: CONTAINER.0,
            reason: ControlReason::Offboarding,
        },
    );
    daemon.apply_gateway_command(&wipe, 100).unwrap();

    let (entries, head) = spool.drain();
    assert!(
        entries.iter().any(|e| e.event.action == AuditAction::Wiped),
        "the wipe was recorded in the device's audit chain"
    );
    let batch = device_key.sign_batch(entries, head);

    let admitted = gw
        .ingest_device_audit(device, &batch)
        .expect("the device's audit verifies at the gateway it enrolled with");
    assert!(admitted.iter().any(|e| e.action == AuditAction::Wiped));
    assert!(
        gw.audit()
            .events_for(device)
            .iter()
            .any(|e| e.action == AuditAction::Wiped),
        "the gateway now holds a verified record of the wipe"
    );
}

#[tokio::test]
async fn a_tampered_report_is_rejected_by_the_gateway() {
    let gw = gateway();
    let tenant = GatewaySigningKey::from_seed(TENANT, [0x6A; 32]);
    let device_key = DeviceSigningKey::from_seed([0xD0; 32]);
    let device = enroll(&gw, &device_key).await;

    let (daemon, spool) = daemon(&tenant);
    daemon.unlock_volume(1).unwrap();
    let lock = tenant.sign(
        1,
        100,
        GatewayCommand::Lock {
            reason: ControlReason::Offboarding,
        },
    );
    daemon.apply_gateway_command(&lock, 100).unwrap();

    let (entries, head) = spool.drain();
    let mut batch = device_key.sign_batch(entries, head);
    assert!(!batch.entries.is_empty());
    batch.entries[0].event = clave_core::AuditEvent::new(
        0,
        AuditAction::ProcessJoinedZone,
        batch.entries[0].event.verdict,
    );

    match gw.ingest_device_audit(device, &batch) {
        Err(IngestError::Rejected(AuditError::Tampered { .. })) => {}
        other => panic!("expected the gateway to reject a rewritten report, got {other:?}"),
    }
    assert!(
        gw.audit().events_for(device).is_empty(),
        "nothing tampered is ever admitted"
    );
}

#[tokio::test]
async fn a_report_signed_by_the_wrong_device_is_rejected() {
    let gw = gateway();
    let tenant = GatewaySigningKey::from_seed(TENANT, [0x6A; 32]);
    let enrolled = DeviceSigningKey::from_seed([0xD0; 32]);
    let device = enroll(&gw, &enrolled).await;

    let (daemon, spool) = daemon(&tenant);
    daemon.unlock_volume(1).unwrap();
    let lock = tenant.sign(
        1,
        100,
        GatewayCommand::Lock {
            reason: ControlReason::Offboarding,
        },
    );
    daemon.apply_gateway_command(&lock, 100).unwrap();

    let impostor = DeviceSigningKey::from_seed([0xEE; 32]);
    let (entries, head) = spool.drain();
    let batch = impostor.sign_batch(entries, head);

    assert!(matches!(
        gw.ingest_device_audit(device, &batch),
        Err(IngestError::Rejected(AuditError::BadSignature))
    ));
}
