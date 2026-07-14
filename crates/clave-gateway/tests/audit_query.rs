use std::sync::Arc;

use clave_core::{AuditAction, AuditEvent, AuditSink, Reason, Verdict};
use clave_gateway::{
    AuditStore, AuthMethod, DeviceId, EmailAddr, Gateway, GatewayError, IngestError, MemAuditStore,
    MemStore, MockIdentityProvider, RequestContext, Role, SsoMode, Store, UserId, VerifiedUser,
    Workspace, WorkspaceId,
};
use clave_proto::{AuditSpool, DeviceSigningKey, SignedSpoolBatch};

const WS: WorkspaceId = WorkspaceId(100);

fn ctx(role: Role) -> RequestContext {
    RequestContext {
        user: UserId(1),
        workspace: WS,
        role,
    }
}

fn event(action: AuditAction) -> AuditEvent {
    AuditEvent::new(0, action, Verdict::deny(Reason::Clipboard))
}

fn batch(spool: &AuditSpool, key: &DeviceSigningKey) -> SignedSpoolBatch {
    let (entries, head) = spool.drain();
    key.sign_batch(entries, head)
}

async fn setup() -> (Gateway<MockIdentityProvider, Arc<MemStore>>, DeviceSigningKey, DeviceId) {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(Workspace {
        id: WS,
        allowed_domains: vec![],
        sso: SsoMode::Optional,
    });
    let key = DeviceSigningKey::from_seed([7u8; 32]);
    let device = store
        .record_device(WS, UserId(1), &key.public_key())
        .await
        .unwrap();
    let vu = VerifiedUser {
        email: EmailAddr::parse("admin@acme.com").unwrap(),
        idp_user_id: "u1".to_string(),
        workspace: WS,
        method: AuthMethod::Password,
        access_token: "a".to_string(),
        refresh_token: "r".to_string(),
    };
    let gw = Gateway::new(MockIdentityProvider::new(vu, "d"), store);
    gw.audit().register_device(device, key.public_key());
    (gw, key, device)
}

#[tokio::test]
async fn ingested_events_surface_in_the_workspace_audit_query() {
    let (gw, key, device) = setup().await;
    let spool = AuditSpool::new();
    spool.emit(event(AuditAction::ClipboardBlocked));
    spool.emit(event(AuditAction::NetworkBlocked));

    let admitted = gw
        .ingest_device_audit(device, &batch(&spool, &key))
        .await
        .expect("ingest");
    assert_eq!(admitted.len(), 2);

    let events = gw.audit_events(&ctx(Role::Admin)).await.unwrap();
    assert_eq!(events.len(), 2);
    assert!(gw.audit_alerts(&ctx(Role::Admin)).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_suppressed_batch_raises_a_gap_alert() {
    let (gw, key, device) = setup().await;
    let spool = AuditSpool::new();

    spool.emit(event(AuditAction::ClipboardBlocked));
    let _dropped = batch(&spool, &key);

    spool.emit(event(AuditAction::NetworkBlocked));
    let next = batch(&spool, &key);

    assert!(gw.ingest_device_audit(device, &next).await.is_err());

    let alerts = gw.audit_alerts(&ctx(Role::Admin)).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "gap");
}

#[tokio::test]
async fn a_plain_member_cannot_read_the_audit_log() {
    let (gw, _key, _device) = setup().await;
    assert!(matches!(
        gw.audit_events(&ctx(Role::Member)).await,
        Err(GatewayError::Forbidden(_))
    ));
    assert!(matches!(
        gw.audit_alerts(&ctx(Role::Member)).await,
        Err(GatewayError::Forbidden(_))
    ));
}

fn mock_idp() -> MockIdentityProvider {
    MockIdentityProvider::new(
        VerifiedUser {
            email: EmailAddr::parse("admin@acme.com").unwrap(),
            idp_user_id: "u1".to_string(),
            workspace: WS,
            method: AuthMethod::Password,
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
        },
        "d",
    )
}

async fn registered_gateway(
    audit: std::sync::Arc<MemAuditStore>,
    key: &DeviceSigningKey,
) -> (Gateway<MockIdentityProvider, Arc<MemStore>>, DeviceId) {
    let store = Arc::new(MemStore::new());
    store.seed_workspace(Workspace {
        id: WS,
        allowed_domains: vec![],
        sso: SsoMode::Optional,
    });
    let device = store
        .record_device(WS, UserId(1), &key.public_key())
        .await
        .unwrap();
    let gw = Gateway::new(mock_idp(), store).with_audit_store(audit.clone());
    gw.audit().register_device(device, key.public_key());
    audit.register(device, key.public_key()).await.unwrap();
    (gw, device)
}

#[tokio::test]
async fn audit_persists_and_a_restarted_gateway_resumes_the_chain() {
    let audit = Arc::new(MemAuditStore::new());
    let key = DeviceSigningKey::from_seed([7u8; 32]);
    let (gw1, device) = registered_gateway(audit.clone(), &key).await;

    let spool = AuditSpool::new();
    spool.emit(event(AuditAction::ClipboardBlocked));
    spool.emit(event(AuditAction::NetworkBlocked));
    gw1.ingest_device_audit(device, &batch(&spool, &key))
        .await
        .unwrap();
    assert_eq!(audit.event_count(), 2, "admitted events are persisted");

    let gw2 = Gateway::new(mock_idp(), Arc::new(MemStore::new())).with_audit_store(audit.clone());
    assert_eq!(gw2.hydrate_audit().await.unwrap(), 1, "one device chain restored");

    spool.emit(event(AuditAction::InputTapOverWork));
    gw2.ingest_device_audit(device, &batch(&spool, &key))
        .await
        .expect("continuation accepted after resume");
    assert_eq!(audit.event_count(), 3);

    let gw3 = Gateway::new(mock_idp(), Arc::new(MemStore::new())).with_audit_store(audit.clone());
    spool.emit(event(AuditAction::ScreenCaptureOverWork));
    assert!(matches!(
        gw3.ingest_device_audit(device, &batch(&spool, &key)).await,
        Err(IngestError::UnknownDevice(_))
    ));
}
