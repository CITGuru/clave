use std::sync::Arc;

use clave_core::{AuditAction, AuditEvent, AuditSink, Reason, Verdict};
use clave_gateway::{
    AuthMethod, DeviceId, EmailAddr, Gateway, GatewayError, MemStore, MockIdentityProvider,
    RequestContext, Role, SsoMode, Store, UserId, VerifiedUser, Workspace, WorkspaceId,
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

    assert!(gw.ingest_device_audit(device, &next).is_err());

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
