#![cfg(feature = "device-link")]

use std::sync::Arc;

use clave_core::{AuditAction, AuditEvent, AuditSink, Reason, Verdict};
use clave_gateway::{
    serve_device_audit, AuditStore, AuthMethod, EmailAddr, Gateway, MemAuditStore, MemStore,
    MockIdentityProvider, SsoMode, Store, UserId, VerifiedUser, Workspace, WorkspaceId,
};
use clave_proto::transport::device_link;
use clave_proto::{AuditSpool, DeviceSigningKey, SignedSpoolBatch};

const WS: WorkspaceId = WorkspaceId(100);

fn event(a: AuditAction) -> AuditEvent {
    AuditEvent::new(0, a, Verdict::deny(Reason::Clipboard))
}

fn batch(spool: &AuditSpool, key: &DeviceSigningKey) -> SignedSpoolBatch {
    let (entries, head) = spool.drain();
    key.sign_batch(entries, head)
}

#[tokio::test]
async fn a_device_link_pumps_audit_batches_into_the_ledger() {
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

    let audit = Arc::new(MemAuditStore::new());
    let vu = VerifiedUser {
        email: EmailAddr::parse("a@acme.com").unwrap(),
        idp_user_id: "u".to_string(),
        workspace: WS,
        method: AuthMethod::Password,
        access_token: "a".to_string(),
        refresh_token: "r".to_string(),
    };
    let gw = Gateway::new(MockIdentityProvider::new(vu, "d"), store).with_audit_store(audit.clone());
    gw.audit().register_device(device, key.public_key());
    audit.register(device, key.public_key()).await.unwrap();

    let (link, ends) = device_link();
    let spool = AuditSpool::new();
    spool.emit(event(AuditAction::ClipboardBlocked));
    ends.send_audit(batch(&spool, &key)).unwrap();
    spool.emit(event(AuditAction::NetworkBlocked));
    ends.send_audit(batch(&spool, &key)).unwrap();
    drop(ends);

    let ingested = serve_device_audit(link, device, &gw).await;
    assert_eq!(ingested, 2);
    assert_eq!(gw.audit().events_for(device).len(), 2);
    assert_eq!(audit.event_count(), 2);
}
