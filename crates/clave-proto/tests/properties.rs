use clave_core::{AuditAction, AuditEvent, AuditSink, Reason, Verdict};
use clave_proto::{
    verify_batch, AuditSpool, DeviceSigningKey, GatewayVerifier, SignedCommand, TenantId, GENESIS,
};
use proptest::prelude::*;

fn audit_action() -> impl Strategy<Value = AuditAction> {
    prop::sample::select(vec![
        AuditAction::Wiped,
        AuditAction::NetworkBlocked,
        AuditAction::ClipboardBlocked,
        AuditAction::FileSaveDenied,
        AuditAction::ProcessJoinedZone,
        AuditAction::VolumeMounted,
    ])
}

proptest! {
    #[test]
    fn audit_chain_verifies_for_any_event_sequence(
        events in prop::collection::vec((any::<u64>(), audit_action()), 0..16),
    ) {
        let spool = AuditSpool::new();
        for (ts, action) in &events {
            spool.emit(AuditEvent::new(*ts, *action, Verdict::allow(Reason::Default)));
        }
        let dev = DeviceSigningKey::from_seed([7u8; 32]);
        let (entries, head) = spool.drain();
        let batch = dev.sign_batch(entries, head);
        let new_head = verify_batch(GENESIS, 1, &batch, dev.public_key()).expect("a valid chain verifies");
        prop_assert_eq!(new_head, head);
    }

    #[test]
    fn command_verify_never_panics_on_arbitrary_bytes(
        envelope in prop::collection::vec(any::<u8>(), 0..512),
        signature in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let pinned = DeviceSigningKey::from_seed([1u8; 32]).public_key();
        let mut v = GatewayVerifier::new(TenantId(1), pinned).unwrap();
        let signed = SignedCommand { envelope, signature };
        let _ = v.verify(&signed, 0);
        prop_assert!(true);
    }
}
