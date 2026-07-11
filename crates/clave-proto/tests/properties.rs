//! Property tests for the gateway control plane: the audit hash chain verifies for any
//! event sequence, and command verification never panics on untrusted (arbitrary) bytes.

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
    /// A device-signed batch of *any* event sequence verifies at the gateway, and the returned head
    /// matches — the hash chain is sound for all inputs.
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

    /// Command verification never panics on arbitrary (untrusted) bytes — it returns an error.
    /// `transport::read_msg` decodes a `SignedCommand` straight off the wire, so this is exactly
    /// the hostile-input surface.
    #[test]
    fn command_verify_never_panics_on_arbitrary_bytes(
        envelope in prop::collection::vec(any::<u8>(), 0..512),
        signature in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let pinned = DeviceSigningKey::from_seed([1u8; 32]).public_key(); // any valid public key
        let mut v = GatewayVerifier::new(TenantId(1), pinned).unwrap();
        let signed = SignedCommand { envelope, signature };
        // The property is simply that this returns rather than panicking on hostile bytes.
        let _ = v.verify(&signed, 0);
        prop_assert!(true);
    }
}
