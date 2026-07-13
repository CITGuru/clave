use std::sync::{Arc, Mutex};

use clave_core::{AuditAction, AuditEvent, AuditSink, Reason, Verdict};
use clave_proto::{verify_batch, AuditError, AuditSpool, DeviceSigningKey, GENESIS};

fn ev(ts: u64, action: AuditAction) -> AuditEvent {
    AuditEvent::new(ts, action, Verdict::allow(Reason::Default))
}

fn device() -> DeviceSigningKey {
    DeviceSigningKey::from_seed([5u8; 32])
}

#[test]
fn emit_builds_a_growing_hash_chain() {
    let spool = AuditSpool::new();
    assert_eq!(spool.seq(), 0);
    assert_eq!(spool.head(), GENESIS);

    spool.emit(ev(1, AuditAction::Wiped));
    spool.emit(ev(2, AuditAction::NetworkBlocked));

    assert_eq!(spool.seq(), 2);
    assert_ne!(spool.head(), GENESIS);
    assert_eq!(spool.pending_len(), 2);
}

#[test]
fn drained_signed_batch_verifies_at_the_gateway() {
    let spool = AuditSpool::new();
    let dev = device();
    spool.emit(ev(1, AuditAction::Wiped));
    spool.emit(ev(2, AuditAction::ClipboardBlocked));

    let (entries, head) = spool.drain();
    let batch = dev.sign_batch(entries, head);

    let new_head =
        verify_batch(GENESIS, 1, &batch, dev.public_key()).expect("valid batch verifies");
    assert_eq!(new_head, head);
    assert_eq!(spool.pending_len(), 0, "drain clears the pending tail");
}

#[test]
fn peek_is_non_destructive_and_confirm_drops_only_acknowledged_entries() {
    let spool = AuditSpool::new();
    spool.emit(ev(1, AuditAction::Wiped));
    spool.emit(ev(2, AuditAction::NetworkBlocked));

    let (entries, _head_at_2) = spool.peek();
    assert_eq!(entries.len(), 2);
    assert_eq!(spool.pending_len(), 2, "peek leaves the tail intact");

    spool.emit(ev(3, AuditAction::ClipboardBlocked));
    let head_at_3 = spool.head();

    spool.confirm_through(2);
    let (remaining, head_after_confirm) = spool.peek();
    assert_eq!(
        remaining.len(),
        1,
        "only the acknowledged entries were dropped"
    );
    assert_eq!(remaining[0].seq, 3);
    assert_eq!(
        head_after_confirm, head_at_3,
        "confirm drops entries but never rewinds the chain head"
    );
}

#[test]
fn a_peeked_batch_verifies_and_the_chain_continues_after_confirm() {
    let spool = AuditSpool::new();
    let dev = device();
    spool.emit(ev(1, AuditAction::Wiped));
    spool.emit(ev(2, AuditAction::NetworkBlocked));

    let (entries, head) = spool.peek();
    let batch1 = dev.sign_batch(entries, head);
    let head1 = verify_batch(GENESIS, 1, &batch1, dev.public_key()).expect("batch 1 verifies");
    spool.confirm_through(2);

    spool.emit(ev(3, AuditAction::ClipboardBlocked));
    let (entries, head) = spool.peek();
    let batch2 = dev.sign_batch(entries, head);
    verify_batch(head1, 3, &batch2, dev.public_key())
        .expect("batch 2 continues the chain from the confirmed head");
}

#[test]
fn tampering_with_an_event_is_detected() {
    let spool = AuditSpool::new();
    let dev = device();
    spool.emit(ev(1, AuditAction::Wiped));

    let (mut entries, head) = spool.drain();
    entries[0].event = ev(1, AuditAction::ProcessJoinedZone);
    let batch = dev.sign_batch(entries, head);

    assert!(matches!(
        verify_batch(GENESIS, 1, &batch, dev.public_key()),
        Err(AuditError::Tampered { seq: 1 })
    ));
}

#[test]
fn dropping_a_middle_entry_is_caught_as_a_gap() {
    let spool = AuditSpool::new();
    let dev = device();
    spool.emit(ev(1, AuditAction::Wiped));
    spool.emit(ev(2, AuditAction::NetworkBlocked));
    spool.emit(ev(3, AuditAction::ClipboardBlocked));

    let (mut entries, head) = spool.drain();
    entries.remove(1);
    let batch = dev.sign_batch(entries, head);

    assert!(matches!(
        verify_batch(GENESIS, 1, &batch, dev.public_key()),
        Err(AuditError::Gap {
            expected: 2,
            got: 3
        })
    ));
}

#[test]
fn truncating_the_tail_is_detected() {
    let spool = AuditSpool::new();
    let dev = device();
    spool.emit(ev(1, AuditAction::Wiped));
    spool.emit(ev(2, AuditAction::NetworkBlocked));

    let (mut entries, head) = spool.drain();
    entries.pop();
    let batch = dev.sign_batch(entries, head);

    assert!(matches!(
        verify_batch(GENESIS, 1, &batch, dev.public_key()),
        Err(AuditError::BrokenChain { .. })
    ));
}

#[test]
fn forged_signature_is_rejected() {
    let spool = AuditSpool::new();
    let dev = device();
    spool.emit(ev(1, AuditAction::Wiped));

    let (entries, head) = spool.drain();
    let attacker = DeviceSigningKey::from_seed([0xAA; 32]);
    let batch = attacker.sign_batch(entries, head);

    assert!(matches!(
        verify_batch(GENESIS, 1, &batch, dev.public_key()),
        Err(AuditError::BadSignature)
    ));
}

#[test]
fn chain_continues_across_drains() {
    let spool = AuditSpool::new();
    let dev = device();

    spool.emit(ev(1, AuditAction::Wiped));
    let (e1, h1) = spool.drain();
    let b1 = dev.sign_batch(e1, h1);
    let head1 = verify_batch(GENESIS, 1, &b1, dev.public_key()).unwrap();

    spool.emit(ev(2, AuditAction::NetworkBlocked));
    let (e2, h2) = spool.drain();
    let b2 = dev.sign_batch(e2, h2);
    let head2 = verify_batch(head1, 2, &b2, dev.public_key()).unwrap();
    assert_eq!(head2, h2);
}

#[test]
fn resume_restores_chain_position() {
    let spool = AuditSpool::new();
    spool.emit(ev(1, AuditAction::Wiped));
    let (seq, head) = (spool.seq(), spool.head());

    let resumed = AuditSpool::resume(seq, head);
    resumed.emit(ev(2, AuditAction::NetworkBlocked));

    let (entries, _h) = resumed.drain();
    assert_eq!(entries[0].seq, 2);
    assert_eq!(
        entries[0].prev, head,
        "the resumed chain links to the persisted head"
    );
}

#[test]
fn spool_forwards_to_an_inner_sink() {
    #[derive(Default)]
    struct Counter(Arc<Mutex<usize>>);
    impl AuditSink for Counter {
        fn emit(&self, _e: AuditEvent) {
            *self.0.lock().unwrap() += 1;
        }
    }

    let count = Arc::new(Mutex::new(0));
    let spool = AuditSpool::with_sink(Arc::new(Counter(count.clone())));
    spool.emit(ev(1, AuditAction::Wiped));
    spool.emit(ev(2, AuditAction::Wiped));

    assert_eq!(
        *count.lock().unwrap(),
        2,
        "events are forwarded to the inner sink"
    );
    assert_eq!(spool.pending_len(), 2, "and also chained in the spool");
}
