use std::collections::HashMap;
use std::sync::Mutex;

use clave_core::AuditEvent;
use clave_proto::{verify_batch, AuditError, ChainHash, SignedSpoolBatch};

use crate::DeviceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    UnknownDevice(DeviceId),
    Rejected(AuditError),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::UnknownDevice(d) => write!(f, "unknown device {:x}", d.0),
            IngestError::Rejected(e) => write!(f, "audit batch rejected: {e}"),
        }
    }
}

impl std::error::Error for IngestError {}

struct DeviceChain {
    public_key: [u8; 32],
    next_seq: u64,
    head: ChainHash,
}

#[derive(Default)]
pub struct AuditLedger {
    chains: Mutex<HashMap<DeviceId, DeviceChain>>,
    verified: Mutex<Vec<(DeviceId, AuditEvent)>>,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_device(&self, device: DeviceId, public_key: [u8; 32]) {
        self.chains.lock().expect("ledger lock").insert(
            device,
            DeviceChain {
                public_key,
                next_seq: 1,
                head: clave_proto::GENESIS,
            },
        );
    }

    pub fn ingest(
        &self,
        device: DeviceId,
        batch: &SignedSpoolBatch,
    ) -> Result<Vec<AuditEvent>, IngestError> {
        let mut chains = self.chains.lock().expect("ledger lock");
        let chain = chains
            .get_mut(&device)
            .ok_or(IngestError::UnknownDevice(device))?;

        let new_head = verify_batch(chain.head, chain.next_seq, batch, chain.public_key)
            .map_err(IngestError::Rejected)?;

        let events: Vec<AuditEvent> = batch.entries.iter().map(|e| e.event).collect();
        chain.next_seq += events.len() as u64;
        chain.head = new_head;

        let mut verified = self.verified.lock().expect("ledger lock");
        for e in &events {
            verified.push((device, *e));
        }
        Ok(events)
    }

    pub fn high_water(&self, device: DeviceId) -> Option<u64> {
        self.chains
            .lock()
            .expect("ledger lock")
            .get(&device)
            .map(|c| c.next_seq)
    }

    pub fn events_for(&self, device: DeviceId) -> Vec<AuditEvent> {
        self.verified
            .lock()
            .expect("ledger lock")
            .iter()
            .filter(|(d, _)| *d == device)
            .map(|(_, e)| *e)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clave_core::{AuditAction, AuditSink, Reason, Verdict};
    use clave_proto::{AuditSpool, DeviceSigningKey};

    const DEVICE: DeviceId = DeviceId(0xD1);

    fn event(action: AuditAction) -> AuditEvent {
        AuditEvent::new(0, action, Verdict::deny(Reason::Clipboard))
    }

    fn device() -> (AuditSpool, DeviceSigningKey, AuditLedger) {
        let key = DeviceSigningKey::from_seed([7u8; 32]);
        let ledger = AuditLedger::new();
        ledger.register_device(DEVICE, key.public_key());
        (AuditSpool::new(), key, ledger)
    }

    fn batch(spool: &AuditSpool, key: &DeviceSigningKey) -> SignedSpoolBatch {
        let (entries, head) = spool.drain();
        key.sign_batch(entries, head)
    }

    #[test]
    fn a_genuine_batch_is_verified_and_its_events_admitted() {
        let (spool, key, ledger) = device();
        spool.emit(event(AuditAction::ClipboardBlocked));
        spool.emit(event(AuditAction::ScreenCaptureOverWork));

        let admitted = ledger
            .ingest(DEVICE, &batch(&spool, &key))
            .expect("verifies");
        assert_eq!(admitted.len(), 2);
        assert_eq!(
            ledger.high_water(DEVICE),
            Some(3),
            "next expected seq after two events"
        );
        assert_eq!(ledger.events_for(DEVICE).len(), 2);
    }

    #[test]
    fn two_batches_in_sequence_extend_one_chain() {
        let (spool, key, ledger) = device();
        spool.emit(event(AuditAction::NetworkBlocked));
        ledger.ingest(DEVICE, &batch(&spool, &key)).expect("first");

        spool.emit(event(AuditAction::InputTapOverWork));
        ledger.ingest(DEVICE, &batch(&spool, &key)).expect("second");

        assert_eq!(ledger.high_water(DEVICE), Some(3));
    }

    #[test]
    fn a_suppressed_batch_is_detected_as_a_gap() {
        let (spool, key, ledger) = device();

        spool.emit(event(AuditAction::ClipboardBlocked));
        let _dropped = batch(&spool, &key);

        spool.emit(event(AuditAction::NetworkBlocked));
        let next = batch(&spool, &key);

        match ledger.ingest(DEVICE, &next) {
            Err(IngestError::Rejected(AuditError::Gap { expected, got })) => {
                assert_eq!(
                    expected, 1,
                    "gateway still expects the dropped batch's first seq"
                );
                assert_eq!(got, 2);
            }
            other => panic!("expected a gap, got {other:?}"),
        }
        assert_eq!(
            ledger.high_water(DEVICE),
            Some(1),
            "a rejected batch admits nothing"
        );
    }

    #[test]
    fn a_rewritten_event_fails_the_hash_chain() {
        let (spool, key, ledger) = device();
        spool.emit(event(AuditAction::ClipboardBlocked));
        let mut tampered = batch(&spool, &key);
        tampered.entries[0].event = event(AuditAction::ProcessJoinedZone);

        assert!(matches!(
            ledger.ingest(DEVICE, &tampered),
            Err(IngestError::Rejected(AuditError::Tampered { seq: 1 }))
        ));
    }

    #[test]
    fn a_batch_signed_by_the_wrong_key_is_rejected() {
        let (spool, _key, ledger) = device();
        spool.emit(event(AuditAction::ClipboardBlocked));
        let forger = DeviceSigningKey::from_seed([9u8; 32]);

        assert!(matches!(
            ledger.ingest(DEVICE, &batch(&spool, &forger)),
            Err(IngestError::Rejected(AuditError::BadSignature))
        ));
    }

    #[test]
    fn audit_from_an_unenrolled_device_is_refused() {
        let key = DeviceSigningKey::from_seed([7u8; 32]);
        let spool = AuditSpool::new();
        spool.emit(event(AuditAction::ClipboardBlocked));
        let ledger = AuditLedger::new();
        assert_eq!(
            ledger.ingest(DEVICE, &batch(&spool, &key)),
            Err(IngestError::UnknownDevice(DEVICE))
        );
    }
}
