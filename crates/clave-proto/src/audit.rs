use std::sync::{Arc, Mutex};

use clave_core::{AuditEvent, AuditSink};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;

pub type ChainHash = [u8; HASH_LEN];

pub const GENESIS: ChainHash = [0u8; HASH_LEN];

const CHAIN_DOMAIN: &[u8] = b"clave-audit-chain/v1\n";
const SIG_DOMAIN: &[u8] = b"clave-audit-sig/v1\n";

fn entry_hash(seq: u64, prev: &ChainHash, event_bytes: &[u8]) -> ChainHash {
    let mut h = Sha256::new();
    h.update(CHAIN_DOMAIN);
    h.update(seq.to_le_bytes());
    h.update(prev);
    h.update(event_bytes);
    let digest = h.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

fn sig_input(head: &ChainHash) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_DOMAIN.len() + HASH_LEN);
    v.extend_from_slice(SIG_DOMAIN);
    v.extend_from_slice(head);
    v
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpoolEntry {
    pub seq: u64,
    pub prev: ChainHash,
    pub event: AuditEvent,
    pub hash: ChainHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSpoolBatch {
    pub entries: Vec<SpoolEntry>,
    pub head: ChainHash,
    pub signature: Vec<u8>,
}

pub struct AuditSpool {
    inner: Mutex<SpoolState>,
    forward: Option<Arc<dyn AuditSink>>,
}

struct SpoolState {
    seq: u64,
    head: ChainHash,
    pending: Vec<SpoolEntry>,
}

impl AuditSpool {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SpoolState {
                seq: 0,
                head: GENESIS,
                pending: Vec::new(),
            }),
            forward: None,
        }
    }

    pub fn with_sink(inner: Arc<dyn AuditSink>) -> Self {
        let mut s = Self::new();
        s.forward = Some(inner);
        s
    }

    pub fn resume(seq: u64, head: ChainHash) -> Self {
        Self::resume_with(seq, head, Vec::new())
    }

    pub fn resume_with(seq: u64, head: ChainHash, pending: Vec<SpoolEntry>) -> Self {
        Self {
            inner: Mutex::new(SpoolState { seq, head, pending }),
            forward: None,
        }
    }

    pub fn head(&self) -> ChainHash {
        self.inner.lock().expect("spool lock poisoned").head
    }

    pub fn seq(&self) -> u64 {
        self.inner.lock().expect("spool lock poisoned").seq
    }

    pub fn pending_len(&self) -> usize {
        self.inner
            .lock()
            .expect("spool lock poisoned")
            .pending
            .len()
    }

    pub fn drain(&self) -> (Vec<SpoolEntry>, ChainHash) {
        let mut s = self.inner.lock().expect("spool lock poisoned");
        (std::mem::take(&mut s.pending), s.head)
    }

    pub fn peek(&self) -> (Vec<SpoolEntry>, ChainHash) {
        let s = self.inner.lock().expect("spool lock poisoned");
        (s.pending.clone(), s.head)
    }

    pub fn confirm_through(&self, through_seq: u64) {
        let mut s = self.inner.lock().expect("spool lock poisoned");
        s.pending.retain(|e| e.seq > through_seq);
    }
}

impl Default for AuditSpool {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for AuditSpool {
    fn emit(&self, event: AuditEvent) {
        {
            let mut s = self.inner.lock().expect("spool lock poisoned");
            let seq = s.seq + 1;
            let bytes = postcard::to_allocvec(&event).expect("postcard serialize of an AuditEvent");
            let prev = s.head;
            let hash = entry_hash(seq, &prev, &bytes);
            s.seq = seq;
            s.head = hash;
            s.pending.push(SpoolEntry {
                seq,
                prev,
                event,
                hash,
            });
        }
        if let Some(f) = &self.forward {
            f.emit(event);
        }
    }
}

pub struct DeviceSigningKey {
    keypair: KeyPair,
}

impl DeviceSigningKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_seed(Seed::new(seed)),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        *self.keypair.pk
    }

    pub fn sign_batch(&self, entries: Vec<SpoolEntry>, head: ChainHash) -> SignedSpoolBatch {
        let sig = self.keypair.sk.sign(sig_input(&head), None);
        SignedSpoolBatch {
            entries,
            head,
            signature: sig.to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    Tampered { seq: u64 },
    BrokenChain { seq: u64 },
    Gap { expected: u64, got: u64 },
    BadSignature,
    Malformed,
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Tampered { seq } => write!(f, "audit entry {seq} was tampered with"),
            AuditError::BrokenChain { seq } => write!(f, "audit chain broke at entry {seq}"),
            AuditError::Gap { expected, got } => {
                write!(f, "audit sequence gap: expected {expected}, got {got}")
            }
            AuditError::BadSignature => write!(f, "audit batch signature verification failed"),
            AuditError::Malformed => write!(f, "malformed audit batch"),
        }
    }
}

impl std::error::Error for AuditError {}

pub fn verify_batch(
    prev: ChainHash,
    next_seq: u64,
    batch: &SignedSpoolBatch,
    device_public_key: [u8; 32],
) -> Result<ChainHash, AuditError> {
    let mut running = prev;
    let mut expect = next_seq;
    for e in &batch.entries {
        if e.seq != expect {
            return Err(AuditError::Gap {
                expected: expect,
                got: e.seq,
            });
        }
        if e.prev != running {
            return Err(AuditError::BrokenChain { seq: e.seq });
        }
        let bytes = postcard::to_allocvec(&e.event).map_err(|_| AuditError::Malformed)?;
        if entry_hash(e.seq, &e.prev, &bytes) != e.hash {
            return Err(AuditError::Tampered { seq: e.seq });
        }
        running = e.hash;
        expect += 1;
    }
    if running != batch.head {
        return Err(AuditError::BrokenChain {
            seq: expect.saturating_sub(1),
        });
    }
    let pk = PublicKey::from_slice(&device_public_key).map_err(|_| AuditError::Malformed)?;
    let sig = Signature::from_slice(&batch.signature).map_err(|_| AuditError::Malformed)?;
    pk.verify(sig_input(&batch.head), &sig)
        .map_err(|_| AuditError::BadSignature)?;
    Ok(batch.head)
}
