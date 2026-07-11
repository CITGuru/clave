//! Tamper-evident, device-signed audit spool drained to the gateway.
//!
//! The audit log is the company's record *and* the user's privacy guarantee, so its integrity
//! matters as much as its schema. Each [`clave_core::AuditEvent`] is appended to a **hash chain**
//! ([`SpoolEntry`]): `hash = SHA-256(domain ++ seq ++ prev_hash ++ event)`. The device signs the
//! chain head when it drains a [`SignedSpoolBatch`] to the gateway, so:
//!
//! * **truncation / suppression** (A6) breaks the sequence or the chain — the gateway
//!   detects it the moment it verifies;
//! * **rewriting** the spool at rest (an attacker with the volume) needs the device key to re-sign
//!   the head, and that key never leaves the device's hardware store;
//! * the chain lets the gateway verify *incrementally* from the last head it accepted.
//!
//! The spool itself lives encrypted inside the Clave Disk; this type is the portable
//! chaining + signing + verification, testable with no gateway. The daemon uses [`AuditSpool`] as
//! its [`AuditSink`]; the sync loop drains it, signs a batch with the device key, and ships it.

use std::sync::{Arc, Mutex};

use clave_core::{AuditEvent, AuditSink};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Length of a chain hash (SHA-256).
pub const HASH_LEN: usize = 32;

/// A link hash in the audit chain.
pub type ChainHash = [u8; HASH_LEN];

/// The chain's genesis: the `prev` of the very first entry.
pub const GENESIS: ChainHash = [0u8; HASH_LEN];

/// Domain tag for the per-entry chain hash (kept distinct from the signing tag).
const CHAIN_DOMAIN: &[u8] = b"clave-audit-chain/v1\n";
/// Domain tag for the device's signature over a batch head.
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

/// One hash-chained audit record. `hash` binds this entry to all prior ones via `prev`, so the
/// gateway can verify the whole history incrementally and detect any rewrite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpoolEntry {
    /// 1-based, strictly increasing — a gap means entries were suppressed.
    pub seq: u64,
    /// The previous entry's `hash` (or [`GENESIS`] for the first).
    pub prev: ChainHash,
    /// The audited event (privacy-by-schema; carries no personal data).
    pub event: AuditEvent,
    /// `SHA-256(domain ++ seq ++ prev ++ event)`.
    pub hash: ChainHash,
}

/// A drained run of entries plus the device's signature over the resulting chain head. Verifying
/// the chain *and* the head signature proves the batch is authentic and untampered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSpoolBatch {
    pub entries: Vec<SpoolEntry>,
    /// The chain head after the last entry (equals `prev` if the batch is an empty heartbeat).
    pub head: ChainHash,
    /// Device Ed25519 signature over `SIG_DOMAIN ++ head` (64 bytes).
    pub signature: Vec<u8>,
}

/// The encrypted-at-rest audit spool: a hash chain plus the undrained tail. Implements
/// [`AuditSink`] so it is a drop-in for the daemon's audit sink, optionally forwarding to an inner
/// sink (e.g. a recording sink in tests, or a metrics sink in production).
pub struct AuditSpool {
    inner: Mutex<SpoolState>,
    forward: Option<Arc<dyn AuditSink>>,
}

struct SpoolState {
    /// Last assigned sequence number (0 ⇒ nothing recorded yet).
    seq: u64,
    /// Hash of the last entry (or [`GENESIS`]).
    head: ChainHash,
    /// Entries recorded since the last [`AuditSpool::drain`].
    pending: Vec<SpoolEntry>,
}

impl AuditSpool {
    /// A fresh, empty spool at genesis.
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

    /// A spool that also forwards every event to `inner` (decorator) — lets the daemon keep a
    /// recording/metrics sink underneath while gaining the chain.
    pub fn with_sink(inner: Arc<dyn AuditSink>) -> Self {
        let mut s = Self::new();
        s.forward = Some(inner);
        s
    }

    /// Resume a persisted chain after a restart (the spool's `seq`/`head` live in the encrypted
    /// volume), so the chain is unbroken across daemon lifetimes. Starts with no
    /// pending entries.
    pub fn resume(seq: u64, head: ChainHash) -> Self {
        Self::resume_with(seq, head, Vec::new())
    }

    /// Resume a persisted chain *including* its unshipped `pending` tail, so audit entries recorded
    /// but not yet acknowledged by the gateway survive a restart and re-ship — rather than
    /// vanishing and leaving the gateway a permanent chain gap. `seq`/`head` must be the state
    /// after the last pending entry (as [`AuditSpool::seq`]/[`AuditSpool::head`] reported it).
    pub fn resume_with(seq: u64, head: ChainHash, pending: Vec<SpoolEntry>) -> Self {
        Self {
            inner: Mutex::new(SpoolState { seq, head, pending }),
            forward: None,
        }
    }

    /// The current chain head — persist this (with [`AuditSpool::seq`]) so a restart can resume.
    pub fn head(&self) -> ChainHash {
        self.inner.lock().expect("spool lock poisoned").head
    }

    /// The last assigned sequence number.
    pub fn seq(&self) -> u64 {
        self.inner.lock().expect("spool lock poisoned").seq
    }

    /// How many entries await draining.
    pub fn pending_len(&self) -> usize {
        self.inner
            .lock()
            .expect("spool lock poisoned")
            .pending
            .len()
    }

    /// Take the undrained entries plus the current chain head, ready to be signed into a
    /// [`SignedSpoolBatch`]. The chain continues from the same head (the next entry's `prev` is
    /// this head), so draining never breaks continuity.
    ///
    /// This is the *destructive* drain: it removes the entries immediately. Prefer the ack-based
    /// [`peek`](AuditSpool::peek) + [`confirm_through`](AuditSpool::confirm_through) pair when
    /// shipping over a link that can fail — removing entries before the gateway has them risks
    /// losing them and wedging the chain (the gateway would then see a permanent gap).
    pub fn drain(&self) -> (Vec<SpoolEntry>, ChainHash) {
        let mut s = self.inner.lock().expect("spool lock poisoned");
        (std::mem::take(&mut s.pending), s.head)
    }

    /// Non-destructively snapshot the pending entries plus the current chain head, ready to sign
    /// and ship. The entries stay in the spool until [`confirm_through`](AuditSpool::confirm_through)
    /// acknowledges the gateway received them, so a failed ship loses nothing and simply retries
    /// next cycle. New entries may accrue after the snapshot; a later `peek` includes them.
    pub fn peek(&self) -> (Vec<SpoolEntry>, ChainHash) {
        let s = self.inner.lock().expect("spool lock poisoned");
        (s.pending.clone(), s.head)
    }

    /// Acknowledge that the gateway durably received every pending entry with `seq <= through_seq`
    /// (the max seq of a successfully-shipped batch); drop exactly those. Entries recorded after
    /// the corresponding [`peek`](AuditSpool::peek) (seq &gt; `through_seq`) are retained for the
    /// next cycle. The chain head is never rewound, so continuity holds regardless.
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
        // Forward outside the lock (AuditEvent is Copy), so a slow inner sink can't stall the
        // chain and an inner sink can never deadlock by re-entering.
        if let Some(f) = &self.forward {
            f.emit(event);
        }
    }
}

/// The device's Ed25519 key for signing audit batches. In production this is hardware-backed
/// (TPM / Secure Enclave) and its public half is enrolled with the gateway; here it is built from
/// a seed so the chain can be exercised with no hardware.
pub struct DeviceSigningKey {
    keypair: KeyPair,
}

impl DeviceSigningKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_seed(Seed::new(seed)),
        }
    }

    /// The 32-byte public key the gateway pins to verify this device's audit batches.
    pub fn public_key(&self) -> [u8; 32] {
        *self.keypair.pk
    }

    /// Sign a drained run into a shippable batch. `head` is the spool's head at drain time (from
    /// [`AuditSpool::drain`]); signing it commits to the entire history up to that point.
    pub fn sign_batch(&self, entries: Vec<SpoolEntry>, head: ChainHash) -> SignedSpoolBatch {
        let sig = self.keypair.sk.sign(sig_input(&head), None);
        SignedSpoolBatch {
            entries,
            head,
            signature: sig.to_vec(),
        }
    }
}

/// Why a drained audit batch failed gateway verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// An entry's recomputed hash didn't match — the event or chain was altered.
    Tampered { seq: u64 },
    /// An entry's `prev` (or the final head) didn't match the running chain — a break or reorder.
    BrokenChain { seq: u64 },
    /// Sequence numbers skipped — entries were dropped / suppressed.
    Gap { expected: u64, got: u64 },
    /// The device signature over the batch head failed (forged or wrong device key).
    BadSignature,
    /// Structurally invalid (e.g. signature not 64 bytes).
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

/// Gateway-side verification: confirm `batch` continues the chain from `prev` (the last head the
/// gateway accepted) starting at `next_seq`, with no tampering, gaps, or forgery, and is signed by
/// the device's pinned key. Returns the new chain head to remember for the next batch.
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
    // The signed head must equal the running head — catches a dropped tail even though the
    // signature itself is valid over the original head.
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
