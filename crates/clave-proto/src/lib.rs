//! # clave-proto — signed gateway control plane
//!
//! The portable trust layer between the corporate **gateway** and the daemon. The gateway is the
//! only party allowed to change a device's posture — push policy, lock it, or **wipe** it — and
//! it proves each command with a detached **Ed25519** signature over a canonical payload. The
//! daemon pins the tenant's public key and refuses anything it cannot verify, so a compromised
//! transport — or a captured-and-replayed command — changes nothing.
//!
//! This crate is **transport-agnostic** (like [`clave_ipc`](https://docs.rs/)); it defines the
//! wire types, the signing/verification, and the anti-replay state. The daemon's gateway sync
//! loop carries [`SignedCommand`]s over mTLS.
//!
//! ## Guarantees
//!
//! * **Authenticity / integrity** — [`GatewayVerifier`] checks the signature against a *pinned*
//!   key (signature pinning). A wrong key, wrong tenant, or one flipped byte ⇒
//!   [`ProtoError::BadSignature`] / [`ProtoError::WrongTenant`]; the command is dropped.
//! * **Anti-replay** — every command carries a strictly increasing per-tenant `counter`; the
//!   verifier holds the high-water mark and rejects any `counter` it has already passed
//!   ([`ProtoError::Replay`]). The mark is meant to live in TPM/Keychain-protected metadata so a
//!   reset cannot rewind it — see [`GatewayVerifier::with_high_water`].
//! * **Freshness** — a signed `issued_at` bounds how long a captured command stays valid
//!   ([`ProtoError::Stale`]); the counter is the primary guard and this is defence in depth.
//! * **Fail-closed** — verification yields the command only when *every* check passes.
//!
//! Keeping the crypto here (not in `clave-core`) lets the policy brain stay
//! `#![forbid(unsafe_code)]` and crypto-free while still being *delivered* as a signed bundle.
#![forbid(unsafe_code)]

mod audit;
mod command;
mod enroll;
mod link;
#[cfg(feature = "mtls")]
pub mod mtls;
mod sign;
#[cfg(feature = "transport")]
pub mod transport;
mod verify;

pub use audit::{
    verify_batch, AuditError, AuditSpool, ChainHash, DeviceSigningKey, SignedSpoolBatch,
    SpoolEntry, GENESIS,
};
pub use command::{ControlReason, Envelope, GatewayCommand, SignedCommand};
pub use enroll::{EnrollmentGrant, WrappedVolumeKey};
pub use link::{GatewayLink, LinkError, LoopbackLink};
pub use sign::GatewaySigningKey;
pub use verify::GatewayVerifier;

use serde::{Deserialize, Serialize};

/// Seconds since the Unix epoch — re-exported so call sites need not reach into `clave_core`.
pub use clave_core::UnixTime;

/// Bumped on any wire-incompatible change to the signed envelope. It is part of the signed
/// payload, so a downgrade cannot slip past verification.
pub const GATEWAY_PROTO_VERSION: u16 = 1;

/// Default freshness window (30 days). A command older than this is rejected as
/// [`ProtoError::Stale`] even if otherwise valid; tune with [`GatewayVerifier::with_max_age`].
/// The monotonic counter, not this window, is the primary anti-replay control.
pub const DEFAULT_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;

/// Tolerance for a future-dated `issued_at` (clock skew between gateway and device).
pub const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

/// Domain-separation tag prepended to the signed bytes, so a Clave gateway signature can never be
/// mistaken for a signature minted in another context.
pub(crate) const DOMAIN: &[u8] = b"clave-proto/v1\n";

/// The exact bytes that are signed and verified: the domain tag followed by the canonical
/// envelope encoding. Signer and verifier compute this identically.
pub(crate) fn signing_input(envelope_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN.len() + envelope_bytes.len());
    v.extend_from_slice(DOMAIN);
    v.extend_from_slice(envelope_bytes);
    v
}

/// Identifies the tenant whose pinned key signs commands for this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub u64);

/// Why a signed gateway command was refused. **Every** variant means the command had no effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Ed25519 verification failed against the pinned key — wrong key, or the payload/signature
    /// was tampered with.
    BadSignature,
    /// The command's `counter` is at or below the high-water mark — a replay or reorder.
    Replay { last: u64, got: u64 },
    /// `issued_at` is outside the accepted freshness window (too old, or too far in the future).
    Stale { issued_at: UnixTime, now: UnixTime },
    /// The envelope names a different tenant than the one this verifier is pinned to.
    WrongTenant { pinned: TenantId, got: TenantId },
    /// The envelope's protocol version is not understood by this build.
    UnsupportedProto { got: u16 },
    /// The signature or envelope bytes were structurally invalid (wrong length / undecodable).
    Malformed,
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::BadSignature => write!(f, "gateway signature verification failed"),
            ProtoError::Replay { last, got } => {
                write!(f, "replayed command: counter {got} <= high-water {last}")
            }
            ProtoError::Stale { issued_at, now } => {
                write!(f, "stale command: issued_at {issued_at}, now {now}")
            }
            ProtoError::WrongTenant { pinned, got } => {
                write!(f, "wrong tenant: pinned {}, got {}", pinned.0, got.0)
            }
            ProtoError::UnsupportedProto { got } => {
                write!(f, "unsupported gateway proto version {got}")
            }
            ProtoError::Malformed => write!(f, "malformed signed command"),
        }
    }
}

impl std::error::Error for ProtoError {}
