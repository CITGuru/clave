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

pub use clave_core::UnixTime;

pub const GATEWAY_PROTO_VERSION: u16 = 1;

pub const DEFAULT_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;

pub const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

pub(crate) const DOMAIN: &[u8] = b"clave-proto/v1\n";

pub(crate) fn signing_input(envelope_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN.len() + envelope_bytes.len());
    v.extend_from_slice(DOMAIN);
    v.extend_from_slice(envelope_bytes);
    v
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    BadSignature,
    Replay { last: u64, got: u64 },
    Stale { issued_at: UnixTime, now: UnixTime },
    WrongTenant { pinned: TenantId, got: TenantId },
    UnsupportedProto { got: u16 },
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
