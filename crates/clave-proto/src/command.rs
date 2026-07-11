//! The signed gateway command wire types.

use clave_core::{PolicyBundle, UnixTime};
use serde::{Deserialize, Serialize};

use crate::{TenantId, GATEWAY_PROTO_VERSION};

/// Why the gateway issued a control command — a *category*, never free-form personal data
/// (mirrors the privacy-by-schema audit log).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlReason {
    /// Planned offboarding (employee left, project ended).
    Offboarding,
    /// Device reported lost or stolen (A5/A6).
    LostOrStolen,
    /// Suspected compromise / incident response.
    Compromise,
    /// Routine administrative action.
    AdminRequest,
}

/// What the gateway is authorising. Carried inside a signed [`Envelope`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayCommand {
    /// Install a new policy bundle. Rollback is additionally guarded by the bundle's
    /// own monotonic `version`, so even a validly signed *old* bundle is refused by the daemon.
    UpdatePolicy(PolicyBundle),
    /// Remotely lock (force-dark) the enclave. Reversible — the user re-unlocks with local
    /// hardware auth (TPM / Secure Enclave); a fail-safe quarantine.
    Lock { reason: ControlReason },
    /// Remote wipe / crypto-shred a container. Irreversible the instant the wrapped
    /// key is destroyed. `container` is the target's UUID — the same value as the target's
    /// `clave_volume::ContainerId` (carried as a bare `u128` to avoid a crate dependency).
    Wipe {
        container: u128,
        reason: ControlReason,
    },
}

/// The signed payload. Its canonical [`postcard`] encoding is exactly what the gateway signs and
/// the daemon verifies (see [`SignedCommand`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Wire version ([`GATEWAY_PROTO_VERSION`]); inside the signature so it cannot be downgraded.
    pub proto: u16,
    /// The signing tenant; the verifier checks it against its pinned tenant.
    pub tenant: TenantId,
    /// Strictly increasing per-tenant sequence number — the anti-replay primitive.
    pub counter: u64,
    /// Issue time (seconds since epoch); bounds freshness.
    pub issued_at: UnixTime,
    /// The authorised action.
    pub command: GatewayCommand,
}

impl Envelope {
    /// Build an envelope at the current protocol version for `tenant`.
    pub fn new(
        tenant: TenantId,
        counter: u64,
        issued_at: UnixTime,
        command: GatewayCommand,
    ) -> Self {
        Self {
            proto: GATEWAY_PROTO_VERSION,
            tenant,
            counter,
            issued_at,
            command,
        }
    }

    /// Canonical bytes to sign / verify. `postcard` is deterministic for these POD types, so the
    /// signer and verifier agree; infallible for our own types.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("postcard serialize of a gateway envelope")
    }
}

/// A gateway command on the wire: the exact signed envelope bytes plus a detached Ed25519
/// signature over them. Carrying the *bytes* (not the struct) means the daemon verifies the
/// signature over precisely what was signed — no re-serialization / canonicalization risk.
///
/// Fully `serde`-serializable, so any transport (mTLS WebSocket, a file, a test) can carry it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCommand {
    /// Canonical postcard encoding of the signed [`Envelope`].
    pub envelope: Vec<u8>,
    /// Detached Ed25519 signature over `DOMAIN ++ envelope` (64 bytes).
    pub signature: Vec<u8>,
}
