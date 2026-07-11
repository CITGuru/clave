//! The **enrollment grant** wire contract: what the gateway issues a device when
//! it finishes enrolling, and what the device's enrollment client consumes to bootstrap its
//! gateway-trust + volume material.
//!
//! It lives here, in the portable gateway↔daemon trust layer, so neither side depends on the other:
//! the gateway ([`clave_gateway`](https://docs.rs/)) *produces* an [`EnrollmentGrant`], the daemon's
//! enrollment client *accepts* it. The signed policy is a [`SignedCommand`] the device's pinned-key
//! [`GatewayVerifier`](crate::GatewayVerifier) already knows how to verify; the volume key is
//! ciphertext the device opens with its hardware key.

use serde::{Deserialize, Serialize};

use crate::SignedCommand;

/// The wrapped Clave Disk key a device receives at enrollment: the container DEK as ciphertext the
/// device opens with its hardware key. Two delivery shapes share this type:
///
/// * **symmetric** (`ephemeral_pub == None`) — `wrapped_dek` is an AES-KW wrap under the device's
///   KEK. The dev/bootstrap path (a shared software KEK), mirroring `clave_volume::MemKeyStore`.
/// * **sealed** (`ephemeral_pub == Some(pk)`) — `wrapped_dek` is an AES-KW wrap under a KEK derived
///   from an X25519 ECDH between the gateway's ephemeral key `pk` and the device's hardware sealing
///   key (an ECIES/sealed-box). The production path: the device private key never leaves hardware.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedVolumeKey {
    /// The device's Clave Disk container — the bare `u128` of a `clave_volume::ContainerId`.
    pub container: u128,
    /// AES-KW ciphertext of the DEK (`clave_volume::WRAPPED_DEK_LEN` bytes).
    pub wrapped_dek: Vec<u8>,
    /// The gateway's ephemeral X25519 public key for the sealed (asymmetric) delivery; `None` for
    /// the symmetric dev wrap.
    pub ephemeral_pub: Option<[u8; 32]>,
}

/// Everything the gateway hands a freshly-enrolled device for its runtime. The
/// device's enrollment client verifies `policy` against its pinned tenant key and opens `volume_key`
/// with its hardware key. Each is `None` when the gateway has not configured that artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EnrollmentGrant {
    /// The tenant-signed initial policy command (`GatewayCommand::UpdatePolicy`).
    pub policy: Option<SignedCommand>,
    /// The wrapped Clave Disk key.
    pub volume_key: Option<WrappedVolumeKey>,
}

impl EnrollmentGrant {
    pub fn new(policy: Option<SignedCommand>, volume_key: Option<WrappedVolumeKey>) -> Self {
        Self { policy, volume_key }
    }
}
