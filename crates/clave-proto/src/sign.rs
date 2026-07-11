//! Gateway-side signing (used by the gateway service and by tests — never by the daemon).
//!
//! The daemon only ever *verifies* (see [`crate::GatewayVerifier`]) and holds no signing key.
//! This type lives here so the gateway — and this crate's tests — can mint [`SignedCommand`]s.

use ed25519_compact::{KeyPair, Seed};

use crate::command::{Envelope, GatewayCommand, SignedCommand};
use crate::{signing_input, TenantId, UnixTime};

/// A tenant's Ed25519 key pair. Construct from the 32-byte seed the tenant generated
/// out-of-band; the matching public key ([`GatewaySigningKey::public_key`]) is pinned into the
/// daemon at enrollment.
pub struct GatewaySigningKey {
    keypair: KeyPair,
    tenant: TenantId,
}

impl GatewaySigningKey {
    /// Build from a tenant id and a 32-byte Ed25519 seed (the secret scalar seed).
    pub fn from_seed(tenant: TenantId, seed: [u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_seed(Seed::new(seed)),
            tenant,
        }
    }

    /// The 32-byte public key to pin into a [`GatewayVerifier`](crate::GatewayVerifier).
    pub fn public_key(&self) -> [u8; 32] {
        *self.keypair.pk
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Sign a caller-built envelope (full control over proto / tenant / counter — used by tests
    /// and by gateways that batch). Signing is deterministic (RFC 8032); the signature covers
    /// `DOMAIN ++ envelope_bytes`.
    pub fn sign_envelope(&self, envelope: &Envelope) -> SignedCommand {
        let bytes = envelope.to_bytes();
        let sig = self.keypair.sk.sign(signing_input(&bytes), None);
        SignedCommand {
            envelope: bytes,
            signature: sig.to_vec(),
        }
    }

    /// Convenience: wrap `command` for this tenant at the current proto version and sign it.
    /// `counter` must strictly increase across the commands a daemon will accept.
    pub fn sign(
        &self,
        counter: u64,
        issued_at: UnixTime,
        command: GatewayCommand,
    ) -> SignedCommand {
        self.sign_envelope(&Envelope::new(self.tenant, counter, issued_at, command))
    }
}
