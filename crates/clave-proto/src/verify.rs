//! Daemon-side verification + anti-replay state — the only gateway-trust code the daemon runs.

use ed25519_compact::{PublicKey, Signature};

use crate::command::{Envelope, GatewayCommand, SignedCommand};
use crate::{
    signing_input, ProtoError, TenantId, UnixTime, DEFAULT_MAX_AGE_SECS, GATEWAY_PROTO_VERSION,
    MAX_FUTURE_SKEW_SECS,
};

/// Verifies signed gateway commands against a *pinned* tenant key and enforces anti-replay +
/// freshness. It holds the high-water mark, so [`GatewayVerifier::verify`] takes `&mut self`; the
/// daemon wraps it in a `Mutex` (as it does the router and the volume).
pub struct GatewayVerifier {
    tenant: TenantId,
    key: PublicKey,
    high_water: u64,
    max_age_secs: u64,
}

impl GatewayVerifier {
    /// Pin `tenant`'s 32-byte public key. Errors ([`ProtoError::Malformed`]) only if the bytes
    /// are not a valid Ed25519 public key.
    pub fn new(tenant: TenantId, pinned_public_key: [u8; 32]) -> Result<Self, ProtoError> {
        let key = PublicKey::from_slice(&pinned_public_key).map_err(|_| ProtoError::Malformed)?;
        Ok(Self {
            tenant,
            key,
            high_water: 0,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
        })
    }

    /// Restore the persisted anti-replay high-water mark (from TPM/Keychain-protected metadata)
    /// so a process restart cannot rewind it. Counters at or below it are rejected.
    pub fn with_high_water(mut self, counter: u64) -> Self {
        self.high_water = counter;
        self
    }

    /// Override the freshness window (default [`DEFAULT_MAX_AGE_SECS`]).
    pub fn with_max_age(mut self, secs: u64) -> Self {
        self.max_age_secs = secs;
        self
    }

    /// The current high-water mark — persist this after each accepted command.
    pub fn high_water(&self) -> u64 {
        self.high_water
    }

    /// Verify a signed command and, if every check passes, return its [`GatewayCommand`] and
    /// advance the anti-replay high-water mark. **Fail-closed:** on any error nothing changes and
    /// no command is returned.
    ///
    /// Order — signature (over the exact received bytes) → decode → proto → tenant → freshness →
    /// anti-replay. The signature is checked first, so forged or undecodable input is rejected
    /// before any field is trusted.
    pub fn verify(
        &mut self,
        signed: &SignedCommand,
        now: UnixTime,
    ) -> Result<GatewayCommand, ProtoError> {
        // 1. Signature over the exact bytes that were signed, against the pinned key.
        //    `from_slice` enforces the 64-byte length, so a truncated signature is Malformed.
        let sig = Signature::from_slice(&signed.signature).map_err(|_| ProtoError::Malformed)?;
        self.key
            .verify(signing_input(&signed.envelope), &sig)
            .map_err(|_| ProtoError::BadSignature)?;

        // 2. Decode only after integrity is proven.
        let env: Envelope =
            postcard::from_bytes(&signed.envelope).map_err(|_| ProtoError::Malformed)?;

        // 3. Protocol + tenant binding.
        if env.proto != GATEWAY_PROTO_VERSION {
            return Err(ProtoError::UnsupportedProto { got: env.proto });
        }
        if env.tenant != self.tenant {
            return Err(ProtoError::WrongTenant {
                pinned: self.tenant,
                got: env.tenant,
            });
        }

        // 4. Freshness (defence in depth; the counter is the primary anti-replay).
        let age = now.saturating_sub(env.issued_at);
        let future = env.issued_at.saturating_sub(now);
        if age > self.max_age_secs || future > MAX_FUTURE_SKEW_SECS {
            return Err(ProtoError::Stale {
                issued_at: env.issued_at,
                now,
            });
        }

        // 5. Anti-replay: strictly increasing counter, then commit the high-water mark.
        if env.counter <= self.high_water {
            return Err(ProtoError::Replay {
                last: self.high_water,
                got: env.counter,
            });
        }
        self.high_water = env.counter;
        Ok(env.command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::SignedCommand;
    use ed25519_compact::{KeyPair, Seed};

    /// A signature can be valid yet the payload not decode to an `Envelope` — the decode-after-
    /// verify step must reject it as `Malformed`. (Defensive: a real gateway never signs garbage.)
    #[test]
    fn valid_signature_over_non_envelope_bytes_is_malformed() {
        let kp = KeyPair::from_seed(Seed::new([1u8; 32]));
        let garbage = vec![0xFFu8]; // an incomplete varint — not a decodable Envelope
        let sig = kp.sk.sign(signing_input(&garbage), None);
        let signed = SignedCommand {
            envelope: garbage,
            signature: sig.to_vec(),
        };
        let mut v = GatewayVerifier::new(TenantId(1), *kp.pk).unwrap();
        assert_eq!(v.verify(&signed, 0), Err(ProtoError::Malformed));
    }
}
