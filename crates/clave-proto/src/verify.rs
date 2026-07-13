use ed25519_compact::{PublicKey, Signature};

use crate::command::{Envelope, GatewayCommand, SignedCommand};
use crate::{
    signing_input, ProtoError, TenantId, UnixTime, DEFAULT_MAX_AGE_SECS, GATEWAY_PROTO_VERSION,
    MAX_FUTURE_SKEW_SECS,
};

pub struct GatewayVerifier {
    tenant: TenantId,
    key: PublicKey,
    high_water: u64,
    max_age_secs: u64,
}

impl GatewayVerifier {
    pub fn new(tenant: TenantId, pinned_public_key: [u8; 32]) -> Result<Self, ProtoError> {
        let key = PublicKey::from_slice(&pinned_public_key).map_err(|_| ProtoError::Malformed)?;
        Ok(Self {
            tenant,
            key,
            high_water: 0,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
        })
    }

    pub fn with_high_water(mut self, counter: u64) -> Self {
        self.high_water = counter;
        self
    }

    pub fn with_max_age(mut self, secs: u64) -> Self {
        self.max_age_secs = secs;
        self
    }

    pub fn high_water(&self) -> u64 {
        self.high_water
    }

    pub fn verify(
        &mut self,
        signed: &SignedCommand,
        now: UnixTime,
    ) -> Result<GatewayCommand, ProtoError> {
        let sig = Signature::from_slice(&signed.signature).map_err(|_| ProtoError::Malformed)?;
        self.key
            .verify(signing_input(&signed.envelope), &sig)
            .map_err(|_| ProtoError::BadSignature)?;

        let env: Envelope =
            postcard::from_bytes(&signed.envelope).map_err(|_| ProtoError::Malformed)?;

        if env.proto != GATEWAY_PROTO_VERSION {
            return Err(ProtoError::UnsupportedProto { got: env.proto });
        }
        if env.tenant != self.tenant {
            return Err(ProtoError::WrongTenant {
                pinned: self.tenant,
                got: env.tenant,
            });
        }

        let age = now.saturating_sub(env.issued_at);
        let future = env.issued_at.saturating_sub(now);
        if age > self.max_age_secs || future > MAX_FUTURE_SKEW_SECS {
            return Err(ProtoError::Stale {
                issued_at: env.issued_at,
                now,
            });
        }

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

    #[test]
    fn valid_signature_over_non_envelope_bytes_is_malformed() {
        let kp = KeyPair::from_seed(Seed::new([1u8; 32]));
        let garbage = vec![0xFFu8];
        let sig = kp.sk.sign(signing_input(&garbage), None);
        let signed = SignedCommand {
            envelope: garbage,
            signature: sig.to_vec(),
        };
        let mut v = GatewayVerifier::new(TenantId(1), *kp.pk).unwrap();
        assert_eq!(v.verify(&signed, 0), Err(ProtoError::Malformed));
    }
}
