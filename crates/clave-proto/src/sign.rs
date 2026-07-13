use ed25519_compact::{KeyPair, Seed};

use crate::command::{Envelope, GatewayCommand, SignedCommand};
use crate::{signing_input, TenantId, UnixTime};

pub struct GatewaySigningKey {
    keypair: KeyPair,
    tenant: TenantId,
}

impl GatewaySigningKey {
    pub fn from_seed(tenant: TenantId, seed: [u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_seed(Seed::new(seed)),
            tenant,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        *self.keypair.pk
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn sign_envelope(&self, envelope: &Envelope) -> SignedCommand {
        let bytes = envelope.to_bytes();
        let sig = self.keypair.sk.sign(signing_input(&bytes), None);
        SignedCommand {
            envelope: bytes,
            signature: sig.to_vec(),
        }
    }

    pub fn sign(
        &self,
        counter: u64,
        issued_at: UnixTime,
        command: GatewayCommand,
    ) -> SignedCommand {
        self.sign_envelope(&Envelope::new(self.tenant, counter, issued_at, command))
    }
}
