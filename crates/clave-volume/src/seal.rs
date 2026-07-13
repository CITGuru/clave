use ed25519_compact::x25519;
use sha2::{Digest, Sha256};

use crate::keys::{Dek, Kek, WrappedDek};
use crate::VolumeError;

const SEAL_KDF_CONTEXT: &[u8] = b"clave-volume/seal/v1";

pub struct DeviceSealingKey {
    keypair: x25519::KeyPair,
}

impl DeviceSealingKey {
    pub fn generate() -> Self {
        Self {
            keypair: x25519::KeyPair::generate(),
        }
    }

    pub fn from_secret(secret: [u8; 32]) -> Result<Self, VolumeError> {
        let sk = x25519::SecretKey::new(secret);
        let pk = sk.recover_public_key().map_err(|_| VolumeError::Seal)?;
        Ok(Self {
            keypair: x25519::KeyPair { pk, sk },
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        *self.keypair.pk
    }
}

pub struct SealedDek {
    pub ephemeral_pub: [u8; 32],
    pub wrapped: WrappedDek,
}

fn derive_kek(shared: &[u8; 32], ephemeral_pub: &[u8; 32], device_pub: &[u8; 32]) -> Kek {
    let mut h = Sha256::new();
    h.update(SEAL_KDF_CONTEXT);
    h.update(ephemeral_pub);
    h.update(device_pub);
    h.update(shared);
    let digest = h.finalize();
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&digest);
    Kek::from_bytes(kek)
}

pub fn seal_dek(device_pub: [u8; 32], dek: &Dek) -> Result<SealedDek, VolumeError> {
    let device_pk = x25519::PublicKey::new(device_pub);
    let ephemeral = x25519::KeyPair::generate();
    let shared = device_pk.dh(&ephemeral.sk).map_err(|_| VolumeError::Seal)?;
    let ephemeral_pub = *ephemeral.pk;
    let kek = derive_kek(&shared, &ephemeral_pub, &device_pub);
    Ok(SealedDek {
        ephemeral_pub,
        wrapped: kek.wrap(dek),
    })
}

pub fn open_dek(device: &DeviceSealingKey, sealed: &SealedDek) -> Result<Dek, VolumeError> {
    let ephemeral_pk = x25519::PublicKey::new(sealed.ephemeral_pub);
    let shared = ephemeral_pk
        .dh(&device.keypair.sk)
        .map_err(|_| VolumeError::Seal)?;
    let kek = derive_kek(&shared, &sealed.ephemeral_pub, &device.public_key());
    kek.unwrap(&sealed.wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DEK_LEN;

    fn dek() -> Dek {
        Dek::from_bytes([0xDE; DEK_LEN])
    }

    #[test]
    fn seal_then_open_recovers_the_dek() {
        let device = DeviceSealingKey::generate();
        let sealed = seal_dek(device.public_key(), &dek()).expect("seal");
        let recovered = open_dek(&device, &sealed).expect("open");
        let probe = Kek::from_bytes([0x77; 32]);
        assert_eq!(
            probe.wrap(&recovered).as_bytes(),
            probe.wrap(&dek()).as_bytes()
        );
    }

    #[test]
    fn a_different_device_cannot_open_the_seal() {
        let device = DeviceSealingKey::generate();
        let attacker = DeviceSealingKey::generate();
        let sealed = seal_dek(device.public_key(), &dek()).expect("seal");
        assert!(matches!(
            open_dek(&attacker, &sealed),
            Err(VolumeError::KeyUnwrap)
        ));
    }

    #[test]
    fn from_secret_round_trips_a_fixed_key() {
        let device = DeviceSealingKey::from_secret([0x42; 32]).expect("valid secret");
        let sealed = seal_dek(device.public_key(), &dek()).expect("seal");
        let recovered = open_dek(&device, &sealed).expect("open");
        let probe = Kek::from_bytes([0x55; 32]);
        assert_eq!(
            probe.wrap(&recovered).as_bytes(),
            probe.wrap(&dek()).as_bytes()
        );
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let device = DeviceSealingKey::generate();
        let a = seal_dek(device.public_key(), &dek()).expect("seal");
        let b = seal_dek(device.public_key(), &dek()).expect("seal");
        assert_ne!(
            a.ephemeral_pub, b.ephemeral_pub,
            "each seal must use a fresh ephemeral key"
        );
        let probe = Kek::from_bytes([0x33; 32]);
        assert_eq!(
            probe.wrap(&open_dek(&device, &a).unwrap()).as_bytes(),
            probe.wrap(&open_dek(&device, &b).unwrap()).as_bytes()
        );
    }
}
