//! The enrollment **sealed-box** for DEKs: the production way the
//! gateway hands a device its volume key without ever holding the device's secret.
//!
//! The symmetric [`Kek`] path ([`keys`](crate::keys)) models a *shared* device key — fine for the
//! in-memory bootstrap, but in production the device's key is hardware-bound and never leaves the
//! Secure Enclave / TPM. So the gateway instead **seals** the DEK to the device's X25519 *public*
//! key (an ECIES / libsodium-`crypto_box_seal` construction):
//!
//! ```text
//! seal:  ephemeral X25519 keypair (e_sk, e_pk)
//!        shared = X25519(e_sk, device_pub)
//!        KEK    = SHA-256(ctx ++ e_pk ++ device_pub ++ shared)
//!        out    = (e_pk, AES-KW(KEK, DEK))
//! open:  shared = X25519(device_sk, e_pk)        // same point — ECDH
//!        KEK    = SHA-256(ctx ++ e_pk ++ device_pub ++ shared)
//!        DEK    = AES-KW^-1(KEK, wrapped)
//! ```
//!
//! Only the device's secret recovers `shared`, so only the device opens the DEK — the gateway keeps
//! nothing that can. The inner wrap reuses the same AES-KW as the symmetric path, so a sealed and a
//! symmetric [`WrappedDek`](crate::WrappedDek) are the same ciphertext shape on the wire. X25519 and
//! SHA-256 are pure-Rust (`ed25519-compact`, `sha2`) so this stays `#![forbid(unsafe_code)]` and
//! testable on any machine; in production the device half runs inside the enclave.

use ed25519_compact::x25519;
use sha2::{Digest, Sha256};

use crate::keys::{Dek, Kek, WrappedDek};
use crate::VolumeError;

/// Domain separation for the KEK derivation; bump the suffix on any change to the construction.
const SEAL_KDF_CONTEXT: &[u8] = b"clave-volume/seal/v1";

/// A device's X25519 sealing keypair. In production the secret is generated in, and never leaves,
/// the Secure Enclave / TPM; here it is software so the seal/open round-trip is testable. The
/// device registers [`DeviceSealingKey::public_key`] with the gateway at enrollment.
pub struct DeviceSealingKey {
    keypair: x25519::KeyPair,
}

impl DeviceSealingKey {
    /// Generate a fresh sealing keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            keypair: x25519::KeyPair::generate(),
        }
    }

    /// Reconstruct from a 32-byte X25519 secret (the deterministic test / restored-from-hardware
    /// path). Errors ([`VolumeError::Seal`]) if the secret does not yield a valid public key.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, VolumeError> {
        let sk = x25519::SecretKey::new(secret);
        let pk = sk.recover_public_key().map_err(|_| VolumeError::Seal)?;
        Ok(Self {
            keypair: x25519::KeyPair { pk, sk },
        })
    }

    /// The 32-byte X25519 public key to register with the gateway (the DEK is sealed to this).
    pub fn public_key(&self) -> [u8; 32] {
        *self.keypair.pk
    }
}

/// A DEK sealed to a device's X25519 public key: the gateway's ephemeral public key plus the DEK
/// AES-KW-wrapped under the ECDH-derived KEK. Carries no long-term secret; only the matching device
/// secret recovers the DEK.
pub struct SealedDek {
    /// The gateway's ephemeral X25519 public key.
    pub ephemeral_pub: [u8; 32],
    /// The DEK wrapped under the derived KEK (same shape as the symmetric path).
    pub wrapped: WrappedDek,
}

/// Derive the wrapping KEK from the ECDH shared secret, bound to both public keys so a swapped
/// ephemeral or device key yields a different KEK.
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

/// Seal `dek` to the device whose X25519 public key is `device_pub` (gateway side). The result is
/// safe to ship over the enrollment response; only that device opens it.
pub fn seal_dek(device_pub: [u8; 32], dek: &Dek) -> Result<SealedDek, VolumeError> {
    let device_pk = x25519::PublicKey::new(device_pub);
    let ephemeral = x25519::KeyPair::generate();
    // ECDH against the device's public key with our ephemeral secret.
    let shared = device_pk
        .dh(&ephemeral.sk)
        .map_err(|_| VolumeError::Seal)?;
    let ephemeral_pub = *ephemeral.pk;
    let kek = derive_kek(&shared, &ephemeral_pub, &device_pub);
    Ok(SealedDek {
        ephemeral_pub,
        wrapped: kek.wrap(dek),
    })
}

/// Open a [`SealedDek`] with the device's sealing key (device side), recovering the DEK. Fail-closed
/// ([`VolumeError::Seal`] on a bad ephemeral key, [`VolumeError::KeyUnwrap`] if the unwrap integrity
/// check fails).
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
        // Prove equality without reading key bytes: AES-KW is deterministic, so wrapping both under
        // a common probe KEK yields identical ciphertext.
        let probe = Kek::from_bytes([0x77; 32]);
        assert_eq!(probe.wrap(&recovered).as_bytes(), probe.wrap(&dek()).as_bytes());
    }

    #[test]
    fn a_different_device_cannot_open_the_seal() {
        let device = DeviceSealingKey::generate();
        let attacker = DeviceSealingKey::generate();
        let sealed = seal_dek(device.public_key(), &dek()).expect("seal");
        // The attacker's secret derives a different shared point ⇒ a different KEK ⇒ unwrap fails.
        assert!(matches!(
            open_dek(&attacker, &sealed),
            Err(VolumeError::KeyUnwrap)
        ));
    }

    #[test]
    fn from_secret_round_trips_a_fixed_key() {
        // A device restored from its hardware-held secret opens what was sealed to its public key.
        let device = DeviceSealingKey::from_secret([0x42; 32]).expect("valid secret");
        let sealed = seal_dek(device.public_key(), &dek()).expect("seal");
        let recovered = open_dek(&device, &sealed).expect("open");
        let probe = Kek::from_bytes([0x55; 32]);
        assert_eq!(probe.wrap(&recovered).as_bytes(), probe.wrap(&dek()).as_bytes());
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
        // ...and both still open to the same DEK.
        let probe = Kek::from_bytes([0x33; 32]);
        assert_eq!(
            probe.wrap(&open_dek(&device, &a).unwrap()).as_bytes(),
            probe.wrap(&open_dek(&device, &b).unwrap()).as_bytes()
        );
    }
}
