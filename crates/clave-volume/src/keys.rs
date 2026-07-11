//! The KEK→DEK key hierarchy and AES-KW (RFC 3394) key wrapping.
//!
//! ```text
//! hardware root (TPM / Secure Enclave)
//!   └── KEK   per-device, hardware-bound                     ── Kek
//!         └── wrap(KEK, DEK)  stored; the DEK never is        ── WrappedDek
//!               └── DEK  AES-256-XTS, 64 B, zeroize-on-drop   ── Dek
//! ```
//!
//! The DEK is **never** persisted in cleartext; only the [`WrappedDek`] is stored, and only the
//! hardware-bound [`Kek`] can recover it (so copying the container to another machine yields
//! nothing). Both key types zeroize their bytes on drop and redact them from `Debug`.

use aes::cipher::generic_array::GenericArray;
use aes_kw::KekAes256;
use zeroize::Zeroizing;

use crate::VolumeError;

/// AES-256-XTS data-encryption key length: two AES-256 keys (data unit + tweak) = 64 bytes.
pub const DEK_LEN: usize = 64;
/// AES-256 key-encryption key length.
pub const KEK_LEN: usize = 32;
/// AES-KW prepends a 64-bit integrity check value, so the wrapped DEK is 8 bytes longer.
pub const WRAPPED_DEK_LEN: usize = DEK_LEN + 8;

/// The volume data-encryption key. Lives only in `zeroize`-on-drop memory while the volume is
/// unlocked; dropped (and zeroized) on lock or wipe.
///
/// > On a real OS the adapter must also `VirtualLock`/`mlock` this so the key never reaches the
/// > pagefile. That is the adapter's job; the zeroize guarantee lives
/// > here.
pub struct Dek(Zeroizing<[u8; DEK_LEN]>);

impl Dek {
    /// Generate a fresh DEK from the OS CSPRNG. The two AES-256 key halves are independent (an
    /// XTS requirement). Use this at provisioning; [`Dek::from_bytes`] is for the hardware-store
    /// unwrap path and deterministic tests.
    pub fn generate() -> Result<Self, VolumeError> {
        let mut bytes = [0u8; DEK_LEN];
        getrandom::getrandom(&mut bytes).map_err(|_| VolumeError::Rng)?;
        Ok(Dek(Zeroizing::new(bytes)))
    }

    /// Wrap raw key bytes. In production these come from the hardware-store unwrap; in tests,
    /// from a deterministic fixture.
    pub fn from_bytes(bytes: [u8; DEK_LEN]) -> Self {
        Dek(Zeroizing::new(bytes))
    }

    /// The raw 64-byte key. `pub(crate)` so key material cannot escape the crate's zeroizing
    /// custody — the OS adapter consumes the [`XtsCipher`](crate::XtsCipher), not the raw DEK.
    pub(crate) fn as_bytes(&self) -> &[u8; DEK_LEN] {
        &self.0
    }
    /// AES-256-XTS key half that encrypts the data unit.
    pub(crate) fn data_key(&self) -> &[u8] {
        &self.0[..32]
    }
    /// AES-256-XTS key half that encrypts the tweak.
    pub(crate) fn tweak_key(&self) -> &[u8] {
        &self.0[32..]
    }
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(<redacted 64B>)")
    }
}

/// The per-device, hardware-bound key-encryption key. Models the key that, in production, never
/// leaves the TPM / Secure Enclave; here it is held in zeroizing memory and AES-KW runs in
/// software so the wrap/unwrap logic is testable on any machine.
pub struct Kek(Zeroizing<[u8; KEK_LEN]>);

impl Kek {
    /// Generate a fresh KEK from the OS CSPRNG. Models the per-device key a TPM / Secure Enclave
    /// would create internally; software-generated here for the portable core.
    pub fn generate() -> Result<Self, VolumeError> {
        let mut bytes = [0u8; KEK_LEN];
        getrandom::getrandom(&mut bytes).map_err(|_| VolumeError::Rng)?;
        Ok(Kek(Zeroizing::new(bytes)))
    }

    pub fn from_bytes(bytes: [u8; KEK_LEN]) -> Self {
        Kek(Zeroizing::new(bytes))
    }

    fn cipher(&self) -> KekAes256 {
        // `from_slice` requires exactly KEK_LEN (32) bytes — guaranteed by the array type.
        KekAes256::new(GenericArray::from_slice(&self.0[..]))
    }

    /// AES-KW wrap a DEK for storage. Infallible for our fixed 64-byte DEK.
    pub fn wrap(&self, dek: &Dek) -> WrappedDek {
        let mut out = [0u8; WRAPPED_DEK_LEN];
        self.cipher()
            .wrap(dek.as_bytes(), &mut out)
            .expect("AES-KW wrap of a 64-byte DEK");
        WrappedDek(out)
    }

    /// AES-KW unwrap a stored DEK. Fails closed ([`VolumeError::KeyUnwrap`]) if the integrity
    /// check fails — i.e. the wrong KEK or a corrupted wrapped key.
    pub fn unwrap(&self, wrapped: &WrappedDek) -> Result<Dek, VolumeError> {
        let mut out = Zeroizing::new([0u8; DEK_LEN]);
        self.cipher()
            .unwrap(&wrapped.0, &mut out[..])
            .map_err(|_| VolumeError::KeyUnwrap)?;
        Ok(Dek(out))
    }
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kek(<redacted 32B>)")
    }
}

/// The AES-KW-wrapped DEK: **ciphertext**, safe to store next to the container. Useless without
/// the hardware-bound [`Kek`]; deleting it is the [crypto-shred](crate::KeyStore::destroy) wipe.
#[derive(Clone)]
pub struct WrappedDek([u8; WRAPPED_DEK_LEN]);

impl WrappedDek {
    pub fn from_bytes(bytes: [u8; WRAPPED_DEK_LEN]) -> Self {
        WrappedDek(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; WRAPPED_DEK_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for WrappedDek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedDek(<{WRAPPED_DEK_LEN} B ciphertext>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dek() -> Dek {
        Dek::from_bytes([7u8; DEK_LEN])
    }

    #[test]
    fn wrap_then_unwrap_recovers_dek() {
        let kek = Kek::from_bytes([3u8; KEK_LEN]);
        let wrapped = kek.wrap(&dek());
        assert_eq!(wrapped.as_bytes().len(), WRAPPED_DEK_LEN);
        let back = kek.unwrap(&wrapped).expect("unwrap with the right KEK");
        assert_eq!(back.as_bytes(), dek().as_bytes());
    }

    #[test]
    fn wrong_kek_fails_closed() {
        let kek = Kek::from_bytes([3u8; KEK_LEN]);
        let wrapped = kek.wrap(&dek());
        let other = Kek::from_bytes([4u8; KEK_LEN]);
        assert!(matches!(
            other.unwrap(&wrapped),
            Err(VolumeError::KeyUnwrap)
        ));
    }

    #[test]
    fn wrapped_dek_is_not_the_plaintext_dek() {
        let kek = Kek::from_bytes([9u8; KEK_LEN]);
        let wrapped = kek.wrap(&dek());
        assert_ne!(&wrapped.as_bytes()[..DEK_LEN], dek().as_bytes().as_slice());
    }

    #[test]
    fn debug_redacts_key_material() {
        assert_eq!(format!("{:?}", dek()), "Dek(<redacted 64B>)");
        assert_eq!(
            format!("{:?}", Kek::from_bytes([3u8; KEK_LEN])),
            "Kek(<redacted 32B>)"
        );
    }

    #[test]
    fn generated_keys_are_random_and_distinct() {
        let a = Dek::generate().unwrap();
        let b = Dek::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes(), "two generated DEKs must differ");
        // XTS independence smoke check: the data-unit and tweak key halves are not equal.
        assert_ne!(
            a.data_key(),
            a.tweak_key(),
            "XTS key halves must be independent"
        );
    }

    #[test]
    fn generated_kek_wraps_and_unwraps_generated_dek() {
        let kek = Kek::generate().unwrap();
        let dek = Dek::generate().unwrap();
        let wrapped = kek.wrap(&dek);
        let back = kek
            .unwrap(&wrapped)
            .expect("round-trip with the generating KEK");
        assert_eq!(back.as_bytes(), dek.as_bytes());
    }
}
