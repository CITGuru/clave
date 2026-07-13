use aes::cipher::generic_array::GenericArray;
use aes_kw::KekAes256;
use zeroize::Zeroizing;

use crate::VolumeError;

pub const DEK_LEN: usize = 64;
pub const KEK_LEN: usize = 32;
pub const WRAPPED_DEK_LEN: usize = DEK_LEN + 8;

pub struct Dek(Zeroizing<[u8; DEK_LEN]>);

impl Dek {
    pub fn generate() -> Result<Self, VolumeError> {
        let mut bytes = [0u8; DEK_LEN];
        getrandom::getrandom(&mut bytes).map_err(|_| VolumeError::Rng)?;
        Ok(Dek(Zeroizing::new(bytes)))
    }

    pub fn from_bytes(bytes: [u8; DEK_LEN]) -> Self {
        Dek(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; DEK_LEN] {
        &self.0
    }
    pub(crate) fn data_key(&self) -> &[u8] {
        &self.0[..32]
    }
    pub(crate) fn tweak_key(&self) -> &[u8] {
        &self.0[32..]
    }
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(<redacted 64B>)")
    }
}

pub struct Kek(Zeroizing<[u8; KEK_LEN]>);

impl Kek {
    pub fn generate() -> Result<Self, VolumeError> {
        let mut bytes = [0u8; KEK_LEN];
        getrandom::getrandom(&mut bytes).map_err(|_| VolumeError::Rng)?;
        Ok(Kek(Zeroizing::new(bytes)))
    }

    pub fn from_bytes(bytes: [u8; KEK_LEN]) -> Self {
        Kek(Zeroizing::new(bytes))
    }

    fn cipher(&self) -> KekAes256 {
        KekAes256::new(GenericArray::from_slice(&self.0[..]))
    }

    pub fn wrap(&self, dek: &Dek) -> WrappedDek {
        let mut out = [0u8; WRAPPED_DEK_LEN];
        self.cipher()
            .wrap(dek.as_bytes(), &mut out)
            .expect("AES-KW wrap of a 64-byte DEK");
        WrappedDek(out)
    }

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
