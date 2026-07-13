use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom,
};
use security_framework_sys::key::SecKeyCreateWithData;
use sha2::{Digest, Sha256};
use std::io;
use zeroize::Zeroizing;

use aes::cipher::generic_array::GenericArray;
use aes_kw::KekAes256;

pub type Passphrase = Zeroizing<[u8; 64]>;

const SE_KEY_LABEL: &str = "com.clave.volume.se-sealing-key";
const SEAL_KDF_CONTEXT: &[u8] = b"clave-mac/se-seal/v1";
const P256_PUBLIC_LEN: usize = 65;
const WRAPPED_LEN: usize = 64 + 8;
pub const SEALED_LEN: usize = P256_PUBLIC_LEN + WRAPPED_LEN;

fn sec_err(context: &str, e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{context}: {e}"))
}

pub struct SeSealingKey {
    key: SecKey,
}

impl SeSealingKey {
    pub fn load() -> io::Result<Option<Self>> {
        let mut opts = ItemSearchOptions::new();
        opts.class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(SE_KEY_LABEL)
            .load_refs(true)
            .limit(Limit::Max(1));
        match opts.search() {
            Ok(mut results) => Ok(results.pop().and_then(|r| match r {
                security_framework::item::SearchResult::Ref(Reference::Key(k)) => {
                    Some(Self { key: k })
                }
                _ => None,
            })),
            Err(e) if e.code() == errSecItemNotFound => Ok(None),
            Err(e) => Err(sec_err("search for SE key", e)),
        }
    }

    pub fn load_or_generate() -> io::Result<Self> {
        if let Some(key) = Self::load()? {
            return Ok(key);
        }
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_label(SE_KEY_LABEL);
        let key = SecKey::new(&opts).map_err(|e| sec_err("generate SE key", e))?;
        Ok(Self { key })
    }

    pub fn public_key_bytes(&self) -> io::Result<Vec<u8>> {
        let public = self
            .key
            .public_key()
            .ok_or_else(|| io::Error::other("SE key has no public half"))?;
        public
            .external_representation()
            .map(|d| d.to_vec())
            .ok_or_else(|| io::Error::other("failed to export SE public key"))
    }

    fn key_exchange(&self, peer_pub: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let peer_key = import_p256_public_key(peer_pub)?;
        self.key
            .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer_key, 32, None)
            .map(Zeroizing::new)
            .map_err(|e| sec_err("SE key exchange", e))
    }
}

fn import_p256_public_key(raw: &[u8]) -> io::Result<SecKey> {
    if raw.len() != P256_PUBLIC_LEN {
        return Err(io::Error::other(format!(
            "expected a {P256_PUBLIC_LEN}-byte P-256 public key, got {}",
            raw.len()
        )));
    }
    let attrs = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyClass) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyClassPublic) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) },
            core_foundation::number::CFNumber::from(256).into_CFType(),
        ),
    ]);
    let data = CFData::from_buffer(raw);
    let mut error = std::ptr::null_mut();
    let key_ref = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attrs.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if key_ref.is_null() {
        let e = unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
        return Err(sec_err("import peer public key", e));
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(key_ref) })
}

fn derive_kek(shared: &[u8], ephemeral_pub: &[u8], se_pub: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(SEAL_KDF_CONTEXT);
    h.update(ephemeral_pub);
    h.update(se_pub);
    h.update(shared);
    let digest = h.finalize();
    let mut kek = Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(&digest);
    kek
}

fn aes_kw_wrap(kek: &[u8; 32], secret: &[u8; 64]) -> [u8; WRAPPED_LEN] {
    let mut out = [0u8; WRAPPED_LEN];
    KekAes256::new(GenericArray::from_slice(kek))
        .wrap(secret, &mut out)
        .expect("AES-KW wrap of a 64-byte secret");
    out
}

fn aes_kw_unwrap(kek: &[u8; 32], wrapped: &[u8; WRAPPED_LEN]) -> io::Result<Passphrase> {
    let mut out = Zeroizing::new([0u8; 64]);
    KekAes256::new(GenericArray::from_slice(kek))
        .unwrap(wrapped, &mut out[..])
        .map_err(|_| io::Error::other("AES-KW unwrap failed (wrong key or corrupted seal)"))?;
    Ok(out)
}

pub fn seal(se_pub: &[u8], secret: &Passphrase) -> io::Result<[u8; SEALED_LEN]> {
    let mut ephemeral_opts = GenerateKeyOptions::default();
    ephemeral_opts
        .set_key_type(KeyType::ec())
        .set_token(Token::Software);
    let ephemeral =
        SecKey::new(&ephemeral_opts).map_err(|e| sec_err("generate ephemeral key", e))?;
    let ephemeral_pub = ephemeral
        .public_key()
        .and_then(|p| p.external_representation())
        .map(|d| d.to_vec())
        .ok_or_else(|| io::Error::other("failed to export ephemeral public key"))?;

    let se_peer = import_p256_public_key(se_pub)?;
    let shared = ephemeral
        .key_exchange(Algorithm::ECDHKeyExchangeStandard, &se_peer, 32, None)
        .map_err(|e| sec_err("ephemeral key exchange", e))?;

    let kek = derive_kek(&shared, &ephemeral_pub, se_pub);
    let wrapped = aes_kw_wrap(&kek, secret);

    let mut out = [0u8; SEALED_LEN];
    out[..P256_PUBLIC_LEN].copy_from_slice(&ephemeral_pub);
    out[P256_PUBLIC_LEN..].copy_from_slice(&wrapped);
    Ok(out)
}

pub fn open(se_key: &SeSealingKey, sealed: &[u8; SEALED_LEN]) -> io::Result<Passphrase> {
    let ephemeral_pub = &sealed[..P256_PUBLIC_LEN];
    let mut wrapped = [0u8; WRAPPED_LEN];
    wrapped.copy_from_slice(&sealed[P256_PUBLIC_LEN..]);

    let shared = se_key.key_exchange(ephemeral_pub)?;
    let se_pub = se_key.public_key_bytes()?;
    let kek = derive_kek(&shared, ephemeral_pub, &se_pub);
    aes_kw_unwrap(&kek, &wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn se_key_or_skip() -> Option<SeSealingKey> {
        match SeSealingKey::load_or_generate() {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!(
                    "skipping (needs the signed ClaveDaemonHost app, not a bare `cargo test` \
                     binary): {e}"
                );
                None
            }
        }
    }

    #[test]
    fn seal_then_open_recovers_the_secret() {
        let Some(se) = se_key_or_skip() else { return };
        let se_pub = se.public_key_bytes().expect("SE public key");
        let secret: Passphrase = Zeroizing::new([0xABu8; 64]);

        let sealed = seal(&se_pub, &secret).expect("seal");
        let recovered = open(&se, &sealed).expect("open");
        assert_eq!(recovered[..], secret[..]);
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let Some(se) = se_key_or_skip() else { return };
        let se_pub = se.public_key_bytes().expect("SE public key");
        let secret: Passphrase = Zeroizing::new([0x11u8; 64]);

        let a = seal(&se_pub, &secret).expect("seal a");
        let b = seal(&se_pub, &secret).expect("seal b");
        assert_ne!(
            &a[..P256_PUBLIC_LEN],
            &b[..P256_PUBLIC_LEN],
            "each seal must use a fresh ephemeral key"
        );
        assert_eq!(open(&se, &a).unwrap()[..], secret[..]);
        assert_eq!(open(&se, &b).unwrap()[..], secret[..]);
    }

    #[test]
    fn load_reuses_the_same_persisted_key_across_loads() {
        let Some(first) = se_key_or_skip() else {
            return;
        };
        let first_pub = first.public_key_bytes().expect("pub 1");
        let second = SeSealingKey::load()
            .expect("search succeeds")
            .expect("the key persisted by the first load must be found");
        let second_pub = second.public_key_bytes().expect("pub 2");
        assert_eq!(
            first_pub, second_pub,
            "a second load must find the persisted key, not generate a new one"
        );
    }

    #[test]
    fn a_corrupted_seal_fails_closed() {
        let Some(se) = se_key_or_skip() else { return };
        let se_pub = se.public_key_bytes().expect("SE public key");
        let mut sealed = seal(&se_pub, &Zeroizing::new([0x22u8; 64])).expect("seal");
        sealed[SEALED_LEN - 1] ^= 0xFF;
        assert!(open(&se, &sealed).is_err());
    }
}
