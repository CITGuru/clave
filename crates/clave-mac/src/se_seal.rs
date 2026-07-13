//! Seal the Clave Disk passphrase to a **Secure-Enclave-resident** key (doc 04 §4.1's
//! `kSecAttrTokenIDSecureEnclave` / `SecAccessControlCreateWithFlags` direction), replacing
//! `volume.rs`'s previous plain-Keychain-stored passphrase.
//!
//! The Secure Enclave only supports **P-256** EC keys (not the X25519 `clave_volume::seal` already
//! uses for the gateway→device enrollment sealed-box — SE hardware has no X25519 support). So this
//! is a parallel, P-256-flavored construction, same ECIES/sealed-box *shape*, different curve:
//!
//! ```text
//! seal:  ephemeral P-256 keypair (software, one-shot)   (e_sk, e_pk)
//!        shared = ECDH(e_sk, se_pub)                     — software side of the exchange
//!        KEK    = SHA-256(ctx ++ e_pk ++ se_pub ++ shared)
//!        out    = (e_pk, AES-KW(KEK, passphrase))
//! open:  shared = ECDH(se_sk, e_pk)                      — runs *inside* the Secure Enclave
//!        KEK    = SHA-256(ctx ++ e_pk ++ se_pub ++ shared)
//!        passphrase = AES-KW^-1(KEK, wrapped)
//! ```
//!
//! `se_sk` (the Secure Enclave private key) never leaves the chip and is not exportable —
//! [`open`] only works by asking the SE to perform the ECDH itself (`SecKeyCopyKeyExchangeResult`),
//! so a copied Keychain database file is useless without this specific device's SE. The SE key is
//! generated once and persisted in the `DataProtectionKeychain` under a fixed label; later runs
//! look it up instead of regenerating (regenerating would orphan every already-sealed passphrase).

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom,
};
use security_framework_sys::key::SecKeyCreateWithData;
use sha2::{Digest, Sha256};
use std::io;

use aes::cipher::generic_array::GenericArray;
use aes_kw::KekAes256;

const SE_KEY_LABEL: &str = "com.clave.volume.se-sealing-key";
const SEAL_KDF_CONTEXT: &[u8] = b"clave-mac/se-seal/v1";
/// P-256 uncompressed point (X9.63): `0x04 || X(32) || Y(32)`.
const P256_PUBLIC_LEN: usize = 65;
/// AES-KW adds an 8-byte integrity check value to the wrapped payload.
const WRAPPED_LEN: usize = 64 + 8;
/// `ephemeral_pub || wrapped` — fixed-length, no framing needed.
pub const SEALED_LEN: usize = P256_PUBLIC_LEN + WRAPPED_LEN;

fn sec_err(context: &str, e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{context}: {e}"))
}

/// The device's Secure-Enclave-resident P-256 sealing key. The private half never leaves the
/// chip; only [`SeSealingKey::open`] (which routes through `SecKeyCopyKeyExchangeResult`) can
/// recover what was sealed to it.
pub struct SeSealingKey {
    key: SecKey,
}

impl SeSealingKey {
    /// Look up the persisted SE key by its fixed label; generate and persist one on first use.
    pub fn load_or_generate() -> io::Result<Self> {
        if let Some(key) = Self::find_existing()? {
            return Ok(Self { key });
        }
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_label(SE_KEY_LABEL);
        let key = SecKey::new(&opts).map_err(|e| sec_err("generate SE key", e))?;
        Ok(Self { key })
    }

    fn find_existing() -> io::Result<Option<SecKey>> {
        let mut opts = ItemSearchOptions::new();
        opts.class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(SE_KEY_LABEL)
            .load_refs(true)
            .limit(Limit::Max(1));
        match opts.search() {
            Ok(mut results) => Ok(results.pop().and_then(|r| match r {
                security_framework::item::SearchResult::Ref(Reference::Key(k)) => Some(k),
                _ => None,
            })),
            // errSecItemNotFound — no key yet, not an error.
            Err(_) => Ok(None),
        }
    }

    /// The raw X9.63 uncompressed public key bytes, for [`seal`].
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

    /// ECDH with `peer_pub` — for a Secure Enclave key this runs *inside the chip*.
    fn key_exchange(&self, peer_pub: &[u8]) -> io::Result<Vec<u8>> {
        let peer_key = import_p256_public_key(peer_pub)?;
        self.key
            .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer_key, 32, None)
            .map_err(|e| sec_err("SE key exchange", e))
    }
}

/// Import raw X9.63 uncompressed P-256 public key bytes as a `SecKey`, via the raw
/// `SecKeyCreateWithData` FFI call — `security-framework` has no safe wrapper for this import
/// direction (only for generating/holding keys), so this mirrors the crate's own dictionary-
/// building pattern (see `GenerateKeyOptions::to_dictionary`) at the FFI boundary.
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
    // SAFETY: `data`/`attrs` are valid, live CF objects for the duration of the call; `error` is
    // a valid out-param. `SecKeyCreateWithData` follows the standard CF create-rule (owned
    // return), matched by `wrap_under_create_rule` below.
    let key_ref = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attrs.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if key_ref.is_null() {
        // SAFETY: non-null `error` on a null return, per `SecKeyCreateWithData`'s documented
        // create-rule error contract.
        let e = unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
        return Err(sec_err("import peer public key", e));
    }
    // SAFETY: non-null owned SecKeyRef from the create-rule call above.
    Ok(unsafe { SecKey::wrap_under_create_rule(key_ref) })
}

fn derive_kek(shared: &[u8], ephemeral_pub: &[u8], se_pub: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SEAL_KDF_CONTEXT);
    h.update(ephemeral_pub);
    h.update(se_pub);
    h.update(shared);
    let digest = h.finalize();
    let mut kek = [0u8; 32];
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

fn aes_kw_unwrap(kek: &[u8; 32], wrapped: &[u8; WRAPPED_LEN]) -> io::Result<[u8; 64]> {
    let mut out = [0u8; 64];
    KekAes256::new(GenericArray::from_slice(kek))
        .unwrap(wrapped, &mut out)
        .map_err(|_| io::Error::other("AES-KW unwrap failed (wrong key or corrupted seal)"))?;
    Ok(out)
}

/// Seal `secret` (the 64-byte hex-encoded sparsebundle passphrase, see `volume.rs`) to the
/// device's SE public key. `se_pub` is [`SeSealingKey::public_key_bytes`] — sealing needs only
/// the public half, so this side never touches the Secure Enclave.
pub fn seal(se_pub: &[u8], secret: &[u8; 64]) -> io::Result<[u8; SEALED_LEN]> {
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

/// Open a blob produced by [`seal`], recovering the passphrase. Routes the ECDH through the
/// Secure Enclave — fails if `se_key` isn't the one `seal` targeted.
pub fn open(se_key: &SeSealingKey, sealed: &[u8; SEALED_LEN]) -> io::Result<[u8; 64]> {
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

    /// Persisting an SE key needs the `keychain-access-groups` entitlement + a real provisioning
    /// profile (doc 04 §4.1) — only present when this binary is the signed `ClaveDaemonHost` app
    /// (`crates/clave-mac/macos/`), never a bare `cargo test` run. Skip rather than fail there: this
    /// is an environment gap, not a bug, and `volume.rs`'s own tests already prove the fallback path
    /// these tests can't reach.
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
        let secret = [0xABu8; 64];

        let sealed = seal(&se_pub, &secret).expect("seal");
        let recovered = open(&se, &sealed).expect("open");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let Some(se) = se_key_or_skip() else { return };
        let se_pub = se.public_key_bytes().expect("SE public key");
        let secret = [0x11u8; 64];

        let a = seal(&se_pub, &secret).expect("seal a");
        let b = seal(&se_pub, &secret).expect("seal b");
        assert_ne!(
            &a[..P256_PUBLIC_LEN],
            &b[..P256_PUBLIC_LEN],
            "each seal must use a fresh ephemeral key"
        );
        assert_eq!(open(&se, &a).unwrap(), secret);
        assert_eq!(open(&se, &b).unwrap(), secret);
    }

    #[test]
    fn find_existing_reuses_the_same_persisted_key_across_loads() {
        let Some(first) = se_key_or_skip() else {
            return;
        };
        let first_pub = first.public_key_bytes().expect("pub 1");
        let second = SeSealingKey::load_or_generate().expect("second load (first succeeded)");
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
        let mut sealed = seal(&se_pub, &[0x22u8; 64]).expect("seal");
        // Flip a byte in the wrapped payload — AES-KW's integrity check must reject it.
        sealed[SEALED_LEN - 1] ^= 0xFF;
        assert!(open(&se, &sealed).is_err());
    }
}
