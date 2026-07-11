//! Property tests for the encrypted-volume crypto core: XTS round-trips and AES-KW key
//! wrapping hold for arbitrary keys, data, and sector indices.

use clave_volume::{Dek, Kek, XtsCipher, SECTOR_SIZE};
use proptest::prelude::*;

fn dek() -> impl Strategy<Value = Dek> {
    prop::collection::vec(any::<u8>(), 64).prop_map(|v| Dek::from_bytes(v.try_into().unwrap()))
}

fn kek_bytes() -> impl Strategy<Value = [u8; 32]> {
    prop::collection::vec(any::<u8>(), 32).prop_map(|v| v.try_into().unwrap())
}

proptest! {
    // The AES is fast but XTS over several sectors per case adds up; 64 cases is plenty.
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// AES-256-XTS decrypt is the exact inverse of encrypt for any key, data, and sector index.
    #[test]
    fn xts_round_trips(d in dek(), sectors in 1usize..=3, first in any::<u64>(), fill in any::<u8>()) {
        let cipher = XtsCipher::new(&d);
        let mut buf = vec![fill; sectors * SECTOR_SIZE];
        let original = buf.clone();
        cipher.encrypt(&mut buf, first);
        prop_assert_ne!(&buf, &original, "the buffer must actually be encrypted");
        cipher.decrypt(&mut buf, first);
        prop_assert_eq!(buf, original);
    }

    /// Wrapping a DEK under a KEK and unwrapping it recovers the *same key material*: a cipher built
    /// from the unwrapped DEK decrypts what a cipher built from the original encrypted.
    #[test]
    fn aes_kw_round_trips_the_key(d in dek(), k in kek_bytes(), fill in any::<u8>()) {
        let kek = Kek::from_bytes(k);
        let wrapped = kek.wrap(&d);
        let recovered = kek.unwrap(&wrapped).expect("unwrap with the right KEK");

        let mut buf = vec![fill; SECTOR_SIZE];
        let original = buf.clone();
        XtsCipher::new(&d).encrypt(&mut buf, 0);
        XtsCipher::new(&recovered).decrypt(&mut buf, 0);
        prop_assert_eq!(buf, original);
    }

    /// A wrong KEK never unwraps a DEK — the AES-KW integrity check fails (fail-closed).
    #[test]
    fn wrong_kek_never_unwraps(d in dek(), k1 in kek_bytes(), k2 in kek_bytes()) {
        prop_assume!(k1 != k2);
        let wrapped = Kek::from_bytes(k1).wrap(&d);
        prop_assert!(Kek::from_bytes(k2).unwrap(&wrapped).is_err());
    }
}
