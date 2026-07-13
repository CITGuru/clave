use aes::cipher::KeyInit;
use aes::Aes256;
use xts_mode::{get_tweak_default, Xts128};

use crate::keys::Dek;

pub const SECTOR_SIZE: usize = 4096;

pub struct XtsCipher {
    xts: Xts128<Aes256>,
}

impl XtsCipher {
    pub fn new(dek: &Dek) -> Self {
        let data = Aes256::new_from_slice(dek.data_key()).expect("32-byte XTS data key");
        let tweak = Aes256::new_from_slice(dek.tweak_key()).expect("32-byte XTS tweak key");
        XtsCipher {
            xts: Xts128::new(data, tweak),
        }
    }

    pub fn encrypt(&self, buf: &mut [u8], first_sector: u64) {
        self.xts
            .encrypt_area(buf, SECTOR_SIZE, first_sector as u128, get_tweak_default);
    }

    pub fn decrypt(&self, buf: &mut [u8], first_sector: u64) {
        self.xts
            .decrypt_area(buf, SECTOR_SIZE, first_sector as u128, get_tweak_default);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Dek;

    fn cipher() -> XtsCipher {
        let mut b = [0u8; 64];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        XtsCipher::new(&Dek::from_bytes(b))
    }

    #[test]
    fn round_trips_one_sector() {
        let c = cipher();
        let mut buf = vec![0xABu8; SECTOR_SIZE];
        let original = buf.clone();
        c.encrypt(&mut buf, 0);
        assert_ne!(buf, original, "ciphertext must differ from plaintext");
        c.decrypt(&mut buf, 0);
        assert_eq!(buf, original);
    }

    #[test]
    fn round_trips_many_sectors() {
        let c = cipher();
        let mut buf: Vec<u8> = (0..SECTOR_SIZE * 3).map(|i| (i % 251) as u8).collect();
        let original = buf.clone();
        c.encrypt(&mut buf, 7);
        c.decrypt(&mut buf, 7);
        assert_eq!(buf, original);
    }

    #[test]
    fn identical_plaintext_differs_per_sector() {
        let c = cipher();
        let mut two = vec![0u8; SECTOR_SIZE * 2];
        c.encrypt(&mut two, 0);
        let (s0, s1) = two.split_at(SECTOR_SIZE);
        assert_ne!(
            s0, s1,
            "equal plaintext sectors must yield different ciphertext"
        );
    }

    #[test]
    fn wrong_sector_index_does_not_decrypt() {
        let c = cipher();
        let mut buf = vec![0x5Au8; SECTOR_SIZE];
        let original = buf.clone();
        c.encrypt(&mut buf, 1);
        c.decrypt(&mut buf, 2);
        assert_ne!(
            buf, original,
            "decrypting at the wrong sector must not recover plaintext"
        );
    }
}
