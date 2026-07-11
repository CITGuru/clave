//! [`ClaveVolume`] — the portable mount lifecycle.
//!
//! Ties the key hierarchy, the XTS block layer, the backing container, and the runtime access
//! gate into one fail-closed object. Tested here, with no OS:
//!
//! * **unlock** — refuse a wiped container, ask the key store to unwrap the DEK, bring up the
//!   XTS cipher in zeroizing memory;
//! * **lock** — drop (zeroize) the cipher/DEK so reads fail closed;
//! * **read / write** — sector I/O through XTS, plaintext never reaching the backing store;
//! * **access gate** — only supervised (work-zone) callers, *even while mounted*;
//! * **wipe** — crypto-shred remote wipe + a fail-closed mount refusal afterward.
//!
//! OS-specific and therefore *not* here: the WinFsp / APFS mount, and the TPM / Secure Enclave
//! behind [`KeyStore`]. The OS adapter shares the daemon's `Arc<Mutex<ClaveVolume>>` (via
//! `Daemon::volume_handle`) and implements `clave_platform::VolumeMount` over it — one instance,
//! one DEK, one lock state, so a remote wipe halts the live mount.

use std::sync::Arc;

use clave_platform::{ProcId, ProcessSupervisor};

use crate::container::{BackingStore, ContainerId, ContainerMeta};
use crate::store::KeyStore;
use crate::xts::{XtsCipher, SECTOR_SIZE};
use crate::VolumeError;

/// The encrypted Clave Disk, portable core. Locked at construction; [`ClaveVolume::unlock`] mounts.
pub struct ClaveVolume {
    meta: ContainerMeta,
    keystore: Arc<dyn KeyStore>,
    backing: Arc<dyn BackingStore>,
    /// The runtime access gate: authoritative work-zone membership. Personal processes
    /// are denied even while the volume is mounted.
    gate: Arc<dyn ProcessSupervisor>,
    /// `Some` only while unlocked. The DEK-derived cipher lives in zeroizing memory and is
    /// dropped (zeroized) on lock/wipe; `None` ⇒ locked ⇒ all I/O fails closed.
    cipher: Option<XtsCipher>,
}

impl ClaveVolume {
    /// Create a locked volume over `meta`'s container. Call [`ClaveVolume::unlock`] to mount.
    pub fn new(
        meta: ContainerMeta,
        keystore: Arc<dyn KeyStore>,
        backing: Arc<dyn BackingStore>,
        gate: Arc<dyn ProcessSupervisor>,
    ) -> Self {
        Self {
            meta,
            keystore,
            backing,
            gate,
            cipher: None,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.cipher.is_some()
    }

    /// The container this volume targets. The daemon matches it against a gateway
    /// [`Wipe`](../clave_proto/enum.GatewayCommand.html) command's `container` so a wipe meant for
    /// another device can't destroy this one.
    pub fn container_id(&self) -> ContainerId {
        self.meta.id
    }

    /// Unlock the volume: refuse a wiped/half-wiped container, ask the hardware store to unwrap
    /// the DEK, and bring up the XTS cipher in zeroizing memory. Fail-closed throughout.
    pub fn unlock(&mut self) -> Result<(), VolumeError> {
        if self.backing.is_wiped() {
            return Err(VolumeError::WipeMarkerSet);
        }
        // `contains` gives a precise error; `unwrap_dek` is the authority and also fails closed.
        if !self.keystore.contains(self.meta.id) {
            return Err(VolumeError::KeyDestroyed);
        }
        let dek = self.keystore.unwrap_dek(self.meta.id)?;
        self.cipher = Some(XtsCipher::new(&dek));
        // `dek` is dropped here → zeroized.
        Ok(())
    }

    /// Lock the volume: drop (zeroize) the cipher/DEK. Reads now fail closed.
    pub fn lock(&mut self) {
        self.cipher = None;
    }

    /// Read `out.len()` bytes of plaintext starting at `first_sector`. Enforces the access gate,
    /// reads the ciphertext sectors from the backing store, then decrypts in place. `out` must
    /// be a whole number of [`SECTOR_SIZE`] sectors.
    pub fn read(
        &self,
        caller: &ProcId,
        first_sector: u64,
        out: &mut [u8],
    ) -> Result<(), VolumeError> {
        let cipher = self.authorize(caller)?;
        if out.len() % SECTOR_SIZE != 0 {
            return Err(VolumeError::Misaligned);
        }
        let count = (out.len() / SECTOR_SIZE) as u64;
        for i in 0..count {
            let off = i as usize * SECTOR_SIZE;
            self.backing
                .read_sector(first_sector + i, &mut out[off..off + SECTOR_SIZE])?;
        }
        cipher.decrypt(out, first_sector);
        Ok(())
    }

    /// Encrypt and write `data` (sector-aligned) starting at `first_sector`. Plaintext never
    /// reaches the backing store — encryption happens before the write.
    pub fn write(
        &self,
        caller: &ProcId,
        first_sector: u64,
        data: &[u8],
    ) -> Result<(), VolumeError> {
        let cipher = self.authorize(caller)?;
        if data.len() % SECTOR_SIZE != 0 {
            return Err(VolumeError::Misaligned);
        }
        let mut ct = data.to_vec();
        cipher.encrypt(&mut ct, first_sector);
        for (i, chunk) in ct.chunks_exact(SECTOR_SIZE).enumerate() {
            self.backing.write_sector(first_sector + i as u64, chunk)?;
        }
        Ok(())
    }

    /// **Remote wipe** (crypto-shred): evict the DEK from memory, destroy the wrapped
    /// key so the container is unrecoverable in O(1), then set the wipe marker so a future mount
    /// fails closed even if the ciphertext blob still lingers (offline-mid-wipe). Personal data
    /// is untouched — it is never inside the container.
    pub fn wipe(&mut self) -> Result<(), VolumeError> {
        self.cipher = None; // live data instantly dark (zeroize)
        self.keystore.destroy(self.meta.id)?; // unrecoverable, O(1)
        self.backing.set_wipe_marker()?; // refuse any future mount
        Ok(())
    }

    /// The per-I/O gate: the caller must be supervised *and* the volume unlocked. Checking
    /// identity before lock state means a personal process can't even probe the mount state — it
    /// is denied unconditionally.
    fn authorize(&self, caller: &ProcId) -> Result<&XtsCipher, VolumeError> {
        if !self.gate.is_supervised(caller) {
            return Err(VolumeError::AccessDenied);
        }
        self.cipher.as_ref().ok_or(VolumeError::Locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{ContainerId, MemBacking};
    use crate::keys::{Dek, Kek};
    use crate::store::MemKeyStore;
    use clave_core::{JoinReason, ZoneRegistry};

    const SECTORS: usize = 8;

    struct Fixture {
        vol: ClaveVolume,
        zones: Arc<ZoneRegistry>,
        backing: Arc<MemBacking>,
    }

    fn setup() -> Fixture {
        let id = ContainerId(0xC1A5E);
        let keystore = Arc::new(MemKeyStore::new());
        keystore.provision(
            id,
            Kek::from_bytes([11u8; 32]),
            &Dek::from_bytes([22u8; 64]),
        );
        let backing = Arc::new(MemBacking::zeroed(SECTORS));
        let zones = Arc::new(ZoneRegistry::new());
        let vol = ClaveVolume::new(
            ContainerMeta::new(id),
            keystore,
            backing.clone(),
            zones.clone(),
        );
        Fixture {
            vol,
            zones,
            backing,
        }
    }

    fn work(n: u32, zones: &ZoneRegistry) -> ProcId {
        let p = ProcId::windows(n, 1);
        zones.join(p, JoinReason::Launcher);
        p
    }

    #[test]
    fn unlock_write_read_round_trip() {
        let mut f = setup();
        let caller = work(1, &f.zones);
        f.vol.unlock().unwrap();
        assert!(f.vol.is_unlocked());
        let plaintext = vec![0x42u8; SECTOR_SIZE * 2];
        f.vol.write(&caller, 0, &plaintext).unwrap();
        let mut got = vec![0u8; SECTOR_SIZE * 2];
        f.vol.read(&caller, 0, &mut got).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn backing_holds_only_ciphertext() {
        let mut f = setup();
        let caller = work(1, &f.zones);
        f.vol.unlock().unwrap();
        let plaintext = vec![0x42u8; SECTOR_SIZE];
        f.vol.write(&caller, 0, &plaintext).unwrap();
        let raw = f.backing.raw();
        assert_ne!(
            &raw[..SECTOR_SIZE],
            plaintext.as_slice(),
            "plaintext must never hit the backing store"
        );
    }

    #[test]
    fn personal_caller_denied_even_when_mounted() {
        let mut f = setup();
        f.vol.unlock().unwrap();
        let personal = ProcId::windows(777, 1); // never joined the zone
        let mut got = vec![0u8; SECTOR_SIZE];
        assert_eq!(
            f.vol.read(&personal, 0, &mut got),
            Err(VolumeError::AccessDenied)
        );
        let data = vec![1u8; SECTOR_SIZE];
        assert_eq!(
            f.vol.write(&personal, 0, &data),
            Err(VolumeError::AccessDenied)
        );
    }

    #[test]
    fn locked_volume_fails_closed() {
        let mut f = setup();
        let caller = work(1, &f.zones);
        f.vol.unlock().unwrap();
        f.vol.lock();
        assert!(!f.vol.is_unlocked());
        let mut got = vec![0u8; SECTOR_SIZE];
        assert_eq!(f.vol.read(&caller, 0, &mut got), Err(VolumeError::Locked));
    }

    #[test]
    fn relock_then_unlock_recovers_data() {
        let mut f = setup();
        let caller = work(1, &f.zones);
        f.vol.unlock().unwrap();
        let plaintext = vec![0x99u8; SECTOR_SIZE];
        f.vol.write(&caller, 3, &plaintext).unwrap();
        f.vol.lock();
        f.vol.unlock().unwrap(); // fresh DEK unwrap, same key
        let mut got = vec![0u8; SECTOR_SIZE];
        f.vol.read(&caller, 3, &mut got).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn misaligned_io_rejected() {
        let mut f = setup();
        let caller = work(1, &f.zones);
        f.vol.unlock().unwrap();
        let mut small = vec![0u8; 100];
        assert_eq!(
            f.vol.read(&caller, 0, &mut small),
            Err(VolumeError::Misaligned)
        );
    }
}
