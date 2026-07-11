//! The opaque ciphertext container + its metadata and wipe marker.
//!
//! On a real OS this is a WinFsp backing file (Windows) or sparsebundle band files (macOS); the
//! [`BackingStore`] seam abstracts it so the XTS layer and the mount lifecycle test with no
//! filesystem. The store is **opaque ciphertext**: it never holds a key and never sees
//! plaintext, so a thief with the powered-off container learns nothing.

use std::sync::Mutex;

use crate::xts::SECTOR_SIZE;
use crate::VolumeError;

/// Opaque per-container identity (the container UUID; a `u128` here to avoid a `uuid` dep).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContainerId(pub u128);

/// Non-secret container metadata, kept in `.clave-meta` next to the ciphertext. It
/// only *identifies* which wrapped key to ask the hardware store for — it holds no key material,
/// so it is safe in the clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainerMeta {
    pub id: ContainerId,
    /// Bumped on DEK rotation so the right wrapped key is selected (forward-compat).
    pub key_version: u32,
}

impl ContainerMeta {
    pub fn new(id: ContainerId) -> Self {
        Self { id, key_version: 1 }
    }
}

/// Sector-addressed opaque ciphertext store. All reads/writes are whole [`SECTOR_SIZE`] sectors
/// of ciphertext; the `.clave-wipe-marker` is set during a wipe and checked at mount.
pub trait BackingStore: Send + Sync {
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), VolumeError>;
    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), VolumeError>;
    fn sector_count(&self) -> u64;
    /// Set `.clave-wipe-marker`. Afterward the container refuses to mount even if its blob still
    /// lingers (e.g. the device went offline mid-wipe) — fail-closed.
    fn set_wipe_marker(&self) -> Result<(), VolumeError>;
    fn is_wiped(&self) -> bool;
}

/// In-memory [`BackingStore`] for tests: a flat ciphertext buffer plus the wipe-marker flag.
pub struct MemBacking {
    inner: Mutex<State>,
}

struct State {
    data: Vec<u8>,
    wiped: bool,
}

impl MemBacking {
    /// A zeroed container of `sectors` sectors.
    pub fn zeroed(sectors: usize) -> Self {
        Self {
            inner: Mutex::new(State {
                data: vec![0u8; sectors * SECTOR_SIZE],
                wiped: false,
            }),
        }
    }

    /// Snapshot the raw on-disk bytes — for "thief with the raw disk" / post-shred assertions.
    pub fn raw(&self) -> Vec<u8> {
        self.inner
            .lock()
            .expect("backing lock poisoned")
            .data
            .clone()
    }

    fn range(sector: u64, len: usize, cap: usize) -> Result<(usize, usize), VolumeError> {
        if len != SECTOR_SIZE {
            return Err(VolumeError::Misaligned);
        }
        let off = sector as usize * SECTOR_SIZE;
        let end = off + SECTOR_SIZE;
        if end > cap {
            return Err(VolumeError::OutOfRange);
        }
        Ok((off, end))
    }
}

impl BackingStore for MemBacking {
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), VolumeError> {
        let g = self.inner.lock().expect("backing lock poisoned");
        let (off, end) = Self::range(sector, buf.len(), g.data.len())?;
        buf.copy_from_slice(&g.data[off..end]);
        Ok(())
    }

    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), VolumeError> {
        let mut g = self.inner.lock().expect("backing lock poisoned");
        let (off, end) = Self::range(sector, buf.len(), g.data.len())?;
        g.data[off..end].copy_from_slice(buf);
        Ok(())
    }

    fn sector_count(&self) -> u64 {
        (self.inner.lock().expect("backing lock poisoned").data.len() / SECTOR_SIZE) as u64
    }

    fn set_wipe_marker(&self) -> Result<(), VolumeError> {
        self.inner.lock().expect("backing lock poisoned").wiped = true;
        Ok(())
    }

    fn is_wiped(&self) -> bool {
        self.inner.lock().expect("backing lock poisoned").wiped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sector_round_trips_opaque_bytes() {
        let b = MemBacking::zeroed(4);
        let sec = [0xC3u8; SECTOR_SIZE];
        b.write_sector(2, &sec).unwrap();
        let mut got = [0u8; SECTOR_SIZE];
        b.read_sector(2, &mut got).unwrap();
        assert_eq!(got, sec);
    }

    #[test]
    fn out_of_range_sector_errs() {
        let b = MemBacking::zeroed(2);
        let mut sec = [0u8; SECTOR_SIZE];
        assert_eq!(b.read_sector(2, &mut sec), Err(VolumeError::OutOfRange));
        assert_eq!(b.write_sector(5, &sec), Err(VolumeError::OutOfRange));
    }

    #[test]
    fn wrong_buffer_size_is_misaligned() {
        let b = MemBacking::zeroed(1);
        let mut small = [0u8; 16];
        assert_eq!(b.read_sector(0, &mut small), Err(VolumeError::Misaligned));
    }

    #[test]
    fn wipe_marker_sets_and_reads() {
        let b = MemBacking::zeroed(1);
        assert!(!b.is_wiped());
        b.set_wipe_marker().unwrap();
        assert!(b.is_wiped());
    }

    #[test]
    fn sector_count_reports_capacity() {
        assert_eq!(MemBacking::zeroed(8).sector_count(), 8);
    }
}
