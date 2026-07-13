use std::sync::{Arc, Mutex};

use clave_core::{JoinReason, ZoneRegistry};
use clave_platform::ProcId;
use clave_volume::{
    BackingStore, ClaveVolume, ContainerId, ContainerMeta, Dek, Kek, MemKeyStore, VolumeError,
    SECTOR_SIZE,
};

struct FailingBacking {
    state: Mutex<State>,
    fail_after: usize,
}

struct State {
    data: Vec<u8>,
    writes: usize,
    wiped: bool,
}

impl FailingBacking {
    fn new(sectors: usize, fail_after: usize) -> Self {
        Self {
            state: Mutex::new(State {
                data: vec![0u8; sectors * SECTOR_SIZE],
                writes: 0,
                wiped: false,
            }),
            fail_after,
        }
    }
    fn raw(&self) -> Vec<u8> {
        self.state.lock().unwrap().data.clone()
    }
}

impl BackingStore for FailingBacking {
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), VolumeError> {
        let g = self.state.lock().unwrap();
        let off = sector as usize * SECTOR_SIZE;
        buf.copy_from_slice(&g.data[off..off + SECTOR_SIZE]);
        Ok(())
    }
    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), VolumeError> {
        let mut g = self.state.lock().unwrap();
        if g.writes >= self.fail_after {
            return Err(VolumeError::Io("simulated power loss".into()));
        }
        g.writes += 1;
        let off = sector as usize * SECTOR_SIZE;
        g.data[off..off + SECTOR_SIZE].copy_from_slice(buf);
        Ok(())
    }
    fn sector_count(&self) -> u64 {
        (self.state.lock().unwrap().data.len() / SECTOR_SIZE) as u64
    }
    fn set_wipe_marker(&self) -> Result<(), VolumeError> {
        self.state.lock().unwrap().wiped = true;
        Ok(())
    }
    fn is_wiped(&self) -> bool {
        self.state.lock().unwrap().wiped
    }
}

#[test]
fn a_write_failing_mid_stream_leaves_only_ciphertext() {
    let id = ContainerId(0xFA17);
    let keystore = Arc::new(MemKeyStore::new());
    keystore.provision(id, Kek::from_bytes([1u8; 32]), &Dek::from_bytes([2u8; 64]));
    let backing = Arc::new(FailingBacking::new(8, 1));
    let zones = Arc::new(ZoneRegistry::new());
    let work = ProcId::windows(10, 1);
    zones.join(work, JoinReason::Launcher);

    let mut vol = ClaveVolume::new(ContainerMeta::new(id), keystore, backing.clone(), zones);
    vol.unlock().unwrap();

    let plaintext = vec![0x42u8; SECTOR_SIZE * 3];
    let result = vol.write(&work, 0, &plaintext);
    assert!(
        matches!(result, Err(VolumeError::Io(_))),
        "the interrupted write fails closed"
    );

    let raw = backing.raw();
    assert_ne!(
        &raw[..SECTOR_SIZE],
        &plaintext[..SECTOR_SIZE],
        "the written sector is ciphertext, not plaintext"
    );
    assert!(
        !raw.chunks_exact(SECTOR_SIZE)
            .any(|s| s == &plaintext[..SECTOR_SIZE]),
        "no plaintext sector ever reached the backing store"
    );
}
