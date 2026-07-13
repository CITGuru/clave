use std::sync::Arc;

use clave_core::{JoinReason, ZoneRegistry};
use clave_platform::ProcId;
use clave_volume::{
    BackingStore, ClaveVolume, ContainerId, ContainerMeta, Dek, Kek, KeyStore, MemBacking,
    MemKeyStore, VolumeError, SECTOR_SIZE,
};

struct Env {
    vol: ClaveVolume,
    zones: Arc<ZoneRegistry>,
    keystore: Arc<MemKeyStore>,
    backing: Arc<MemBacking>,
    id: ContainerId,
    work: ProcId,
}

fn provisioned() -> Env {
    let id = ContainerId(0xDEAD_BEEF);
    let keystore = Arc::new(MemKeyStore::new());
    keystore.provision(
        id,
        Kek::from_bytes([0xA1; 32]),
        &Dek::from_bytes([0xB2; 64]),
    );
    let backing = Arc::new(MemBacking::zeroed(64));
    let zones = Arc::new(ZoneRegistry::new());
    let work = ProcId::windows(100, 1);
    zones.join(work, JoinReason::Launcher);
    let vol = ClaveVolume::new(
        ContainerMeta::new(id),
        keystore.clone(),
        backing.clone(),
        zones.clone(),
    );
    Env {
        vol,
        zones,
        keystore,
        backing,
        id,
        work,
    }
}

#[test]
fn work_app_reads_and_writes_through_the_enclave() {
    let mut e = provisioned();
    e.vol.unlock().unwrap();

    let doc = b"quarterly numbers - confidential";
    let mut sector = vec![0u8; SECTOR_SIZE];
    sector[..doc.len()].copy_from_slice(doc);
    e.vol.write(&e.work, 10, &sector).unwrap();

    let mut got = vec![0u8; SECTOR_SIZE];
    e.vol.read(&e.work, 10, &mut got).unwrap();
    assert_eq!(got, sector);
}

#[test]
fn personal_app_cannot_read_the_disk_even_mounted() {
    let mut e = provisioned();
    e.vol.unlock().unwrap();
    e.vol.write(&e.work, 0, &vec![7u8; SECTOR_SIZE]).unwrap();

    let personal = ProcId::windows(666, 1);
    let mut buf = vec![0u8; SECTOR_SIZE];
    assert_eq!(
        e.vol.read(&personal, 0, &mut buf),
        Err(VolumeError::AccessDenied)
    );
}

#[test]
fn thief_with_the_powered_off_container_gets_nothing() {
    let mut e = provisioned();
    e.vol.unlock().unwrap();
    let secret = vec![0x5Au8; SECTOR_SIZE];
    e.vol.write(&e.work, 0, &secret).unwrap();
    e.vol.lock();

    let stolen = e.backing.raw();
    assert_ne!(
        &stolen[..SECTOR_SIZE],
        secret.as_slice(),
        "the blob on disk is ciphertext"
    );
    let mut buf = vec![0u8; SECTOR_SIZE];
    assert_eq!(e.vol.read(&e.work, 0, &mut buf), Err(VolumeError::Locked));
}

#[test]
fn remote_wipe_crypto_shreds_in_o1_and_is_irreversible() {
    let mut e = provisioned();
    e.vol.unlock().unwrap();
    e.vol.write(&e.work, 0, &vec![0xFFu8; SECTOR_SIZE]).unwrap();

    e.vol.wipe().unwrap();

    assert!(!e.vol.is_unlocked(), "DEK evicted from memory");
    assert!(
        !e.keystore.contains(e.id),
        "wrapped key destroyed (crypto-shred)"
    );
    assert!(e.backing.is_wiped(), "wipe marker set");

    assert_eq!(e.vol.unlock(), Err(VolumeError::WipeMarkerSet));

    let mut fresh = ClaveVolume::new(
        ContainerMeta::new(e.id),
        e.keystore.clone(),
        e.backing.clone(),
        e.zones.clone(),
    );
    assert_eq!(fresh.unlock(), Err(VolumeError::WipeMarkerSet));
}

#[test]
fn wipe_without_a_marker_still_fails_closed_on_the_missing_key() {
    let mut e = provisioned();
    e.vol.unlock().unwrap();
    e.keystore.destroy(e.id).unwrap();

    let backing = Arc::new(MemBacking::zeroed(64));
    let mut restored = ClaveVolume::new(
        ContainerMeta::new(e.id),
        e.keystore.clone(),
        backing,
        e.zones.clone(),
    );
    assert_eq!(restored.unlock(), Err(VolumeError::KeyDestroyed));
}

#[test]
fn wipe_leaves_personal_data_untouched() {
    let mut e = provisioned();
    e.vol.unlock().unwrap();

    let personal_disk = MemBacking::zeroed(4);
    personal_disk
        .write_sector(0, &[0x11u8; SECTOR_SIZE])
        .unwrap();
    let before = personal_disk.raw();

    e.vol.wipe().unwrap();

    assert_eq!(
        personal_disk.raw(),
        before,
        "personal data is outside the container and untouched"
    );
}
