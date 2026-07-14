use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clave_core::{PolicyBundle, UnixTime};
use clave_proto::{
    DeviceSigningKey, EnrollmentGrant, GatewayCommand, GatewaySigningKey, GatewayVerifier, TenantId,
    WrappedVolumeKey,
};
use clave_volume::{ContainerId, Dek, DeviceSealingKey, Kek, DEK_LEN};
use serde::{Deserialize, Serialize};

use crate::enroll::{DeviceEnrollment, DeviceVolumeKey, EnrollError};
use crate::{CheckpointStore, FileCheckpointStore};

const DEV_TENANT_SEED: [u8; 32] = [0x6A; 32];
const DEV_DEVICE_KEK: [u8; 32] = [0x4B; 32];
const DEV_DEK: [u8; DEK_LEN] = [0xDE; DEK_LEN];
const DEV_DEVICE_SIGNING_SEED: [u8; 32] = [0xD5; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    pub tenant: TenantId,
    pub pinned_tenant_key: [u8; 32],
    pub policy: PolicyBundle,
    pub volume_key: Option<WrappedVolumeKey>,
    pub device_signing_seed: [u8; 32],
    pub device_kek: Option<[u8; 32]>,
}

impl EnrollmentRecord {
    pub fn open_volume(
        &self,
        sealing: Option<DeviceSealingKey>,
        now: UnixTime,
    ) -> Result<(ContainerId, Dek), EnrollError> {
        let device_key = match (self.device_kek, sealing) {
            (Some(kek), _) => DeviceVolumeKey::Symmetric(kek),
            (None, Some(seal)) => DeviceVolumeKey::Sealed(seal),
            (None, None) => return Err(EnrollError::UnexpectedSymmetricKey),
        };
        let enrollment = DeviceEnrollment::new(self.tenant, self.pinned_tenant_key, device_key);
        let grant = EnrollmentGrant::new(None, self.volume_key.clone());
        let (_verifier, _policy, volume) = enrollment.accept(&grant, now)?.into_parts();
        volume.ok_or(EnrollError::MalformedVolumeKey)
    }
}

pub fn bootstrap_dev_enrollment(
    policy: PolicyBundle,
    container: u128,
    now: UnixTime,
) -> EnrollmentRecord {
    let signer = GatewaySigningKey::from_seed(TenantId(1), DEV_TENANT_SEED);
    let signed = signer.sign(1, now, GatewayCommand::UpdatePolicy(Box::new(policy.clone())));
    let wrapped = Kek::from_bytes(DEV_DEVICE_KEK).wrap(&Dek::from_bytes(DEV_DEK));
    let volume_key = WrappedVolumeKey {
        container,
        wrapped_dek: wrapped.as_bytes().to_vec(),
        ephemeral_pub: None,
    };
    let grant = EnrollmentGrant::new(Some(signed), Some(volume_key.clone()));
    let enrollment = DeviceEnrollment::new(
        TenantId(1),
        signer.public_key(),
        DeviceVolumeKey::Symmetric(DEV_DEVICE_KEK),
    );
    let accepted = enrollment
        .accept(&grant, now)
        .expect("locally issued dev grant must accept");
    let verified = accepted.policy().cloned().unwrap_or(policy);
    EnrollmentRecord {
        tenant: TenantId(1),
        pinned_tenant_key: signer.public_key(),
        policy: verified,
        volume_key: Some(volume_key),
        device_signing_seed: DEV_DEVICE_SIGNING_SEED,
        device_kek: Some(DEV_DEVICE_KEK),
    }
}

pub trait EnrollmentStore: Send + Sync {
    fn load(&self) -> Option<EnrollmentRecord>;
    fn save(&self, record: &EnrollmentRecord);
}

pub struct FileEnrollmentStore {
    path: PathBuf,
}

impl FileEnrollmentStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn tmp_path(&self) -> PathBuf {
        let mut p = self.path.clone();
        let mut name = p.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        p.set_file_name(name);
        p
    }
}

impl EnrollmentStore for FileEnrollmentStore {
    fn load(&self) -> Option<EnrollmentRecord> {
        let bytes = std::fs::read(&self.path).ok()?;
        postcard::from_bytes(&bytes).ok()
    }

    fn save(&self, record: &EnrollmentRecord) {
        let Ok(bytes) = postcard::to_allocvec(record) else {
            return;
        };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = self.tmp_path();
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

pub struct BootedEnrollment {
    pub record: Arc<Mutex<EnrollmentRecord>>,
    pub store: Arc<FileEnrollmentStore>,
    pub policy: PolicyBundle,
    pub container: ContainerId,
    pub dek: Dek,
    pub gateway: GatewayVerifier,
    pub device_signer: DeviceSigningKey,
    pub checkpoint_store: FileCheckpointStore,
    pub bootstrapped: bool,
}

pub fn boot_enrollment(
    state_dir: PathBuf,
    tag: &str,
    container: u128,
    demo: impl FnOnce() -> PolicyBundle,
    now: UnixTime,
) -> BootedEnrollment {
    let store = Arc::new(FileEnrollmentStore::new(
        state_dir.join(format!("enrollment-{tag}.bin")),
    ));
    let checkpoint_store = FileCheckpointStore::new(state_dir.join(format!("checkpoint-{tag}.bin")));

    let mut bootstrapped = false;
    let record = store.load().unwrap_or_else(|| {
        bootstrapped = true;
        let r = bootstrap_dev_enrollment(demo(), container, now);
        store.save(&r);
        r
    });

    let (container, dek) = record
        .open_volume(None, now)
        .expect("open enrolled Clave Disk key");
    let high_water = checkpoint_store
        .load()
        .map(|c| c.gateway_high_water)
        .unwrap_or(0);
    let gateway = GatewayVerifier::new(record.tenant, record.pinned_tenant_key)
        .expect("valid pinned tenant key")
        .with_high_water(high_water);
    let device_signer = DeviceSigningKey::from_seed(record.device_signing_seed);
    let policy = record.policy.clone();

    BootedEnrollment {
        record: Arc::new(Mutex::new(record)),
        store,
        policy,
        container,
        dek,
        gateway,
        device_signer,
        checkpoint_store,
        bootstrapped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Checkpoint;
    use crate::CheckpointStore;
    use clave_proto::GENESIS;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "clave-enroll-test-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn assert_dek_eq(a: &Dek, b: &Dek) {
        let probe = Kek::from_bytes([0x77; 32]);
        assert_eq!(probe.wrap(a).as_bytes(), probe.wrap(b).as_bytes());
    }

    #[test]
    fn file_store_round_trips_a_record() {
        let dir = temp_dir();
        let store = FileEnrollmentStore::new(dir.join("enrollment.bin"));
        assert!(store.load().is_none());

        let record = bootstrap_dev_enrollment(PolicyBundle::restrictive_default(), 0xC1A5, 1_000);
        store.save(&record);
        assert_eq!(store.load().as_ref(), Some(&record));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_recovers_the_dek_and_keeps_the_policy() {
        let mut policy = PolicyBundle::restrictive_default();
        policy.version = 7;
        let record = bootstrap_dev_enrollment(policy, 0xC1A5, 1_000);
        assert_eq!(record.policy.version, 7);

        let (container, dek) = record.open_volume(None, 1_000).expect("open volume");
        assert_eq!(container, ContainerId(0xC1A5));
        assert_dek_eq(&dek, &Dek::from_bytes(DEV_DEK));
    }

    #[test]
    fn boot_is_idempotent_and_restores_high_water() {
        let dir = temp_dir();

        let first = boot_enrollment(
            dir.clone(),
            "dev",
            0xC1A5,
            PolicyBundle::restrictive_default,
            1_000,
        );
        assert!(first.bootstrapped);
        assert_eq!(first.gateway.high_water(), 0);
        first.checkpoint_store.save(Checkpoint {
            gateway_high_water: 42,
            audit_seq: 0,
            audit_head: GENESIS,
            audit_pending: Vec::new(),
        });

        let second = boot_enrollment(
            dir.clone(),
            "dev",
            0xC1A5,
            PolicyBundle::restrictive_default,
            2_000,
        );
        assert!(!second.bootstrapped);
        assert_eq!(second.gateway.high_water(), 42);
        assert_dek_eq(&first.dek, &second.dek);
        assert_eq!(
            first.record.lock().unwrap().pinned_tenant_key,
            second.record.lock().unwrap().pinned_tenant_key
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
