use std::collections::HashMap;
use std::sync::Mutex;

use crate::container::ContainerId;
use crate::keys::{Dek, Kek, WrappedDek};
use crate::VolumeError;

pub trait KeyStore: Send + Sync {
    fn unwrap_dek(&self, container: ContainerId) -> Result<Dek, VolumeError>;

    fn contains(&self, container: ContainerId) -> bool;

    fn destroy(&self, container: ContainerId) -> Result<(), VolumeError>;
}

#[derive(Default)]
pub struct MemKeyStore {
    inner: Mutex<HashMap<ContainerId, Entry>>,
}

struct Entry {
    kek: Kek,
    wrapped: WrappedDek,
}

impl MemKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn provision(&self, container: ContainerId, kek: Kek, dek: &Dek) {
        let wrapped = kek.wrap(dek);
        self.inner
            .lock()
            .expect("keystore lock poisoned")
            .insert(container, Entry { kek, wrapped });
    }
}

impl KeyStore for MemKeyStore {
    fn unwrap_dek(&self, container: ContainerId) -> Result<Dek, VolumeError> {
        let g = self.inner.lock().expect("keystore lock poisoned");
        let entry = g.get(&container).ok_or(VolumeError::KeyDestroyed)?;
        entry.kek.unwrap(&entry.wrapped)
    }

    fn contains(&self, container: ContainerId) -> bool {
        self.inner
            .lock()
            .expect("keystore lock poisoned")
            .contains_key(&container)
    }

    fn destroy(&self, container: ContainerId) -> Result<(), VolumeError> {
        self.inner
            .lock()
            .expect("keystore lock poisoned")
            .remove(&container);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (ContainerId, Kek, Dek) {
        (
            ContainerId(42),
            Kek::from_bytes([1u8; 32]),
            Dek::from_bytes([2u8; 64]),
        )
    }

    #[test]
    fn provision_then_unwrap_round_trips() {
        let (id, kek, dek) = fixture();
        let ks = MemKeyStore::new();
        ks.provision(id, kek, &dek);
        assert!(ks.contains(id));
        let back = ks.unwrap_dek(id).expect("unwrap a provisioned container");
        assert_eq!(back.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn destroy_is_crypto_shred() {
        let (id, kek, dek) = fixture();
        let ks = MemKeyStore::new();
        ks.provision(id, kek, &dek);
        ks.destroy(id).unwrap();
        assert!(!ks.contains(id));
        assert!(matches!(ks.unwrap_dek(id), Err(VolumeError::KeyDestroyed)));
    }

    #[test]
    fn destroy_is_idempotent() {
        let ks = MemKeyStore::new();
        assert!(ks.destroy(ContainerId(1)).is_ok());
    }

    #[test]
    fn unknown_container_unwrap_fails_closed() {
        let ks = MemKeyStore::new();
        assert!(matches!(
            ks.unwrap_dek(ContainerId(99)),
            Err(VolumeError::KeyDestroyed)
        ));
    }
}
