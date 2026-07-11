//! The hardware-root key-store seam + an in-memory double.
//!
//! In production a TPM 2.0 (Windows) or the Secure Enclave (macOS) holds the [`Kek`] and
//! performs the unwrap *inside the secure element*, so the KEK never leaves hardware. This trait
//! is how the portable core asks for the DEK and requests crypto-shred; [`MemKeyStore`] models
//! it for tests by holding the KEK in zeroizing memory and running AES-KW in software.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::container::ContainerId;
use crate::keys::{Dek, Kek, WrappedDek};
use crate::VolumeError;

/// A per-device, hardware-bound key store. For each container it holds the wrapped DEK; only it
/// can unwrap. **Crypto-shred** ([`KeyStore::destroy`]) is the O(1), irreversible remote-wipe
/// primitive: destroying the wrapped DEK renders the container unrecoverable.
pub trait KeyStore: Send + Sync {
    /// Unwrap this container's DEK into zeroizing memory. Fails closed
    /// ([`VolumeError::KeyDestroyed`]) if the wrapped key was shredded or never provisioned.
    fn unwrap_dek(&self, container: ContainerId) -> Result<Dek, VolumeError>;

    /// Whether a (non-shredded) wrapped DEK exists for `container`.
    fn contains(&self, container: ContainerId) -> bool;

    /// Crypto-shred: irreversibly destroy the wrapped DEK. Idempotent — destroying an
    /// already-gone key still leaves the goal state (unrecoverable), so it returns `Ok` (this
    /// models an offline device whose key was already destroyed before it came back).
    fn destroy(&self, container: ContainerId) -> Result<(), VolumeError>;
}

/// In-memory [`KeyStore`] for tests. Holds, per container, the hardware-bound [`Kek`] (here in
/// zeroizing RAM instead of a TPM / Secure Enclave) and the [`WrappedDek`].
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

    /// Provision a container: store `wrap(kek, dek)` and the (modelled hardware-bound) KEK. The
    /// caller's `dek` handle is borrowed and may be dropped (zeroized) afterward.
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
        // Dropping the Entry zeroizes the KEK; without it the WrappedDek is unrecoverable.
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
        // Destroying a never-provisioned (or already-shredded) container is still Ok — the goal
        // state (unrecoverable) holds.
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
