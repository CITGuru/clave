//! The [`VolumeKeyService`] seam: the **wrapped volume key** a device receives when it finishes
//! enrolling — the other half of step 5 alongside the signed policy
//! ([`crate::PolicyIssuer`]).
//!
//! The Clave Disk is encrypted under a per-container **DEK** (AES-256-XTS). The DEK is never stored
//! in cleartext; only its AES-KW wrapping is, and only a **device-held KEK** can unwrap it — so a
//! copied container, or a stolen disk, yields nothing. At enrollment the gateway hands
//! the device exactly that wrapping: the workspace's container DEK, wrapped to the device's KEK,
//! which the device then keeps in its hardware key store and unwraps locally at every unlock.
//!
//! This is a **seam** with an in-memory double ([`MemVolumeKeyService`]) so the flow is testable
//! with no TPM / Secure Enclave. The double escrows a DEK per workspace and AES-KW-wraps it on
//! demand under the supplied device KEK — reusing `clave_volume`'s software wrap path exactly as
//! `clave_volume::MemKeyStore` does. The **production** seam differs in one place: a device KEK is
//! hardware-bound and never leaves the enclave, so a real service seals the DEK to the device's
//! *asymmetric* hardware public key (an ECIES/sealed-box wrap) rather than a shared symmetric KEK.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use clave_identity::WorkspaceId;
use clave_proto::WrappedVolumeKey;
use clave_volume::{seal_dek, ContainerId, Dek, Kek, DEK_LEN};

use crate::GatewayError;

/// Issues the wrapped volume key a device gets at enrollment. `None` ⇒ the
/// workspace has no provisioned Clave Disk container yet; enrollment still succeeds.
#[async_trait]
pub trait VolumeKeyService: Send + Sync {
    /// Wrap the workspace's container DEK to `device_kek` (the device's wrapping key, established
    /// over the authenticated enrollment channel). Fail-closed: any error yields no key.
    async fn issue_wrapped_volume_key(
        &self,
        workspace: WorkspaceId,
        device_kek: &[u8; 32],
    ) -> Result<Option<WrappedVolumeKey>, GatewayError>;
}

/// In-memory [`VolumeKeyService`] for tests/dev and the single-workspace bootstrap: escrows one
/// container DEK per workspace (raw bytes, as `clave_volume::MemKeyStore` holds the KEK in memory)
/// and AES-KW-wraps it on demand. See the module note on the production asymmetric seal.
#[derive(Default)]
pub struct MemVolumeKeyService {
    containers: Mutex<HashMap<WorkspaceId, (ContainerId, [u8; DEK_LEN])>>,
}

impl MemVolumeKeyService {
    /// An empty service — no containers until [`MemVolumeKeyService::set_container`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Provision (or replace) the escrowed Clave Disk DEK for `workspace`. `dek` is the raw 64-byte
    /// XTS key; in production it is generated where the gateway has byte custody and held in the
    /// key-management service, never on disk in cleartext.
    pub fn set_container(&self, workspace: WorkspaceId, container: ContainerId, dek: [u8; DEK_LEN]) {
        self.containers
            .lock()
            .unwrap()
            .insert(workspace, (container, dek));
    }
}

#[async_trait]
impl VolumeKeyService for MemVolumeKeyService {
    async fn issue_wrapped_volume_key(
        &self,
        workspace: WorkspaceId,
        device_kek: &[u8; 32],
    ) -> Result<Option<WrappedVolumeKey>, GatewayError> {
        let (container, dek_bytes) = match self.containers.lock().unwrap().get(&workspace) {
            Some((id, dek)) => (*id, *dek),
            None => return Ok(None),
        };
        let dek = Dek::from_bytes(dek_bytes);
        let wrapped = Kek::from_bytes(*device_kek).wrap(&dek);
        Ok(Some(WrappedVolumeKey {
            container: container.0,
            wrapped_dek: wrapped.as_bytes().to_vec(),
            ephemeral_pub: None, // symmetric dev wrap; the sealed path sets this (see SealedVolumeKeyService)
        }))
    }
}

/// **Production** [`VolumeKeyService`]: seals the container DEK to the device's X25519 **public**
/// key (an ECIES sealed-box, `clave_volume::seal_dek`), so the gateway holds nothing that can open
/// it — the device's private key never leaves its hardware. The
/// `device_kek` argument is the device's 32-byte X25519 public key (registered at enrollment), not
/// a shared symmetric key. Escrows the container DEK per workspace exactly like
/// [`MemVolumeKeyService`]; in deployment that escrow is the KMS.
#[derive(Default)]
pub struct SealedVolumeKeyService {
    containers: Mutex<HashMap<WorkspaceId, (ContainerId, [u8; DEK_LEN])>>,
}

impl SealedVolumeKeyService {
    /// An empty service — no containers until [`SealedVolumeKeyService::set_container`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Provision (or replace) the escrowed Clave Disk DEK for `workspace`.
    pub fn set_container(&self, workspace: WorkspaceId, container: ContainerId, dek: [u8; DEK_LEN]) {
        self.containers
            .lock()
            .unwrap()
            .insert(workspace, (container, dek));
    }
}

#[async_trait]
impl VolumeKeyService for SealedVolumeKeyService {
    async fn issue_wrapped_volume_key(
        &self,
        workspace: WorkspaceId,
        device_kek: &[u8; 32],
    ) -> Result<Option<WrappedVolumeKey>, GatewayError> {
        let (container, dek_bytes) = match self.containers.lock().unwrap().get(&workspace) {
            Some((id, dek)) => (*id, *dek),
            None => return Ok(None),
        };
        // `device_kek` is the device's X25519 public key; seal the DEK to it.
        let sealed = seal_dek(*device_kek, &Dek::from_bytes(dek_bytes))
            .map_err(|e| GatewayError::Store(e.to_string()))?;
        Ok(Some(WrappedVolumeKey {
            container: container.0,
            wrapped_dek: sealed.wrapped.as_bytes().to_vec(),
            ephemeral_pub: Some(sealed.ephemeral_pub),
        }))
    }
}
