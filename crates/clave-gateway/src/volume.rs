use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use clave_identity::WorkspaceId;
use clave_proto::WrappedVolumeKey;
use clave_volume::{seal_dek, ContainerId, Dek, Kek, DEK_LEN};

use crate::GatewayError;

#[async_trait]
pub trait VolumeKeyService: Send + Sync {
    async fn issue_wrapped_volume_key(
        &self,
        workspace: WorkspaceId,
        device_kek: &[u8; 32],
    ) -> Result<Option<WrappedVolumeKey>, GatewayError>;
}

#[derive(Default)]
pub struct MemVolumeKeyService {
    containers: Mutex<HashMap<WorkspaceId, (ContainerId, [u8; DEK_LEN])>>,
}

impl MemVolumeKeyService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_container(
        &self,
        workspace: WorkspaceId,
        container: ContainerId,
        dek: [u8; DEK_LEN],
    ) {
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
            ephemeral_pub: None,
        }))
    }
}

#[derive(Default)]
pub struct SealedVolumeKeyService {
    containers: Mutex<HashMap<WorkspaceId, (ContainerId, [u8; DEK_LEN])>>,
}

impl SealedVolumeKeyService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_container(
        &self,
        workspace: WorkspaceId,
        container: ContainerId,
        dek: [u8; DEK_LEN],
    ) {
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
        let sealed = seal_dek(*device_kek, &Dek::from_bytes(dek_bytes))
            .map_err(|e| GatewayError::Store(e.to_string()))?;
        Ok(Some(WrappedVolumeKey {
            container: container.0,
            wrapped_dek: sealed.wrapped.as_bytes().to_vec(),
            ephemeral_pub: Some(sealed.ephemeral_pub),
        }))
    }
}
