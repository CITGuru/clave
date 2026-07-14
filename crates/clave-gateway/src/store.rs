use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use clave_identity::{
    EmailAddr, Invitation, Membership, MembershipStatus, Role, UserId, Workspace, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::GatewayError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub u128);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Pending,
    Active,
    Locked,
    Wiped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub enrolled_by: UserId,
    pub status: DeviceStatus,
    pub pubkey: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemberRecord {
    pub user: UserId,
    pub email: String,
    pub role: Role,
    pub status: MembershipStatus,
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn workspace(&self, id: WorkspaceId) -> Result<Option<Workspace>, GatewayError>;

    async fn upsert_user(
        &self,
        email: &EmailAddr,
        idp_user_id: &str,
    ) -> Result<UserId, GatewayError>;

    async fn membership(
        &self,
        workspace: WorkspaceId,
        user: UserId,
    ) -> Result<Option<Membership>, GatewayError>;

    async fn put_membership(&self, membership: &Membership) -> Result<(), GatewayError>;

    async fn list_members(&self, workspace: WorkspaceId)
        -> Result<Vec<MemberRecord>, GatewayError>;

    async fn invitation(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<Option<Invitation>, GatewayError>;

    async fn put_invitation(&self, invitation: &Invitation) -> Result<(), GatewayError>;

    async fn list_invitations(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<Invitation>, GatewayError>;

    async fn mark_invitation_accepted(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<(), GatewayError>;

    async fn record_device(
        &self,
        workspace: WorkspaceId,
        enrolled_by: UserId,
        device_pubkey: &[u8; 32],
    ) -> Result<DeviceId, GatewayError>;

    async fn list_devices(&self, workspace: WorkspaceId)
        -> Result<Vec<DeviceRecord>, GatewayError>;

    async fn device(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
    ) -> Result<Option<DeviceRecord>, GatewayError>;

    async fn set_device_status(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
        status: DeviceStatus,
    ) -> Result<(), GatewayError>;
}

struct StoredDevice {
    workspace: WorkspaceId,
    enrolled_by: UserId,
    pubkey: [u8; 32],
    status: DeviceStatus,
}

impl StoredDevice {
    fn record(&self, id: DeviceId) -> DeviceRecord {
        DeviceRecord {
            id,
            enrolled_by: self.enrolled_by,
            status: self.status,
            pubkey: hex(&self.pubkey),
        }
    }
}

#[derive(Default)]
pub struct MemStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    next_user: u64,
    next_device: u128,
    workspaces: HashMap<WorkspaceId, Workspace>,
    users: HashMap<String, UserId>,
    emails: HashMap<UserId, String>,
    memberships: HashMap<(WorkspaceId, UserId), Membership>,
    invitations: HashMap<(WorkspaceId, String), Invitation>,
    devices_by_key: HashMap<(WorkspaceId, [u8; 32]), DeviceId>,
    devices: HashMap<DeviceId, StoredDevice>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed_workspace(&self, ws: Workspace) {
        self.inner.lock().unwrap().workspaces.insert(ws.id, ws);
    }

    pub fn seed_membership(&self, m: Membership) {
        self.inner
            .lock()
            .unwrap()
            .memberships
            .insert((m.workspace, m.user), m);
    }

    pub fn seed_invitation(&self, inv: Invitation) {
        let key = (inv.workspace, inv.email.as_str().to_string());
        self.inner.lock().unwrap().invitations.insert(key, inv);
    }
}

#[async_trait]
impl Store for MemStore {
    async fn workspace(&self, id: WorkspaceId) -> Result<Option<Workspace>, GatewayError> {
        Ok(self.inner.lock().unwrap().workspaces.get(&id).cloned())
    }

    async fn upsert_user(
        &self,
        email: &EmailAddr,
        _idp_user_id: &str,
    ) -> Result<UserId, GatewayError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(id) = inner.users.get(email.as_str()) {
            return Ok(*id);
        }
        inner.next_user += 1;
        let id = UserId(inner.next_user);
        inner.users.insert(email.as_str().to_string(), id);
        inner.emails.insert(id, email.as_str().to_string());
        Ok(id)
    }

    async fn membership(
        &self,
        workspace: WorkspaceId,
        user: UserId,
    ) -> Result<Option<Membership>, GatewayError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .memberships
            .get(&(workspace, user))
            .cloned())
    }

    async fn put_membership(&self, membership: &Membership) -> Result<(), GatewayError> {
        self.inner
            .lock()
            .unwrap()
            .memberships
            .insert((membership.workspace, membership.user), membership.clone());
        Ok(())
    }

    async fn list_members(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<MemberRecord>, GatewayError> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<MemberRecord> = inner
            .memberships
            .values()
            .filter(|m| m.workspace == workspace)
            .map(|m| MemberRecord {
                user: m.user,
                email: inner.emails.get(&m.user).cloned().unwrap_or_default(),
                role: m.role,
                status: m.status,
            })
            .collect();
        out.sort_by_key(|m| m.user.0);
        Ok(out)
    }

    async fn invitation(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<Option<Invitation>, GatewayError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .invitations
            .get(&(workspace, email.as_str().to_string()))
            .cloned())
    }

    async fn put_invitation(&self, invitation: &Invitation) -> Result<(), GatewayError> {
        let key = (invitation.workspace, invitation.email.as_str().to_string());
        self.inner
            .lock()
            .unwrap()
            .invitations
            .insert(key, invitation.clone());
        Ok(())
    }

    async fn list_invitations(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<Invitation>, GatewayError> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<Invitation> = inner
            .invitations
            .values()
            .filter(|i| i.workspace == workspace)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.email.as_str().cmp(b.email.as_str()));
        Ok(out)
    }

    async fn mark_invitation_accepted(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<(), GatewayError> {
        if let Some(inv) = self
            .inner
            .lock()
            .unwrap()
            .invitations
            .get_mut(&(workspace, email.as_str().to_string()))
        {
            inv.accepted = true;
        }
        Ok(())
    }

    async fn record_device(
        &self,
        workspace: WorkspaceId,
        enrolled_by: UserId,
        device_pubkey: &[u8; 32],
    ) -> Result<DeviceId, GatewayError> {
        let mut inner = self.inner.lock().unwrap();
        let key = (workspace, *device_pubkey);
        if let Some(id) = inner.devices_by_key.get(&key).copied() {
            if let Some(d) = inner.devices.get_mut(&id) {
                d.status = DeviceStatus::Active;
            }
            return Ok(id);
        }
        inner.next_device += 1;
        let id = DeviceId(inner.next_device);
        inner.devices_by_key.insert(key, id);
        inner.devices.insert(
            id,
            StoredDevice {
                workspace,
                enrolled_by,
                pubkey: *device_pubkey,
                status: DeviceStatus::Active,
            },
        );
        Ok(id)
    }

    async fn list_devices(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<DeviceRecord>, GatewayError> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<DeviceRecord> = inner
            .devices
            .iter()
            .filter(|(_, d)| d.workspace == workspace)
            .map(|(id, d)| d.record(*id))
            .collect();
        out.sort_by_key(|d| d.id.0);
        Ok(out)
    }

    async fn device(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
    ) -> Result<Option<DeviceRecord>, GatewayError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .devices
            .get(&device)
            .filter(|d| d.workspace == workspace)
            .map(|d| d.record(device)))
    }

    async fn set_device_status(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
        status: DeviceStatus,
    ) -> Result<(), GatewayError> {
        let mut inner = self.inner.lock().unwrap();
        match inner.devices.get_mut(&device) {
            Some(d) if d.workspace == workspace => {
                d.status = status;
                Ok(())
            }
            _ => Err(GatewayError::NotFound(format!("device {}", device.0))),
        }
    }
}

#[async_trait]
impl<T: Store + ?Sized> Store for Arc<T> {
    async fn workspace(&self, id: WorkspaceId) -> Result<Option<Workspace>, GatewayError> {
        (**self).workspace(id).await
    }
    async fn upsert_user(
        &self,
        email: &EmailAddr,
        idp_user_id: &str,
    ) -> Result<UserId, GatewayError> {
        (**self).upsert_user(email, idp_user_id).await
    }
    async fn membership(
        &self,
        workspace: WorkspaceId,
        user: UserId,
    ) -> Result<Option<Membership>, GatewayError> {
        (**self).membership(workspace, user).await
    }
    async fn put_membership(&self, membership: &Membership) -> Result<(), GatewayError> {
        (**self).put_membership(membership).await
    }
    async fn list_members(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<MemberRecord>, GatewayError> {
        (**self).list_members(workspace).await
    }
    async fn invitation(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<Option<Invitation>, GatewayError> {
        (**self).invitation(workspace, email).await
    }
    async fn put_invitation(&self, invitation: &Invitation) -> Result<(), GatewayError> {
        (**self).put_invitation(invitation).await
    }
    async fn list_invitations(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<Invitation>, GatewayError> {
        (**self).list_invitations(workspace).await
    }
    async fn mark_invitation_accepted(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<(), GatewayError> {
        (**self).mark_invitation_accepted(workspace, email).await
    }
    async fn record_device(
        &self,
        workspace: WorkspaceId,
        enrolled_by: UserId,
        device_pubkey: &[u8; 32],
    ) -> Result<DeviceId, GatewayError> {
        (**self)
            .record_device(workspace, enrolled_by, device_pubkey)
            .await
    }
    async fn list_devices(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<DeviceRecord>, GatewayError> {
        (**self).list_devices(workspace).await
    }
    async fn device(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
    ) -> Result<Option<DeviceRecord>, GatewayError> {
        (**self).device(workspace, device).await
    }
    async fn set_device_status(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
        status: DeviceStatus,
    ) -> Result<(), GatewayError> {
        (**self).set_device_status(workspace, device, status).await
    }
}
