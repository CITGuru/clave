//! The [`Store`] seam: the gateway's persistent state. The production impl is Postgres via sqlx;
//! [`MemStore`] is the in-memory double that lets the whole control plane be tested with no DB.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use clave_identity::{EmailAddr, Invitation, Membership, UserId, Workspace, WorkspaceId};
use serde::{Deserialize, Serialize};

use crate::GatewayError;

/// A registered device's stable id. 128-bit so it maps directly onto the Postgres `uuid` primary
/// key, while [`MemStore`] can assign it sequentially. The device's Ed25519 public key is the
/// runtime trust anchor; this id is just the gateway's handle for the row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub u128);

/// Persistent control-plane state. All authoritative identity records live here; the
/// `membership` rows are the source of truth for the invited-only gate and SCIM suspension.
#[async_trait]
pub trait Store: Send + Sync {
    /// Look up a workspace.
    async fn workspace(&self, id: WorkspaceId) -> Result<Option<Workspace>, GatewayError>;

    /// Resolve an authenticated email to a stable [`UserId`], creating the user on first sight.
    async fn upsert_user(
        &self,
        email: &EmailAddr,
        idp_user_id: &str,
    ) -> Result<UserId, GatewayError>;

    /// The user's membership in a workspace, if any.
    async fn membership(
        &self,
        workspace: WorkspaceId,
        user: UserId,
    ) -> Result<Option<Membership>, GatewayError>;

    /// Insert or replace a membership (also used to suspend by writing a `Suspended` status).
    async fn put_membership(&self, membership: &Membership) -> Result<(), GatewayError>;

    /// A pending invitation addressed to `email` for `workspace`, if any.
    async fn invitation(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<Option<Invitation>, GatewayError>;

    /// Mark an invitation accepted so it cannot be reused.
    async fn mark_invitation_accepted(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<(), GatewayError>;

    /// Register an enrolled device by its Ed25519 public key (the runtime trust anchor), recording
    /// who enrolled it and marking it active. **Idempotent**: re-enrolling the same key in the same
    /// workspace (e.g. a retried poll) returns the existing [`DeviceId`] rather than duplicating it.
    async fn record_device(
        &self,
        workspace: WorkspaceId,
        enrolled_by: UserId,
        device_pubkey: &[u8; 32],
    ) -> Result<DeviceId, GatewayError>;
}

/// In-memory [`Store`] for tests/dev. Uses a plain `Mutex` per table; locks are never held across
/// an `await`, so this is sound under any runtime.
#[derive(Default)]
pub struct MemStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    next_user: u64,
    next_device: u128,
    workspaces: HashMap<WorkspaceId, Workspace>,
    users: HashMap<String, UserId>, // normalized email → id
    memberships: HashMap<(WorkspaceId, UserId), Membership>,
    invitations: HashMap<(WorkspaceId, String), Invitation>, // (ws, normalized email) → invite
    devices: HashMap<(WorkspaceId, [u8; 32]), DeviceId>,     // (ws, pubkey) → id
}

impl MemStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a workspace (test/dev helper).
    pub fn seed_workspace(&self, ws: Workspace) {
        self.inner.lock().unwrap().workspaces.insert(ws.id, ws);
    }

    /// Seed a membership (test/dev helper).
    pub fn seed_membership(&self, m: Membership) {
        self.inner
            .lock()
            .unwrap()
            .memberships
            .insert((m.workspace, m.user), m);
    }

    /// Seed an invitation (test/dev helper).
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
        _enrolled_by: UserId,
        device_pubkey: &[u8; 32],
    ) -> Result<DeviceId, GatewayError> {
        let mut inner = self.inner.lock().unwrap();
        let key = (workspace, *device_pubkey);
        if let Some(id) = inner.devices.get(&key) {
            return Ok(*id); // idempotent re-enrollment
        }
        inner.next_device += 1;
        let id = DeviceId(inner.next_device);
        inner.devices.insert(key, id);
        Ok(id)
    }
}

/// Delegating impl so a shared `Arc<MemStore>` (or `Arc<dyn Store>`) is itself a [`Store`] — how
/// the Axum app shares one pool across handlers, and how tests hold a handle to the store after
/// the gateway owns its clone.
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
    async fn invitation(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<Option<Invitation>, GatewayError> {
        (**self).invitation(workspace, email).await
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
        (**self).record_device(workspace, enrolled_by, device_pubkey).await
    }
}
