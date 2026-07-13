use std::sync::Arc;

use clave_identity::{
    accept_invitation, authorize_enrollment, authorize_login, EnrollmentDecision, LoginDecision,
    MembershipStatus, Role, UnixTime, UserId, WorkspaceId,
};
use clave_proto::SignedCommand;
use serde::{Deserialize, Serialize};

use crate::{
    DenyReason, DeviceId, GatewayError, IdentityProvider, PolicyIssuer, RequestContext, Session,
    Store, VolumeKeyService, WrappedVolumeKey,
};

pub struct Gateway<I, S> {
    idp: I,
    store: S,
    policy_issuer: Option<Arc<dyn PolicyIssuer>>,
    volume_keys: Option<Arc<dyn VolumeKeyService>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EnrollmentOutcome {
    Pending,
    Approved { user: UserId, role: Role },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EnrollmentCompletion {
    Pending,
    Approved {
        device: DeviceId,
        user: UserId,
        role: Role,
        policy: Option<SignedCommand>,
        volume_key: Option<WrappedVolumeKey>,
    },
}

impl<I: IdentityProvider, S: Store> Gateway<I, S> {
    pub fn new(idp: I, store: S) -> Self {
        Self {
            idp,
            store,
            policy_issuer: None,
            volume_keys: None,
        }
    }

    pub fn with_policy_issuer(mut self, issuer: Arc<dyn PolicyIssuer>) -> Self {
        self.policy_issuer = Some(issuer);
        self
    }

    pub fn with_volume_key_service(mut self, service: Arc<dyn VolumeKeyService>) -> Self {
        self.volume_keys = Some(service);
        self
    }

    pub async fn console_login(
        &self,
        code: &str,
        now: UnixTime,
        ttl: u64,
    ) -> Result<Session, GatewayError> {
        let vu = self.idp.exchange_console_code(code).await?;
        let ws = self
            .store
            .workspace(vu.workspace)
            .await?
            .ok_or(GatewayError::NoSuchWorkspace)?;
        let user = self.store.upsert_user(&vu.email, &vu.idp_user_id).await?;

        let membership = match self.store.membership(vu.workspace, user).await? {
            Some(m) => Some(m),
            None => match self.store.invitation(vu.workspace, &vu.email).await? {
                Some(inv) => {
                    let m = accept_invitation(user, &vu.email, vu.method, &ws, &inv, now)?;
                    self.store.put_membership(&m).await?;
                    self.store
                        .mark_invitation_accepted(vu.workspace, &vu.email)
                        .await?;
                    Some(m)
                }
                None => None,
            },
        };

        match authorize_login(&vu.email, vu.method, &ws, membership.as_ref()) {
            LoginDecision::Allow { role } => Ok(Session {
                user,
                workspace: vu.workspace,
                role,
                expires_at: now.saturating_add(ttl),
                refresh_token: vu.refresh_token,
            }),
            LoginDecision::Deny(r) => Err(GatewayError::Unauthorized(r)),
        }
    }

    pub async fn authorize_request(
        &self,
        session: &Session,
        now: UnixTime,
    ) -> Result<RequestContext, GatewayError> {
        if now > session.expires_at {
            return Err(GatewayError::SessionInvalid);
        }
        match self
            .store
            .membership(session.workspace, session.user)
            .await?
        {
            Some(m) if m.status == MembershipStatus::Active => Ok(RequestContext {
                user: session.user,
                workspace: session.workspace,
                role: m.role,
            }),
            Some(m) if m.status == MembershipStatus::Suspended => {
                Err(GatewayError::Unauthorized(DenyReason::Suspended))
            }
            _ => Err(GatewayError::Unauthorized(DenyReason::NotAMember)),
        }
    }

    pub async fn begin_enrollment(
        &self,
        workspace: WorkspaceId,
    ) -> Result<crate::DeviceAuth, GatewayError> {
        self.idp.begin_device_auth(workspace).await
    }

    pub async fn poll_enrollment(
        &self,
        workspace: WorkspaceId,
        device_code: &str,
    ) -> Result<EnrollmentOutcome, GatewayError> {
        match self
            .authorize_enrollment_poll(workspace, device_code)
            .await?
        {
            None => Ok(EnrollmentOutcome::Pending),
            Some((user, role)) => Ok(EnrollmentOutcome::Approved { user, role }),
        }
    }

    pub async fn complete_enrollment(
        &self,
        workspace: WorkspaceId,
        device_code: &str,
        device_pubkey: &[u8; 32],
        device_wrapping_key: Option<&[u8; 32]>,
        now: UnixTime,
    ) -> Result<EnrollmentCompletion, GatewayError> {
        match self
            .authorize_enrollment_poll(workspace, device_code)
            .await?
        {
            None => Ok(EnrollmentCompletion::Pending),
            Some((user, role)) => {
                let device = self
                    .store
                    .record_device(workspace, user, device_pubkey)
                    .await?;
                let policy = match &self.policy_issuer {
                    Some(issuer) => issuer.issue_initial_policy(workspace, now).await?,
                    None => None,
                };
                let volume_key = match (&self.volume_keys, device_wrapping_key) {
                    (Some(service), Some(kek)) => {
                        service.issue_wrapped_volume_key(workspace, kek).await?
                    }
                    _ => None,
                };
                Ok(EnrollmentCompletion::Approved {
                    device,
                    user,
                    role,
                    policy,
                    volume_key,
                })
            }
        }
    }

    async fn authorize_enrollment_poll(
        &self,
        workspace: WorkspaceId,
        device_code: &str,
    ) -> Result<Option<(UserId, Role)>, GatewayError> {
        let vu = match self.idp.poll_device_auth(device_code).await? {
            None => return Ok(None),
            Some(vu) => vu,
        };
        let ws = self
            .store
            .workspace(workspace)
            .await?
            .ok_or(GatewayError::NoSuchWorkspace)?;
        let user = self.store.upsert_user(&vu.email, &vu.idp_user_id).await?;
        let membership = self.store.membership(workspace, user).await?;

        match authorize_enrollment(&ws, membership.as_ref()) {
            EnrollmentDecision::Allow { role, .. } => Ok(Some((user, role))),
            EnrollmentDecision::Deny(r) => Err(GatewayError::Unauthorized(r)),
        }
    }
}
