//! The orchestration that ties authentication ([`IdentityProvider`]) and state ([`Store`]) to the
//! pure admission decisions ([`clave_identity`]). This is where the division of labor
//! lives: WorkOS proves *who*, `clave-identity` decides *whether*, and the gateway carries the
//! session and re-checks membership on every request.

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

/// The control-plane gateway, generic over its two seams so tests use in-memory doubles and
/// production uses WorkOS + Postgres. An optional [`PolicyIssuer`] lets it hand a freshly-enrolled
/// device its signed initial policy bundle; without one, enrollment still
/// succeeds and the device gets its first bundle on its first gateway sync instead.
pub struct Gateway<I, S> {
    idp: I,
    store: S,
    policy_issuer: Option<Arc<dyn PolicyIssuer>>,
    volume_keys: Option<Arc<dyn VolumeKeyService>>,
}

/// The result of polling a device-enrollment grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EnrollmentOutcome {
    /// The human has not finished the browser login yet.
    Pending,
    /// Enrollment is authorized: the device may now submit its key to [`Gateway::complete_enrollment`].
    Approved { user: UserId, role: Role },
}

/// The result of completing a device enrollment: like [`EnrollmentOutcome`], but on approval the
/// device's public key has been **registered** (its [`DeviceId`] is returned) and the two
/// enrollment artifacts are issued when their services are attached: the device's
/// **tenant-signed initial policy bundle** ([`PolicyIssuer`]) and its **wrapped volume key**
/// ([`VolumeKeyService`] — the Clave Disk DEK wrapped to the device's KEK). The device
/// feeds `policy` to its pinned-key [`GatewayVerifier`](clave_proto::GatewayVerifier) and unwraps
/// `volume_key` with its hardware KEK to open the disk. Each is `None` when unconfigured / not
/// requested (the device gets the policy on its first sync; the volume key needs a wrapping key).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EnrollmentCompletion {
    /// The human has not finished the browser login yet; the device should keep polling.
    Pending,
    /// Enrollment is authorized and the device is registered under `device`.
    Approved {
        device: DeviceId,
        user: UserId,
        role: Role,
        /// The tenant-signed initial policy command, if a policy issuer is configured.
        policy: Option<SignedCommand>,
        /// The wrapped Clave Disk key, if a volume-key service is configured and the device
        /// submitted a wrapping key.
        volume_key: Option<WrappedVolumeKey>,
    },
}

impl<I: IdentityProvider, S: Store> Gateway<I, S> {
    /// Build a gateway over an identity provider and a store. No policy issuer is attached, so
    /// [`complete_enrollment`](Self::complete_enrollment) registers the device but issues no bundle
    /// — add one with [`with_policy_issuer`](Self::with_policy_issuer).
    pub fn new(idp: I, store: S) -> Self {
        Self {
            idp,
            store,
            policy_issuer: None,
            volume_keys: None,
        }
    }

    /// Attach a [`PolicyIssuer`] so approved enrollments also receive a tenant-signed initial policy
    /// bundle.
    pub fn with_policy_issuer(mut self, issuer: Arc<dyn PolicyIssuer>) -> Self {
        self.policy_issuer = Some(issuer);
        self
    }

    /// Attach a [`VolumeKeyService`] so a device that submits its wrapping key at enrollment also
    /// receives its [`WrappedVolumeKey`] — the Clave Disk DEK wrapped to that key.
    pub fn with_volume_key_service(mut self, service: Arc<dyn VolumeKeyService>) -> Self {
        self.volume_keys = Some(service);
        self
    }

    /// Complete an admin-console login. Exchanges the WorkOS code, accepts a pending invitation if
    /// the user has one and no membership yet, then makes the authoritative admission decision.
    /// Returns the [`Session`] to seal into the cookie (`ttl` seconds from `now`).
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

        // Resolve to a membership: an existing one, or accept a matching pending invitation.
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

        // Authoritative decision — also enforces the workspace's domain + SSO policy.
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

    /// Validate a session on an incoming request and resolve the current authoritative identity.
    /// Re-reads membership every call so a suspended (SCIM-deprovisioned) user is rejected
    /// immediately — the session role from the cookie is never trusted on its own.
    pub async fn authorize_request(
        &self,
        session: &Session,
        now: UnixTime,
    ) -> Result<RequestContext, GatewayError> {
        if now > session.expires_at {
            return Err(GatewayError::SessionInvalid);
        }
        match self.store.membership(session.workspace, session.user).await? {
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

    /// Begin a device-enrollment grant; the daemon shows the returned code/URI to the user.
    pub async fn begin_enrollment(
        &self,
        workspace: WorkspaceId,
    ) -> Result<crate::DeviceAuth, GatewayError> {
        self.idp.begin_device_auth(workspace).await
    }

    /// Poll a device-enrollment grant. Once the human completes the browser login, authorize the
    /// enrollment against their workspace membership.
    pub async fn poll_enrollment(
        &self,
        workspace: WorkspaceId,
        device_code: &str,
    ) -> Result<EnrollmentOutcome, GatewayError> {
        match self.authorize_enrollment_poll(workspace, device_code).await? {
            None => Ok(EnrollmentOutcome::Pending),
            Some((user, role)) => Ok(EnrollmentOutcome::Approved { user, role }),
        }
    }

    /// Complete a device enrollment: like [`Gateway::poll_enrollment`], but on approval the device's
    /// Ed25519 public key is **registered** and, when their services are attached,
    /// its initial enrollment artifacts are issued — the tenant-signed policy bundle ([`PolicyIssuer`])
    /// and, if `device_wrapping_key` is supplied, its wrapped volume key ([`VolumeKeyService`]) — all
    /// returned in [`EnrollmentCompletion::Approved`]. `device_pubkey` is the runtime trust anchor;
    /// `device_wrapping_key` is the hardware KEK the Clave Disk DEK is wrapped to; `now` stamps the
    /// signed command's freshness. Idempotent in the store, so a
    /// retried call with the same key returns the same device.
    pub async fn complete_enrollment(
        &self,
        workspace: WorkspaceId,
        device_code: &str,
        device_pubkey: &[u8; 32],
        device_wrapping_key: Option<&[u8; 32]>,
        now: UnixTime,
    ) -> Result<EnrollmentCompletion, GatewayError> {
        match self.authorize_enrollment_poll(workspace, device_code).await? {
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

    /// Shared body of [`poll_enrollment`](Self::poll_enrollment) /
    /// [`complete_enrollment`](Self::complete_enrollment): poll the IdP and, if the human has
    /// finished, authorize the enrollment against workspace membership. `Ok(None)` ⇒ still pending.
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
