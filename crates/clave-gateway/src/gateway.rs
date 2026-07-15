use std::collections::HashSet;
use std::sync::Arc;

use clave_identity::{
    accept_invitation, authorize_enrollment, authorize_login, can, min_role, AdminAction, EmailAddr,
    EnrollmentDecision, Invitation, LoginDecision, Membership, MembershipStatus, Role, UnixTime,
    UserId, WorkspaceId,
};
use clave_core::PolicyBundle;
use clave_proto::{SignedCommand, TlsCredentials};
use serde::{Deserialize, Serialize};

use crate::{
    AuditAlert, AuditLedger, AuditRecord, AuditStore, DenyReason, DeviceCertIssuer, DeviceId,
    DeviceRecord, DeviceStatus, GatewayError, IdentityProvider, IngestError, MemberRecord,
    MembershipDelta, PolicyIssuer, RequestContext, ScimEvent, Session, SignedSpoolBatch, Store,
    VolumeKeyService, WrappedVolumeKey,
};

pub struct Gateway<I, S> {
    idp: I,
    store: S,
    policy_issuer: Option<Arc<dyn PolicyIssuer>>,
    volume_keys: Option<Arc<dyn VolumeKeyService>>,
    audit: Arc<AuditLedger>,
    audit_store: Option<Arc<dyn AuditStore>>,
    device_ca: Option<Arc<dyn DeviceCertIssuer>>,
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
        #[serde(default)]
        tls: Option<Box<TlsCredentials>>,
    },
}

impl<I: IdentityProvider, S: Store> Gateway<I, S> {
    pub fn new(idp: I, store: S) -> Self {
        Self {
            idp,
            store,
            policy_issuer: None,
            volume_keys: None,
            audit: Arc::new(AuditLedger::new()),
            audit_store: None,
            device_ca: None,
        }
    }

    pub fn with_audit_store(mut self, store: Arc<dyn AuditStore>) -> Self {
        self.audit_store = Some(store);
        self
    }

    pub fn with_device_ca(mut self, issuer: Arc<dyn DeviceCertIssuer>) -> Self {
        self.device_ca = Some(issuer);
        self
    }

    pub async fn device_for_fingerprint(
        &self,
        fingerprint: &[u8; 32],
    ) -> Result<Option<DeviceId>, GatewayError> {
        self.store.device_by_fingerprint(fingerprint).await
    }

    pub async fn ingest_device_audit(
        &self,
        device: DeviceId,
        batch: &SignedSpoolBatch,
    ) -> Result<Vec<clave_core::AuditEvent>, IngestError> {
        let result = self.audit.ingest(device, batch);
        let Some(store) = &self.audit_store else {
            return result;
        };
        match &result {
            Ok(_) => {
                let next_seq = self.audit.high_water(device).unwrap_or(1);
                let head = self.audit.head_for(device).unwrap_or(clave_proto::GENESIS);
                if let Err(e) = store.append(device, &batch.entries, next_seq, head).await {
                    eprintln!("clave-gateway: audit persist failed for device {:x}: {e}", device.0);
                }
            }
            Err(_) => {
                if let Some(alert) = self.audit.alerts().into_iter().rev().find(|a| a.device == device)
                {
                    let _ = store.record_alert(&alert).await;
                }
            }
        }
        result
    }

    pub async fn hydrate_audit(&self) -> Result<usize, GatewayError> {
        let Some(store) = &self.audit_store else {
            return Ok(0);
        };
        let chains = store.load_chains().await?;
        let n = chains.len();
        for c in chains {
            self.audit
                .restore_device(c.device, c.public_key, c.next_seq, c.head);
        }
        Ok(n)
    }

    pub fn audit(&self) -> &Arc<AuditLedger> {
        &self.audit
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

    pub async fn refresh_session(
        &self,
        session: &Session,
        now: UnixTime,
        ttl: u64,
    ) -> Result<Session, GatewayError> {
        let vu = self.idp.refresh_session(&session.refresh_token).await?;
        let ws = self
            .store
            .workspace(vu.workspace)
            .await?
            .ok_or(GatewayError::NoSuchWorkspace)?;
        let user = self.store.upsert_user(&vu.email, &vu.idp_user_id).await?;
        let membership = self.store.membership(vu.workspace, user).await?;

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
                self.audit.register_device(device, *device_pubkey);
                if let Some(store) = &self.audit_store {
                    let _ = store.register(device, *device_pubkey).await;
                }
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
                let tls = match &self.device_ca {
                    Some(issuer) => match issuer.issue(device.0) {
                        Ok(issued) => {
                            self.store
                                .set_device_fingerprint(device, issued.fingerprint)
                                .await?;
                            Some(Box::new(TlsCredentials {
                                ca_pem: issued.ca_pem,
                                cert_pem: issued.cert_pem,
                                key_pem: issued.key_pem,
                                server_name: issuer.server_name().to_string(),
                                gateway_addr: issuer.gateway_addr().to_string(),
                            }))
                        }
                        Err(e) => {
                            eprintln!("clave-gateway: device cert issue failed: {e}");
                            None
                        }
                    },
                    None => None,
                };
                Ok(EnrollmentCompletion::Approved {
                    device,
                    user,
                    role,
                    policy,
                    volume_key,
                    tls,
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

    fn require(ctx: &RequestContext, action: AdminAction) -> Result<(), GatewayError> {
        if can(ctx.role, action) {
            Ok(())
        } else {
            Err(GatewayError::Forbidden(format!(
                "{action:?} requires at least {:?}",
                min_role(action)
            )))
        }
    }

    async fn target_membership(
        &self,
        ctx: &RequestContext,
        user: UserId,
    ) -> Result<Membership, GatewayError> {
        self.store
            .membership(ctx.workspace, user)
            .await?
            .ok_or_else(|| GatewayError::NotFound(format!("member {}", user.0)))
    }

    pub async fn invite_member(
        &self,
        ctx: &RequestContext,
        email: &str,
        role: Role,
        expires_at: UnixTime,
    ) -> Result<Invitation, GatewayError> {
        Self::require(ctx, AdminAction::ManageMembers)?;
        if role > ctx.role {
            return Err(GatewayError::Forbidden(
                "cannot invite above your own role".into(),
            ));
        }
        let email =
            EmailAddr::parse(email).ok_or_else(|| GatewayError::Store("invalid email".into()))?;
        let inv = Invitation {
            workspace: ctx.workspace,
            email,
            role,
            expires_at,
            accepted: false,
        };
        self.store.put_invitation(&inv).await?;
        Ok(inv)
    }

    pub async fn list_invitations(
        &self,
        ctx: &RequestContext,
    ) -> Result<Vec<Invitation>, GatewayError> {
        Self::require(ctx, AdminAction::ManageMembers)?;
        self.store.list_invitations(ctx.workspace).await
    }

    pub async fn list_members(
        &self,
        ctx: &RequestContext,
    ) -> Result<Vec<MemberRecord>, GatewayError> {
        Self::require(ctx, AdminAction::ManageMembers)?;
        self.store.list_members(ctx.workspace).await
    }

    pub async fn change_role(
        &self,
        ctx: &RequestContext,
        user: UserId,
        role: Role,
    ) -> Result<(), GatewayError> {
        Self::require(ctx, AdminAction::ChangeRoles)?;
        if role > ctx.role {
            return Err(GatewayError::Forbidden(
                "cannot grant a role above your own".into(),
            ));
        }
        let mut m = self.target_membership(ctx, user).await?;
        if m.role > ctx.role {
            return Err(GatewayError::Forbidden(
                "cannot modify a more senior member".into(),
            ));
        }
        m.role = role;
        self.store.put_membership(&m).await
    }

    pub async fn suspend_member(
        &self,
        ctx: &RequestContext,
        user: UserId,
    ) -> Result<(), GatewayError> {
        self.set_member_status(ctx, user, MembershipStatus::Suspended)
            .await
    }

    pub async fn restore_member(
        &self,
        ctx: &RequestContext,
        user: UserId,
    ) -> Result<(), GatewayError> {
        self.set_member_status(ctx, user, MembershipStatus::Active)
            .await
    }

    async fn set_member_status(
        &self,
        ctx: &RequestContext,
        user: UserId,
        status: MembershipStatus,
    ) -> Result<(), GatewayError> {
        Self::require(ctx, AdminAction::ManageMembers)?;
        let mut m = self.target_membership(ctx, user).await?;
        if m.role > ctx.role {
            return Err(GatewayError::Forbidden(
                "cannot modify a more senior member".into(),
            ));
        }
        m.status = status;
        self.store.put_membership(&m).await
    }

    pub async fn list_devices(
        &self,
        ctx: &RequestContext,
    ) -> Result<Vec<DeviceRecord>, GatewayError> {
        Self::require(ctx, AdminAction::ViewAudit)?;
        self.store.list_devices(ctx.workspace).await
    }

    pub async fn lock_device(
        &self,
        ctx: &RequestContext,
        device: DeviceId,
    ) -> Result<(), GatewayError> {
        Self::require(ctx, AdminAction::ControlDevice)?;
        self.store
            .set_device_status(ctx.workspace, device, DeviceStatus::Locked)
            .await
    }

    pub async fn wipe_device(
        &self,
        ctx: &RequestContext,
        device: DeviceId,
    ) -> Result<(), GatewayError> {
        Self::require(ctx, AdminAction::ControlDevice)?;
        self.store
            .set_device_status(ctx.workspace, device, DeviceStatus::Wiped)
            .await
    }

    fn policy_issuer(&self) -> Result<&Arc<dyn PolicyIssuer>, GatewayError> {
        self.policy_issuer
            .as_ref()
            .ok_or_else(|| GatewayError::NotFound("policy issuer not configured".into()))
    }

    pub async fn get_policy(
        &self,
        ctx: &RequestContext,
    ) -> Result<Option<PolicyBundle>, GatewayError> {
        Self::require(ctx, AdminAction::ManagePolicy)?;
        match &self.policy_issuer {
            Some(issuer) => issuer.current_policy(ctx.workspace).await,
            None => Ok(None),
        }
    }

    pub async fn author_policy(
        &self,
        ctx: &RequestContext,
        bundle: PolicyBundle,
    ) -> Result<PolicyBundle, GatewayError> {
        Self::require(ctx, AdminAction::ManagePolicy)?;
        self.policy_issuer()?.author_policy(ctx.workspace, bundle).await
    }

    pub async fn reissue_policy(
        &self,
        ctx: &RequestContext,
        now: UnixTime,
    ) -> Result<SignedCommand, GatewayError> {
        Self::require(ctx, AdminAction::ManagePolicy)?;
        self.policy_issuer()?
            .reissue_policy(ctx.workspace, now)
            .await?
            .ok_or_else(|| GatewayError::NotFound("no policy to reissue".into()))
    }

    pub async fn policy_versions(
        &self,
        ctx: &RequestContext,
    ) -> Result<Vec<u64>, GatewayError> {
        Self::require(ctx, AdminAction::ManagePolicy)?;
        match &self.policy_issuer {
            Some(issuer) => issuer.policy_versions(ctx.workspace).await,
            None => Ok(Vec::new()),
        }
    }

    pub async fn audit_events(
        &self,
        ctx: &RequestContext,
    ) -> Result<Vec<AuditRecord>, GatewayError> {
        Self::require(ctx, AdminAction::ViewAudit)?;
        let devices = self.store.list_devices(ctx.workspace).await?;
        let mut out = Vec::new();
        for d in devices {
            for event in self.audit.events_for(d.id) {
                out.push(AuditRecord { device: d.id, event });
            }
        }
        Ok(out)
    }

    pub async fn audit_alerts(
        &self,
        ctx: &RequestContext,
    ) -> Result<Vec<AuditAlert>, GatewayError> {
        Self::require(ctx, AdminAction::ViewAudit)?;
        let ids: HashSet<DeviceId> = self
            .store
            .list_devices(ctx.workspace)
            .await?
            .into_iter()
            .map(|d| d.id)
            .collect();
        Ok(self
            .audit
            .alerts()
            .into_iter()
            .filter(|a| ids.contains(&a.device))
            .collect())
    }

    pub async fn apply_directory_event(
        &self,
        event: ScimEvent,
    ) -> Result<MembershipDelta, GatewayError> {
        let workspace = event.workspace();
        let email = event.email();
        let members = self.store.list_members(workspace).await?;
        let Some(user) = members
            .iter()
            .find(|m| m.email.eq_ignore_ascii_case(email.as_str()))
            .map(|m| m.user)
        else {
            return Ok(MembershipDelta::Unchanged);
        };

        let mut membership = self
            .store
            .membership(workspace, user)
            .await?
            .ok_or_else(|| GatewayError::NotFound(format!("member {}", user.0)))?;

        let target = if event.activates() {
            MembershipStatus::Active
        } else {
            MembershipStatus::Suspended
        };
        if membership.status == target {
            return Ok(MembershipDelta::Unchanged);
        }
        membership.status = target;
        self.store.put_membership(&membership).await?;

        Ok(if event.activates() {
            MembershipDelta::Restored { user }
        } else {
            MembershipDelta::Suspended { user }
        })
    }
}
