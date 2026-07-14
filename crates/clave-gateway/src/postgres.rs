use async_trait::async_trait;
use clave_identity::{
    EmailAddr, Invitation, Membership, MembershipStatus, Role, SsoMode, UserId, Workspace,
    WorkspaceId,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use crate::store::hex;
use crate::{DeviceId, DeviceRecord, DeviceStatus, GatewayError, MemberRecord, Store};

pub struct PgStore {
    pool: PgPool,
}

fn store_err<E: std::fmt::Display>(e: E) -> GatewayError {
    GatewayError::Store(e.to_string())
}

fn role_to(r: Role) -> &'static str {
    match r {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "member",
    }
}

fn role_from(s: &str) -> Role {
    match s {
        "owner" => Role::Owner,
        "admin" => Role::Admin,
        _ => Role::Member,
    }
}

fn status_to(s: MembershipStatus) -> &'static str {
    match s {
        MembershipStatus::Active => "active",
        MembershipStatus::Suspended => "suspended",
        MembershipStatus::Invited => "invited",
    }
}

fn status_from(s: &str) -> MembershipStatus {
    match s {
        "active" => MembershipStatus::Active,
        "suspended" => MembershipStatus::Suspended,
        _ => MembershipStatus::Invited,
    }
}

fn sso_from(s: &str) -> SsoMode {
    if s == "required" {
        SsoMode::Required
    } else {
        SsoMode::Optional
    }
}

fn sso_to(s: SsoMode) -> &'static str {
    match s {
        SsoMode::Required => "required",
        SsoMode::Optional => "optional",
    }
}

fn device_status_to(s: DeviceStatus) -> &'static str {
    match s {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Active => "active",
        DeviceStatus::Locked => "locked",
        DeviceStatus::Wiped => "wiped",
    }
}

fn device_status_from(s: &str) -> DeviceStatus {
    match s {
        "pending" => DeviceStatus::Pending,
        "locked" => DeviceStatus::Locked,
        "wiped" => DeviceStatus::Wiped,
        _ => DeviceStatus::Active,
    }
}

fn device_record(row: &sqlx::postgres::PgRow) -> Result<DeviceRecord, GatewayError> {
    let id: uuid::Uuid = row.try_get("id").map_err(store_err)?;
    let enrolled_by: i64 = row.try_get("enrolled_by").map_err(store_err)?;
    let pubkey: Vec<u8> = row.try_get("device_pubkey").map_err(store_err)?;
    let status: String = row.try_get("status").map_err(store_err)?;
    Ok(DeviceRecord {
        id: DeviceId(id.as_u128()),
        enrolled_by: UserId(enrolled_by as u64),
        status: device_status_from(&status),
        pubkey: hex(&pubkey),
    })
}

impl PgStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect(url: &str) -> Result<Self, GatewayError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(url)
            .await
            .map_err(store_err)?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<(), GatewayError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(store_err)
    }

    pub async fn upsert_workspace(&self, ws: &Workspace) -> Result<(), GatewayError> {
        sqlx::query(
            "INSERT INTO workspace (id, allowed_domains, sso_mode) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET allowed_domains = EXCLUDED.allowed_domains, \
             sso_mode = EXCLUDED.sso_mode",
        )
        .bind(ws.id.0 as i64)
        .bind(&ws.allowed_domains)
        .bind(sso_to(ws.sso))
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    pub async fn upsert_invitation(&self, inv: &Invitation) -> Result<(), GatewayError> {
        sqlx::query(
            "INSERT INTO invitation (workspace_id, email, role, expires_at, accepted) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (workspace_id, email) DO UPDATE SET role = EXCLUDED.role, \
             expires_at = EXCLUDED.expires_at, accepted = EXCLUDED.accepted",
        )
        .bind(inv.workspace.0 as i64)
        .bind(inv.email.as_str())
        .bind(role_to(inv.role))
        .bind(inv.expires_at as i64)
        .bind(inv.accepted)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }
}

#[async_trait]
impl Store for PgStore {
    async fn workspace(&self, id: WorkspaceId) -> Result<Option<Workspace>, GatewayError> {
        let row = sqlx::query("SELECT allowed_domains, sso_mode FROM workspace WHERE id = $1")
            .bind(id.0 as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err)?;
        match row {
            None => Ok(None),
            Some(r) => {
                let allowed_domains: Vec<String> =
                    r.try_get("allowed_domains").map_err(store_err)?;
                let sso: String = r.try_get("sso_mode").map_err(store_err)?;
                Ok(Some(Workspace {
                    id,
                    allowed_domains,
                    sso: sso_from(&sso),
                }))
            }
        }
    }

    async fn upsert_user(
        &self,
        email: &EmailAddr,
        idp_user_id: &str,
    ) -> Result<UserId, GatewayError> {
        let row = sqlx::query(
            "INSERT INTO app_user (email, idp_user_id) VALUES ($1, $2) \
             ON CONFLICT (email) DO UPDATE SET idp_user_id = EXCLUDED.idp_user_id \
             RETURNING id",
        )
        .bind(email.as_str())
        .bind(idp_user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(store_err)?;
        let id: i64 = row.try_get("id").map_err(store_err)?;
        Ok(UserId(id as u64))
    }

    async fn membership(
        &self,
        workspace: WorkspaceId,
        user: UserId,
    ) -> Result<Option<Membership>, GatewayError> {
        let row = sqlx::query(
            "SELECT role, status FROM membership WHERE workspace_id = $1 AND user_id = $2",
        )
        .bind(workspace.0 as i64)
        .bind(user.0 as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        match row {
            None => Ok(None),
            Some(r) => {
                let role: String = r.try_get("role").map_err(store_err)?;
                let status: String = r.try_get("status").map_err(store_err)?;
                Ok(Some(Membership {
                    workspace,
                    user,
                    role: role_from(&role),
                    status: status_from(&status),
                }))
            }
        }
    }

    async fn put_membership(&self, m: &Membership) -> Result<(), GatewayError> {
        sqlx::query(
            "INSERT INTO membership (workspace_id, user_id, role, status) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role, status = EXCLUDED.status",
        )
        .bind(m.workspace.0 as i64)
        .bind(m.user.0 as i64)
        .bind(role_to(m.role))
        .bind(status_to(m.status))
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn invitation(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<Option<Invitation>, GatewayError> {
        let row = sqlx::query(
            "SELECT role, expires_at, accepted FROM invitation WHERE workspace_id = $1 AND email = $2",
        )
        .bind(workspace.0 as i64)
        .bind(email.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        match row {
            None => Ok(None),
            Some(r) => {
                let role: String = r.try_get("role").map_err(store_err)?;
                let expires_at: i64 = r.try_get("expires_at").map_err(store_err)?;
                let accepted: bool = r.try_get("accepted").map_err(store_err)?;
                Ok(Some(Invitation {
                    workspace,
                    email: email.clone(),
                    role: role_from(&role),
                    expires_at: expires_at as u64,
                    accepted,
                }))
            }
        }
    }

    async fn mark_invitation_accepted(
        &self,
        workspace: WorkspaceId,
        email: &EmailAddr,
    ) -> Result<(), GatewayError> {
        sqlx::query("UPDATE invitation SET accepted = TRUE WHERE workspace_id = $1 AND email = $2")
            .bind(workspace.0 as i64)
            .bind(email.as_str())
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn record_device(
        &self,
        workspace: WorkspaceId,
        enrolled_by: UserId,
        device_pubkey: &[u8; 32],
    ) -> Result<DeviceId, GatewayError> {
        let new_id = uuid::Uuid::new_v4();
        let row = sqlx::query(
            "INSERT INTO device (id, workspace_id, enrolled_by, device_pubkey, status) \
             VALUES ($1, $2, $3, $4, 'active') \
             ON CONFLICT (workspace_id, device_pubkey) \
             DO UPDATE SET status = 'active', last_seen = now() \
             RETURNING id",
        )
        .bind(new_id)
        .bind(workspace.0 as i64)
        .bind(enrolled_by.0 as i64)
        .bind(&device_pubkey[..])
        .fetch_one(&self.pool)
        .await
        .map_err(store_err)?;
        let id: uuid::Uuid = row.try_get("id").map_err(store_err)?;
        Ok(DeviceId(id.as_u128()))
    }

    async fn list_members(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<MemberRecord>, GatewayError> {
        let rows = sqlx::query(
            "SELECT m.user_id, u.email, m.role, m.status FROM membership m \
             JOIN app_user u ON u.id = m.user_id WHERE m.workspace_id = $1 ORDER BY m.user_id",
        )
        .bind(workspace.0 as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        rows.iter()
            .map(|r| {
                let user: i64 = r.try_get("user_id").map_err(store_err)?;
                let email: String = r.try_get("email").map_err(store_err)?;
                let role: String = r.try_get("role").map_err(store_err)?;
                let status: String = r.try_get("status").map_err(store_err)?;
                Ok(MemberRecord {
                    user: UserId(user as u64),
                    email,
                    role: role_from(&role),
                    status: status_from(&status),
                })
            })
            .collect()
    }

    async fn put_invitation(&self, invitation: &Invitation) -> Result<(), GatewayError> {
        self.upsert_invitation(invitation).await
    }

    async fn list_invitations(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<Invitation>, GatewayError> {
        let rows = sqlx::query(
            "SELECT email, role, expires_at, accepted FROM invitation \
             WHERE workspace_id = $1 ORDER BY email",
        )
        .bind(workspace.0 as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        rows.iter()
            .map(|r| {
                let email: String = r.try_get("email").map_err(store_err)?;
                let role: String = r.try_get("role").map_err(store_err)?;
                let expires_at: i64 = r.try_get("expires_at").map_err(store_err)?;
                let accepted: bool = r.try_get("accepted").map_err(store_err)?;
                Ok(Invitation {
                    workspace,
                    email: EmailAddr::parse(&email)
                        .ok_or_else(|| store_err("stored email is invalid"))?,
                    role: role_from(&role),
                    expires_at: expires_at as u64,
                    accepted,
                })
            })
            .collect()
    }

    async fn list_devices(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<DeviceRecord>, GatewayError> {
        let rows = sqlx::query(
            "SELECT id, enrolled_by, device_pubkey, status FROM device \
             WHERE workspace_id = $1 ORDER BY enrolled_at",
        )
        .bind(workspace.0 as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        rows.iter().map(device_record).collect()
    }

    async fn device(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
    ) -> Result<Option<DeviceRecord>, GatewayError> {
        let row = sqlx::query(
            "SELECT id, enrolled_by, device_pubkey, status FROM device \
             WHERE workspace_id = $1 AND id = $2",
        )
        .bind(workspace.0 as i64)
        .bind(uuid::Uuid::from_u128(device.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        row.as_ref().map(device_record).transpose()
    }

    async fn set_device_status(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
        status: DeviceStatus,
    ) -> Result<(), GatewayError> {
        let result = sqlx::query("UPDATE device SET status = $3 WHERE workspace_id = $1 AND id = $2")
            .bind(workspace.0 as i64)
            .bind(uuid::Uuid::from_u128(device.0))
            .bind(device_status_to(status))
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        if result.rows_affected() == 0 {
            return Err(GatewayError::NotFound(format!("device {}", device.0)));
        }
        Ok(())
    }
}
