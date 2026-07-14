use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use clave_identity::{Role, UserId, WorkspaceId};
use cookie::{Cookie, SameSite};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    DeviceId, Gateway, GatewayError, IdentityProvider, IngestError, PolicyBundle, RequestContext,
    ScimEvent, Session, SignedSpoolBatch, Store,
};

pub const SESSION_COOKIE: &str = "clave_session";

const SESSION_TTL_SECS: u64 = 8 * 60 * 60;

pub type DynGateway = Gateway<Arc<dyn IdentityProvider>, Arc<dyn Store>>;

pub struct SessionSealer {
    key: [u8; 32],
}

impl SessionSealer {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key))
    }

    pub fn seal(&self, session: &Session) -> Result<String, GatewayError> {
        let plaintext =
            serde_json::to_vec(session).map_err(|e| GatewayError::Store(e.to_string()))?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher()
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|_| GatewayError::Store("seal failed".into()))?;
        let mut blob = Vec::with_capacity(nonce.len() + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(URL_SAFE_NO_PAD.encode(blob))
    }

    pub fn unseal(&self, token: &str) -> Option<Session> {
        let blob = URL_SAFE_NO_PAD.decode(token).ok()?;
        if blob.len() < 12 {
            return None;
        }
        let (nonce, ct) = blob.split_at(12);
        let pt = self.cipher().decrypt(Nonce::from_slice(nonce), ct).ok()?;
        serde_json::from_slice(&pt).ok()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub gateway: Arc<DynGateway>,
    pub sealer: Arc<SessionSealer>,
    pub scim_token: Option<Arc<String>>,
}

impl AppState {
    pub fn new(gateway: Arc<DynGateway>, sealer: SessionSealer) -> Self {
        Self {
            gateway,
            sealer: Arc::new(sealer),
            scim_token: None,
        }
    }

    pub fn with_scim_token(mut self, token: impl Into<String>) -> Self {
        self.scim_token = Some(Arc::new(token.into()));
        self
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/auth/console/callback", post(console_callback))
        .route("/auth/me", get(auth_me))
        .route("/auth/logout", post(logout))
        .route("/enroll/start", post(enroll_start))
        .route("/enroll/poll", post(enroll_poll))
        .route("/enroll/complete", post(enroll_complete))
        .route("/admin/members", get(admin_list_members))
        .route("/admin/members/invite", post(admin_invite))
        .route("/admin/members/role", post(admin_change_role))
        .route("/admin/members/suspend", post(admin_suspend))
        .route("/admin/members/restore", post(admin_restore))
        .route("/admin/invitations", get(admin_list_invitations))
        .route("/admin/devices", get(admin_list_devices))
        .route("/admin/devices/lock", post(admin_lock_device))
        .route("/admin/devices/wipe", post(admin_wipe_device))
        .route("/admin/policy", get(admin_get_policy).post(admin_author_policy))
        .route("/admin/policy/versions", get(admin_policy_versions))
        .route("/admin/policy/reissue", post(admin_reissue_policy))
        .route("/admin/audit", get(admin_audit_events))
        .route("/admin/audit/alerts", get(admin_audit_alerts))
        .route("/audit/ingest", post(audit_ingest))
        .route("/scim/events", post(scim_events))
        .with_state(state)
}

fn scim_authorized(st: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = &st.scim_token else {
        return false;
    };
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|token| token == expected.as_str())
}

async fn scim_events(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<ScimEvent>,
) -> Response {
    if !scim_authorized(&st, &headers) {
        return (StatusCode::UNAUTHORIZED, "invalid or missing SCIM token").into_response();
    }
    match st.gateway.apply_directory_event(event).await {
        Ok(delta) => Json(delta).into_response(),
        Err(e) => err_response(e),
    }
}

#[derive(Deserialize)]
struct AuditIngestBody {
    device: String,
    batch: SignedSpoolBatch,
}

#[derive(Serialize)]
struct Admitted {
    admitted: usize,
}

fn audit_err_response(e: IngestError) -> Response {
    let code = match &e {
        IngestError::UnknownDevice(_) => StatusCode::NOT_FOUND,
        IngestError::Rejected(_) => StatusCode::CONFLICT,
    };
    (code, e.to_string()).into_response()
}

async fn audit_ingest(State(st): State<AppState>, Json(body): Json<AuditIngestBody>) -> Response {
    let Ok(id) = body.device.parse::<u128>() else {
        return (StatusCode::BAD_REQUEST, "device must be a decimal u128").into_response();
    };
    match st.gateway.ingest_device_audit(DeviceId(id), &body.batch) {
        Ok(events) => Json(Admitted {
            admitted: events.len(),
        })
        .into_response(),
        Err(e) => audit_err_response(e),
    }
}

async fn admin_audit_events(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.audit_events(&ctx).await {
        Ok(events) => Json(events).into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_audit_alerts(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.audit_alerts(&ctx).await {
        Ok(alerts) => Json(alerts).into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_ctx(st: &AppState, headers: &HeaderMap) -> Result<RequestContext, Response> {
    let session = read_session(headers, &st.sealer)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "no session").into_response())?;
    st.gateway
        .authorize_request(&session, now())
        .await
        .map_err(err_response)
}

#[derive(Deserialize)]
struct InviteBody {
    email: String,
    role: Role,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct UserBody {
    user: u64,
}

#[derive(Deserialize)]
struct RoleBody {
    user: u64,
    role: Role,
}

#[derive(Deserialize)]
struct DeviceBody {
    device: String,
}

async fn admin_list_members(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.list_members(&ctx).await {
        Ok(members) => Json(members).into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_invite(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<InviteBody>,
) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let expires_at = body.expires_at.unwrap_or_else(|| now() + 7 * 24 * 3600);
    match st
        .gateway
        .invite_member(&ctx, &body.email, body.role, expires_at)
        .await
    {
        Ok(inv) => Json(inv).into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_change_role(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RoleBody>,
) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.change_role(&ctx, UserId(body.user), body.role).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_suspend(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UserBody>,
) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.suspend_member(&ctx, UserId(body.user)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_restore(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UserBody>,
) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.restore_member(&ctx, UserId(body.user)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_list_invitations(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.list_invitations(&ctx).await {
        Ok(invites) => Json(invites).into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_list_devices(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.list_devices(&ctx).await {
        Ok(devices) => Json(devices).into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_lock_device(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeviceBody>,
) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(id) = body.device.parse::<u128>() else {
        return (StatusCode::BAD_REQUEST, "device must be a decimal u128").into_response();
    };
    match st.gateway.lock_device(&ctx, DeviceId(id)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_wipe_device(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeviceBody>,
) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(id) = body.device.parse::<u128>() else {
        return (StatusCode::BAD_REQUEST, "device must be a decimal u128").into_response();
    };
    match st.gateway.wipe_device(&ctx, DeviceId(id)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_get_policy(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.get_policy(&ctx).await {
        Ok(policy) => Json(policy).into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_author_policy(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(bundle): Json<PolicyBundle>,
) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.author_policy(&ctx, bundle).await {
        Ok(new) => Json(new).into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_policy_versions(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.policy_versions(&ctx).await {
        Ok(versions) => Json(versions).into_response(),
        Err(e) => err_response(e),
    }
}

async fn admin_reissue_policy(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = match admin_ctx(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match st.gateway.reissue_policy(&ctx, now()).await {
        Ok(signed) => Json(signed).into_response(),
        Err(e) => err_response(e),
    }
}

#[derive(Deserialize)]
struct ConsoleCallback {
    code: String,
}

#[derive(Serialize)]
struct SessionInfo {
    workspace: u64,
    role: Role,
}

#[derive(Serialize)]
struct MeResponse {
    user: u64,
    workspace: u64,
    role: Role,
}

#[derive(Deserialize)]
struct EnrollStart {
    workspace: u64,
}

#[derive(Deserialize)]
struct EnrollPoll {
    workspace: u64,
    device_code: String,
}

#[derive(Deserialize)]
struct EnrollComplete {
    workspace: u64,
    device_code: String,
    device_pubkey: String,
    device_wrapping_key: Option<String>,
}

async fn console_callback(
    State(st): State<AppState>,
    Json(body): Json<ConsoleCallback>,
) -> Response {
    match st
        .gateway
        .console_login(&body.code, now(), SESSION_TTL_SECS)
        .await
    {
        Ok(session) => {
            let cookie = match st.sealer.seal(&session) {
                Ok(c) => c,
                Err(e) => return err_response(e),
            };
            let info = SessionInfo {
                workspace: session.workspace.0,
                role: session.role,
            };
            with_cookie(Json(info).into_response(), &set_cookie(&cookie))
        }
        Err(e) => err_response(e),
    }
}

async fn auth_me(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = read_session(&headers, &st.sealer) else {
        return (StatusCode::UNAUTHORIZED, "no session").into_response();
    };
    match st.gateway.authorize_request(&session, now()).await {
        Ok(ctx) => Json(MeResponse {
            user: ctx.user.0,
            workspace: ctx.workspace.0,
            role: ctx.role,
        })
        .into_response(),
        Err(e) => err_response(e),
    }
}

async fn logout() -> Response {
    with_cookie(StatusCode::NO_CONTENT.into_response(), &clear_cookie())
}

async fn enroll_start(State(st): State<AppState>, Json(body): Json<EnrollStart>) -> Response {
    match st
        .gateway
        .begin_enrollment(WorkspaceId(body.workspace))
        .await
    {
        Ok(device_auth) => Json(device_auth).into_response(),
        Err(e) => err_response(e),
    }
}

async fn enroll_poll(State(st): State<AppState>, Json(body): Json<EnrollPoll>) -> Response {
    match st
        .gateway
        .poll_enrollment(WorkspaceId(body.workspace), &body.device_code)
        .await
    {
        Ok(outcome) => Json(outcome).into_response(),
        Err(e) => err_response(e),
    }
}

async fn enroll_complete(State(st): State<AppState>, Json(body): Json<EnrollComplete>) -> Response {
    let Some(pubkey) = parse_pubkey(&body.device_pubkey) else {
        return (
            StatusCode::BAD_REQUEST,
            "device_pubkey must be 64 hex chars (32 bytes)",
        )
            .into_response();
    };
    let wrapping_key = match body.device_wrapping_key.as_deref().map(parse_pubkey) {
        None => None,
        Some(Some(k)) => Some(k),
        Some(None) => {
            return (
                StatusCode::BAD_REQUEST,
                "device_wrapping_key must be 64 hex chars (32 bytes)",
            )
                .into_response()
        }
    };
    match st
        .gateway
        .complete_enrollment(
            WorkspaceId(body.workspace),
            &body.device_code,
            &pubkey,
            wrapping_key.as_ref(),
            now(),
        )
        .await
    {
        Ok(outcome) => Json(outcome).into_response(),
        Err(e) => err_response(e),
    }
}

fn parse_pubkey(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn err_response(e: GatewayError) -> Response {
    let code = match &e {
        GatewayError::Unauthorized(_) | GatewayError::Invite(_) | GatewayError::Forbidden(_) => {
            StatusCode::FORBIDDEN
        }
        GatewayError::SessionInvalid => StatusCode::UNAUTHORIZED,
        GatewayError::NoSuchWorkspace | GatewayError::NotFound(_) => StatusCode::NOT_FOUND,
        GatewayError::Idp(_) => StatusCode::BAD_GATEWAY,
        GatewayError::Store(_) | GatewayError::Counter(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, e.to_string()).into_response()
}

fn set_cookie(value: &str) -> String {
    Cookie::build((SESSION_COOKIE, value.to_owned()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .build()
        .to_string()
}

fn clear_cookie() -> String {
    Cookie::build((SESSION_COOKIE, ""))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(0))
        .build()
        .to_string()
}

fn with_cookie(mut resp: Response, set_cookie_value: &str) -> Response {
    if let Ok(v) = HeaderValue::from_str(set_cookie_value) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

fn read_session(headers: &HeaderMap, sealer: &SessionSealer) -> Option<Session> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    Cookie::split_parse(raw)
        .flatten()
        .find(|c| c.name() == SESSION_COOKIE)
        .and_then(|c| sealer.unseal(c.value()))
}
