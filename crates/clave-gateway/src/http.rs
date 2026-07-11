//! The Axum HTTP edge. It is a thin shell over [`crate::Gateway`]: parse the
//! request, call the orchestration, map the outcome to a status code, and carry the session in a
//! **sealed cookie**. All policy lives in `clave-identity`; all state behind the [`Store`] seam.
//!
//! The router is **type-erased** ([`DynGateway`]) so handlers are non-generic and the same binary
//! serves whatever `IdentityProvider`/`Store` it was built with (mock in tests, WorkOS + Postgres
//! in production).

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
use clave_identity::{Role, WorkspaceId};
use cookie::{Cookie, SameSite};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{Gateway, GatewayError, IdentityProvider, Session, Store};

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "clave_session";

/// How long a console session is valid before a fresh login is required (8 hours).
const SESSION_TTL_SECS: u64 = 8 * 60 * 60;

/// A type-erased gateway: the concrete `IdentityProvider`/`Store` are chosen at construction, so
/// the HTTP layer compiles once regardless of which adapters are wired in.
pub type DynGateway = Gateway<Arc<dyn IdentityProvider>, Arc<dyn Store>>;

/// Encrypts/decrypts the session blob carried in the cookie (the sealed-cookie
/// carrier). ChaCha20-Poly1305 AEAD under a 32-byte server key, with a fresh random nonce.
pub struct SessionSealer {
    key: [u8; 32],
}

impl SessionSealer {
    /// Build a sealer from a 32-byte secret key (rotate by re-keying; old cookies then fail to
    /// unseal and the user re-logs in).
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key))
    }

    /// Seal a session into an opaque, URL-safe cookie value.
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

    /// Recover a session from a cookie value. Any tampering or wrong key yields `None` (fail-closed).
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

/// Shared application state handed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub gateway: Arc<DynGateway>,
    pub sealer: Arc<SessionSealer>,
}

impl AppState {
    /// Assemble the state from a (type-erased) gateway and a session sealer.
    pub fn new(gateway: Arc<DynGateway>, sealer: SessionSealer) -> Self {
        Self {
            gateway,
            sealer: Arc::new(sealer),
        }
    }
}

/// The control-plane router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/auth/console/callback", post(console_callback))
        .route("/auth/me", get(auth_me))
        .route("/auth/logout", post(logout))
        .route("/enroll/start", post(enroll_start))
        .route("/enroll/poll", post(enroll_poll))
        .route("/enroll/complete", post(enroll_complete))
        .with_state(state)
}

#[derive(Deserialize)]
struct ConsoleCallback {
    /// The WorkOS authorization code from the AuthKit redirect.
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
    /// The device's Ed25519 public key (the runtime trust anchor), hex-encoded — 64 hex chars.
    device_pubkey: String,
    /// Optional: the device's volume wrapping key (hardware KEK), hex-encoded — 64 hex chars. When
    /// present and a volume-key service is configured, the response carries the wrapped volume key.
    device_wrapping_key: Option<String>,
}

async fn console_callback(State(st): State<AppState>, Json(body): Json<ConsoleCallback>) -> Response {
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
    match st.gateway.begin_enrollment(WorkspaceId(body.workspace)).await {
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
        return (StatusCode::BAD_REQUEST, "device_pubkey must be 64 hex chars (32 bytes)")
            .into_response();
    };
    // The wrapping key is optional, but if present it must be well-formed.
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

/// Parse a 64-char hex string into a 32-byte Ed25519 public key. `None` on any malformed input.
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

/// Map a [`GatewayError`] to an HTTP status: refusals are 4xx, infra faults 5xx.
fn err_response(e: GatewayError) -> Response {
    let code = match &e {
        GatewayError::Unauthorized(_) | GatewayError::Invite(_) => StatusCode::FORBIDDEN,
        GatewayError::SessionInvalid => StatusCode::UNAUTHORIZED,
        GatewayError::NoSuchWorkspace => StatusCode::NOT_FOUND,
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
