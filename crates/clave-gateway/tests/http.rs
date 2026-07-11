//! HTTP-layer tests driven through `tower::oneshot` over the in-memory seams — no server socket,
//! no Postgres, no network. Exercises the sealed-cookie round-trip and the status-code mapping.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use clave_gateway::{
    build_router, AppState, AuthMethod, DynGateway, EmailAddr, Gateway, IdentityProvider, MemStore,
    Membership, MembershipStatus, MockIdentityProvider, Role, SessionSealer, Store, VerifiedUser,
    Workspace, WorkspaceId,
};
use tower::ServiceExt; // for `oneshot`

const WS: u64 = 100;

fn ws_id() -> WorkspaceId {
    WorkspaceId(WS)
}

fn verified(email: &str, method: AuthMethod) -> VerifiedUser {
    VerifiedUser {
        email: EmailAddr::parse(email).unwrap(),
        idp_user_id: "user_workos_1".into(),
        workspace: ws_id(),
        method,
        access_token: "access.jwt".into(),
        refresh_token: "refresh.tok".into(),
    }
}

/// Build (router, store-handle) wired to a mock IdP authenticating as `user`.
fn app(user: VerifiedUser) -> (axum::Router, Arc<MemStore>) {
    let mem = Arc::new(MemStore::new());
    mem.seed_workspace(Workspace {
        id: ws_id(),
        allowed_domains: vec![],
        sso: clave_gateway::SsoMode::Optional,
    });
    let idp: Arc<dyn IdentityProvider> = Arc::new(MockIdentityProvider::new(user, "approved-device"));
    let store: Arc<dyn Store> = mem.clone();
    let gw: DynGateway = Gateway::new(idp, store);
    let state = AppState::new(Arc::new(gw), SessionSealer::new([7u8; 32]));
    (build_router(state), mem)
}

fn active(user: u64, role: Role) -> Membership {
    Membership {
        workspace: ws_id(),
        user: clave_gateway::UserId(user),
        role,
        status: MembershipStatus::Active,
    }
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn post_json(uri: &str, json: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(json.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn login_sets_a_sealed_cookie_and_me_round_trips() {
    let (router, store) = app(verified("ceo@acme.com", AuthMethod::Password));
    store.seed_membership(active(1, Role::Admin));

    // Login.
    let resp = router
        .clone()
        .oneshot(post_json("/auth/console/callback", r#"{"code":"abc"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    // The cookie pair (everything before the first `;`) is a valid Cookie request header.
    let cookie_pair = set_cookie.split(';').next().unwrap().to_string();

    // /auth/me with the cookie resolves the identity.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/me")
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("\"role\":\"Admin\""), "body was {body}");
}

#[tokio::test]
async fn me_without_a_cookie_is_unauthorized() {
    let (router, store) = app(verified("ceo@acme.com", AuthMethod::Password));
    store.seed_membership(active(1, Role::Admin));

    let resp = router
        .oneshot(Request::builder().uri("/auth/me").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn uninvited_login_is_forbidden() {
    let (router, _store) = app(verified("stranger@evil.com", AuthMethod::Password));

    let resp = router
        .oneshot(post_json("/auth/console/callback", r#"{"code":"abc"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn suspension_forbids_the_next_request_with_the_same_cookie() {
    let (router, store) = app(verified("ceo@acme.com", AuthMethod::Password));
    store.seed_membership(active(1, Role::Admin));

    let resp = router
        .clone()
        .oneshot(post_json("/auth/console/callback", r#"{"code":"abc"}"#))
        .await
        .unwrap();
    let cookie_pair = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // SCIM suspends the member; the same cookie is now rejected.
    store.seed_membership(Membership {
        status: MembershipStatus::Suspended,
        ..active(1, Role::Admin)
    });
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/auth/me")
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn enrollment_endpoints_work_end_to_end() {
    let (router, store) = app(verified("dev@acme.com", AuthMethod::Sso { verified: true }));
    store.seed_membership(active(1, Role::Member));

    // Start: returns the device-code grant.
    let resp = router
        .clone()
        .oneshot(post_json("/enroll/start", &format!("{{\"workspace\":{WS}}}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("approved-device"), "body was {body}");

    // Poll with the approved code: enrollment is authorized.
    let resp = router
        .oneshot(post_json(
            "/enroll/poll",
            &format!("{{\"workspace\":{WS},\"device_code\":\"approved-device\"}}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("\"status\":\"approved\""), "body was {body}");
}

#[tokio::test]
async fn completing_enrollment_over_http_registers_the_device() {
    let (router, store) = app(verified("dev@acme.com", AuthMethod::Sso { verified: true }));
    store.seed_membership(active(1, Role::Member));
    let pubkey_hex = "aa".repeat(32); // 64 hex chars = 32 bytes

    let resp = router
        .clone()
        .oneshot(post_json(
            "/enroll/complete",
            &format!(
                "{{\"workspace\":{WS},\"device_code\":\"approved-device\",\"device_pubkey\":\"{pubkey_hex}\"}}"
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("\"status\":\"approved\""), "body was {body}");
    assert!(body.contains("\"device\":"), "grant must carry a device id; body was {body}");
}

#[tokio::test]
async fn completing_enrollment_rejects_a_malformed_pubkey() {
    let (router, store) = app(verified("dev@acme.com", AuthMethod::Sso { verified: true }));
    store.seed_membership(active(1, Role::Member));

    let resp = router
        .oneshot(post_json(
            "/enroll/complete",
            &format!("{{\"workspace\":{WS},\"device_code\":\"approved-device\",\"device_pubkey\":\"xyz\"}}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
