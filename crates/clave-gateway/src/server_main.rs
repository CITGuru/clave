//! The production gateway binary: wires Postgres + WorkOS behind the seams and serves the router.
//! Built only with `--features server`; configured entirely via environment variables.

use std::sync::Arc;

use clave_gateway::{
    build_router, AppState, DynGateway, FileCounter, Gateway, GatewaySigningKey, IdentityProvider,
    MemPolicyIssuer, PgStore, PolicyBundle, SealedVolumeKeyService, SessionSealer, Store, TenantId,
    WorkosProvider, WorkspaceId,
};
use clave_volume::{ContainerId, DEK_LEN};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let workos_api_key = std::env::var("WORKOS_API_KEY")?;
    let workos_client_id = std::env::var("WORKOS_CLIENT_ID")?;
    let session_key = std::env::var("SESSION_KEY")?; // 64 hex chars = 32 bytes
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let store = PgStore::connect(&database_url).await?;
    store.migrate().await?;

    // Resolve a WorkOS organization id → our WorkspaceId. Single-tenant env mapping here keeps the
    // skeleton runnable; production swaps in a DB lookup over `workspace.workos_org_id`.
    let org = std::env::var("WORKOS_ORG_ID").unwrap_or_default();
    let workspace_id: u64 = std::env::var("WORKSPACE_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let resolve: clave_gateway::WorkspaceResolver = Arc::new(move |o: &str| {
        if !org.is_empty() && o == org {
            Some(WorkspaceId(workspace_id))
        } else {
            None
        }
    });

    let idp: Arc<dyn IdentityProvider> =
        Arc::new(WorkosProvider::new(workos_api_key, workos_client_id, resolve));
    let store: Arc<dyn Store> = Arc::new(store);
    let mut gateway: DynGateway = Gateway::new(idp, store);

    // Optional: if a tenant signing seed is configured, enrolled devices receive a signed initial
    // policy bundle. The seed is the 32-byte Ed25519 secret seed as 64 hex chars
    // — in production released from the HSM, never an env var; the device pins the matching public
    // key. The bootstrap issues a restrictive-default bundle for the single configured workspace.
    if let Some(seed) = std::env::var("GATEWAY_SIGNING_SEED").ok().and_then(|s| parse_key(&s)) {
        // The per-tenant command counter MUST be durable: a restart that rewound it to 0 would
        // reissue commands under counters a device has already pinned, and the device would reject
        // every one as a replay. A file-backed counter is the portable durable store;
        // production swaps in a DB sequence / HSM monotonic counter. Path is configurable so it can
        // live on persistent storage; defaults next to the working directory.
        let counter_path = std::env::var("GATEWAY_COUNTER_PATH")
            .unwrap_or_else(|_| format!("clave-gateway-counter-{workspace_id}"));
        let issuer = MemPolicyIssuer::with_counter(
            GatewaySigningKey::from_seed(TenantId(workspace_id), seed),
            Box::new(FileCounter::new(counter_path)),
        );
        issuer.set_policy(WorkspaceId(workspace_id), PolicyBundle::restrictive_default());
        gateway = gateway.with_policy_issuer(Arc::new(issuer));
        println!("policy issuer enabled for workspace {workspace_id}");
    }

    // Optional: if the workspace's Clave Disk DEK is configured, a device that submits its X25519
    // sealing **public** key at enrollment receives its DEK sealed to it — the production
    // asymmetric path, so the gateway holds nothing that can open it. The
    // DEK is the 64-byte XTS key as 128 hex chars; in production it lives in the KMS, never an env var.
    if let Some(dek) = std::env::var("GATEWAY_VOLUME_DEK").ok().and_then(|s| parse_dek(&s)) {
        let svc = SealedVolumeKeyService::new();
        svc.set_container(
            WorkspaceId(workspace_id),
            ContainerId(workspace_id as u128),
            dek,
        );
        gateway = gateway.with_volume_key_service(Arc::new(svc));
        println!("sealed volume-key service enabled for workspace {workspace_id}");
    }

    let key = parse_key(&session_key).ok_or("SESSION_KEY must be 64 hex chars (32 bytes)")?;
    let state = AppState::new(Arc::new(gateway), SessionSealer::new(key));
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("clave-gateway listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn parse_key(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Parse the 64-byte XTS DEK from 128 hex chars.
fn parse_dek(s: &str) -> Option<[u8; DEK_LEN]> {
    if s.len() != DEK_LEN * 2 {
        return None;
    }
    let mut out = [0u8; DEK_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
