//! # clave-gateway — the control-plane gateway
//!
//! The cloud service that fronts Clave's identity layer: it logs admins into the console, runs
//! the device-enrollment handshake, and authorizes every request — all by delegating the actual
//! *admission* decisions to the pure [`clave_identity`] core and the *authentication* to an
//! [`IdentityProvider`] (WorkOS in production).
//!
//! This crate is the **portable orchestration core**, built the way the rest of the workspace is:
//! every side effect is a **seam** ([`IdentityProvider`], [`Store`]) with an in-memory double
//! ([`MockIdentityProvider`], [`MemStore`]) so the whole control plane is testable on any machine
//! with no Postgres and no network — mirroring `clave_proto::GatewayLink` / `LoopbackLink`. The
//! Axum HTTP layer and the real sqlx/WorkOS adapters bolt onto these seams.
//!
//! ## The session model it encodes
//!
//! WorkOS owns **authentication** and the **token lifecycle** (a short access JWT + a refresh
//! token); this gateway owns **authorization** and the **session carrier**:
//!
//! * [`Gateway::console_login`] exchanges the WorkOS code, accepts a pending invitation if needed,
//!   then runs [`clave_identity::authorize_login`] against *our* membership (the source of truth) —
//!   only then minting the [`Session`] whose WorkOS refresh token the cookie will seal.
//! * [`Gateway::authorize_request`] re-checks **active membership on every request**, so a
//!   SCIM-suspended user is locked out immediately, not just at the next token refresh.
#![forbid(unsafe_code)]

mod error;
mod gateway;
mod http;
mod idp;
mod policy;
mod session;
mod store;
mod volume;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "workos")]
mod workos;

pub use error::GatewayError;
pub use gateway::{EnrollmentCompletion, EnrollmentOutcome, Gateway};
pub use http::{build_router, AppState, DynGateway, SessionSealer, SESSION_COOKIE};
pub use idp::{DeviceAuth, IdentityProvider, MockIdentityProvider, VerifiedUser};
pub use policy::{CounterStore, FileCounter, MemCounter, MemPolicyIssuer, PolicyIssuer};
pub use session::{RequestContext, Session};
pub use store::{DeviceId, MemStore, Store};
pub use volume::{MemVolumeKeyService, SealedVolumeKeyService, VolumeKeyService};

// Re-export the signed-control-plane + enrollment-grant vocabulary the issuer/enrollment surface
// deals in, so call sites (and the device's verifier in tests) need not also depend on
// `clave-proto` / `clave-core`.
pub use clave_core::PolicyBundle;
pub use clave_proto::{
    EnrollmentGrant, GatewayCommand, GatewaySigningKey, GatewayVerifier, SignedCommand, TenantId,
    WrappedVolumeKey,
};

#[cfg(feature = "postgres")]
pub use postgres::PgStore;
#[cfg(feature = "workos")]
pub use workos::{WorkosProvider, WorkspaceResolver};

// Re-export the identity vocabulary so call sites need not also depend on `clave-identity`.
pub use clave_identity::{
    AuthMethod, DenyReason, EmailAddr, Invitation, InviteError, Membership, MembershipStatus, Role,
    SsoMode, UnixTime, UserId, Workspace, WorkspaceId,
};
