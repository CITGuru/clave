#![forbid(unsafe_code)]

mod audit_ingest;
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

pub use audit_ingest::{AuditLedger, IngestError};
pub use error::GatewayError;
pub use gateway::{EnrollmentCompletion, EnrollmentOutcome, Gateway};
pub use http::{build_router, AppState, DynGateway, SessionSealer, SESSION_COOKIE};
pub use idp::{DeviceAuth, IdentityProvider, MockIdentityProvider, VerifiedUser};
pub use policy::{CounterStore, FileCounter, MemCounter, MemPolicyIssuer, PolicyIssuer};
pub use session::{RequestContext, Session};
pub use store::{DeviceId, DeviceRecord, DeviceStatus, MemStore, MemberRecord, Store};
pub use volume::{MemVolumeKeyService, SealedVolumeKeyService, VolumeKeyService};

pub use clave_core::PolicyBundle;
pub use clave_proto::{
    EnrollmentGrant, GatewayCommand, GatewaySigningKey, GatewayVerifier, SignedCommand,
    SignedSpoolBatch, TenantId, WrappedVolumeKey,
};

#[cfg(feature = "postgres")]
pub use postgres::PgStore;
#[cfg(feature = "workos")]
pub use workos::{WorkosProvider, WorkspaceResolver};

pub use clave_identity::{
    AuthMethod, DenyReason, EmailAddr, Invitation, InviteError, Membership, MembershipStatus, Role,
    SsoMode, UnixTime, UserId, Workspace, WorkspaceId,
};
