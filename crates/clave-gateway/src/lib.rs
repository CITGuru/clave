#![forbid(unsafe_code)]

mod audit_ingest;
mod cert;
mod error;
mod gateway;
mod http;
mod idp;
mod policy;
mod scim;
mod session;
mod store;
mod volume;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "workos")]
mod workos;
#[cfg(feature = "device-link")]
mod device_link;

#[cfg(feature = "device-link")]
pub use device_link::serve_device_audit;

pub use cert::{DeviceCertIssuer, IssuedTls};
#[cfg(feature = "device-link")]
pub use cert::DeviceCaIssuer;

pub use audit_ingest::{
    AuditAlert, AuditLedger, AuditRecord, AuditStore, IngestError, MemAuditStore, PersistedChain,
};
pub use error::GatewayError;
pub use gateway::{EnrollmentCompletion, EnrollmentOutcome, Gateway};
pub use http::{build_router, AppState, DynGateway, SessionSealer, SESSION_COOKIE};
pub use idp::{DeviceAuth, IdentityProvider, MockIdentityProvider, VerifiedUser};
pub use policy::{CounterStore, FileCounter, MemCounter, MemPolicyIssuer, PolicyIssuer};
pub use scim::{MembershipDelta, ScimEvent};
pub use session::{RequestContext, Session};
pub use store::{DeviceId, DeviceRecord, DeviceStatus, MemStore, MemberRecord, Store};
pub use volume::{MemVolumeKeyService, SealedVolumeKeyService, VolumeKeyService};

pub use clave_core::PolicyBundle;
pub use clave_proto::{
    EnrollmentGrant, GatewayCommand, GatewaySigningKey, GatewayVerifier, SignedCommand,
    SignedSpoolBatch, TenantId, WrappedVolumeKey,
};

#[cfg(feature = "postgres")]
pub use postgres::{PgAuditStore, PgStore};
#[cfg(feature = "workos")]
pub use workos::{WorkosProvider, WorkspaceResolver};

pub use clave_identity::{
    AuthMethod, DenyReason, EmailAddr, Invitation, InviteError, Membership, MembershipStatus, Role,
    SsoMode, UnixTime, UserId, Workspace, WorkspaceId,
};
