//! # clave-identity — the control-plane identity brain
//!
//! Portable, **`#![forbid(unsafe_code)]`**, **no-I/O** authorization logic for Clave's gateway:
//! *who may sign in to the admin console, accept a workspace invitation, or enroll a device.*
//! It is to human identity what [`clave_core::decide`](https://docs.rs/) is to runtime
//! policy — a pure, deterministic, **fail-closed** function that the database-backed gateway
//! ([`clave-gateway`]) calls after hydrating rows into the value types here.
//!
//! ## The one principle
//!
//! Human identity gates **enrollment** and **console access**; it is **never** a *runtime* trust
//! anchor. The device's posture stays rooted in the pinned tenant key + hardware device key +
//! signed policy bundle (`clave-proto`). So everything in this crate decides
//! *admission*, not device authority — a stolen session can open a console, never change a device.
//!
//! ## Guarantees (pinned by proptest)
//!
//! * **Invited-only** — a non-member is never admitted, for any email / method / workspace.
//! * **Fail-closed** — suspended members, expired invitations, unmet SSO/domain policy ⇒ the
//!   restrictive outcome (deny / `Err`), never a silent allow.
//! * **Normalized matching** — email and domain comparison is case- and whitespace-insensitive.
//! * **Monotonic roles** — `Owner ⊇ Admin ⊇ Member` for every [`AdminAction`].
//!
//! ## Mapping to the rest of the workspace
//!
//! A [`Workspace`] *is* a tenant: [`WorkspaceId`]`.0` is the value the gateway uses as
//! `clave_proto::TenantId` when it issues a policy bundle to an enrolled device. This crate keeps
//! its own light id newtypes (serde only) so the portable identity core never pulls the crypto
//! stack — exactly how `clave-proto` defines its own `TenantId`.
#![forbid(unsafe_code)]

mod authz;
mod model;

pub use authz::{
    accept_invitation, authorize_enrollment, authorize_login, can, min_role, AdminAction,
    DenyReason, EnrollmentDecision, InviteError, LoginDecision,
};
pub use model::{
    AuthMethod, Invitation, Membership, MembershipStatus, Role, SsoMode, Workspace,
};

use serde::{Deserialize, Serialize};

/// Seconds since the Unix epoch — same convention as `clave_core::UnixTime`, re-declared here so
/// the identity core needs no dependency on `clave-core`.
pub type UnixTime = u64;

/// A workspace == one tenant/customer org. `WorkspaceId.0` is the value used as the proto-layer
/// `clave_proto::TenantId` when the gateway issues a policy bundle to an enrolled device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId(pub u64);

/// A person (an `app_user` row). One human, potentially a member of several workspaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub u64);

/// A normalized email address: trimmed and lower-cased so membership and domain checks are
/// case- and whitespace-insensitive. Construct with [`EmailAddr::parse`]; this is *not* a full
/// RFC 5322 validator, just a normalizer with enough structure to extract a [domain](Self::domain).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmailAddr(String);

impl EmailAddr {
    /// Normalize and lightly validate `raw`. Returns `None` unless it has exactly one `@` with a
    /// non-empty local part and a dotted, whitespace-free domain.
    pub fn parse(raw: &str) -> Option<EmailAddr> {
        let s = raw.trim().to_ascii_lowercase();
        if s.contains(char::is_whitespace) {
            return None;
        }
        let (local, domain) = s.split_once('@')?;
        if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
            return None;
        }
        Some(EmailAddr(s))
    }

    /// The full normalized address.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The domain part (everything after the `@`). Always non-empty for a value built by
    /// [`parse`](Self::parse).
    pub fn domain(&self) -> &str {
        self.0.split_once('@').map(|(_, d)| d).unwrap_or("")
    }
}

impl std::fmt::Display for EmailAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
