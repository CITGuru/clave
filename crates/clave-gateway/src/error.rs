//! The gateway's error type. Like `clave_proto::ProtoError`, every variant is a *refusal*: the
//! request is rejected and nothing changes.

use clave_identity::{DenyReason, InviteError};

/// Why a control-plane operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    /// The authenticated human is not permitted (carries the [`clave_identity`] reason).
    Unauthorized(DenyReason),
    /// An invitation could not be accepted.
    Invite(InviteError),
    /// The identity provider (WorkOS) call failed.
    Idp(String),
    /// The backing store (Postgres) call failed.
    Store(String),
    /// The request named a workspace that does not exist.
    NoSuchWorkspace,
    /// The session is expired or otherwise invalid.
    SessionInvalid,
    /// The durable command counter could not be advanced/persisted — fail closed rather than
    /// issue a command under a counter value that a restart might reuse.
    Counter(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayError::Unauthorized(r) => write!(f, "unauthorized: {r}"),
            GatewayError::Invite(e) => write!(f, "invitation: {e}"),
            GatewayError::Idp(m) => write!(f, "identity provider error: {m}"),
            GatewayError::Store(m) => write!(f, "store error: {m}"),
            GatewayError::NoSuchWorkspace => f.write_str("no such workspace"),
            GatewayError::SessionInvalid => f.write_str("invalid or expired session"),
            GatewayError::Counter(m) => write!(f, "command counter error: {m}"),
        }
    }
}

impl std::error::Error for GatewayError {}

impl From<InviteError> for GatewayError {
    fn from(e: InviteError) -> Self {
        GatewayError::Invite(e)
    }
}
