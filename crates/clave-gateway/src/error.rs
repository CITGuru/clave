use clave_identity::{DenyReason, InviteError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    Unauthorized(DenyReason),
    Invite(InviteError),
    Idp(String),
    Store(String),
    NoSuchWorkspace,
    SessionInvalid,
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
