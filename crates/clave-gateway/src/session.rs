use clave_identity::{Role, UnixTime, UserId, WorkspaceId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub user: UserId,
    pub workspace: WorkspaceId,
    pub role: Role,
    pub expires_at: UnixTime,
    pub refresh_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestContext {
    pub user: UserId,
    pub workspace: WorkspaceId,
    pub role: Role,
}
