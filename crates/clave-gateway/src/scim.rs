use clave_identity::{EmailAddr, UserId, WorkspaceId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScimEvent {
    UserActivated { workspace: WorkspaceId, email: EmailAddr },
    UserDeactivated { workspace: WorkspaceId, email: EmailAddr },
    UserDeleted { workspace: WorkspaceId, email: EmailAddr },
}

impl ScimEvent {
    pub fn workspace(&self) -> WorkspaceId {
        match self {
            ScimEvent::UserActivated { workspace, .. }
            | ScimEvent::UserDeactivated { workspace, .. }
            | ScimEvent::UserDeleted { workspace, .. } => *workspace,
        }
    }

    pub fn email(&self) -> &EmailAddr {
        match self {
            ScimEvent::UserActivated { email, .. }
            | ScimEvent::UserDeactivated { email, .. }
            | ScimEvent::UserDeleted { email, .. } => email,
        }
    }

    pub fn activates(&self) -> bool {
        matches!(self, ScimEvent::UserActivated { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "delta", rename_all = "snake_case")]
pub enum MembershipDelta {
    Suspended { user: UserId },
    Restored { user: UserId },
    Unchanged,
}
