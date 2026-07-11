//! What a logged-in console session carries, and the per-request identity it resolves to.
//!
//! In the sealed-cookie model a [`Session`] is what gets encrypted into the
//! httpOnly cookie; there is no server-side session table. The HTTP layer unseals the cookie into
//! a [`Session`] and calls [`crate::Gateway::authorize_request`] to turn it into a
//! [`RequestContext`] — re-validating membership every time.

use clave_identity::{Role, UnixTime, UserId, WorkspaceId};
use serde::{Deserialize, Serialize};

/// The session minted on a successful console login. Sealed into the cookie; carries WorkOS's
/// refresh token so the access JWT can be rotated without a fresh login.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub user: UserId,
    pub workspace: WorkspaceId,
    /// Role captured at login — advisory only; [`crate::Gateway::authorize_request`] re-reads the
    /// authoritative role from the store on every request.
    pub role: Role,
    /// Absolute expiry (seconds since epoch). Past this the session is invalid regardless of the
    /// WorkOS token state.
    pub expires_at: UnixTime,
    /// The WorkOS refresh token (opaque here; the cookie carrier seals it).
    pub refresh_token: String,
}

/// The authenticated, authorized identity attached to a request after [`Session`] validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestContext {
    pub user: UserId,
    pub workspace: WorkspaceId,
    /// The current authoritative role (freshly read from the store, not the cookie).
    pub role: Role,
}
