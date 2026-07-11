//! The [`IdentityProvider`] seam: authentication is delegated to WorkOS, abstracted here so the
//! control plane is testable without it. The production impl calls the WorkOS REST API (AuthKit
//! code exchange, JWKS verification, the device-authorization grant); [`MockIdentityProvider`] is
//! the in-memory double.

use std::sync::Arc;

use async_trait::async_trait;
use clave_identity::{AuthMethod, EmailAddr, WorkspaceId};
use serde::{Deserialize, Serialize};

use crate::GatewayError;

/// A human the identity provider has already **authenticated** — proven, not yet authorized. The
/// gateway decides admission from this via [`clave_identity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedUser {
    pub email: EmailAddr,
    /// The provider's stable user id (e.g. WorkOS `user_..`).
    pub idp_user_id: String,
    /// Which workspace this sign-in is for (the provider's organization → our workspace).
    pub workspace: WorkspaceId,
    /// How they authenticated, so SSO-required policy can be enforced.
    pub method: AuthMethod,
    /// The short-lived access JWT WorkOS issued (verified against its JWKS by the real adapter).
    pub access_token: String,
    /// The rotating refresh token WorkOS issued; the cookie carrier seals this.
    pub refresh_token: String,
}

/// The pending state of a device-authorization grant: show `user_code` at `verification_uri`,
/// then poll with `device_code`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuth {
    pub user_code: String,
    pub verification_uri: String,
    pub device_code: String,
}

/// Authentication provider (WorkOS in production). Authorization is *not* its job — see
/// [`crate::Gateway`].
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Exchange a console auth code for the authenticated user + WorkOS session tokens.
    async fn exchange_console_code(&self, code: &str) -> Result<VerifiedUser, GatewayError>;

    /// Begin a device-authorization grant for a device enrolling into `workspace`.
    async fn begin_device_auth(&self, workspace: WorkspaceId)
        -> Result<DeviceAuth, GatewayError>;

    /// Poll a device-authorization grant. `Ok(None)` means still pending; `Ok(Some(user))` means
    /// the human completed the browser login.
    async fn poll_device_auth(&self, device_code: &str)
        -> Result<Option<VerifiedUser>, GatewayError>;
}

/// In-memory [`IdentityProvider`] double for tests/dev (mirrors `clave_proto::LoopbackLink`).
/// `exchange_console_code` returns the canned user; `poll_device_auth` reports the user once the
/// caller polls with the configured "approved" device code.
pub struct MockIdentityProvider {
    user: VerifiedUser,
    approved_device_code: String,
}

impl MockIdentityProvider {
    /// Build a mock that authenticates everyone as `user`, approving the device grant when polled
    /// with `approved_device_code`.
    pub fn new(user: VerifiedUser, approved_device_code: impl Into<String>) -> Self {
        Self {
            user,
            approved_device_code: approved_device_code.into(),
        }
    }
}

#[async_trait]
impl IdentityProvider for MockIdentityProvider {
    async fn exchange_console_code(&self, _code: &str) -> Result<VerifiedUser, GatewayError> {
        Ok(self.user.clone())
    }

    async fn begin_device_auth(
        &self,
        _workspace: WorkspaceId,
    ) -> Result<DeviceAuth, GatewayError> {
        Ok(DeviceAuth {
            user_code: "WXYZ-1234".to_string(),
            verification_uri: "https://example.test/activate".to_string(),
            device_code: self.approved_device_code.clone(),
        })
    }

    async fn poll_device_auth(
        &self,
        device_code: &str,
    ) -> Result<Option<VerifiedUser>, GatewayError> {
        if device_code == self.approved_device_code {
            Ok(Some(self.user.clone()))
        } else {
            Ok(None)
        }
    }
}

/// Delegating impl so a shared `Arc<dyn IdentityProvider>` is itself an [`IdentityProvider`] — lets
/// the Axum router hold a non-generic, type-erased gateway (see `crate::http`).
#[async_trait]
impl<T: IdentityProvider + ?Sized> IdentityProvider for Arc<T> {
    async fn exchange_console_code(&self, code: &str) -> Result<VerifiedUser, GatewayError> {
        (**self).exchange_console_code(code).await
    }
    async fn begin_device_auth(
        &self,
        workspace: WorkspaceId,
    ) -> Result<DeviceAuth, GatewayError> {
        (**self).begin_device_auth(workspace).await
    }
    async fn poll_device_auth(
        &self,
        device_code: &str,
    ) -> Result<Option<VerifiedUser>, GatewayError> {
        (**self).poll_device_auth(device_code).await
    }
}
