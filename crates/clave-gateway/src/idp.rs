use std::sync::Arc;

use async_trait::async_trait;
use clave_identity::{AuthMethod, EmailAddr, WorkspaceId};
use serde::{Deserialize, Serialize};

use crate::GatewayError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedUser {
    pub email: EmailAddr,
    pub idp_user_id: String,
    pub workspace: WorkspaceId,
    pub method: AuthMethod,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuth {
    pub user_code: String,
    pub verification_uri: String,
    pub device_code: String,
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn exchange_console_code(&self, code: &str) -> Result<VerifiedUser, GatewayError>;

    async fn begin_device_auth(&self, workspace: WorkspaceId) -> Result<DeviceAuth, GatewayError>;

    async fn poll_device_auth(
        &self,
        device_code: &str,
    ) -> Result<Option<VerifiedUser>, GatewayError>;

    async fn refresh_session(&self, refresh_token: &str) -> Result<VerifiedUser, GatewayError>;
}

pub struct MockIdentityProvider {
    user: VerifiedUser,
    approved_device_code: String,
}

impl MockIdentityProvider {
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

    async fn begin_device_auth(&self, _workspace: WorkspaceId) -> Result<DeviceAuth, GatewayError> {
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

    async fn refresh_session(&self, refresh_token: &str) -> Result<VerifiedUser, GatewayError> {
        if refresh_token.is_empty() {
            return Err(GatewayError::Idp("no refresh token".into()));
        }
        Ok(self.user.clone())
    }
}

#[async_trait]
impl<T: IdentityProvider + ?Sized> IdentityProvider for Arc<T> {
    async fn exchange_console_code(&self, code: &str) -> Result<VerifiedUser, GatewayError> {
        (**self).exchange_console_code(code).await
    }
    async fn begin_device_auth(&self, workspace: WorkspaceId) -> Result<DeviceAuth, GatewayError> {
        (**self).begin_device_auth(workspace).await
    }
    async fn poll_device_auth(
        &self,
        device_code: &str,
    ) -> Result<Option<VerifiedUser>, GatewayError> {
        (**self).poll_device_auth(device_code).await
    }
    async fn refresh_session(&self, refresh_token: &str) -> Result<VerifiedUser, GatewayError> {
        (**self).refresh_session(refresh_token).await
    }
}
