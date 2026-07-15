use std::sync::Arc;

use async_trait::async_trait;
use clave_identity::{AuthMethod, EmailAddr, WorkspaceId};
use serde::Deserialize;

use crate::{DeviceAuth, GatewayError, IdentityProvider, VerifiedUser};

pub type WorkspaceResolver = Arc<dyn Fn(&str) -> Option<WorkspaceId> + Send + Sync>;

pub struct WorkosProvider {
    http: reqwest::Client,
    api_key: String,
    client_id: String,
    base_url: String,
    resolve_workspace: WorkspaceResolver,
}

fn idp_err<E: std::fmt::Display>(e: E) -> GatewayError {
    GatewayError::Idp(e.to_string())
}

fn map_method(m: Option<&str>) -> AuthMethod {
    match m {
        Some("SSO") => AuthMethod::Sso { verified: true },
        Some("Password") => AuthMethod::Password,
        Some("MagicAuth") => AuthMethod::EmailCode,
        // OAuth social logins (GoogleOAuth, MicrosoftOAuth, …) are not enterprise SSO and must
        // not satisfy a workspace's `SsoMode::Required`.
        Some(other) if other.ends_with("OAuth") => AuthMethod::Sso { verified: false },
        _ => AuthMethod::EmailCode,
    }
}

#[derive(Deserialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
    user: WorkosUser,
    organization_id: Option<String>,
    authentication_method: Option<String>,
}

#[derive(Deserialize)]
struct WorkosUser {
    id: String,
    email: String,
}

#[derive(Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
}

#[derive(Deserialize)]
struct AccessClaims {
    #[allow(dead_code)]
    sub: Option<String>,
    #[allow(dead_code)]
    exp: usize,
}

impl WorkosProvider {
    pub fn new(
        api_key: impl Into<String>,
        client_id: impl Into<String>,
        resolve_workspace: WorkspaceResolver,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: api_key.into(),
            client_id: client_id.into(),
            base_url: "https://api.workos.com".to_string(),
            resolve_workspace,
        }
    }

    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    async fn verify_access_token(&self, token: &str) -> Result<(), GatewayError> {
        use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
        use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

        let header = decode_header(token).map_err(idp_err)?;
        let kid = header
            .kid
            .ok_or_else(|| GatewayError::Idp("access token missing kid".into()))?;
        let jwks_url = format!("{}/sso/jwks/{}", self.base_url, self.client_id);
        let jwks: JwkSet = self
            .http
            .get(jwks_url)
            .send()
            .await
            .map_err(idp_err)?
            .json()
            .await
            .map_err(idp_err)?;
        let jwk = jwks
            .find(&kid)
            .ok_or_else(|| GatewayError::Idp("no JWKS key for kid".into()))?;
        let key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                DecodingKey::from_rsa_components(&rsa.n, &rsa.e).map_err(idp_err)?
            }
            _ => return Err(GatewayError::Idp("unsupported JWKS key type".into())),
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        decode::<AccessClaims>(token, &key, &validation).map_err(idp_err)?;
        Ok(())
    }

    async fn verify_and_build(&self, body: AuthResponse) -> Result<VerifiedUser, GatewayError> {
        self.verify_access_token(&body.access_token).await?;
        let email = EmailAddr::parse(&body.user.email).ok_or_else(|| {
            GatewayError::Idp("identity provider returned an invalid email".into())
        })?;
        let workspace = body
            .organization_id
            .as_deref()
            .and_then(|org| (self.resolve_workspace)(org))
            .ok_or_else(|| GatewayError::Idp("no workspace for WorkOS organization".into()))?;
        Ok(VerifiedUser {
            email,
            idp_user_id: body.user.id,
            workspace,
            method: map_method(body.authentication_method.as_deref()),
            access_token: body.access_token,
            refresh_token: body.refresh_token,
        })
    }
}

#[async_trait]
impl IdentityProvider for WorkosProvider {
    async fn exchange_console_code(&self, code: &str) -> Result<VerifiedUser, GatewayError> {
        let resp = self
            .http
            .post(format!("{}/user_management/authenticate", self.base_url))
            .json(&serde_json::json!({
                "client_id": self.client_id,
                "client_secret": self.api_key,
                "grant_type": "authorization_code",
                "code": code,
            }))
            .send()
            .await
            .map_err(idp_err)?;
        if !resp.status().is_success() {
            return Err(GatewayError::Idp(format!(
                "WorkOS authenticate failed: HTTP {}",
                resp.status()
            )));
        }
        let body: AuthResponse = resp.json().await.map_err(idp_err)?;
        self.verify_and_build(body).await
    }

    async fn begin_device_auth(&self, _workspace: WorkspaceId) -> Result<DeviceAuth, GatewayError> {
        let resp = self
            .http
            .post(format!(
                "{}/user_management/authorize/device",
                self.base_url
            ))
            .json(&serde_json::json!({ "client_id": self.client_id }))
            .send()
            .await
            .map_err(idp_err)?;
        if !resp.status().is_success() {
            return Err(GatewayError::Idp(format!(
                "WorkOS device authorize failed: HTTP {}",
                resp.status()
            )));
        }
        let body: DeviceAuthResponse = resp.json().await.map_err(idp_err)?;
        Ok(DeviceAuth {
            user_code: body.user_code,
            verification_uri: body.verification_uri,
            device_code: body.device_code,
        })
    }

    async fn poll_device_auth(
        &self,
        device_code: &str,
    ) -> Result<Option<VerifiedUser>, GatewayError> {
        let resp = self
            .http
            .post(format!("{}/user_management/authenticate", self.base_url))
            .json(&serde_json::json!({
                "client_id": self.client_id,
                "client_secret": self.api_key,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            }))
            .send()
            .await
            .map_err(idp_err)?;
        if resp.status().is_success() {
            let body: AuthResponse = resp.json().await.map_err(idp_err)?;
            return Ok(Some(self.verify_and_build(body).await?));
        }
        Ok(None)
    }

    async fn refresh_session(&self, refresh_token: &str) -> Result<VerifiedUser, GatewayError> {
        let resp = self
            .http
            .post(format!("{}/user_management/authenticate", self.base_url))
            .json(&serde_json::json!({
                "client_id": self.client_id,
                "client_secret": self.api_key,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }))
            .send()
            .await
            .map_err(idp_err)?;
        if !resp.status().is_success() {
            return Err(GatewayError::Idp(format!(
                "WorkOS refresh failed: HTTP {}",
                resp.status()
            )));
        }
        let body: AuthResponse = resp.json().await.map_err(idp_err)?;
        self.verify_and_build(body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_enterprise_sso_maps_to_verified_sso() {
        assert_eq!(map_method(Some("SSO")), AuthMethod::Sso { verified: true });
        assert_eq!(
            map_method(Some("GoogleOAuth")),
            AuthMethod::Sso { verified: false }
        );
        assert_eq!(map_method(Some("Password")), AuthMethod::Password);
        assert_eq!(map_method(Some("MagicAuth")), AuthMethod::EmailCode);
        assert_eq!(map_method(None), AuthMethod::EmailCode);
    }
}
