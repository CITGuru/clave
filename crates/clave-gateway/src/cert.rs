use crate::GatewayError;

pub struct IssuedTls {
    pub ca_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub fingerprint: [u8; 32],
}

pub trait DeviceCertIssuer: Send + Sync {
    fn issue(&self, device_id: u128) -> Result<IssuedTls, GatewayError>;
    fn server_name(&self) -> &str;
    fn gateway_addr(&self) -> &str;
}

#[cfg(feature = "device-link")]
pub struct DeviceCaIssuer {
    ca: clave_proto::mtls::DeviceCa,
    ca_pem: Vec<u8>,
    server_name: String,
    gateway_addr: String,
}

#[cfg(feature = "device-link")]
impl DeviceCaIssuer {
    pub fn new(
        ca: clave_proto::mtls::DeviceCa,
        server_name: impl Into<String>,
        gateway_addr: impl Into<String>,
    ) -> Self {
        let ca_pem = ca.ca_pem().as_bytes().to_vec();
        Self {
            ca,
            ca_pem,
            server_name: server_name.into(),
            gateway_addr: gateway_addr.into(),
        }
    }

    pub fn ca_pem(&self) -> &[u8] {
        &self.ca_pem
    }

    pub fn issue_server(&self, dns_name: &str) -> Result<(Vec<u8>, Vec<u8>), GatewayError> {
        self.ca
            .issue_server(dns_name)
            .map_err(|e| GatewayError::Store(e.to_string()))
    }
}

#[cfg(feature = "device-link")]
impl DeviceCertIssuer for DeviceCaIssuer {
    fn issue(&self, device_id: u128) -> Result<IssuedTls, GatewayError> {
        let issued = self
            .ca
            .issue_device(device_id)
            .map_err(|e| GatewayError::Store(e.to_string()))?;
        Ok(IssuedTls {
            ca_pem: self.ca_pem.clone(),
            cert_pem: issued.cert_pem,
            key_pem: issued.key_pem,
            fingerprint: issued.fingerprint,
        })
    }

    fn server_name(&self) -> &str {
        &self.server_name
    }

    fn gateway_addr(&self) -> &str {
        &self.gateway_addr
    }
}
