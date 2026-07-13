use std::io;
use std::sync::Arc;

use rustls_pemfile as pem;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub use tokio_rustls::client::TlsStream as ClientTlsStream;
pub use tokio_rustls::server::TlsStream as ServerTlsStream;

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
}

fn provider() -> Arc<tokio_rustls::rustls::crypto::CryptoProvider> {
    Arc::new(tokio_rustls::rustls::crypto::ring::default_provider())
}

pub struct Identity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<Self> {
        let certs = pem::certs(&mut &cert_pem[..]).collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(io_err("no certificate found in PEM"));
        }
        let key = pem::private_key(&mut &key_pem[..])?
            .ok_or_else(|| io_err("no private key found in PEM"))?;
        Ok(Self { certs, key })
    }
}

pub fn roots_from_pem(ca_pem: &[u8]) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let mut added = 0usize;
    for cert in pem::certs(&mut &ca_pem[..]) {
        roots.add(cert?).map_err(io_err)?;
        added += 1;
    }
    if added == 0 {
        return Err(io_err("no CA certificates found in PEM"));
    }
    Ok(roots)
}

pub fn client_config(ca_pem: &[u8], identity: Identity) -> io::Result<Arc<ClientConfig>> {
    let roots = roots_from_pem(ca_pem)?;
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(io_err)?
        .with_root_certificates(roots)
        .with_client_auth_cert(identity.certs, identity.key)
        .map_err(io_err)?;
    Ok(Arc::new(cfg))
}

pub fn server_config(client_ca_pem: &[u8], identity: Identity) -> io::Result<Arc<ServerConfig>> {
    let client_roots = Arc::new(roots_from_pem(client_ca_pem)?);
    let verifier = WebPkiClientVerifier::builder_with_provider(client_roots, provider())
        .build()
        .map_err(io_err)?;
    let cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(io_err)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.certs, identity.key)
        .map_err(io_err)?;
    Ok(Arc::new(cfg))
}

pub async fn connect<IO>(
    config: Arc<ClientConfig>,
    server_name: &str,
    io: IO,
) -> io::Result<ClientTlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(server_name.to_string()).map_err(io_err)?;
    TlsConnector::from(config).connect(name, io).await
}

pub async fn accept<IO>(config: Arc<ServerConfig>, io: IO) -> io::Result<ServerTlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    TlsAcceptor::from(config).accept(io).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{read_msg, write_msg};
    use crate::{ControlReason, GatewayCommand, GatewaySigningKey, SignedCommand, TenantId};

    fn self_signed(name: &str) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    fn a_command() -> SignedCommand {
        GatewaySigningKey::from_seed(TenantId(7), [9u8; 32]).sign(
            1,
            0,
            GatewayCommand::Lock {
                reason: ControlReason::AdminRequest,
            },
        )
    }

    #[tokio::test]
    async fn mutual_handshake_then_command_round_trips_encrypted() {
        let (gw_cert, gw_key) = self_signed("gateway.test");
        let (dev_cert, dev_key) = self_signed("device.test");

        let client_cfg =
            client_config(&gw_cert, Identity::from_pem(&dev_cert, &dev_key).unwrap()).unwrap();
        let server_cfg =
            server_config(&dev_cert, Identity::from_pem(&gw_cert, &gw_key).unwrap()).unwrap();

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        let server = tokio::spawn(async move { accept(server_cfg, server_io).await });
        let mut client = connect(client_cfg, "gateway.test", client_io)
            .await
            .unwrap();
        let mut server = server.await.unwrap().unwrap();

        let cmd = a_command();
        write_msg(&mut client, &cmd).await.unwrap();
        let got: Option<SignedCommand> = read_msg(&mut server).await.unwrap();
        assert_eq!(got, Some(cmd));
    }

    #[tokio::test]
    async fn server_rejects_a_device_whose_cert_is_not_pinned() {
        let (gw_cert, gw_key) = self_signed("gateway.test");
        let (dev_a_cert, _dev_a_key) = self_signed("device-a.test");
        let (dev_b_cert, dev_b_key) = self_signed("device-b.test");

        let client_cfg = client_config(
            &gw_cert,
            Identity::from_pem(&dev_b_cert, &dev_b_key).unwrap(),
        )
        .unwrap();
        let server_cfg =
            server_config(&dev_a_cert, Identity::from_pem(&gw_cert, &gw_key).unwrap()).unwrap();

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move { accept(server_cfg, server_io).await });
        let _ = connect(client_cfg, "gateway.test", client_io).await;
        assert!(
            server.await.unwrap().is_err(),
            "untrusted client must be rejected"
        );
    }
}
