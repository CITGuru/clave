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

pub async fn connect_gateway_link(
    addr: &str,
    server_name: &str,
    ca_pem: &[u8],
    identity: Identity,
) -> io::Result<crate::transport::ChannelGatewayLink> {
    let config = client_config(ca_pem, identity)?;
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let tls = connect(config, server_name, tcp).await?;
    let (link, ends) = crate::transport::channel_link();
    tokio::spawn(async move {
        let _ = crate::transport::pump(tls, ends).await;
    });
    Ok(link)
}

pub async fn accept_device_link<IO>(
    config: Arc<ServerConfig>,
    io: IO,
) -> io::Result<crate::transport::DeviceLink>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tls = accept(config, io).await?;
    let (link, ends) = crate::transport::device_link();
    tokio::spawn(async move {
        let _ = crate::transport::serve_device_pump(tls, ends).await;
    });
    Ok(link)
}

pub fn cert_fingerprint(der: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(der);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

pub async fn accept_device_session<IO>(
    config: Arc<ServerConfig>,
    io: IO,
) -> io::Result<(crate::transport::DeviceLink, [u8; 32])>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tls = accept(config, io).await?;
    let fingerprint = {
        let (_io, conn) = tls.get_ref();
        let leaf = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| io_err("device presented no client certificate"))?;
        cert_fingerprint(leaf.as_ref())
    };
    let (link, ends) = crate::transport::device_link();
    tokio::spawn(async move {
        let _ = crate::transport::serve_device_pump(tls, ends).await;
    });
    Ok((link, fingerprint))
}

#[cfg(feature = "ca")]
pub struct IssuedDeviceCert {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub fingerprint: [u8; 32],
}

#[cfg(feature = "ca")]
pub struct DeviceCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
    ca_pem: String,
}

#[cfg(feature = "ca")]
impl DeviceCa {
    pub fn generate() -> io::Result<Self> {
        let key = rcgen::KeyPair::generate().map_err(io_err)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(io_err)?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Clave Device CA");
        let cert = params.self_signed(&key).map_err(io_err)?;
        let ca_pem = cert.pem();
        Ok(Self { cert, key, ca_pem })
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn issue_server(&self, dns_name: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let key = rcgen::KeyPair::generate().map_err(io_err)?;
        let params = rcgen::CertificateParams::new(vec![dns_name.to_string()]).map_err(io_err)?;
        let cert = params.signed_by(&key, &self.cert, &self.key).map_err(io_err)?;
        Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
    }

    pub fn issue_device(&self, device_id: u128) -> io::Result<IssuedDeviceCert> {
        let key = rcgen::KeyPair::generate().map_err(io_err)?;
        let name = format!("device-{device_id:032x}.clave");
        let params = rcgen::CertificateParams::new(vec![name]).map_err(io_err)?;
        let cert = params.signed_by(&key, &self.cert, &self.key).map_err(io_err)?;
        let fingerprint = cert_fingerprint(cert.der().as_ref());
        Ok(IssuedDeviceCert {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
            fingerprint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{read_msg, write_msg};
    use crate::{
        ControlReason, DeviceSigningKey, GatewayCommand, GatewayLink, GatewaySigningKey,
        SignedCommand, SignedSpoolBatch, TenantId, GENESIS,
    };

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
    async fn connect_gateway_link_round_trips_over_tcp_and_mtls() {
        let (gw_cert, gw_key) = self_signed("gateway.test");
        let (dev_cert, dev_key) = self_signed("device.test");
        let server_cfg =
            server_config(&dev_cert, Identity::from_pem(&gw_cert, &gw_key).unwrap()).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let cmd = a_command();
        let server_cmd = cmd.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = accept(server_cfg, tcp).await.unwrap();
            write_msg(&mut tls, &server_cmd).await.unwrap();
            let got: Option<SignedSpoolBatch> = read_msg(&mut tls).await.unwrap();
            got
        });

        let mut link = connect_gateway_link(
            &addr,
            "gateway.test",
            &gw_cert,
            Identity::from_pem(&dev_cert, &dev_key).unwrap(),
        )
        .await
        .unwrap();

        let mut pulled = Vec::new();
        for _ in 0..1000 {
            pulled = link.poll_commands();
            if !pulled.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(pulled, vec![cmd]);

        let batch = DeviceSigningKey::from_seed([7u8; 32]).sign_batch(Vec::new(), GENESIS);
        link.push_audit(batch.clone()).unwrap();

        assert_eq!(server.await.unwrap(), Some(batch));
    }

    #[tokio::test]
    async fn device_and_gateway_exchange_audit_and_commands_over_mtls() {
        let (gw_cert, gw_key) = self_signed("gateway.test");
        let (dev_cert, dev_key) = self_signed("device.test");
        let server_cfg =
            server_config(&dev_cert, Identity::from_pem(&gw_cert, &gw_key).unwrap()).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            accept_device_link(server_cfg, tcp).await.unwrap()
        });

        let mut device = connect_gateway_link(
            &addr,
            "gateway.test",
            &gw_cert,
            Identity::from_pem(&dev_cert, &dev_key).unwrap(),
        )
        .await
        .unwrap();
        let mut gateway = server.await.unwrap();

        let batch = DeviceSigningKey::from_seed([7u8; 32]).sign_batch(Vec::new(), GENESIS);
        device.push_audit(batch.clone()).unwrap();
        assert_eq!(gateway.recv_audit().await, Some(batch));

        let cmd = a_command();
        gateway.send_command(cmd.clone()).unwrap();
        let mut pulled = Vec::new();
        for _ in 0..1000 {
            pulled = device.poll_commands();
            if !pulled.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(pulled, vec![cmd]);
    }

    #[cfg(feature = "ca")]
    #[tokio::test]
    async fn an_issued_device_cert_authenticates_and_binds_to_its_fingerprint() {
        let ca = DeviceCa::generate().unwrap();
        let (server_cert, server_key) = ca.issue_server("gateway.test").unwrap();
        let issued = ca.issue_device(0xABCD).unwrap();
        let server_cfg = server_config(
            ca.ca_pem().as_bytes(),
            Identity::from_pem(&server_cert, &server_key).unwrap(),
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            accept_device_session(server_cfg, tcp).await.unwrap()
        });

        let mut device = connect_gateway_link(
            &addr,
            "gateway.test",
            ca.ca_pem().as_bytes(),
            Identity::from_pem(&issued.cert_pem, &issued.key_pem).unwrap(),
        )
        .await
        .unwrap();
        let (mut gwlink, fingerprint) = server.await.unwrap();

        assert_eq!(
            fingerprint, issued.fingerprint,
            "the gateway binds the connection to the issued cert"
        );

        let batch = DeviceSigningKey::from_seed([7u8; 32]).sign_batch(Vec::new(), GENESIS);
        device.push_audit(batch.clone()).unwrap();
        assert_eq!(gwlink.recv_audit().await, Some(batch));
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
