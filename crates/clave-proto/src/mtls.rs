//! Production **mutual-TLS** link (`mtls` feature): the rustls connector/acceptor that produces the
//! authenticated byte stream [`transport::pump`](crate::transport::pump) runs over.
//!
//! The signed-command layer ([`SignedCommand`](crate::SignedCommand)) already guarantees that only
//! the pinned tenant key can change a device's posture, so the channel itself is *not* the trust
//! anchor. mTLS adds the complementary transport guarantees the daemon still wants: it
//! authenticates the **gateway endpoint** (so a device only ships its audit spool to the real
//! gateway), proves the **device's** identity to the gateway, and encrypts the link so a passive
//! observer learns nothing.
//!
//! Both sides present a certificate and verify the peer's against pinned roots (a private per-tenant
//! CA — not the public Web PKI). The resulting `TlsStream` is `AsyncRead + AsyncWrite`, so it drops
//! straight into [`pump`](crate::transport::pump):
//!
//! ```ignore
//! // device side
//! let cfg = mtls::client_config(&ca_pem, mtls::Identity::from_pem(&dev_cert, &dev_key)?)?;
//! let tls = mtls::connect(cfg, "gw.tenant.clave.example", tcp).await?;
//! let (link, ends) = transport::channel_link();
//! tokio::spawn(transport::pump(tls, ends));   // link now drives GatewaySync unchanged
//! ```
//!
//! The crypto provider is pinned to **ring** to match the rest of the workspace (reqwest's rustls in
//! `clave-gateway`), so the build never pulls a second provider.

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

/// The `ring` crypto provider, used for every config built here so the link never depends on a
/// process-wide default provider being installed.
fn provider() -> Arc<tokio_rustls::rustls::crypto::CryptoProvider> {
    Arc::new(tokio_rustls::rustls::crypto::ring::default_provider())
}

/// A leaf certificate chain plus its private key — one endpoint's TLS identity, loaded from the
/// PEM the deploy keystore (TPM / Secure Enclave-wrapped on the device; HSM on the gateway) hands
/// out. Consumed when a config is built.
pub struct Identity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    /// Parse an identity from a PEM certificate chain and a PEM private key (PKCS#8/PKCS#1/SEC1).
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

/// Parse one or more PEM CA certificates into a root store (the pinned per-tenant roots).
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

/// Build the **device-side** client config: trust `roots` for the gateway's certificate and present
/// `identity` as the device's client certificate (mutual auth).
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

/// Build the **gateway-side** server config: present `identity` as the gateway certificate and
/// **require** a client certificate that verifies against `client_ca_pem` (mutual auth — an
/// unauthenticated device cannot complete the handshake).
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

/// Device side: TLS-connect to the gateway over an established byte stream (e.g. a `TcpStream`),
/// verifying the gateway certificate's name against `server_name`. The returned stream feeds
/// straight into [`pump`](crate::transport::pump).
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

/// Gateway side: accept a device's TLS connection over an established byte stream, requiring and
/// verifying its client certificate. The returned stream feeds straight into
/// [`pump`](crate::transport::pump).
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

    /// A throwaway self-signed identity (PEM cert, PEM key) for one endpoint. Self-signed, so the
    /// same cert is both the leaf the peer presents and the root the other side pins.
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
        // Each side gets its own self-signed identity; each pins the other's cert as its root.
        let (gw_cert, gw_key) = self_signed("gateway.test");
        let (dev_cert, dev_key) = self_signed("device.test");

        let client_cfg =
            client_config(&gw_cert, Identity::from_pem(&dev_cert, &dev_key).unwrap()).unwrap();
        let server_cfg =
            server_config(&dev_cert, Identity::from_pem(&gw_cert, &gw_key).unwrap()).unwrap();

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        // Drive both handshakes concurrently.
        let server = tokio::spawn(async move { accept(server_cfg, server_io).await });
        let mut client = connect(client_cfg, "gateway.test", client_io).await.unwrap();
        let mut server = server.await.unwrap().unwrap();

        // A signed command survives the encrypted, mutually-authenticated channel intact.
        let cmd = a_command();
        write_msg(&mut client, &cmd).await.unwrap();
        let got: Option<SignedCommand> = read_msg(&mut server).await.unwrap();
        assert_eq!(got, Some(cmd));
    }

    #[tokio::test]
    async fn server_rejects_a_device_whose_cert_is_not_pinned() {
        // The gateway pins device A's cert; device B (a different cert) presents and is refused.
        let (gw_cert, gw_key) = self_signed("gateway.test");
        let (dev_a_cert, _dev_a_key) = self_signed("device-a.test");
        let (dev_b_cert, dev_b_key) = self_signed("device-b.test");

        let client_cfg =
            client_config(&gw_cert, Identity::from_pem(&dev_b_cert, &dev_b_key).unwrap()).unwrap();
        // Server trusts only device A's CA, so device B's handshake must fail.
        let server_cfg =
            server_config(&dev_a_cert, Identity::from_pem(&gw_cert, &gw_key).unwrap()).unwrap();

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move { accept(server_cfg, server_io).await });
        // The client may error on connect or on first I/O; either way the server must reject.
        let _ = connect(client_cfg, "gateway.test", client_io).await;
        assert!(server.await.unwrap().is_err(), "untrusted client must be rejected");
    }
}
