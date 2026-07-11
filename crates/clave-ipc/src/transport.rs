//! Authenticated IPC transport over the message contracts.
//!
//! A Unix-domain-socket server + framed [`Connection`] for the daemon↔shim and daemon↔UI
//! links. The transport is **mechanism only**: it reads the connecting peer's credentials and
//! delegates the *policy* (code-signature check, supervised-set membership, per-launch nonce)
//! to a [`PeerAuthenticator`] supplied by the daemon. The Windows named-pipe
//! transport (`tokio::net::windows::named_pipe`) is the analogous future scaffold.
//!
//! Available on Unix; gated out elsewhere.

use crate::{
    encode, try_decode, DaemonMsg, FrameError, LauncherReply, LauncherRequest, ShimMsg,
    PROTO_VERSION,
};
use clave_core::{AppId, LaunchSpec, LaunchableApp};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// Transport-layer errors.
#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    Frame(FrameError),
    /// The handshake failed (bad version, rejected peer, or unexpected message).
    Handshake(&'static str),
    /// The peer closed the connection in the middle of a frame.
    Truncated,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "io: {e}"),
            TransportError::Frame(e) => write!(f, "frame: {e:?}"),
            TransportError::Handshake(m) => write!(f, "handshake: {m}"),
            TransportError::Truncated => write!(f, "peer closed mid-frame"),
        }
    }
}
impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}
impl From<FrameError> for TransportError {
    fn from(e: FrameError) -> Self {
        TransportError::Frame(e)
    }
}

/// Credentials of the connected peer (from `SO_PEERCRED` / `LOCAL_PEERCRED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub pid: Option<i32>,
}

/// Admits or rejects a peer after the handshake.
///
/// The production implementation (in the daemon) verifies the peer's code signature
/// (`SecCodeCheckValidity`), confirms its pid/audit-token is in the supervised set, and matches
/// the per-launch nonce handed to the shim at injection time. Keeping it a trait
/// means the transport never bakes in policy.
pub trait PeerAuthenticator: Send + Sync {
    fn authenticate(&self, cred: &PeerCred, nonce: u64) -> bool;
}

/// A framed message connection over a Unix stream. Symmetric: either side can read/write any
/// message type (the daemon reads [`ShimMsg`]/writes [`DaemonMsg`]; the shim does the reverse).
pub struct Connection {
    stream: UnixStream,
    buf: Vec<u8>,
}

impl Connection {
    /// Connect to a listening [`IpcServer`] (client side).
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        Ok(Self {
            stream: UnixStream::connect(path).await?,
            buf: Vec::new(),
        })
    }

    fn from_stream(stream: UnixStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
        }
    }

    /// Read the connecting peer's credentials (the basis for authentication).
    pub fn peer_cred(&self) -> Result<PeerCred, TransportError> {
        let c = self.stream.peer_cred()?;
        Ok(PeerCred {
            uid: c.uid(),
            pid: c.pid(),
        })
    }

    /// Write one framed message.
    pub async fn write<T: Serialize>(&mut self, msg: &T) -> Result<(), TransportError> {
        let bytes = encode(msg);
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read one framed message, or `None` on a clean EOF at a frame boundary.
    pub async fn read<T: DeserializeOwned>(&mut self) -> Result<Option<T>, TransportError> {
        loop {
            if let Some((msg, consumed)) = try_decode::<T>(&self.buf)? {
                self.buf.drain(..consumed);
                return Ok(Some(msg));
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(TransportError::Truncated)
                };
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// A listening IPC endpoint over a Unix-domain socket.
pub struct IpcServer {
    listener: UnixListener,
}

impl IpcServer {
    /// Bind to `path`, removing any stale socket file first. Restrict the socket's permissions
    /// at the directory level in production.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let _ = std::fs::remove_file(path.as_ref());
        Ok(Self {
            listener: UnixListener::bind(path)?,
        })
    }

    pub async fn accept(&self) -> Result<Connection, TransportError> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(Connection::from_stream(stream))
    }
}

/// Server side of the handshake: read [`ShimMsg::Hello`], check the protocol version and the
/// [`PeerAuthenticator`], then reply [`DaemonMsg::Welcome`].
pub async fn server_handshake(
    conn: &mut Connection,
    auth: &dyn PeerAuthenticator,
) -> Result<PeerCred, TransportError> {
    let cred = conn.peer_cred()?;
    match conn.read::<ShimMsg>().await? {
        Some(ShimMsg::Hello { proto, nonce }) => {
            if proto != PROTO_VERSION {
                return Err(TransportError::Handshake("protocol version mismatch"));
            }
            if !auth.authenticate(&cred, nonce) {
                return Err(TransportError::Handshake("peer authentication rejected"));
            }
            conn.write(&DaemonMsg::Welcome {
                proto: PROTO_VERSION,
            })
            .await?;
            Ok(cred)
        }
        Some(_) => Err(TransportError::Handshake("expected Hello")),
        None => Err(TransportError::Truncated),
    }
}

/// Client side of the handshake: send [`ShimMsg::Hello`], expect [`DaemonMsg::Welcome`].
pub async fn client_handshake(conn: &mut Connection, nonce: u64) -> Result<(), TransportError> {
    conn.write(&ShimMsg::Hello {
        proto: PROTO_VERSION,
        nonce,
    })
    .await?;
    match conn.read::<DaemonMsg>().await? {
        Some(DaemonMsg::Welcome { proto }) if proto == PROTO_VERSION => Ok(()),
        Some(_) => Err(TransportError::Handshake("expected Welcome")),
        None => Err(TransportError::Truncated),
    }
}

/// Serve requests until the peer closes: read each [`ShimMsg`], map it via `handler`, and write
/// any [`DaemonMsg`] reply. The daemon passes a handler that calls into its policy brain.
pub async fn serve<F>(mut conn: Connection, mut handler: F) -> Result<(), TransportError>
where
    F: FnMut(ShimMsg) -> Option<DaemonMsg>,
{
    while let Some(msg) = conn.read::<ShimMsg>().await? {
        if let Some(reply) = handler(msg) {
            conn.write(&reply).await?;
        }
    }
    Ok(())
}

// The daemon↔launcher-UI link.

/// Serve the **launcher UI** over a connection: complete the [`LauncherRequest::Hello`] handshake,
/// then answer each request via `handler` until the UI disconnects. The daemon passes a handler
/// that calls `Daemon::handle_launcher_request` (catalog / launch spec / posture). Every request
/// gets exactly one reply — unlike the shim link, which fires-and-forgets some messages.
pub async fn serve_launcher<F>(mut conn: Connection, mut handler: F) -> Result<(), TransportError>
where
    F: FnMut(LauncherRequest) -> LauncherReply,
{
    match conn.read::<LauncherRequest>().await? {
        Some(LauncherRequest::Hello { proto }) if proto == PROTO_VERSION => {
            conn.write(&LauncherReply::Welcome {
                proto: PROTO_VERSION,
            })
            .await?;
        }
        Some(LauncherRequest::Hello { .. }) => {
            return Err(TransportError::Handshake("protocol version mismatch"))
        }
        Some(_) => return Err(TransportError::Handshake("expected Hello")),
        None => return Err(TransportError::Truncated),
    }
    while let Some(req) = conn.read::<LauncherRequest>().await? {
        let reply = handler(req);
        conn.write(&reply).await?;
    }
    Ok(())
}

/// Client handle for the launcher UI (the Tauri backend): connects, handshakes, then issues typed
/// request/reply round-trips. Each call writes one [`LauncherRequest`] and awaits its
/// [`LauncherReply`], so it is **not** safe to share across tasks without external serialization.
pub struct LauncherClient {
    conn: Connection,
}

impl LauncherClient {
    /// Connect to the daemon's launcher socket and complete the version handshake.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let mut conn = Connection::connect(path).await?;
        conn.write(&LauncherRequest::Hello {
            proto: PROTO_VERSION,
        })
        .await?;
        match conn.read::<LauncherReply>().await? {
            Some(LauncherReply::Welcome { proto }) if proto == PROTO_VERSION => Ok(Self { conn }),
            Some(LauncherReply::Welcome { .. }) => {
                Err(TransportError::Handshake("protocol version mismatch"))
            }
            Some(_) => Err(TransportError::Handshake("expected Welcome")),
            None => Err(TransportError::Truncated),
        }
    }

    /// The launch catalog (allow-listed work apps with an executable).
    pub async fn list_apps(&mut self) -> Result<Vec<LaunchableApp>, TransportError> {
        self.conn.write(&LauncherRequest::ListApps).await?;
        match self.conn.read::<LauncherReply>().await? {
            Some(LauncherReply::Apps { apps }) => Ok(apps),
            Some(_) => Err(TransportError::Handshake("expected Apps")),
            None => Err(TransportError::Truncated),
        }
    }

    /// Resolve the contained spawn spec for one app (`None` if unknown / volume not mounted).
    pub async fn prepare_launch(
        &mut self,
        app_id: AppId,
    ) -> Result<Option<LaunchSpec>, TransportError> {
        self.conn
            .write(&LauncherRequest::PrepareLaunch { app_id })
            .await?;
        match self.conn.read::<LauncherReply>().await? {
            Some(LauncherReply::LaunchSpec { spec }) => Ok(spec),
            Some(_) => Err(TransportError::Handshake("expected LaunchSpec")),
            None => Err(TransportError::Truncated),
        }
    }

    /// This OS adapter's enforcement posture as `capability → status` pairs.
    pub async fn enforcement(&mut self) -> Result<Vec<(String, String)>, TransportError> {
        self.conn.write(&LauncherRequest::Enforcement).await?;
        match self.conn.read::<LauncherReply>().await? {
            Some(LauncherReply::Enforcement { caps }) => Ok(caps),
            Some(_) => Err(TransportError::Handshake("expected Enforcement")),
            None => Err(TransportError::Truncated),
        }
    }
}
