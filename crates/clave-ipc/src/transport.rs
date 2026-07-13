use crate::{
    encode, try_decode, DaemonMsg, FrameError, LauncherReply, LauncherRequest, ShimMsg,
    PROTO_VERSION,
};
use clave_core::{AppId, LaunchSpec, LaunchableApp};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    Frame(FrameError),
    Handshake(&'static str),
    Truncated,
    LaunchFailed(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "io: {e}"),
            TransportError::Frame(e) => write!(f, "frame: {e:?}"),
            TransportError::Handshake(m) => write!(f, "handshake: {m}"),
            TransportError::Truncated => write!(f, "peer closed mid-frame"),
            TransportError::LaunchFailed(e) => f.write_str(e),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub pid: Option<i32>,
}

pub trait PeerAuthenticator: Send + Sync {
    fn authenticate(&self, cred: &PeerCred, nonce: u64) -> bool;
}

pub struct Connection {
    stream: UnixStream,
    buf: Vec<u8>,
}

impl Connection {
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

    pub fn peer_cred(&self) -> Result<PeerCred, TransportError> {
        let c = self.stream.peer_cred()?;
        Ok(PeerCred {
            uid: c.uid(),
            pid: c.pid(),
        })
    }

    pub async fn write<T: Serialize>(&mut self, msg: &T) -> Result<(), TransportError> {
        let bytes = encode(msg);
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

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

pub struct IpcServer {
    listener: UnixListener,
}

impl IpcServer {
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

pub struct LauncherClient {
    conn: Connection,
}

impl LauncherClient {
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

    pub async fn list_apps(&mut self) -> Result<Vec<LaunchableApp>, TransportError> {
        self.conn.write(&LauncherRequest::ListApps).await?;
        match self.conn.read::<LauncherReply>().await? {
            Some(LauncherReply::Apps { apps }) => Ok(apps),
            Some(_) => Err(TransportError::Handshake("expected Apps")),
            None => Err(TransportError::Truncated),
        }
    }

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

    pub async fn launch(&mut self, app_id: AppId) -> Result<Option<u32>, TransportError> {
        self.conn.write(&LauncherRequest::Launch { app_id }).await?;
        match self.conn.read::<LauncherReply>().await? {
            Some(LauncherReply::Launched { pid }) => Ok(pid),
            Some(LauncherReply::LaunchFailed { error }) => Err(TransportError::LaunchFailed(error)),
            Some(_) => Err(TransportError::Handshake("expected Launched")),
            None => Err(TransportError::Truncated),
        }
    }

    pub async fn enforcement(&mut self) -> Result<Vec<(String, String)>, TransportError> {
        self.conn.write(&LauncherRequest::Enforcement).await?;
        match self.conn.read::<LauncherReply>().await? {
            Some(LauncherReply::Enforcement { caps }) => Ok(caps),
            Some(_) => Err(TransportError::Handshake("expected Enforcement")),
            None => Err(TransportError::Truncated),
        }
    }
}
