//! The live gateway transport (`transport` feature): length-prefixed messages over a byte stream,
//! plus a channel-backed [`GatewayLink`] bridged to that stream by a [`pump`] task.
//!
//! In production the byte stream is a **mTLS** connection to the corporate gateway: a rustls
//! `TlsStream<TcpStream>` (which is `AsyncRead + AsyncWrite`) plugged straight into [`pump`]. That
//! TLS/cert/endpoint wiring is deployment glue and lives outside this crate; everything here — the
//! framing and the sync-link bridge — is exercised over an in-memory `tokio::io::duplex`.
//!
//! Why a channel-backed link: [`GatewayLink`] is **synchronous** (the policy loop calls
//! `poll_commands`/`push_audit` without awaiting), while the network is async. [`ChannelGatewayLink`]
//! buffers both directions in channels; [`pump`] does the async stream I/O. So
//! `clave_daemon::GatewaySync` drives the link unchanged, and the transport is just the pump.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::{GatewayLink, SignedCommand, SignedSpoolBatch};

/// Hard cap on a single frame body, bounding the allocation an attacker can induce via the length
/// prefix (1 MiB — generous for control messages and audit batches).
pub const MAX_FRAME: usize = 1 << 20;

/// Write `msg` as a `[u32 little-endian length][postcard body]` frame.
pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let body = postcard::to_allocvec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode: {e}")))?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    w.write_all(&(body.len() as u32).to_le_bytes()).await?;
    w.write_all(&body).await?;
    Ok(())
}

/// Read one framed message. `Ok(None)` is a clean end-of-stream before a frame begins (the peer
/// closed). A length over [`MAX_FRAME`] or a decode failure is an error (drop the connection).
pub async fn read_msg<R, T>(r: &mut R) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    postcard::from_bytes(&body)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decode: {e}")))
}

/// A synchronous [`GatewayLink`] backed by channels. The policy loop drains inbound commands and
/// enqueues outbound audit batches without blocking; [`pump`] moves them to/from the stream.
pub struct ChannelGatewayLink {
    inbound: UnboundedReceiver<SignedCommand>,
    outbound: UnboundedSender<SignedSpoolBatch>,
}

impl GatewayLink for ChannelGatewayLink {
    fn poll_commands(&mut self) -> Vec<SignedCommand> {
        let mut out = Vec::new();
        while let Ok(cmd) = self.inbound.try_recv() {
            out.push(cmd);
        }
        out
    }

    fn push_audit(&mut self, batch: SignedSpoolBatch) -> Result<(), crate::LinkError> {
        // If the pump has exited (the connection is gone), report failure so the sync loop retains
        // the entries and retries — silently dropping here is what used to wedge the audit chain.
        self.outbound
            .send(batch)
            .map_err(|_| crate::LinkError::Unavailable)
    }
}

/// The stream-facing half of a [`ChannelGatewayLink`], handed to [`pump`].
pub struct PumpEnds {
    inbound: UnboundedSender<SignedCommand>,
    outbound: UnboundedReceiver<SignedSpoolBatch>,
}

/// Create a [`ChannelGatewayLink`] (give to `GatewaySync`) and its [`PumpEnds`] (give to [`pump`]).
pub fn channel_link() -> (ChannelGatewayLink, PumpEnds) {
    let (in_tx, in_rx) = unbounded_channel();
    let (out_tx, out_rx) = unbounded_channel();
    (
        ChannelGatewayLink {
            inbound: in_rx,
            outbound: out_tx,
        },
        PumpEnds {
            inbound: in_tx,
            outbound: out_rx,
        },
    )
}

/// Bridge a framed byte stream (e.g. a rustls `TlsStream`) to a [`ChannelGatewayLink`]: forward
/// inbound [`SignedCommand`]s from the stream to the link, and outbound [`SignedSpoolBatch`]es from
/// the link to the stream, until either side closes. Run as a task alongside the sync loop.
pub async fn pump<S>(stream: S, mut ends: PumpEnds) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut r, mut w) = tokio::io::split(stream);
    loop {
        tokio::select! {
            incoming = read_msg::<_, SignedCommand>(&mut r) => match incoming? {
                Some(cmd) => {
                    if ends.inbound.send(cmd).is_err() {
                        break; // the link was dropped
                    }
                }
                None => break, // the gateway closed the stream
            },
            outgoing = ends.outbound.recv() => match outgoing {
                Some(batch) => write_msg(&mut w, &batch).await?,
                None => break, // the link was dropped
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlReason, DeviceSigningKey, GatewayCommand, GatewaySigningKey, TenantId, GENESIS};

    fn a_command() -> SignedCommand {
        GatewaySigningKey::from_seed(TenantId(1), [1u8; 32]).sign(
            1,
            0,
            GatewayCommand::Lock {
                reason: ControlReason::AdminRequest,
            },
        )
    }

    #[tokio::test]
    async fn frames_round_trip_a_command_and_a_batch() {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let cmd = a_command();
        write_msg(&mut a, &cmd).await.unwrap();
        let got: Option<SignedCommand> = read_msg(&mut b).await.unwrap();
        assert_eq!(got, Some(cmd));

        let batch = DeviceSigningKey::from_seed([2u8; 32]).sign_batch(Vec::new(), GENESIS);
        write_msg(&mut a, &batch).await.unwrap();
        let got: Option<SignedSpoolBatch> = read_msg(&mut b).await.unwrap();
        assert_eq!(got, Some(batch));
    }

    #[tokio::test]
    async fn clean_eof_reads_none() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a); // peer closes before any frame
        let got: Option<SignedCommand> = read_msg(&mut b).await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn pump_delivers_inbound_commands_to_the_link() {
        let (client, server) = tokio::io::duplex(8192);
        let (mut link, ends) = channel_link();
        let task = tokio::spawn(pump(server, ends));

        let mut client = client;
        let cmd = a_command();
        write_msg(&mut client, &cmd).await.unwrap();

        // Let the pump run and surface the command through the sync link.
        let mut pulled = Vec::new();
        for _ in 0..1000 {
            pulled = link.poll_commands();
            if !pulled.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(pulled, vec![cmd]);

        drop(client); // close the stream → pump exits cleanly
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pump_writes_pushed_audit_batches_to_the_stream() {
        let (mut client, server) = tokio::io::duplex(8192);
        let (mut link, ends) = channel_link();

        let batch = DeviceSigningKey::from_seed([3u8; 32]).sign_batch(Vec::new(), GENESIS);
        link.push_audit(batch.clone()).expect("queued for the pump");
        drop(link); // after the queued batch, the pump's outbound recv ends → it exits

        let task = tokio::spawn(pump(server, ends));
        let got: Option<SignedSpoolBatch> = read_msg(&mut client).await.unwrap();
        assert_eq!(got, Some(batch));
        task.await.unwrap().unwrap();
    }
}
