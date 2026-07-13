use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::{GatewayLink, SignedCommand, SignedSpoolBatch};

pub const MAX_FRAME: usize = 1 << 20;

pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let body = postcard::to_allocvec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode: {e}")))?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    w.write_all(&(body.len() as u32).to_le_bytes()).await?;
    w.write_all(&body).await?;
    Ok(())
}

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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    postcard::from_bytes(&body)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decode: {e}")))
}

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
        self.outbound
            .send(batch)
            .map_err(|_| crate::LinkError::Unavailable)
    }
}

pub struct PumpEnds {
    inbound: UnboundedSender<SignedCommand>,
    outbound: UnboundedReceiver<SignedSpoolBatch>,
}

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
                        break;
                    }
                }
                None => break,
            },
            outgoing = ends.outbound.recv() => match outgoing {
                Some(batch) => write_msg(&mut w, &batch).await?,
                None => break,
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ControlReason, DeviceSigningKey, GatewayCommand, GatewaySigningKey, TenantId, GENESIS,
    };

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
        drop(a);
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

        let mut pulled = Vec::new();
        for _ in 0..1000 {
            pulled = link.poll_commands();
            if !pulled.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(pulled, vec![cmd]);

        drop(client);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pump_writes_pushed_audit_batches_to_the_stream() {
        let (mut client, server) = tokio::io::duplex(8192);
        let (mut link, ends) = channel_link();

        let batch = DeviceSigningKey::from_seed([3u8; 32]).sign_batch(Vec::new(), GENESIS);
        link.push_audit(batch.clone()).expect("queued for the pump");
        drop(link);

        let task = tokio::spawn(pump(server, ends));
        let got: Option<SignedSpoolBatch> = read_msg(&mut client).await.unwrap();
        assert_eq!(got, Some(batch));
        task.await.unwrap().unwrap();
    }
}
