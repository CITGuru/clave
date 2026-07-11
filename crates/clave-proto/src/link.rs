//! The gateway transport seam + an in-memory double.
//!
//! [`GatewayLink`] abstracts the daemon↔gateway connection (an mTLS WebSocket in production) so
//! the sync orchestration is testable with no network. The daemon pulls inbound
//! [`SignedCommand`]s and pushes drained [`SignedSpoolBatch`]es; the real mTLS implementation
//! drops in behind this trait, exactly as the boringtun engine drops in behind
//! `clave_net::Tunnel`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::{SignedCommand, SignedSpoolBatch};

/// Why shipping an audit batch failed. The sync loop treats any error as "the gateway does not
/// have these entries yet" and retains them to retry — it must never advance past unshipped audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The link is down (not connected / pump gone). The batch was not delivered.
    Unavailable,
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::Unavailable => write!(f, "gateway link unavailable"),
        }
    }
}

impl std::error::Error for LinkError {}

/// The daemon↔gateway link. Implementations own the transport (mTLS, reconnection, framing); the
/// portable sync loop only pulls commands and pushes audit batches through this seam.
pub trait GatewayLink: Send {
    /// Signed commands the gateway has delivered since the last poll (may be empty).
    fn poll_commands(&mut self) -> Vec<SignedCommand>;
    /// Ship a drained, device-signed audit batch toward the gateway. `Ok(())` means the link
    /// accepted it for delivery (the caller may now acknowledge those entries);
    /// `Err(LinkError::Unavailable)` means the link is down and nothing was sent — the caller must
    /// keep the entries and retry. Silently dropping a batch here is what wedged the audit chain.
    fn push_audit(&mut self, batch: SignedSpoolBatch) -> Result<(), LinkError>;
}

/// In-memory [`GatewayLink`] double for tests/dev: a queue of inbound commands and a log of pushed
/// audit batches. `Clone` shares one state, so a test keeps a handle to drive and inspect it after
/// the link is moved into the sync loop (mirrors `clave_net::LoopbackTunnel` and the mocks).
#[derive(Clone, Default)]
pub struct LoopbackLink {
    inner: Arc<Mutex<LinkState>>,
}

struct LinkState {
    inbound: VecDeque<SignedCommand>,
    pushed: Vec<SignedSpoolBatch>,
    /// When false, `push_audit` fails as if the link were down — lets a test exercise the
    /// retain-and-retry path without a real transport.
    online: bool,
}

impl Default for LinkState {
    fn default() -> Self {
        Self {
            inbound: VecDeque::new(),
            pushed: Vec::new(),
            online: true,
        }
    }
}

impl LoopbackLink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a command as if the gateway had pushed it.
    pub fn enqueue_command(&self, command: SignedCommand) {
        self.inner
            .lock()
            .expect("link lock poisoned")
            .inbound
            .push_back(command);
    }

    /// The audit batches shipped so far (the gateway's view).
    pub fn pushed_batches(&self) -> Vec<SignedSpoolBatch> {
        self.inner
            .lock()
            .expect("link lock poisoned")
            .pushed
            .clone()
    }

    /// Simulate the link going up or down. While down, `push_audit` returns
    /// [`LinkError::Unavailable`] and delivers nothing.
    pub fn set_online(&self, online: bool) {
        self.inner.lock().expect("link lock poisoned").online = online;
    }
}

impl GatewayLink for LoopbackLink {
    fn poll_commands(&mut self) -> Vec<SignedCommand> {
        self.inner
            .lock()
            .expect("link lock poisoned")
            .inbound
            .drain(..)
            .collect()
    }

    fn push_audit(&mut self, batch: SignedSpoolBatch) -> Result<(), crate::LinkError> {
        let mut s = self.inner.lock().expect("link lock poisoned");
        if !s.online {
            return Err(crate::LinkError::Unavailable);
        }
        s.pushed.push(batch);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ControlReason, DeviceSigningKey, GatewayCommand, GatewaySigningKey, TenantId, GENESIS,
    };

    #[test]
    fn loopback_round_trips_commands_and_batches() {
        let mut link = LoopbackLink::new();
        let handle = link.clone(); // shares state with `link`

        let signer = GatewaySigningKey::from_seed(TenantId(1), [1u8; 32]);
        handle.enqueue_command(signer.sign(
            1,
            0,
            GatewayCommand::Lock {
                reason: ControlReason::AdminRequest,
            },
        ));

        assert_eq!(link.poll_commands().len(), 1);
        assert!(
            link.poll_commands().is_empty(),
            "commands are consumed once"
        );

        let dev = DeviceSigningKey::from_seed([2u8; 32]);
        link.push_audit(dev.sign_batch(Vec::new(), GENESIS))
            .expect("online link accepts the batch");
        assert_eq!(
            handle.pushed_batches().len(),
            1,
            "the shared handle sees pushes"
        );
    }

    #[test]
    fn offline_link_rejects_pushes() {
        let mut link = LoopbackLink::new();
        link.set_online(false);
        let dev = DeviceSigningKey::from_seed([2u8; 32]);
        assert_eq!(
            link.push_audit(dev.sign_batch(Vec::new(), GENESIS)),
            Err(crate::LinkError::Unavailable)
        );
        assert!(link.pushed_batches().is_empty(), "nothing is delivered while down");
    }
}
