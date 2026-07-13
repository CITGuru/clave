use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::{SignedCommand, SignedSpoolBatch};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
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

pub trait GatewayLink: Send {
    fn poll_commands(&mut self) -> Vec<SignedCommand>;
    fn push_audit(&mut self, batch: SignedSpoolBatch) -> Result<(), LinkError>;
}

#[derive(Clone, Default)]
pub struct LoopbackLink {
    inner: Arc<Mutex<LinkState>>,
}

struct LinkState {
    inbound: VecDeque<SignedCommand>,
    pushed: Vec<SignedSpoolBatch>,
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

    pub fn enqueue_command(&self, command: SignedCommand) {
        self.inner
            .lock()
            .expect("link lock poisoned")
            .inbound
            .push_back(command);
    }

    pub fn pushed_batches(&self) -> Vec<SignedSpoolBatch> {
        self.inner
            .lock()
            .expect("link lock poisoned")
            .pushed
            .clone()
    }

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
        let handle = link.clone();

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
        assert!(
            link.pushed_batches().is_empty(),
            "nothing is delivered while down"
        );
    }
}
