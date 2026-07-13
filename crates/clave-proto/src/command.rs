use clave_core::{PolicyBundle, UnixTime};
use serde::{Deserialize, Serialize};

use crate::{TenantId, GATEWAY_PROTO_VERSION};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlReason {
    Offboarding,
    LostOrStolen,
    Compromise,
    AdminRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayCommand {
    /// Boxed so a `Lock`/`Wipe` — the commands that matter in an incident — isn't carried around at
    /// the size of a whole policy bundle. `Box<T>` serializes exactly as `T`, so the canonical bytes
    /// this command is **signed over** are unchanged.
    UpdatePolicy(Box<PolicyBundle>),
    Lock {
        reason: ControlReason,
    },
    Wipe {
        container: u128,
        reason: ControlReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub proto: u16,
    pub tenant: TenantId,
    pub counter: u64,
    pub issued_at: UnixTime,
    pub command: GatewayCommand,
}

impl Envelope {
    pub fn new(
        tenant: TenantId,
        counter: u64,
        issued_at: UnixTime,
        command: GatewayCommand,
    ) -> Self {
        Self {
            proto: GATEWAY_PROTO_VERSION,
            tenant,
            counter,
            issued_at,
            command,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("postcard serialize of a gateway envelope")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCommand {
    pub envelope: Vec<u8>,
    pub signature: Vec<u8>,
}
