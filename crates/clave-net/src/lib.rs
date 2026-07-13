#![forbid(unsafe_code)]

use clave_core::ZoneRegistry;
use clave_platform::{ProcId, Route};

pub mod loopback;
pub mod router;
pub mod wireguard;

pub use loopback::LoopbackTunnel;
pub use router::{FlowDisposition, FlowId, Inbound, Outbound, SplitRouter};

pub fn route(proc: &ProcId, zones: &ZoneRegistry, dst_blocked: bool) -> Route {
    clave_core::classify_flow(proc, zones, dst_blocked)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelOut {
    SendToGateway(Vec<u8>),
    Idle,
}

pub trait Tunnel: Send {
    fn encapsulate(&mut self, ip_packet: &[u8]) -> TunnelOut;
    fn decapsulate(&mut self, datagram: &[u8]) -> Inbound;
    fn poll_outgoing(&mut self) -> Option<Vec<u8>> {
        None
    }
    fn update_timers(&mut self) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clave_core::JoinReason;

    fn pid(n: u32) -> ProcId {
        ProcId::windows(n, 1)
    }

    #[test]
    fn route_delegates_to_core_classifier() {
        let zones = ZoneRegistry::new();
        let work = pid(1);
        zones.join(work, JoinReason::Launcher);

        assert_eq!(route(&work, &zones, false), Route::Tunnel);
        assert_eq!(route(&work, &zones, true), Route::Block);
        assert_eq!(route(&pid(2), &zones, false), Route::Direct);
    }
}
