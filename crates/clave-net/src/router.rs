use crate::{route, Tunnel, TunnelOut};
use clave_core::ZoneRegistry;
use clave_platform::{ProcId, Route};
use std::collections::HashMap;

pub type FlowId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowDisposition {
    Tunnel,
    Direct,
    Block,
}

#[derive(Debug)]
pub enum Outbound {
    ToGateway(Vec<u8>),
    PassThrough,
    Idle,
    Dropped,
}

#[derive(Debug)]
pub enum Inbound {
    ToProcess(Vec<u8>),
    ToGateway(Vec<u8>),
    Idle,
}

pub struct SplitRouter {
    tunnel: Box<dyn Tunnel>,
    flows: HashMap<FlowId, FlowDisposition>,
}

impl SplitRouter {
    pub fn new(tunnel: Box<dyn Tunnel>) -> Self {
        Self {
            tunnel,
            flows: HashMap::new(),
        }
    }

    pub fn open_flow(
        &mut self,
        id: FlowId,
        proc: &ProcId,
        zones: &ZoneRegistry,
        dst_blocked: bool,
    ) -> FlowDisposition {
        let disposition = match route(proc, zones, dst_blocked) {
            Route::Tunnel => FlowDisposition::Tunnel,
            Route::Direct => FlowDisposition::Direct,
            Route::Block => FlowDisposition::Block,
        };
        self.flows.insert(id, disposition);
        disposition
    }

    pub fn disposition(&self, id: FlowId) -> Option<FlowDisposition> {
        self.flows.get(&id).copied()
    }

    pub fn open_flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn close_flow(&mut self, id: FlowId) {
        self.flows.remove(&id);
    }

    pub fn outbound(&mut self, id: FlowId, ip_packet: &[u8]) -> Outbound {
        match self.flows.get(&id).copied() {
            Some(FlowDisposition::Tunnel) => match self.tunnel.encapsulate(ip_packet) {
                TunnelOut::SendToGateway(datagram) => Outbound::ToGateway(datagram),
                TunnelOut::Idle => Outbound::Idle,
            },
            Some(FlowDisposition::Direct) => Outbound::PassThrough,
            Some(FlowDisposition::Block) | None => Outbound::Dropped,
        }
    }

    pub fn inbound(&mut self, datagram: &[u8]) -> Inbound {
        self.tunnel.decapsulate(datagram)
    }

    pub fn poll_outgoing(&mut self) -> Option<Vec<u8>> {
        self.tunnel.poll_outgoing()
    }

    pub fn tick(&mut self) -> Option<Vec<u8>> {
        self.tunnel.update_timers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoopbackTunnel;
    use crate::{Tunnel, TunnelOut};
    use clave_core::JoinReason;

    fn pid(n: u32) -> ProcId {
        ProcId::windows(n, 1)
    }

    #[test]
    fn work_flow_tunnels_and_round_trips_via_loopback() {
        let zones = ZoneRegistry::new();
        let work = pid(1);
        zones.join(work, JoinReason::Launcher);

        let mut router = SplitRouter::new(Box::new(LoopbackTunnel::new(0x5A)));
        let mut gateway = LoopbackTunnel::new(0x5A);

        assert_eq!(
            router.open_flow(1, &work, &zones, false),
            FlowDisposition::Tunnel
        );

        let packet = b"GET /secret HTTP/1.1".to_vec();
        let datagram = match router.outbound(1, &packet) {
            Outbound::ToGateway(d) => d,
            other => panic!("expected ToGateway, got {other:?}"),
        };
        assert_ne!(datagram, packet, "must be obscured on the wire");
        assert!(matches!(
            gateway.decapsulate(&datagram),
            Inbound::ToProcess(p) if p == packet
        ));

        let reply = b"HTTP/1.1 200 OK".to_vec();
        let wire = match gateway.encapsulate(&reply) {
            TunnelOut::SendToGateway(d) => d,
            TunnelOut::Idle => panic!(),
        };
        match router.inbound(&wire) {
            Inbound::ToProcess(p) => assert_eq!(p, reply),
            other => panic!("expected an inner packet for the process, got {other:?}"),
        }
    }

    #[test]
    fn personal_flow_passes_through() {
        let zones = ZoneRegistry::new();
        let mut router = SplitRouter::new(Box::new(LoopbackTunnel::new(1)));
        assert_eq!(
            router.open_flow(2, &pid(9), &zones, false),
            FlowDisposition::Direct
        );
        assert!(matches!(router.outbound(2, b"x"), Outbound::PassThrough));
    }

    #[test]
    fn blocked_and_unknown_flows_drop() {
        let zones = ZoneRegistry::new();
        let work = pid(1);
        zones.join(work, JoinReason::Launcher);

        let mut router = SplitRouter::new(Box::new(LoopbackTunnel::new(1)));
        assert_eq!(
            router.open_flow(3, &work, &zones, true),
            FlowDisposition::Block
        );
        assert!(matches!(router.outbound(3, b"x"), Outbound::Dropped));
        assert!(matches!(router.outbound(999, b"x"), Outbound::Dropped));
    }

    #[test]
    fn close_flow_forgets_disposition() {
        let zones = ZoneRegistry::new();
        let work = pid(1);
        zones.join(work, JoinReason::Launcher);
        let mut router = SplitRouter::new(Box::new(LoopbackTunnel::new(1)));
        router.open_flow(1, &work, &zones, false);
        assert_eq!(router.open_flow_count(), 1);
        router.close_flow(1);
        assert_eq!(router.open_flow_count(), 0);
        assert!(matches!(router.outbound(1, b"x"), Outbound::Dropped));
    }
}
