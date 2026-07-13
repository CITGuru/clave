use crate::{route, route_dns, Tunnel, TunnelOut};
use clave_core::{DnsSteering, ZoneRegistry};
use clave_platform::{ProcId, Route};
use std::collections::HashMap;

pub type FlowId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowDisposition {
    Tunnel,
    Direct,
    Block,
    HeldOffline,
}

impl From<Route> for FlowDisposition {
    fn from(route: Route) -> Self {
        match route {
            Route::Tunnel => FlowDisposition::Tunnel,
            Route::Direct => FlowDisposition::Direct,
            Route::Block => FlowDisposition::Block,
        }
    }
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

    pub fn link_is_up(&self) -> bool {
        self.tunnel.is_established()
    }

    fn resolve(&self, route: Route) -> FlowDisposition {
        match route {
            Route::Tunnel if !self.tunnel.is_established() => FlowDisposition::HeldOffline,
            other => other.into(),
        }
    }

    pub fn open_flow(
        &mut self,
        id: FlowId,
        proc: &ProcId,
        zones: &ZoneRegistry,
        dst_blocked: bool,
    ) -> FlowDisposition {
        let disposition = self.resolve(route(proc, zones, dst_blocked));
        self.flows.insert(id, disposition);
        disposition
    }

    pub fn open_dns_flow(
        &mut self,
        id: FlowId,
        proc: &ProcId,
        zones: &ZoneRegistry,
        qname: &str,
        steering: Option<&DnsSteering>,
    ) -> FlowDisposition {
        let disposition = self.resolve(route_dns(proc, zones, qname, steering));
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
            Some(FlowDisposition::Tunnel) | Some(FlowDisposition::HeldOffline) => {
                match self.tunnel.encapsulate(ip_packet) {
                    TunnelOut::SendToGateway(datagram) => Outbound::ToGateway(datagram),
                    TunnelOut::Idle => Outbound::Idle,
                }
            }
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
    fn work_dns_flow_tunnels_and_personal_dns_passes_through() {
        let zones = ZoneRegistry::new();
        let work = pid(1);
        zones.join(work, JoinReason::Launcher);

        let mut router = SplitRouter::new(Box::new(LoopbackTunnel::new(0x5A)));
        assert_eq!(
            router.open_dns_flow(1, &work, &zones, "intra.corp", None),
            FlowDisposition::Tunnel
        );
        assert!(matches!(
            router.outbound(1, b"dns-query"),
            Outbound::ToGateway(_)
        ));

        assert_eq!(
            router.open_dns_flow(2, &pid(9), &zones, "intra.corp", None),
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

    struct OfflineTunnel;

    impl Tunnel for OfflineTunnel {
        fn encapsulate(&mut self, ip_packet: &[u8]) -> TunnelOut {
            if ip_packet.is_empty() {
                TunnelOut::Idle
            } else {
                TunnelOut::SendToGateway(vec![0xFF])
            }
        }
        fn decapsulate(&mut self, _datagram: &[u8]) -> Inbound {
            Inbound::Idle
        }
        fn is_established(&self) -> bool {
            false
        }
    }

    #[test]
    fn work_flow_fails_closed_offline_while_personal_stays_online() {
        let zones = ZoneRegistry::new();
        let work = pid(1);
        zones.join(work, JoinReason::Launcher);

        let mut router = SplitRouter::new(Box::new(OfflineTunnel));
        assert!(!router.link_is_up());

        assert_eq!(
            router.open_flow(1, &work, &zones, false),
            FlowDisposition::HeldOffline
        );
        assert!(
            matches!(router.outbound(1, b"work-data"), Outbound::ToGateway(_)),
            "held work traffic rides the tunnel handshake, never a direct passthrough"
        );

        assert_eq!(
            router.open_flow(2, &pid(9), &zones, false),
            FlowDisposition::Direct
        );
        assert!(
            matches!(router.outbound(2, b"portal-auth"), Outbound::PassThrough),
            "personal path reaches the underlay/captive portal even while the tunnel is down"
        );
    }

    #[test]
    fn work_flow_resumes_tunneling_once_the_link_is_up() {
        let zones = ZoneRegistry::new();
        let work = pid(1);
        zones.join(work, JoinReason::Launcher);

        let mut router = SplitRouter::new(Box::new(LoopbackTunnel::new(0x5A)));
        assert!(router.link_is_up());
        assert_eq!(
            router.open_flow(1, &work, &zones, false),
            FlowDisposition::Tunnel
        );
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
