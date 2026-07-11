//! Split-tunnel flow router — ties the routing *decision* to the *data plane*.
//!
//! Classification happens once, when a flow opens (the OS layer knows the owning process
//! before any packet flows). The router remembers each flow's disposition and then:
//!
//! * **Tunnel** flows → packets are encapsulated through the [`Tunnel`] (WireGuard) to the
//!   gateway;
//! * **Direct** flows → packets pass through untouched (personal traffic, never re-inspected);
//! * **Block** flows (and unknown flows) → packets are dropped.

use crate::{route, Tunnel, TunnelOut};
use clave_core::ZoneRegistry;
use clave_platform::{ProcId, Route};
use std::collections::HashMap;

/// Opaque per-flow identifier assigned by the OS network layer (WFP flow context / NE flow).
pub type FlowId = u64;

/// How a flow's packets are handled for its lifetime, fixed at open by classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowDisposition {
    Tunnel,
    Direct,
    Block,
}

/// What to do with an outbound packet.
#[derive(Debug)]
pub enum Outbound {
    /// Encrypted datagram to UDP-send to the gateway.
    ToGateway(Vec<u8>),
    /// Direct flow — the caller sends it on the normal path (we never see personal traffic).
    PassThrough,
    /// The tunnel produced nothing yet (e.g. session handshake still pending).
    Idle,
    /// Dropped — blocked destination, or an unknown/closed flow.
    Dropped,
}

/// The result of decapsulating an inbound datagram from the gateway.
#[derive(Debug)]
pub enum Inbound {
    /// A decrypted inner IP packet to deliver to the owning work process.
    ToProcess(Vec<u8>),
    /// A WireGuard control reply (handshake response / keepalive) that MUST be sent back to the
    /// gateway over UDP. This is the case the old `Option<Vec<u8>>` return silently dropped —
    /// with it dropped, a gateway-initiated handshake was never answered and the session never
    /// came up.
    ToGateway(Vec<u8>),
    /// Nothing resulted — an unauthenticated/garbage datagram, or a decrypt that completed with
    /// no packet or reply to emit.
    Idle,
}

/// Owns the WireGuard [`Tunnel`] and the per-flow disposition table.
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

    /// Classify a newly opened flow and remember its disposition.
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

    /// Handle an outbound IP packet on flow `id`.
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

    /// Decapsulate an inbound datagram from the gateway. The result is either an inner packet for
    /// the work process, a control reply the caller must send back to the gateway, or nothing
    /// (see [`Inbound`]). The driver must not discard [`Inbound::ToGateway`] — that stalls the
    /// handshake.
    pub fn inbound(&mut self, datagram: &[u8]) -> Inbound {
        self.tunnel.decapsulate(datagram)
    }

    /// Flush a control/data packet the tunnel has queued to send to the gateway (see
    /// [`Tunnel::poll_outgoing`]). The driver loops on this until it returns `None`.
    pub fn poll_outgoing(&mut self) -> Option<Vec<u8>> {
        self.tunnel.poll_outgoing()
    }

    /// Advance the tunnel's session timers on the data-plane cadence (see
    /// [`Tunnel::update_timers`]); returns a control packet to send to the gateway if any.
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
        let mut gateway = LoopbackTunnel::new(0x5A); // the peer end, same key

        assert_eq!(
            router.open_flow(1, &work, &zones, false),
            FlowDisposition::Tunnel
        );

        // Outbound: the work packet is encapsulated toward the gateway.
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

        // Inbound: a reply from the gateway is decapsulated for the work process.
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
        // an id we never opened
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
