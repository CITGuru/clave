//! # clave-net — shared network data plane (Phase 2)
//!
//! The OS adapters capture flows and supply the authoritative process identity (WFP callout on
//! Windows; `NETransparentProxyProvider` on macOS). This crate holds the **portable** parts so
//! both adapters share one implementation and one test surface:
//!
//! * [`route`] — the split-tunnel decision (re-exports [`clave_core::classify_flow`]).
//! * the [`Tunnel`] seam + an in-memory [`LoopbackTunnel`] double for tests.
//! * [`wireguard`] — the production data plane to the corporate gateway (static egress IP),
//!   implemented with **boringtun** behind the `wireguard` feature (a real Noise handshake +
//!   encrypted round-trip, covered by `wireguard::wg_tests`).
//!
//! ## Routing happens at flow-open, not per packet
//!
//! Classification keys on the flow's owning process, which the OS layer knows *before* any
//! packet flows. So the security decision is [`route`] (called once per flow); [`Tunnel`] then
//! just pumps that flow's packets. Personal flows are returned [`Route::Direct`] and never
//! touched — the company never sees personal traffic.
#![forbid(unsafe_code)]

use clave_core::ZoneRegistry;
use clave_platform::{ProcId, Route};

pub mod loopback;
pub mod router;
pub mod wireguard;

pub use loopback::LoopbackTunnel;
pub use router::{FlowDisposition, FlowId, Inbound, Outbound, SplitRouter};

/// Decide where a flow egresses. Thin re-export of [`clave_core::classify_flow`] so the OS
/// network adapters depend only on `clave-net`.
pub fn route(proc: &ProcId, zones: &ZoneRegistry, dst_blocked: bool) -> Route {
    clave_core::classify_flow(proc, zones, dst_blocked)
}

/// What a [`Tunnel`] emits when fed a plaintext IP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelOut {
    /// An encrypted datagram to send to the gateway over UDP.
    SendToGateway(Vec<u8>),
    /// Nothing to emit right now (e.g. buffered awaiting handshake completion).
    Idle,
}

/// A WireGuard-style tunnel endpoint to the corporate gateway.
///
/// The OS data path feeds outbound work packets to [`Tunnel::encapsulate`] and inbound
/// datagrams to [`Tunnel::decapsulate`]; the concrete implementation owns the crypto/session.
/// Abstracting it lets the routing layer be tested with [`LoopbackTunnel`] and lets the real
/// boringtun engine drop in unchanged (see [`wireguard`]).
///
/// A real WireGuard session is not just data in / data out: the handshake and keepalive are
/// *control* traffic the peer must receive, and the session needs a timer tick to retransmit a
/// handshake, rekey (~every 2 minutes), and expire dead sessions. The seam therefore surfaces
/// three things a naive "bytes in → bytes out" trait would drop: an inbound datagram can decrypt
/// to a packet for the process **or** to a control reply that must go back to the gateway
/// ([`Inbound`]); [`Tunnel::poll_outgoing`] flushes control/data packets the engine has queued;
/// and [`Tunnel::update_timers`] drives the session clock. Dropping any of these silently stalls
/// the tunnel (traffic fails closed, but the "data plane" never actually connects).
pub trait Tunnel: Send {
    /// Encapsulate/encrypt an outbound IP packet for the gateway.
    fn encapsulate(&mut self, ip_packet: &[u8]) -> TunnelOut;
    /// Decapsulate an inbound datagram: a decrypted inner packet for the process, a control
    /// reply to send back to the gateway, or nothing (see [`Inbound`]).
    fn decapsulate(&mut self, datagram: &[u8]) -> Inbound;
    /// Flush a packet the engine has queued to send to the gateway — e.g. a handshake initiation
    /// queued behind the first outbound data packet, or a data packet released once the session
    /// comes up. Returns `None` when nothing is pending. The data-plane driver drains this after
    /// an [`encapsulate`](Tunnel::encapsulate) returns [`TunnelOut::Idle`]. Default: nothing to
    /// flush.
    fn poll_outgoing(&mut self) -> Option<Vec<u8>> {
        None
    }
    /// Advance the session timers (handshake retransmit, rekey, keepalive, expiry). The driver
    /// calls this on a fixed cadence; returns a control packet to send to the gateway if the
    /// timers produced one. Default: no timers (e.g. the loopback double).
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
        assert_eq!(route(&pid(2), &zones, false), Route::Direct); // personal → direct
    }
}
