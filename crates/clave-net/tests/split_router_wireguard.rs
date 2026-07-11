//! Composed data-plane test: a real **boringtun** WireGuard session driven end-to-end through
//! [`SplitRouter`] (not the tunnel directly). This is the composition the daemon actually runs,
//! and the one the crate never exercised before — the unit `wg_tests` drives `WireguardTunnel`
//! directly and so never notices that the router's `inbound` used to drop control replies.
//!
//! Runs only with `--features wireguard` (the boringtun engine).
#![cfg(feature = "wireguard")]

use clave_core::{JoinReason, ZoneRegistry};
use clave_net::wireguard::{DecapResult, GatewayConfig, WireguardTunnel};
use clave_net::{FlowDisposition, Inbound, Outbound, SplitRouter, Tunnel, TunnelOut};
use clave_platform::ProcId;

fn pid(n: u32) -> ProcId {
    ProcId::windows(n, 1)
}

/// A minimal well-formed IPv4 packet so boringtun can recover the exact inner length on
/// decapsulation (WireGuard pads data packets to a 16-byte boundary).
fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45; // IPv4, IHL=5
    p[2] = (total >> 8) as u8;
    p[3] = (total & 0xff) as u8;
    p[8] = 64; // TTL
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    p.extend_from_slice(payload);
    p
}

/// Build the router (device side) and a bare gateway-side tunnel, sharing a keypair.
fn endpoints() -> (SplitRouter, WireguardTunnel) {
    let dev_priv = [1u8; 32];
    let gw_priv = [2u8; 32];
    let dev_pub = WireguardTunnel::public_key(dev_priv);
    let gw_pub = WireguardTunnel::public_key(gw_priv);

    let dev_cfg = GatewayConfig::new(dev_priv, gw_pub, "gw:51820");
    let gw_cfg = GatewayConfig::new(gw_priv, dev_pub, "dev:51820");

    let router = SplitRouter::new(Box::new(WireguardTunnel::new(&dev_cfg, 1).expect("device tun")));
    let gateway = WireguardTunnel::new(&gw_cfg, 2).expect("gateway tun");
    (router, gateway)
}

/// The regression the widened seam fixes: when the **gateway initiates** the handshake, the
/// router's device tunnel must produce a handshake *response* and surface it to be sent back.
/// Under the old `inbound -> Option<Vec<u8>>` seam that reply was mapped to `None` and dropped,
/// so the session never came up and every work packet was silently lost. Here we assert the
/// response is surfaced as [`Inbound::ToGateway`], complete the handshake, and confirm real data
/// then decrypts through the router.
#[test]
fn gateway_initiated_handshake_is_answered_through_the_router() {
    let (mut router, mut gateway) = endpoints();

    // Gateway wants to reach the device → the first packet triggers a handshake initiation.
    let init = match gateway.encapsulate(&ipv4_packet(b"warmup from gw")) {
        TunnelOut::SendToGateway(d) => d,
        TunnelOut::Idle => panic!("gateway should emit a handshake initiation"),
    };

    // Router receives it and MUST answer with a handshake response to send back to the gateway.
    let response = match router.inbound(&init) {
        Inbound::ToGateway(r) => r,
        other => panic!("router must answer a handshake initiation, got {other:?}"),
    };

    // Gateway consumes the response → its session is established.
    match gateway.decapsulate_raw(&response) {
        DecapResult::Reply(_) | DecapResult::Done => {}
        DecapResult::Packet(_) => panic!("unexpected inner packet during handshake"),
    }

    // Now the gateway sends real work data; the router decrypts it for the process.
    let packet = ipv4_packet(b"payload from the corporate side");
    let ciphertext = match gateway.encapsulate(&packet) {
        TunnelOut::SendToGateway(d) => d,
        TunnelOut::Idle => panic!("gateway should emit an encrypted data packet"),
    };
    match router.inbound(&ciphertext) {
        Inbound::ToProcess(p) => assert_eq!(p, packet, "router must decrypt the inner packet"),
        other => panic!("expected an inner packet for the process, got {other:?}"),
    }
}

/// The device-initiated direction, also entirely through the router: opening a work flow and
/// sending a packet triggers a handshake, the gateway answers, and once the session is up the
/// router encrypts real data that the gateway decrypts. Exercises `open_flow` → `outbound` →
/// `inbound` on the same `SplitRouter`.
#[test]
fn device_initiated_session_round_trips_data_through_the_router() {
    let (mut router, mut gateway) = endpoints();
    let zones = ZoneRegistry::new();
    let work = pid(10);
    zones.join(work, JoinReason::Launcher);

    assert_eq!(router.open_flow(1, &work, &zones, false), FlowDisposition::Tunnel);

    // First outbound packet → the router emits a handshake initiation (the data is queued).
    let init = match router.outbound(1, &ipv4_packet(b"warmup")) {
        Outbound::ToGateway(d) => d,
        other => panic!("expected a handshake initiation, got {other:?}"),
    };

    // Gateway answers; the router consumes the response and comes up (surfacing any keepalive).
    let response = match gateway.decapsulate_raw(&init) {
        DecapResult::Reply(r) => r,
        _ => panic!("gateway should reply to the initiation"),
    };
    let _ = router.inbound(&response); // ToGateway(keepalive) or Idle — must not panic/drop-crash

    // With the session up, real work data encrypts through the router and the gateway decrypts it.
    let packet = ipv4_packet(b"the quick brown fox");
    let ciphertext = match router.outbound(1, &packet) {
        Outbound::ToGateway(d) => d,
        other => panic!("expected an encrypted data packet, got {other:?}"),
    };
    assert_ne!(ciphertext, packet, "must be encrypted on the wire");
    match gateway.decapsulate_raw(&ciphertext) {
        DecapResult::Packet(p) => assert_eq!(p, packet),
        other => panic!("gateway should decrypt the data packet, got {other:?}"),
    }

    // The timer tick and outgoing-flush are wired and safe to call on a live session.
    let _ = router.tick();
    let _ = router.poll_outgoing();
}
