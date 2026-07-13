#![cfg(feature = "wireguard")]

use clave_core::{JoinReason, ZoneRegistry};
use clave_net::wireguard::{DecapResult, GatewayConfig, WireguardTunnel};
use clave_net::{FlowDisposition, Inbound, Outbound, SplitRouter, Tunnel, TunnelOut};
use clave_platform::ProcId;

fn pid(n: u32) -> ProcId {
    ProcId::windows(n, 1)
}

fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2] = (total >> 8) as u8;
    p[3] = (total & 0xff) as u8;
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    p.extend_from_slice(payload);
    p
}

fn endpoints() -> (SplitRouter, WireguardTunnel) {
    let dev_priv = [1u8; 32];
    let gw_priv = [2u8; 32];
    let dev_pub = WireguardTunnel::public_key(dev_priv);
    let gw_pub = WireguardTunnel::public_key(gw_priv);

    let dev_cfg = GatewayConfig::new(dev_priv, gw_pub, "gw:51820");
    let gw_cfg = GatewayConfig::new(gw_priv, dev_pub, "dev:51820");

    let router = SplitRouter::new(Box::new(
        WireguardTunnel::new(&dev_cfg, 1).expect("device tun"),
    ));
    let gateway = WireguardTunnel::new(&gw_cfg, 2).expect("gateway tun");
    (router, gateway)
}

#[test]
fn gateway_initiated_handshake_is_answered_through_the_router() {
    let (mut router, mut gateway) = endpoints();

    let init = match gateway.encapsulate(&ipv4_packet(b"warmup from gw")) {
        TunnelOut::SendToGateway(d) => d,
        TunnelOut::Idle => panic!("gateway should emit a handshake initiation"),
    };

    let response = match router.inbound(&init) {
        Inbound::ToGateway(r) => r,
        other => panic!("router must answer a handshake initiation, got {other:?}"),
    };

    match gateway.decapsulate_raw(&response) {
        DecapResult::Reply(_) | DecapResult::Done => {}
        DecapResult::Packet(_) => panic!("unexpected inner packet during handshake"),
    }

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

#[test]
fn device_initiated_session_round_trips_data_through_the_router() {
    let (mut router, mut gateway) = endpoints();
    let zones = ZoneRegistry::new();
    let work = pid(10);
    zones.join(work, JoinReason::Launcher);

    assert_eq!(
        router.open_flow(1, &work, &zones, false),
        FlowDisposition::HeldOffline
    );
    assert!(!router.link_is_up());

    let init = match router.outbound(1, &ipv4_packet(b"warmup")) {
        Outbound::ToGateway(d) => d,
        other => panic!("expected a handshake initiation, got {other:?}"),
    };

    let response = match gateway.decapsulate_raw(&init) {
        DecapResult::Reply(r) => r,
        _ => panic!("gateway should reply to the initiation"),
    };
    let _ = router.inbound(&response);

    assert!(
        router.link_is_up(),
        "the completed handshake brings the link up"
    );
    assert_eq!(
        router.open_flow(2, &work, &zones, false),
        FlowDisposition::Tunnel
    );

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

    let _ = router.tick();
    let _ = router.poll_outgoing();
}
