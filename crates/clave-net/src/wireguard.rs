#[derive(Clone)]
pub struct GatewayConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub endpoint: String,
    pub static_egress_ip: Option<String>,
}

impl GatewayConfig {
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            private_key,
            peer_public_key,
            endpoint: endpoint.into(),
            static_egress_ip: None,
        }
    }
}

impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("private_key", &"<redacted>")
            .field("peer_public_key", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("static_egress_ip", &self.static_egress_ip)
            .finish()
    }
}

#[cfg(feature = "wireguard")]
pub use engine::{DecapResult, WireguardTunnel};

#[cfg(feature = "wireguard")]
mod engine {
    use super::GatewayConfig;
    use crate::{Inbound, Tunnel, TunnelOut};
    use boringtun::noise::{Tunn, TunnResult};
    use boringtun::x25519::{PublicKey, StaticSecret};

    const SCRATCH: usize = 2048;

    pub struct WireguardTunnel {
        tun: Tunn,
    }

    #[derive(Debug)]
    pub enum DecapResult {
        Packet(Vec<u8>),
        Reply(Vec<u8>),
        Done,
    }

    impl WireguardTunnel {
        pub fn new(cfg: &GatewayConfig, index: u32) -> Result<Self, String> {
            let secret = StaticSecret::from(cfg.private_key);
            let peer = PublicKey::from(cfg.peer_public_key);
            let tun =
                Tunn::new(secret, peer, None, None, index, None).map_err(|e| format!("{e:?}"))?;
            Ok(Self { tun })
        }

        pub fn public_key(private_key: [u8; 32]) -> [u8; 32] {
            let secret = StaticSecret::from(private_key);
            PublicKey::from(&secret).to_bytes()
        }

        pub fn decapsulate_raw(&mut self, datagram: &[u8]) -> DecapResult {
            let mut buf = vec![0u8; SCRATCH];
            match self.tun.decapsulate(None, datagram, &mut buf) {
                TunnResult::WriteToNetwork(b) => DecapResult::Reply(b.to_vec()),
                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                    DecapResult::Packet(p.to_vec())
                }
                TunnResult::Done | TunnResult::Err(_) => DecapResult::Done,
            }
        }
    }

    impl Tunnel for WireguardTunnel {
        fn encapsulate(&mut self, ip_packet: &[u8]) -> TunnelOut {
            let mut buf = vec![0u8; SCRATCH];
            match self.tun.encapsulate(ip_packet, &mut buf) {
                TunnResult::WriteToNetwork(b) => TunnelOut::SendToGateway(b.to_vec()),
                _ => TunnelOut::Idle,
            }
        }

        fn decapsulate(&mut self, datagram: &[u8]) -> Inbound {
            match self.decapsulate_raw(datagram) {
                DecapResult::Packet(p) => Inbound::ToProcess(p),
                DecapResult::Reply(r) => Inbound::ToGateway(r),
                DecapResult::Done => Inbound::Idle,
            }
        }

        fn poll_outgoing(&mut self) -> Option<Vec<u8>> {
            let mut buf = vec![0u8; SCRATCH];
            match self.tun.encapsulate(&[], &mut buf) {
                TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
                _ => None,
            }
        }

        fn update_timers(&mut self) -> Option<Vec<u8>> {
            let mut buf = vec![0u8; SCRATCH];
            match self.tun.update_timers(&mut buf) {
                TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_config_builds_and_redacts_keys() {
        let c = GatewayConfig::new([1u8; 32], [2u8; 32], "gw.example:51820");
        assert_eq!(c.endpoint, "gw.example:51820");
        assert!(c.static_egress_ip.is_none());
        let dbg = format!("{c:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(
            !dbg.contains("[1,"),
            "key byte array must not appear in Debug"
        );
    }
}

#[cfg(all(test, feature = "wireguard"))]
mod wg_tests {
    use super::{DecapResult, GatewayConfig, WireguardTunnel};
    use crate::{Inbound, Tunnel, TunnelOut};

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

    #[test]
    fn handshake_then_encrypted_round_trip() {
        let a_priv = [1u8; 32];
        let b_priv = [2u8; 32];
        let a_pub = WireguardTunnel::public_key(a_priv);
        let b_pub = WireguardTunnel::public_key(b_priv);

        let cfg_a = GatewayConfig::new(a_priv, b_pub, "b:51820");
        let cfg_b = GatewayConfig::new(b_priv, a_pub, "a:51820");
        let mut a = WireguardTunnel::new(&cfg_a, 1).expect("tunnel A");
        let mut b = WireguardTunnel::new(&cfg_b, 2).expect("tunnel B");

        let init = match a.encapsulate(&ipv4_packet(b"warmup")) {
            TunnelOut::SendToGateway(d) => d,
            TunnelOut::Idle => panic!("expected handshake initiation"),
        };

        let resp = match b.decapsulate_raw(&init) {
            DecapResult::Reply(r) => r,
            _ => panic!("B should reply with a handshake response"),
        };

        match a.decapsulate_raw(&resp) {
            DecapResult::Reply(_) | DecapResult::Done => {}
            DecapResult::Packet(_) => panic!("unexpected inner packet during handshake"),
        }

        let packet = ipv4_packet(b"the quick brown fox");
        let ciphertext = match a.encapsulate(&packet) {
            TunnelOut::SendToGateway(d) => d,
            TunnelOut::Idle => panic!("expected an encrypted data packet"),
        };
        assert_ne!(ciphertext, packet, "must be encrypted on the wire");

        let recovered = match b.decapsulate(&ciphertext) {
            Inbound::ToProcess(p) => p,
            other => panic!("B should decrypt an inner packet, got {other:?}"),
        };
        assert_eq!(recovered, packet);
    }
}
