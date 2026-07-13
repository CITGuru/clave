use crate::{Inbound, Tunnel, TunnelOut};

pub struct LoopbackTunnel {
    key: u8,
}

impl LoopbackTunnel {
    pub fn new(key: u8) -> Self {
        Self { key }
    }
}

impl Tunnel for LoopbackTunnel {
    fn encapsulate(&mut self, ip_packet: &[u8]) -> TunnelOut {
        if ip_packet.is_empty() {
            return TunnelOut::Idle;
        }
        TunnelOut::SendToGateway(ip_packet.iter().map(|b| b ^ self.key).collect())
    }

    fn decapsulate(&mut self, datagram: &[u8]) -> Inbound {
        if datagram.is_empty() {
            return Inbound::Idle;
        }
        Inbound::ToProcess(datagram.iter().map(|b| b ^ self.key).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_obscures_plaintext() {
        let mut sender = LoopbackTunnel::new(0x5A);
        let mut gateway = LoopbackTunnel::new(0x5A);

        let packet = b"the quick brown fox jumps".to_vec();
        let wire = match sender.encapsulate(&packet) {
            TunnelOut::SendToGateway(w) => w,
            TunnelOut::Idle => panic!("expected wire output"),
        };
        assert_ne!(
            wire, packet,
            "encapsulated bytes must differ from plaintext"
        );

        let recovered = match gateway.decapsulate(&wire) {
            Inbound::ToProcess(p) => p,
            other => panic!("expected an inner packet, got {other:?}"),
        };
        assert_eq!(recovered, packet);
    }

    #[test]
    fn empty_input_is_idle() {
        let mut t = LoopbackTunnel::new(1);
        assert_eq!(t.encapsulate(&[]), TunnelOut::Idle);
        assert!(matches!(t.decapsulate(&[]), Inbound::Idle));
    }
}
