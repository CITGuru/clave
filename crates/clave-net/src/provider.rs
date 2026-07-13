use crate::{GatewayConfig, Tunnel};
use clave_core::{ForwardMode, NetworkProvider, ProviderError};

pub enum EgressSeam {
    Packet(Box<dyn Tunnel>),
    DnsOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeamError {
    Invalid(ProviderError),
    Unsupported(ForwardMode),
    MissingKeys,
    Backend(String),
}

pub fn build_egress(
    provider: &NetworkProvider,
    wg: Option<&GatewayConfig>,
    index: u32,
) -> Result<EgressSeam, SeamError> {
    provider.forwarding().map_err(SeamError::Invalid)?;
    match provider.mode {
        ForwardMode::Wireguard => build_wireguard(wg, index),
        ForwardMode::Dns => Ok(EgressSeam::DnsOnly),
        mode @ (ForwardMode::Ipsec | ForwardMode::ExplicitProxy) => {
            Err(SeamError::Unsupported(mode))
        }
    }
}

#[cfg(feature = "wireguard")]
fn build_wireguard(wg: Option<&GatewayConfig>, index: u32) -> Result<EgressSeam, SeamError> {
    let cfg = wg.ok_or(SeamError::MissingKeys)?;
    let tun = crate::wireguard::WireguardTunnel::new(cfg, index).map_err(SeamError::Backend)?;
    Ok(EgressSeam::Packet(Box::new(tun)))
}

#[cfg(not(feature = "wireguard"))]
fn build_wireguard(_wg: Option<&GatewayConfig>, _index: u32) -> Result<EgressSeam, SeamError> {
    Err(SeamError::Unsupported(ForwardMode::Wireguard))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clave_core::{DnsSteering, Forwarding};
    use std::collections::BTreeMap;

    fn provider(mode: ForwardMode, endpoints: &[&str]) -> NetworkProvider {
        NetworkProvider {
            id: "p".into(),
            display_name: String::new(),
            mode,
            endpoints: endpoints.iter().map(|s| s.to_string()).collect(),
            static_egress_ip: None,
            dns: None,
            params: BTreeMap::new(),
        }
    }

    fn err(r: Result<EgressSeam, SeamError>) -> SeamError {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected a refusal, got a live seam"),
        }
    }

    #[test]
    fn dns_provider_yields_dns_only_seam() {
        let mut p = provider(ForwardMode::Dns, &[]);
        p.dns = Some(DnsSteering {
            resolvers: vec!["208.67.222.222".into()],
            match_domains: Vec::new(),
            steer_all: true,
        });
        assert_eq!(p.forwarding(), Ok(Forwarding::DnsOnly));
        assert!(matches!(build_egress(&p, None, 0), Ok(EgressSeam::DnsOnly)));
    }

    #[test]
    fn unbuilt_modes_are_refused_not_downgraded() {
        assert_eq!(
            err(build_egress(
                &provider(ForwardMode::Ipsec, &["gw:4500"]),
                None,
                0
            )),
            SeamError::Unsupported(ForwardMode::Ipsec)
        );
        assert_eq!(
            err(build_egress(
                &provider(ForwardMode::ExplicitProxy, &["proxy:443"]),
                None,
                0
            )),
            SeamError::Unsupported(ForwardMode::ExplicitProxy)
        );
    }

    #[test]
    fn invalid_provider_is_rejected_before_any_seam() {
        assert_eq!(
            err(build_egress(&provider(ForwardMode::Ipsec, &[]), None, 0)),
            SeamError::Invalid(ProviderError::MissingEndpoint)
        );
    }

    #[cfg(feature = "wireguard")]
    #[test]
    fn wireguard_needs_key_material() {
        let p = provider(ForwardMode::Wireguard, &["gw:51820"]);
        assert_eq!(err(build_egress(&p, None, 0)), SeamError::MissingKeys);
        let cfg = GatewayConfig::new([1u8; 32], [2u8; 32], "gw:51820");
        assert!(matches!(
            build_egress(&p, Some(&cfg), 0),
            Ok(EgressSeam::Packet(_))
        ));
    }

    #[cfg(not(feature = "wireguard"))]
    #[test]
    fn wireguard_unsupported_without_feature() {
        let p = provider(ForwardMode::Wireguard, &["gw:51820"]);
        assert_eq!(
            err(build_egress(&p, None, 0)),
            SeamError::Unsupported(ForwardMode::Wireguard)
        );
    }
}
