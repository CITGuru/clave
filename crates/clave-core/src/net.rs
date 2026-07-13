use crate::policy::normalize_host;
use crate::zone::ZoneRegistry;
use clave_platform::{ProcId, Route};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub fn classify_flow(proc: &ProcId, zones: &ZoneRegistry, dst_blocked: bool) -> Route {
    if !zones.is_supervised(proc) {
        Route::Direct
    } else if dst_blocked {
        Route::Block
    } else {
        Route::Tunnel
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardMode {
    Wireguard,
    Ipsec,
    ExplicitProxy,
    Dns,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forwarding {
    PacketTunnel,
    FlowProxy,
    DnsOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderError {
    MissingEndpoint,
    MissingResolvers,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSteering {
    #[serde(default)]
    pub resolvers: Vec<String>,
    #[serde(default)]
    pub match_domains: Vec<String>,
    #[serde(default)]
    pub steer_all: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProvider {
    pub id: String,
    #[serde(default)]
    pub display_name: String,
    pub mode: ForwardMode,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub static_egress_ip: Option<String>,
    #[serde(default)]
    pub dns: Option<DnsSteering>,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

impl NetworkProvider {
    pub fn forwarding(&self) -> Result<Forwarding, ProviderError> {
        match self.mode {
            ForwardMode::Wireguard | ForwardMode::Ipsec => {
                if self.endpoints.is_empty() {
                    Err(ProviderError::MissingEndpoint)
                } else {
                    Ok(Forwarding::PacketTunnel)
                }
            }
            ForwardMode::ExplicitProxy => {
                if self.endpoints.is_empty() {
                    Err(ProviderError::MissingEndpoint)
                } else {
                    Ok(Forwarding::FlowProxy)
                }
            }
            ForwardMode::Dns => match &self.dns {
                Some(d) if !d.resolvers.is_empty() => Ok(Forwarding::DnsOnly),
                _ => Err(ProviderError::MissingResolvers),
            },
        }
    }

    pub fn is_egress(&self) -> bool {
        !matches!(self.mode, ForwardMode::Dns)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsDecision {
    Steer,
    Personal,
}

pub fn decide_dns(
    proc: &ProcId,
    qname: &str,
    zones: &ZoneRegistry,
    steering: &DnsSteering,
) -> DnsDecision {
    if !zones.is_supervised(proc) {
        return DnsDecision::Personal;
    }
    if steering.steer_all {
        return DnsDecision::Steer;
    }
    let qname = normalize_host(qname);
    if steering
        .match_domains
        .iter()
        .any(|domain| suffix_matches(&qname, domain))
    {
        DnsDecision::Steer
    } else {
        DnsDecision::Personal
    }
}

fn suffix_matches(qname: &str, domain: &str) -> bool {
    let domain = normalize_host(domain);
    if domain.is_empty() {
        return false;
    }
    qname == domain || qname.ends_with(&format!(".{domain}"))
}

pub fn classify_dns_flow(
    proc: &ProcId,
    zones: &ZoneRegistry,
    qname: &str,
    steering: Option<&DnsSteering>,
) -> Route {
    if !zones.is_supervised(proc) {
        return Route::Direct;
    }
    match steering {
        Some(steering) => match decide_dns(proc, qname, zones, steering) {
            DnsDecision::Steer => Route::Tunnel,
            DnsDecision::Personal => Route::Direct,
        },
        None => Route::Tunnel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JoinReason;

    fn pid(n: u32) -> ProcId {
        ProcId::windows(n, 1)
    }

    fn work(zones: &ZoneRegistry, n: u32) -> ProcId {
        let p = pid(n);
        zones.join(p, JoinReason::Launcher);
        p
    }

    #[test]
    fn personal_flows_route_direct_even_when_host_is_denylisted() {
        let zones = ZoneRegistry::new();
        assert_eq!(classify_flow(&pid(1), &zones, true), Route::Direct);
    }

    #[test]
    fn work_flow_tunnels_unless_blocked() {
        let zones = ZoneRegistry::new();
        let p = work(&zones, 1);
        assert_eq!(classify_flow(&p, &zones, false), Route::Tunnel);
        assert_eq!(classify_flow(&p, &zones, true), Route::Block);
    }

    fn ipsec(endpoints: &[&str]) -> NetworkProvider {
        NetworkProvider {
            id: "zscaler-zia".into(),
            display_name: "Zscaler Internet Access".into(),
            mode: ForwardMode::Ipsec,
            endpoints: endpoints.iter().map(|s| s.to_string()).collect(),
            static_egress_ip: Some("203.0.113.10".into()),
            dns: None,
            params: BTreeMap::new(),
        }
    }

    fn umbrella(steer_all: bool, resolvers: &[&str]) -> NetworkProvider {
        NetworkProvider {
            id: "cisco-umbrella".into(),
            display_name: "Cisco Umbrella (DNS)".into(),
            mode: ForwardMode::Dns,
            endpoints: Vec::new(),
            static_egress_ip: None,
            dns: Some(DnsSteering {
                resolvers: resolvers.iter().map(|s| s.to_string()).collect(),
                match_domains: Vec::new(),
                steer_all,
            }),
            params: BTreeMap::new(),
        }
    }

    #[test]
    fn dispatch_is_vendor_neutral() {
        assert_eq!(
            ipsec(&["gre1.zscaler.net:4500"]).forwarding(),
            Ok(Forwarding::PacketTunnel)
        );
        assert_eq!(
            umbrella(true, &["208.67.222.222"]).forwarding(),
            Ok(Forwarding::DnsOnly)
        );
    }

    #[test]
    fn provider_missing_required_fields_is_rejected() {
        assert_eq!(ipsec(&[]).forwarding(), Err(ProviderError::MissingEndpoint));
        assert_eq!(
            umbrella(true, &[]).forwarding(),
            Err(ProviderError::MissingResolvers)
        );
    }

    #[test]
    fn explicit_proxy_needs_endpoint_and_drives_flow_proxy() {
        let mut p = ipsec(&["proxy.zscaler.net:443"]);
        p.mode = ForwardMode::ExplicitProxy;
        assert_eq!(p.forwarding(), Ok(Forwarding::FlowProxy));
        p.endpoints.clear();
        assert_eq!(p.forwarding(), Err(ProviderError::MissingEndpoint));
    }

    #[test]
    fn vendor_profile_round_trips_through_json() {
        let p = ipsec(&["gre1.zscaler.net:4500"]);
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"ipsec\""));
        assert_eq!(serde_json::from_str::<NetworkProvider>(&json).unwrap(), p);
    }

    #[test]
    fn umbrella_steers_all_work_dns_but_never_personal() {
        let zones = ZoneRegistry::new();
        let w = work(&zones, 1);
        let steering = umbrella(true, &["208.67.222.222"]).dns.unwrap();
        assert_eq!(
            decide_dns(&w, "example.com", &zones, &steering),
            DnsDecision::Steer
        );
        assert_eq!(
            decide_dns(&pid(2), "example.com", &zones, &steering),
            DnsDecision::Personal
        );
    }

    #[test]
    fn split_horizon_steers_only_work_domains() {
        let zones = ZoneRegistry::new();
        let w = work(&zones, 1);
        let steering = DnsSteering {
            resolvers: vec!["10.0.0.53".into()],
            match_domains: vec!["corp.example".into()],
            steer_all: false,
        };
        assert_eq!(
            decide_dns(&w, "git.corp.example", &zones, &steering),
            DnsDecision::Steer
        );
        assert_eq!(
            decide_dns(&w, "corp.example.", &zones, &steering),
            DnsDecision::Steer
        );
        assert_eq!(
            decide_dns(&w, "notcorp.example", &zones, &steering),
            DnsDecision::Personal
        );
        assert_eq!(
            decide_dns(&w, "public.com", &zones, &steering),
            DnsDecision::Personal
        );
    }

    #[test]
    fn dns_flow_keeps_personal_queries_off_the_tunnel() {
        let zones = ZoneRegistry::new();
        let steering = umbrella(true, &["208.67.222.222"]).dns.unwrap();
        assert_eq!(
            classify_dns_flow(&pid(9), &zones, "anything.com", Some(&steering)),
            Route::Direct
        );
        assert_eq!(
            classify_dns_flow(&pid(9), &zones, "anything.com", None),
            Route::Direct
        );
    }

    #[test]
    fn work_dns_tunnels_by_default_and_when_steered() {
        let zones = ZoneRegistry::new();
        let w = work(&zones, 1);
        assert_eq!(
            classify_dns_flow(&w, &zones, "intra.corp", None),
            Route::Tunnel
        );
        let steer_all = umbrella(true, &["208.67.222.222"]).dns.unwrap();
        assert_eq!(
            classify_dns_flow(&w, &zones, "intra.corp", Some(&steer_all)),
            Route::Tunnel
        );
    }

    #[test]
    fn split_horizon_dns_flow_keeps_public_work_names_direct() {
        let zones = ZoneRegistry::new();
        let w = work(&zones, 1);
        let steering = DnsSteering {
            resolvers: vec!["10.0.0.53".into()],
            match_domains: vec!["corp.example".into()],
            steer_all: false,
        };
        assert_eq!(
            classify_dns_flow(&w, &zones, "git.corp.example", Some(&steering)),
            Route::Tunnel
        );
        assert_eq!(
            classify_dns_flow(&w, &zones, "news.example.com", Some(&steering)),
            Route::Direct
        );
    }
}
