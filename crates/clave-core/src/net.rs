use crate::zone::ZoneRegistry;
use clave_platform::{ProcId, Route};

pub fn classify_flow(proc: &ProcId, zones: &ZoneRegistry, dst_blocked: bool) -> Route {
    if !zones.is_supervised(proc) {
        Route::Direct
    } else if dst_blocked {
        Route::Block
    } else {
        Route::Tunnel
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JoinReason;

    fn pid(n: u32) -> ProcId {
        ProcId::windows(n, 1)
    }

    #[test]
    fn personal_flows_route_direct_even_when_host_is_denylisted() {
        let zones = ZoneRegistry::new();
        assert_eq!(classify_flow(&pid(1), &zones, true), Route::Direct);
    }

    #[test]
    fn work_flow_tunnels_unless_blocked() {
        let zones = ZoneRegistry::new();
        let p = pid(1);
        zones.join(p, JoinReason::Launcher);
        assert_eq!(classify_flow(&p, &zones, false), Route::Tunnel);
        assert_eq!(classify_flow(&p, &zones, true), Route::Block);
    }
}
