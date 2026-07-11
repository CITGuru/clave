//! Portable network-flow classification — the split-tunnel decision.
//!
//! This is the security-relevant half of the network subsystem and lives here, OS-free, so it
//! is shared by both platform tunnel adapters and tested without a driver, a gateway, or a TUN
//! device. The OS layers (WFP callout / `NETransparentProxyProvider`) only *capture* flows and
//! supply the authoritative identity; the routing *decision* is this function.

use crate::zone::ZoneRegistry;
use clave_platform::{ProcId, Route};

/// Decide where a flow egresses.
///
/// * **Personal (unsupervised) flows** always go [`Route::Direct`] and are never inspected —
///   the company never sees personal traffic (privacy by construction).
/// * **Work flows** are [`Route::Tunnel`]ed through the corporate gateway (static egress IP)
///   unless the destination is on the work-egress denylist, in which case [`Route::Block`].
///
/// `dst_blocked` is the policy allowlist result (computed by the caller from
/// [`crate::policy::NetworkPolicy::is_blocked`]).
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
        // host "blocked" is irrelevant: a personal process is never inspected or tunneled.
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
