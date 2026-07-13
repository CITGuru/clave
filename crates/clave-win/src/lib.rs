#![forbid(unsafe_code)]

use clave_core::ZoneRegistry;
use clave_platform::{ProcId, Route};

mod platform;
pub use platform::WindowsPlatform;

pub fn route(proc: &ProcId, zones: &ZoneRegistry, dst_blocked: bool) -> Route {
    clave_net::route(proc, zones, dst_blocked)
}

#[cfg(windows)]
mod imp {}

#[cfg(test)]
mod tests {
    use super::*;
    use clave_core::JoinReason;

    #[test]
    fn route_matches_shared_semantics() {
        let zones = ZoneRegistry::new();
        let work = ProcId::windows(1, 1);
        zones.join(work, JoinReason::Launcher);

        assert_eq!(route(&work, &zones, false), Route::Tunnel);
        assert_eq!(route(&work, &zones, true), Route::Block);
        assert_eq!(route(&ProcId::windows(2, 1), &zones, false), Route::Direct);
    }
}
