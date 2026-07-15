// The portable core stays unsafe-free everywhere; the Windows enforcement adapters
// (clipboard, screen, etc.) confine their Win32 FFI to `#[allow(unsafe_code)]` modules.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

use clave_core::ZoneRegistry;
use clave_platform::{ProcId, Route};

mod clipboard;
mod divert;
mod platform;
pub use clipboard::{ClipboardGuard, GuardAction};
pub use divert::NetVerdict;
pub use platform::WindowsPlatform;

#[cfg(windows)]
mod edge;
#[cfg(windows)]
mod input;
#[cfg(windows)]
mod job;
#[cfg(windows)]
mod mount;
#[cfg(windows)]
mod screen;
#[cfg(windows)]
pub use clipboard::run_clipboard_guard;
#[cfg(windows)]
pub use divert::run_split_tunnel;
#[cfg(windows)]
pub use edge::run_clave_edge;
#[cfg(windows)]
pub use input::run_input_guard;
#[cfg(windows)]
pub use job::ContainmentJob;
#[cfg(windows)]
pub use mount::spawn_clave_disk;
#[cfg(windows)]
pub use screen::exclude_from_capture;

pub fn route(proc: &ProcId, zones: &ZoneRegistry, dst_blocked: bool) -> Route {
    clave_net::route(proc, zones, dst_blocked)
}

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
