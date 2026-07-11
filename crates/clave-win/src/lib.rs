//! # clave-win — Windows platform adapter (Phase 2 scaffold)
//!
//! Windows enforcement is a **WFP callout** (split-tunnel `ALE_CONNECT_REDIRECT`), a
//! **minifilter** (Clave Disk gating), and the injected **shim** — none of
//! which build on a non-Windows host. On macOS/Linux this crate compiles to a near-empty lib
//! (the `cfg(windows)` module is excluded) so the workspace builds everywhere; the portable
//! routing entry point below is shared with the real WFP callout.
#![forbid(unsafe_code)]

use clave_core::ZoneRegistry;
use clave_platform::{ProcId, Route};

mod platform;
pub use platform::WindowsPlatform;

/// Split-tunnel decision — the exact `clave-net`/`clave-core` logic the WFP callout invokes for
/// each `ALE_CONNECT_REDIRECT` classify on Windows (keyed on the metadata process id).
pub fn route(proc: &ProcId, zones: &ZoneRegistry, dst_blocked: bool) -> Route {
    clave_net::route(proc, zones, dst_blocked)
}

#[cfg(windows)]
mod imp {
    //! Real Windows enforcement — built only on Windows.
    //!
    //! * **WFP callout** registered at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`; its `classifyFn`
    //!   reads the process id from the classify metadata and calls [`super::route`], then
    //!   bind-redirects work flows onto the `wintun` tunnel (boringtun → gateway).
    //! * A **WinDivert** user-mode prototype of the same classifier for pre-driver iteration.
    //!
    //! The minifilter and any kernel driver are separate WDK / `windows-drivers-rs` projects
    //! (`native/win-driver`), signed via the Hardware Dashboard.
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
