//! [`MacPlatform`] — the daemon-side macOS [`Platform`] adapter.
//!
//! This is the object a `clave-daemon` runs on macOS. Two capabilities are wired to real Rust
//! decision logic that the System Extensions drive over XPC (deferred): **process supervision**
//! (the ES-fed zone mirror) and **network split-tunnel** (the shared `clave-net` classifier — the
//! same decision the FFI and Windows use). The rest are honest stubs for unbuilt subsystems.
//!
//! Crucially, [`Platform::enforcement`] reports each capability's *true* posture, so a production
//! build refuses to claim a control it doesn't actually enforce: nothing here reaches
//! `Enforced`. The ES/NE paths are `DevelopmentOnly` (they need the entitlements / a SIP-disabled
//! lab Mac); the unbuilt subsystems are `Unavailable`. A real adapter recomputes these
//! at runtime as it detects the extensions connecting, entitlements present, and SIP state.

use std::sync::{Arc, Mutex};

use clave_core::ZoneRegistry;
use clave_platform::{
    Capability, ClipFormat, ClipboardBroker, Decision, EnforcementStatus, InputGuard,
    NetworkTunnel, PResult, Platform, ProcId, ProcessSupervisor, Rgba, Route, ScreenGuard,
    VolumeMount, WindowId, WindowOverlay, Zone,
};

/// Split-tunnel routing via the shared classifier — the same decision as Windows and the FFI path.
pub struct MacNetwork {
    zones: Arc<ZoneRegistry>,
}

impl NetworkTunnel for MacNetwork {
    fn route(&self, proc: &ProcId, dst_blocked: bool) -> Route {
        clave_net::route(proc, &self.zones, dst_blocked)
    }
}

/// The encrypted-volume mount (encrypted APFS / sparsebundle) — not built yet.
#[derive(Default)]
pub struct MacVolumeMount;

impl VolumeMount for MacVolumeMount {
    fn is_mounted(&self) -> bool {
        false
    }
    fn mount_point(&self) -> Option<String> {
        None
    }
    fn request_wipe(&self) -> PResult<()> {
        // The authoritative crypto-shred is the volume core's job (`clave-volume`); with no OS
        // mount there is nothing to tear down here.
        Ok(())
    }
}

/// Clipboard DLP — the macOS broker is Phase 5. No enforcement yet.
#[derive(Default)]
pub struct MacClipboard;

impl ClipboardBroker for MacClipboard {
    fn classify_and_gate(&self, src: Zone, dst: Zone, _fmt: ClipFormat) -> Decision {
        // Fail-closed: with no broker installed we cannot enforce the nuanced policy matrix, so
        // allow same-zone and deny cross-zone. (The real broker consults the policy.)
        if src == dst {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

/// Screen-capture protection — Phase 5. No protection yet.
#[derive(Default)]
pub struct MacScreen;

impl ScreenGuard for MacScreen {
    fn protect_window(&self, _w: WindowId) -> PResult<()> {
        Ok(()) // best-effort no-op until the Phase-5 ScreenCaptureKit path exists
    }
}

/// Clave Edge overlay — Phase 5. No overlay yet.
#[derive(Default)]
pub struct MacOverlay;

impl WindowOverlay for MacOverlay {
    fn track(&self, _w: WindowId, _color: Rgba) {}
    fn untrack(&self, _w: WindowId) {}
}

/// Input isolation — Phase 6, optional. Not protected.
#[derive(Default)]
pub struct MacInput;

impl InputGuard for MacInput {
    fn protect_input_enabled(&self) -> bool {
        false
    }
}

/// The macOS platform adapter, built around the daemon's shared zone mirror (`zones`), which the
/// ES System Extension feeds over XPC in production (deferred). See the module docs.
pub struct MacPlatform {
    zones: Arc<ZoneRegistry>,
    network: MacNetwork,
    volume: MacVolumeMount,
    clipboard: MacClipboard,
    screen: MacScreen,
    overlay: MacOverlay,
    input: MacInput,
    enforcement: Mutex<[(Capability, EnforcementStatus); Capability::COUNT]>,
}

impl MacPlatform {
    /// Build the adapter around `zones` — the daemon's mirror, shared so one membership set governs
    /// both routing and the access gate (as `MockPlatform` does in tests).
    pub fn new(zones: Arc<ZoneRegistry>) -> Self {
        let network = MacNetwork {
            zones: Arc::clone(&zones),
        };
        Self {
            zones,
            network,
            volume: MacVolumeMount,
            clipboard: MacClipboard,
            screen: MacScreen,
            overlay: MacOverlay,
            input: MacInput,
            enforcement: Mutex::new(default_enforcement()),
        }
    }

    /// Update a capability's reported posture. A production adapter calls this at runtime as it
    /// detects the System Extensions connecting, entitlements present, SIP state, etc. Nothing
    /// should be set to `Enforced` unless running on a stock, properly-signed/entitled OS.
    pub fn set_enforcement(&self, cap: Capability, status: EnforcementStatus) {
        for e in self
            .enforcement
            .lock()
            .expect("enforcement lock poisoned")
            .iter_mut()
        {
            if e.0 == cap {
                e.1 = status;
            }
        }
    }
}

/// Honest defaults for the current scaffold: the ES/NE paths have real Rust decision logic but only
/// dev-grade enforcement (they need entitlements / a SIP-disabled Mac); the unbuilt
/// subsystems are `Unavailable`.
fn default_enforcement() -> [(Capability, EnforcementStatus); Capability::COUNT] {
    use Capability::*;
    use EnforcementStatus::*;
    [
        (ProcessSupervision, DevelopmentOnly),
        (Volume, Unavailable),
        (Clipboard, Unavailable),
        (Network, DevelopmentOnly),
        (Screen, Unavailable),
        (Overlay, Unavailable),
        (Input, Unavailable),
    ]
}

impl Platform for MacPlatform {
    fn supervisor(&self) -> &dyn ProcessSupervisor {
        &*self.zones
    }
    fn volume(&self) -> &dyn VolumeMount {
        &self.volume
    }
    fn clipboard(&self) -> &dyn ClipboardBroker {
        &self.clipboard
    }
    fn network(&self) -> &dyn NetworkTunnel {
        &self.network
    }
    fn screen(&self) -> &dyn ScreenGuard {
        &self.screen
    }
    fn overlay(&self) -> &dyn WindowOverlay {
        &self.overlay
    }
    fn input(&self) -> &dyn InputGuard {
        &self.input
    }
    fn enforcement(&self, cap: Capability) -> EnforcementStatus {
        self.enforcement
            .lock()
            .expect("enforcement lock poisoned")
            .iter()
            .find(|e| e.0 == cap)
            .map(|e| e.1)
            .unwrap_or(EnforcementStatus::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clave_core::JoinReason;
    use clave_platform::EnforcementReport;

    fn platform() -> MacPlatform {
        MacPlatform::new(Arc::new(ZoneRegistry::new()))
    }

    #[test]
    fn supervisor_and_network_share_the_zone_mirror() {
        let p = platform();
        let work = ProcId::macos([1, 2, 3, 4, 5, 6, 7, 8]);
        // Personal until the ES client seeds membership → never inspected, routes Direct.
        assert!(!p.supervisor().is_supervised(&work));
        assert_eq!(p.network().route(&work, false), Route::Direct);

        p.zones.join(work, JoinReason::Launcher);
        assert!(p.supervisor().is_supervised(&work));
        assert_eq!(p.network().route(&work, false), Route::Tunnel);
        assert_eq!(p.network().route(&work, true), Route::Block);
    }

    #[test]
    fn enforcement_report_is_honest_and_not_production_ready() {
        let p = platform();
        let r: EnforcementReport = p.enforcement_report();
        assert!(
            !r.is_production_ready(),
            "a dev/scaffold adapter is never production-ready"
        );
        // Wired but dev-grade:
        assert_eq!(
            r.status(Capability::ProcessSupervision),
            EnforcementStatus::DevelopmentOnly
        );
        assert_eq!(
            r.status(Capability::Network),
            EnforcementStatus::DevelopmentOnly
        );
        // Unbuilt subsystems:
        assert_eq!(r.status(Capability::Volume), EnforcementStatus::Unavailable);
        assert_eq!(
            r.status(Capability::Clipboard),
            EnforcementStatus::Unavailable
        );
    }

    #[test]
    fn enforcement_can_be_promoted_at_runtime() {
        let p = platform();
        // A production adapter never does this on a SIP-off box, but the mechanism exists for when
        // a capability genuinely reaches production posture.
        for cap in Capability::ALL {
            p.set_enforcement(cap, EnforcementStatus::Enforced);
        }
        assert!(p.enforcement_report().is_production_ready());
    }
}
