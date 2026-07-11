//! [`WindowsPlatform`] — the daemon-side Windows [`Platform`] adapter.
//!
//! The Windows mechanism is a signed **WFP callout** (split tunnel), a **minifilter**
//! (Clave Disk gating), and a **process-notify driver** that feeds the supervised set over
//! an inverted-call `DeviceIoControl` channel — none of which build on a non-Windows
//! host (they live behind `cfg(windows)` and in the WDK driver project). This adapter is the
//! portable daemon-side seam: **process supervision** (the driver-fed zone mirror) and **network
//! split-tunnel** (the shared `clave-net` classifier the WFP callout invokes) are wired to real
//! decision logic; the rest are honest stubs.
//!
//! [`Platform::enforcement`] reports the truth: nothing reaches `Enforced`
//! without Microsoft-signed drivers on a Secure-Boot machine. The process/network paths are
//! `DevelopmentOnly` (a WinDivert / toolhelp / Job-object stand-in or a test-signed driver);
//! the unbuilt subsystems are `Unavailable`.

use std::sync::{Arc, Mutex};

use clave_core::ZoneRegistry;
use clave_platform::{
    Capability, ClipFormat, ClipboardBroker, Decision, EnforcementStatus, InputGuard,
    NetworkTunnel, PResult, Platform, ProcId, ProcessSupervisor, Rgba, Route, ScreenGuard,
    VolumeMount, WindowId, WindowOverlay, Zone,
};

/// Split-tunnel routing via the shared classifier — the same decision the WFP callout invokes for
/// each `ALE_CONNECT_REDIRECT` classify, and the same as macOS.
pub struct WinNetwork {
    zones: Arc<ZoneRegistry>,
}

impl NetworkTunnel for WinNetwork {
    fn route(&self, proc: &ProcId, dst_blocked: bool) -> Route {
        clave_net::route(proc, &self.zones, dst_blocked)
    }
}

/// The encrypted-volume mount (a WinFsp encrypting filesystem) — not built yet.
#[derive(Default)]
pub struct WinVolumeMount;

impl VolumeMount for WinVolumeMount {
    fn is_mounted(&self) -> bool {
        false
    }
    fn mount_point(&self) -> Option<String> {
        None
    }
    fn request_wipe(&self) -> PResult<()> {
        // The authoritative crypto-shred is the volume core's job (`clave-volume`); with no WinFsp
        // mount there is nothing to tear down here.
        Ok(())
    }
}

/// Clipboard DLP — the Windows broker (per-process clipboard gate) is Phase 5.
#[derive(Default)]
pub struct WinClipboard;

impl ClipboardBroker for WinClipboard {
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

/// Screen-capture protection — `SetWindowDisplayAffinity` via the shim, Phase 5.
#[derive(Default)]
pub struct WinScreen;

impl ScreenGuard for WinScreen {
    fn protect_window(&self, _w: WindowId) -> PResult<()> {
        Ok(()) // best-effort no-op until the Phase-5 affinity path exists
    }
}

/// Clave Edge overlay — layered window + `SetWinEventHook`, Phase 5.
#[derive(Default)]
pub struct WinOverlay;

impl WindowOverlay for WinOverlay {
    fn track(&self, _w: WindowId, _color: Rgba) {}
    fn untrack(&self, _w: WindowId) {}
}

/// Input isolation — keyboard filter driver, Phase 6 (optional). Not protected.
#[derive(Default)]
pub struct WinInput;

impl InputGuard for WinInput {
    fn protect_input_enabled(&self) -> bool {
        false
    }
}

/// The Windows platform adapter, built around the daemon's shared zone mirror (`zones`), which the
/// process-notify driver feeds over the inverted-call IOCTL channel in production (deferred).
pub struct WindowsPlatform {
    zones: Arc<ZoneRegistry>,
    network: WinNetwork,
    volume: WinVolumeMount,
    clipboard: WinClipboard,
    screen: WinScreen,
    overlay: WinOverlay,
    input: WinInput,
    enforcement: Mutex<[(Capability, EnforcementStatus); Capability::COUNT]>,
}

impl WindowsPlatform {
    /// Build the adapter around `zones` — the daemon's mirror, shared so one membership set governs
    /// both routing and the access gate.
    pub fn new(zones: Arc<ZoneRegistry>) -> Self {
        let network = WinNetwork {
            zones: Arc::clone(&zones),
        };
        Self {
            zones,
            network,
            volume: WinVolumeMount,
            clipboard: WinClipboard,
            screen: WinScreen,
            overlay: WinOverlay,
            input: WinInput,
            enforcement: Mutex::new(default_enforcement()),
        }
    }

    /// Update a capability's reported posture. A production adapter calls this at runtime as it
    /// detects the signed drivers loaded, Secure Boot state, etc. Nothing should be set to
    /// `Enforced` unless running on a stock, Microsoft-signed, Secure-Boot machine.
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

/// Honest defaults: the WFP/process paths have real Rust decision logic but only dev-grade
/// enforcement (a WinDivert/toolhelp stand-in or a test-signed driver); the unbuilt
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

impl Platform for WindowsPlatform {
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

    fn platform() -> WindowsPlatform {
        WindowsPlatform::new(Arc::new(ZoneRegistry::new()))
    }

    #[test]
    fn supervisor_and_network_share_the_zone_mirror() {
        let p = platform();
        let work = ProcId::windows(1234, 1);
        // Personal until the driver seeds membership → never inspected, routes Direct.
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
        assert_eq!(
            r.status(Capability::ProcessSupervision),
            EnforcementStatus::DevelopmentOnly
        );
        assert_eq!(
            r.status(Capability::Network),
            EnforcementStatus::DevelopmentOnly
        );
        assert_eq!(r.status(Capability::Volume), EnforcementStatus::Unavailable);
    }

    #[test]
    fn enforcement_can_be_promoted_at_runtime() {
        let p = platform();
        for cap in Capability::ALL {
            p.set_enforcement(cap, EnforcementStatus::Enforced);
        }
        assert!(p.enforcement_report().is_production_ready());
    }
}
