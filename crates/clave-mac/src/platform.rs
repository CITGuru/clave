//! [`MacPlatform`] — the daemon-side macOS [`Platform`] adapter.
//!
//! Process supervision (the ES-fed zone mirror) and network split-tunnel (the shared `clave-net`
//! classifier) are wired to real decision logic; the rest are honest stubs. [`Platform::enforcement`]
//! reports each capability's true posture — nothing here reaches `Enforced`: the ES/NE paths are
//! `DevelopmentOnly` (need entitlements / a SIP-disabled Mac), the unbuilt subsystems `Unavailable`.

use std::sync::{Arc, Mutex};

use clave_core::ZoneRegistry;
use clave_platform::{
    Capability, ClipFormat, ClipboardBroker, Decision, EnforcementStatus, InputGuard,
    NetworkTunnel, PResult, Platform, ProcId, ProcessSupervisor, Rgba, Route, ScreenGuard,
    VolumeMount, WindowId, WindowOverlay, Zone,
};

use crate::sip::SipStatus;

/// Split-tunnel routing via the shared classifier — the same decision as Windows and the FFI path.
pub struct MacNetwork {
    zones: Arc<ZoneRegistry>,
}

impl NetworkTunnel for MacNetwork {
    fn route(&self, proc: &ProcId, dst_blocked: bool) -> Route {
        clave_net::route(proc, &self.zones, dst_blocked)
    }
}

/// The encrypted-volume mount (encrypted APFS / sparsebundle) — not built yet. A lab build may set a
/// dev mount point so contained launch specs resolve before the real mount exists; the volume's
/// [`EnforcementStatus`] stays `Unavailable`.
#[derive(Default)]
pub struct MacVolumeMount {
    dev_mount_point: Option<String>,
}

impl VolumeMount for MacVolumeMount {
    fn is_mounted(&self) -> bool {
        self.dev_mount_point.is_some()
    }
    fn mount_point(&self) -> Option<String> {
        self.dev_mount_point.clone()
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

/// Windows explicitly tracked as work windows (via the shim/ES path) plus the color to frame each
/// with. Shared (`Arc`) so the native drawer can read the current set.
pub type TrackedWindows = Arc<Mutex<std::collections::HashMap<WindowId, Rgba>>>;

/// Clave Edge overlay bookkeeping: the explicitly-tracked window set. The pixels are drawn by the
/// native drawer, which also discovers launched-app windows by owner pid. A dev-grade affordance,
/// never `Enforced`.
#[derive(Clone, Default)]
pub struct MacOverlay {
    tracked: TrackedWindows,
}

impl MacOverlay {
    /// The shared handle to the tracked-window set, for a native drawer to read.
    pub fn tracked_handle(&self) -> TrackedWindows {
        Arc::clone(&self.tracked)
    }
}

impl WindowOverlay for MacOverlay {
    fn track(&self, w: WindowId, color: Rgba) {
        self.tracked
            .lock()
            .expect("overlay lock poisoned")
            .insert(w, color);
    }
    fn untrack(&self, w: WindowId) {
        self.tracked
            .lock()
            .expect("overlay lock poisoned")
            .remove(&w);
    }
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
            volume: MacVolumeMount::default(),
            clipboard: MacClipboard,
            screen: MacScreen,
            overlay: MacOverlay::default(),
            input: MacInput,
            enforcement: Mutex::new(default_enforcement()),
        }
    }

    /// Reconcile the ES/NE posture with the machine's live SIP state, returning the applied
    /// [`SipStatus`]. The dev enforcement path is an unsigned extension that only loads on a
    /// SIP-disabled Mac: SIP disabled → `DevelopmentOnly`, else `Unavailable`. Never `Enforced`.
    pub fn apply_sip_posture(&self, sip: SipStatus) -> SipStatus {
        let status = if sip.is_disabled() {
            EnforcementStatus::DevelopmentOnly
        } else {
            EnforcementStatus::Unavailable
        };
        self.set_enforcement(Capability::ProcessSupervision, status);
        self.set_enforcement(Capability::Network, status);
        sip
    }

    /// Detect the live SIP state and apply it via [`MacPlatform::apply_sip_posture`].
    pub fn detect_and_apply_sip_posture(&self) -> SipStatus {
        self.apply_sip_posture(SipStatus::detect())
    }

    /// The shared zone mirror — the native Clave Edge drawer reads `supervised_pids()` from it to
    /// pick which on-screen windows to frame.
    pub fn zones(&self) -> Arc<ZoneRegistry> {
        Arc::clone(&self.zones)
    }

    /// The shared handle to the explicitly-tracked window set (shim/ES `WindowCreated` path).
    pub fn overlay_tracked(&self) -> TrackedWindows {
        self.overlay.tracked_handle()
    }

    /// Set a dev Clave Disk mount point so a lab daemon can resolve contained launch specs before the
    /// real mount exists. Does not promote the volume's enforcement posture (stays `Unavailable`).
    pub fn set_dev_mount_point(&mut self, path: impl Into<String>) {
        self.volume.dev_mount_point = Some(path.into());
    }

    /// Update a capability's reported posture (a production adapter calls this as it detects
    /// extensions connecting, entitlements, SIP state, etc.).
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

/// Honest defaults: the ES/NE paths are `DevelopmentOnly`; the unbuilt subsystems are `Unavailable`.
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
    fn sip_disabled_keeps_es_ne_paths_development_only() {
        let p = platform();
        p.apply_sip_posture(SipStatus::Disabled);
        let r = p.enforcement_report();
        assert_eq!(
            r.status(Capability::ProcessSupervision),
            EnforcementStatus::DevelopmentOnly
        );
        assert_eq!(
            r.status(Capability::Network),
            EnforcementStatus::DevelopmentOnly
        );
        assert!(!r.is_production_ready());
    }

    #[test]
    fn sip_enabled_without_entitlement_makes_es_ne_paths_unavailable() {
        let p = platform();
        // SIP on and no entitled extension connected: an unsigned dev extension can't load, so the
        // honest posture is that nothing can enforce these yet.
        for sip in [SipStatus::Enabled, SipStatus::Unknown] {
            p.apply_sip_posture(sip);
            let r = p.enforcement_report();
            assert_eq!(
                r.status(Capability::ProcessSupervision),
                EnforcementStatus::Unavailable
            );
            assert_eq!(r.status(Capability::Network), EnforcementStatus::Unavailable);
        }
    }

    #[test]
    fn overlay_records_and_forgets_tracked_windows() {
        let p = platform();
        let tracked = p.overlay_tracked();
        assert!(tracked.lock().unwrap().is_empty());
        p.overlay().track(WindowId(7), Rgba::CLAVE_EDGE);
        p.overlay().track(WindowId(9), Rgba::CLAVE_EDGE);
        let mut ids: Vec<u64> = tracked.lock().unwrap().keys().map(|w| w.0).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![7, 9]);
        p.overlay().untrack(WindowId(7));
        let ids: Vec<u64> = tracked.lock().unwrap().keys().map(|w| w.0).collect();
        assert_eq!(ids, vec![9]);
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
