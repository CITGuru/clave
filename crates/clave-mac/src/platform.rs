use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clave_core::ZoneRegistry;
use clave_platform::{
    Capability, ClipFormat, ClipboardBroker, Decision, EnforcementStatus, InputGuard,
    NetworkTunnel, PResult, Platform, PlatformError, ProcId, ProcessSupervisor, Rgba, Route,
    ScreenGuard,
    VolumeMount, WindowId, WindowOverlay, Zone,
};

use crate::sip::SipStatus;
use crate::volume::{Custody, MacVolumeMount};

pub struct MacNetwork {
    zones: Arc<ZoneRegistry>,
}

impl NetworkTunnel for MacNetwork {
    fn route(&self, proc: &ProcId, dst_blocked: bool) -> Route {
        clave_net::route(proc, &self.zones, dst_blocked)
    }
}

#[derive(Default)]
pub struct MacClipboard;

impl ClipboardBroker for MacClipboard {
    fn classify_and_gate(&self, src: Zone, dst: Zone, _fmt: ClipFormat) -> Decision {
        if src == dst {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

#[derive(Default)]
pub struct MacScreen;

impl ScreenGuard for MacScreen {
    /// macOS cannot exclude a window it does not own from capture: `sharingType` is an instance
    /// property on your own `NSWindow`, and injecting into the work app to set it is ruled out by
    /// SIP/library validation (doc 07 §3.2). Reporting `Ok` here would tell the daemon a work
    /// window was protected when it is fully capturable. What macOS *can* do — notice a capture
    /// over work content and audit it — is `screen.rs`.
    fn protect_window(&self, _w: WindowId) -> PResult<()> {
        Err(PlatformError::Unsupported)
    }
}

pub type TrackedWindows = Arc<Mutex<std::collections::HashMap<WindowId, Rgba>>>;

#[derive(Clone, Default)]
pub struct MacOverlay {
    tracked: TrackedWindows,
}

impl MacOverlay {
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

#[derive(Default)]
pub struct MacInput;

impl InputGuard for MacInput {
    /// macOS ships no kernel input filter, so no work app can be given a keystroke channel a
    /// permitted tapper cannot see (doc 06 §3.1). The adapter monitors and audits taps (`input.rs`)
    /// but never *protects* input — so this is honestly `false`.
    fn protect_input_enabled(&self) -> bool {
        false
    }
}

pub struct MacPlatform {
    zones: Arc<ZoneRegistry>,
    network: MacNetwork,
    volume: Arc<MacVolumeMount>,
    clipboard: MacClipboard,
    screen: MacScreen,
    overlay: MacOverlay,
    input: MacInput,
    enforcement: Mutex<[(Capability, EnforcementStatus); Capability::COUNT]>,
}

impl MacPlatform {
    pub fn new(zones: Arc<ZoneRegistry>) -> Self {
        let network = MacNetwork {
            zones: Arc::clone(&zones),
        };
        Self {
            zones,
            network,
            volume: Arc::new(MacVolumeMount::default()),
            clipboard: MacClipboard,
            screen: MacScreen,
            overlay: MacOverlay::default(),
            input: MacInput,
            enforcement: Mutex::new(default_enforcement()),
        }
    }

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

    pub fn detect_and_apply_sip_posture(&self) -> SipStatus {
        self.apply_sip_posture(SipStatus::detect())
    }

    pub fn zones(&self) -> Arc<ZoneRegistry> {
        Arc::clone(&self.zones)
    }

    pub fn overlay_tracked(&self) -> TrackedWindows {
        self.overlay.tracked_handle()
    }

    /// Point the volume at a real container. Call before boxing the platform into `Daemon::new`,
    /// then attach through [`MacPlatform::volume_mac`].
    pub fn configure_volume(
        &mut self,
        container: u128,
        bundle_path: impl Into<PathBuf>,
        custody: Custody,
    ) {
        self.volume = Arc::new(MacVolumeMount::new(container, bundle_path, custody));
    }

    /// The concrete mount, for the `attach`/`detach` calls the `VolumeMount` trait doesn't expose.
    /// The `Arc` keeps it reachable after `MacPlatform` is boxed into `Box<dyn Platform>`.
    pub fn volume_mac(&self) -> Arc<MacVolumeMount> {
        Arc::clone(&self.volume)
    }

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

fn default_enforcement() -> [(Capability, EnforcementStatus); Capability::COUNT] {
    use Capability::*;
    use EnforcementStatus::*;
    [
        (ProcessSupervision, DevelopmentOnly),
        // Real encryption, hardware key custody, and crypto-shred (volume.rs, se_seal.rs) — but the
        // mount is not yet ES `AUTH_OPEN`-gated, so `DevelopmentOnly` (doc 04 §4).
        (Volume, DevelopmentOnly),
        // Monitor + reactive-clear + audit (clipboard.rs). macOS offers no way to intercept a paste,
        // so this can never reach `Enforced` — it narrows the leak window and records every
        // work→personal transfer, but a paste inside the poll window still wins (doc 05 §3.3).
        (Clipboard, DevelopmentOnly),
        (Network, DevelopmentOnly),
        // Detect + audit only (screen.rs). macOS cannot exclude a third-party window from capture
        // at all (doc 07 §3.2), so this never reaches `Enforced`: it records screenshots taken over
        // work content, it does not stop them. The one hard block — ES `AUTH_EXEC`-denying
        // `screencapture` — needs the Endpoint Security entitlement.
        (Screen, DevelopmentOnly),
        // The Clave Edge border is drawn and running (edge.rs): a CGWindowList poll, needing no TCC
        // grant. It is a UI affordance, not a control (doc 09 §3.3), so it is never `Enforced` — but
        // reporting `Unavailable` for something that visibly runs would be the same lie in reverse.
        (Overlay, DevelopmentOnly),
        // Event taps are enumerated and audited (input.rs). macOS ships no kernel input filter, so
        // prevention is impossible; TCC's Input Monitoring prompt is the platform's real backstop
        // (doc 06 §3.3).
        (Input, DevelopmentOnly),
    ]
}

impl Platform for MacPlatform {
    fn supervisor(&self) -> &dyn ProcessSupervisor {
        &*self.zones
    }
    fn volume(&self) -> &dyn VolumeMount {
        &*self.volume
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
        assert_eq!(
            r.status(Capability::Volume),
            EnforcementStatus::DevelopmentOnly
        );
        // Clipboard is monitored and reactively cleared, but macOS cannot hard-block a paste — it
        // must never claim `Enforced` (doc 05 §3.3).
        assert_eq!(
            r.status(Capability::Clipboard),
            EnforcementStatus::DevelopmentOnly
        );
        // Screen capture is detected and audited, never blocked — macOS cannot exclude a window it
        // does not own from capture, so this must never claim `Enforced` (doc 07 §3.4).
        assert_eq!(
            r.status(Capability::Screen),
            EnforcementStatus::DevelopmentOnly
        );
        // Overlay and input are detect/draw/audit only — real, running, but never `Enforced`
        // (the overlay is a UI affordance, input has no shippable kernel filter).
        assert_eq!(
            r.status(Capability::Overlay),
            EnforcementStatus::DevelopmentOnly
        );
        assert_eq!(
            r.status(Capability::Input),
            EnforcementStatus::DevelopmentOnly
        );
    }

    /// macOS cannot protect a third-party window from capture. Reporting `Ok` would tell the daemon
    /// the window was protected when it is fully capturable (doc 07 §3.2).
    #[test]
    fn protecting_a_window_from_capture_is_reported_as_unsupported() {
        let p = platform();
        assert_eq!(
            p.screen().protect_window(WindowId(1)),
            Err(clave_platform::PlatformError::Unsupported)
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
        for sip in [SipStatus::Enabled, SipStatus::Unknown] {
            p.apply_sip_posture(sip);
            let r = p.enforcement_report();
            assert_eq!(
                r.status(Capability::ProcessSupervision),
                EnforcementStatus::Unavailable
            );
            assert_eq!(
                r.status(Capability::Network),
                EnforcementStatus::Unavailable
            );
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
        for cap in Capability::ALL {
            p.set_enforcement(cap, EnforcementStatus::Enforced);
        }
        assert!(p.enforcement_report().is_production_ready());
    }
}
