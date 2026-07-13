use std::sync::{Arc, Mutex};

use clave_core::ZoneRegistry;
use clave_platform::{
    Capability, ClipFormat, ClipboardBroker, Decision, EnforcementStatus, InputGuard,
    NetworkTunnel, PResult, Platform, ProcId, ProcessSupervisor, Rgba, Route, ScreenGuard,
    VolumeMount, WindowId, WindowOverlay, Zone,
};

pub struct WinNetwork {
    zones: Arc<ZoneRegistry>,
}

impl NetworkTunnel for WinNetwork {
    fn route(&self, proc: &ProcId, dst_blocked: bool) -> Route {
        clave_net::route(proc, &self.zones, dst_blocked)
    }
}

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
        Ok(())
    }
}

#[derive(Default)]
pub struct WinClipboard;

impl ClipboardBroker for WinClipboard {
    fn classify_and_gate(&self, src: Zone, dst: Zone, _fmt: ClipFormat) -> Decision {
        if src == dst {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

#[derive(Default)]
pub struct WinScreen;

impl ScreenGuard for WinScreen {
    fn protect_window(&self, _w: WindowId) -> PResult<()> {
        Ok(())
    }
}

#[derive(Default)]
pub struct WinOverlay;

impl WindowOverlay for WinOverlay {
    fn track(&self, _w: WindowId, _color: Rgba) {}
    fn untrack(&self, _w: WindowId) {}
}

#[derive(Default)]
pub struct WinInput;

impl InputGuard for WinInput {
    fn protect_input_enabled(&self) -> bool {
        false
    }
}

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
