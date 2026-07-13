#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use clave_core::{classify_flow, clip_decision, AuditEvent, AuditSink, PolicyBundle, ZoneRegistry};
use clave_platform::{
    Capability, ClipFormat, ClipboardBroker, Decision, EnforcementStatus, InputGuard,
    NetworkTunnel, PResult, Platform, ProcId, ProcessSupervisor, Rgba, Route, ScreenGuard,
    VolumeMount, WindowId, WindowOverlay, Zone,
};

#[derive(Clone)]
pub struct MockVolume {
    inner: Arc<Mutex<VolumeState>>,
}

struct VolumeState {
    mounted: bool,
    mount_point: Option<String>,
    wipes: usize,
}

impl MockVolume {
    pub fn mounted_at(mp: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VolumeState {
                mounted: true,
                mount_point: Some(mp.to_string()),
                wipes: 0,
            })),
        }
    }
    pub fn wipe_count(&self) -> usize {
        self.inner.lock().unwrap().wipes
    }
}

impl VolumeMount for MockVolume {
    fn is_mounted(&self) -> bool {
        self.inner.lock().unwrap().mounted
    }
    fn mount_point(&self) -> Option<String> {
        self.inner.lock().unwrap().mount_point.clone()
    }
    fn request_wipe(&self) -> PResult<()> {
        let mut g = self.inner.lock().unwrap();
        g.wipes += 1;
        g.mounted = false;
        g.mount_point = None;
        Ok(())
    }
}

#[derive(Clone)]
pub struct MockClipboard {
    policy: Arc<Mutex<PolicyBundle>>,
    calls: Arc<Mutex<Vec<(Zone, Zone, ClipFormat)>>>,
}

impl MockClipboard {
    fn new(policy: Arc<Mutex<PolicyBundle>>) -> Self {
        Self {
            policy,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
    pub fn calls(&self) -> Vec<(Zone, Zone, ClipFormat)> {
        self.calls.lock().unwrap().clone()
    }
}

impl ClipboardBroker for MockClipboard {
    fn classify_and_gate(&self, src: Zone, dst: Zone, fmt: ClipFormat) -> Decision {
        self.calls.lock().unwrap().push((src, dst, fmt));
        clip_decision(src, dst, fmt, &self.policy.lock().unwrap())
    }
}

#[derive(Clone)]
pub struct MockNetwork {
    zones: Arc<ZoneRegistry>,
    routes: Arc<Mutex<Vec<(ProcId, Route)>>>,
}

impl MockNetwork {
    fn new(zones: Arc<ZoneRegistry>) -> Self {
        Self {
            zones,
            routes: Arc::new(Mutex::new(Vec::new())),
        }
    }
    pub fn routes(&self) -> Vec<(ProcId, Route)> {
        self.routes.lock().unwrap().clone()
    }
}

impl NetworkTunnel for MockNetwork {
    fn route(&self, proc: &ProcId, dst_blocked: bool) -> Route {
        let r = classify_flow(proc, &self.zones, dst_blocked);
        self.routes.lock().unwrap().push((*proc, r));
        r
    }
}

#[derive(Clone, Default)]
pub struct MockScreen {
    protected: Arc<Mutex<Vec<WindowId>>>,
}

impl MockScreen {
    pub fn protected(&self) -> Vec<WindowId> {
        self.protected.lock().unwrap().clone()
    }
}

impl ScreenGuard for MockScreen {
    fn protect_window(&self, w: WindowId) -> PResult<()> {
        self.protected.lock().unwrap().push(w);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MockOverlay {
    tracked: Arc<Mutex<HashSet<WindowId>>>,
}

impl MockOverlay {
    pub fn tracked(&self) -> Vec<WindowId> {
        let mut v: Vec<WindowId> = self.tracked.lock().unwrap().iter().copied().collect();
        v.sort_by_key(|w| w.0);
        v
    }
    pub fn is_tracking(&self, w: WindowId) -> bool {
        self.tracked.lock().unwrap().contains(&w)
    }
}

impl WindowOverlay for MockOverlay {
    fn track(&self, w: WindowId, _color: Rgba) {
        self.tracked.lock().unwrap().insert(w);
    }
    fn untrack(&self, w: WindowId) {
        self.tracked.lock().unwrap().remove(&w);
    }
}

#[derive(Clone)]
pub struct MockInput {
    enabled: bool,
}

impl InputGuard for MockInput {
    fn protect_input_enabled(&self) -> bool {
        self.enabled
    }
}

#[derive(Clone)]
pub struct MockPlatform {
    pub zones: Arc<ZoneRegistry>,
    pub policy: Arc<Mutex<PolicyBundle>>,
    pub volume: MockVolume,
    pub clipboard: MockClipboard,
    pub network: MockNetwork,
    pub screen: MockScreen,
    pub overlay: MockOverlay,
    pub input: MockInput,
    pub enforcement: Arc<Mutex<[(Capability, EnforcementStatus); Capability::COUNT]>>,
}

impl MockPlatform {
    pub fn new() -> Self {
        let zones = Arc::new(ZoneRegistry::new());
        let policy = Arc::new(Mutex::new(PolicyBundle::restrictive_default()));
        Self {
            zones: Arc::clone(&zones),
            policy: Arc::clone(&policy),
            volume: MockVolume::mounted_at("/Volumes/ClaveDisk"),
            clipboard: MockClipboard::new(Arc::clone(&policy)),
            network: MockNetwork::new(Arc::clone(&zones)),
            screen: MockScreen::default(),
            overlay: MockOverlay::default(),
            input: MockInput { enabled: false },
            enforcement: Arc::new(Mutex::new(
                Capability::ALL.map(|cap| (cap, EnforcementStatus::DevelopmentOnly)),
            )),
        }
    }

    pub fn set_enforcement(&self, cap: Capability, status: EnforcementStatus) {
        for e in self.enforcement.lock().unwrap().iter_mut() {
            if e.0 == cap {
                e.1 = status;
            }
        }
    }

    pub fn set_all_enforced(&self) {
        for e in self.enforcement.lock().unwrap().iter_mut() {
            e.1 = EnforcementStatus::Enforced;
        }
    }
}

impl Default for MockPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for MockPlatform {
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
            .unwrap()
            .iter()
            .find(|e| e.0 == cap)
            .map(|e| e.1)
            .unwrap_or(EnforcementStatus::DevelopmentOnly)
    }
}

#[derive(Clone, Default)]
pub struct RecordingAuditSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl RecordingAuditSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }
    pub fn count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl AuditSink for RecordingAuditSink {
    fn emit(&self, event: AuditEvent) {
        self.events.lock().unwrap().push(event);
    }
}
