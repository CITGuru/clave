#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use clave_core::{
    classify_exec, decide, Action, AppId, AuditAction, AuditEvent, AuditSink, BinaryMatch,
    ExecVerdict, JoinReason, LaunchSpec, LaunchableApp, PathClass, PolicyBundle, Reason,
    ResolvedLaunch, UnixTime, Verdict, ZoneRegistry,
};
use clave_ipc::{DaemonMsg, LauncherReply, LauncherRequest, ShimMsg};
use clave_net::{FlowDisposition, FlowId, Inbound, Outbound, SplitRouter, Tunnel};
use clave_platform::{EnforcementReport, Platform, ProcId, Route, WindowId};
use clave_proto::{
    AuditSpool, ChainHash, DeviceSigningKey, GatewayCommand, GatewayLink, GatewayVerifier,
    LinkError, ProtoError, SignedCommand, SpoolEntry,
};
use clave_volume::{ClaveVolume, VolumeError};
use serde::{Deserialize, Serialize};

mod enroll;
pub use enroll::{AcceptedEnrollment, DeviceEnrollment, DeviceVolumeKey, EnrollError};

#[cfg(target_os = "macos")]
pub mod mac_main;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Rollback { current: u64, offered: u64 },
}

#[derive(Debug)]
pub enum LaunchError {
    NotLaunchable,
    Spawn(std::io::Error),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaunchError::NotLaunchable => {
                f.write_str("app is unknown, not launchable, or the Clave Disk is not mounted")
            }
            LaunchError::Spawn(e) => write!(f, "spawn failed: {e}"),
        }
    }
}

impl std::error::Error for LaunchError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchedApp {
    pub pid: u32,
    pub proc: ProcId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    Rejected(ProtoError),
    WrongContainer,
    Policy(PolicyError),
    Volume(VolumeError),
}

pub struct Daemon {
    zones: Arc<ZoneRegistry>,
    policy: ArcSwap<PolicyBundle>,
    platform: Box<dyn Platform>,
    audit: Arc<AuditSpool>,
    router: Mutex<SplitRouter>,
    volume: Arc<Mutex<ClaveVolume>>,
    gateway: Mutex<GatewayVerifier>,
}

impl Daemon {
    pub fn new(
        zones: Arc<ZoneRegistry>,
        platform: Box<dyn Platform>,
        audit: Arc<AuditSpool>,
        policy: PolicyBundle,
        tunnel: Box<dyn Tunnel>,
        volume: Arc<Mutex<ClaveVolume>>,
        gateway: GatewayVerifier,
    ) -> Self {
        Self {
            zones,
            policy: ArcSwap::from_pointee(policy),
            platform,
            audit,
            router: Mutex::new(SplitRouter::new(tunnel)),
            volume,
            gateway: Mutex::new(gateway),
        }
    }

    pub fn zones(&self) -> &Arc<ZoneRegistry> {
        &self.zones
    }

    pub fn policy_version(&self) -> u64 {
        self.policy.load().version
    }

    pub fn on_zone_join(&self, id: ProcId, reason: JoinReason, now: UnixTime) {
        self.zones.join(id, reason);
        self.audit.emit(AuditEvent::new(
            now,
            AuditAction::ProcessJoinedZone,
            Verdict::allow(Reason::Default),
        ));
    }

    pub fn on_zone_leave(&self, id: ProcId, now: UnixTime) {
        self.zones.leave(&id);
        self.audit.emit(AuditEvent::new(
            now,
            AuditAction::ProcessLeftZone,
            Verdict::allow(Reason::Default),
        ));
    }

    pub fn on_exec(
        &self,
        proc: ProcId,
        parent: Option<ProcId>,
        binary: &BinaryMatch,
        now: UnixTime,
    ) -> ExecVerdict {
        let parent_supervised = parent.is_some_and(|p| self.zones.is_supervised(&p));
        let verdict = classify_exec(binary, parent_supervised, &self.policy.load().apps);
        if verdict.joins_zone {
            let reason = match (&verdict.matched, parent) {
                (Some(_), _) => JoinReason::AllowList,
                (None, Some(p)) => JoinReason::Child(p),
                (None, None) => JoinReason::Launcher,
            };
            self.zones.join(proc, reason);
            self.audit.emit(AuditEvent::new(
                now,
                AuditAction::ProcessJoinedZone,
                Verdict::allow(Reason::Default),
            ));
        }
        verdict
    }

    pub fn resolve_launch(&self, app_id: &AppId) -> Option<ResolvedLaunch> {
        let mount = self.platform.volume().mount_point()?;
        let policy = self.policy.load();
        let rule = policy.apps.rule(app_id)?;
        Some(rule.launch.resolve(app_id, &mount))
    }

    pub fn classify_path(&self, app_id: &AppId, path: &str) -> Option<PathClass> {
        let mount = self.platform.volume().mount_point()?;
        let policy = self.policy.load();
        let rule = policy.apps.rule(app_id)?;
        Some(clave_core::classify_path(
            path,
            &mount,
            &rule.launch.passthrough_paths,
            &policy.files,
        ))
    }

    pub fn launchable_apps(&self) -> Vec<LaunchableApp> {
        self.policy
            .load()
            .apps
            .allow
            .iter()
            .filter(|r| r.is_launchable())
            .map(|r| LaunchableApp {
                app_id: r.app_id.clone(),
                label: r.label().to_string(),
            })
            .collect()
    }

    pub fn prepare_launch(&self, app_id: &AppId) -> Option<LaunchSpec> {
        let mount = self.platform.volume().mount_point()?;
        let policy = self.policy.load();
        let rule = policy.apps.rule(app_id)?;
        if !rule.is_launchable() {
            return None;
        }
        Some(rule.launch_spec(&mount))
    }

    pub fn launch(&self, app_id: &AppId, now: UnixTime) -> Result<LaunchedApp, LaunchError> {
        let spec = self
            .prepare_launch(app_id)
            .ok_or(LaunchError::NotLaunchable)?;
        let launched = spawn_contained(&spec).map_err(LaunchError::Spawn)?;
        self.on_zone_join(launched.proc, JoinReason::Launcher, now);
        Ok(launched)
    }

    pub fn decide_action(&self, action: &Action, now: UnixTime) -> Verdict {
        let pol = self.policy.load_full();
        let verdict = decide(action, &self.zones, &pol, now);
        if !verdict.is_allow() {
            if let Some(a) = audit_action_for(action, &verdict) {
                self.audit.emit(AuditEvent::new(now, a, verdict));
            }
        }
        verdict
    }

    pub fn on_work_window_created(&self, w: WindowId) {
        self.platform
            .overlay()
            .track(w, self.policy.load().overlay.color);
        let _ = self.platform.screen().protect_window(w);
    }

    pub fn on_work_window_destroyed(&self, w: WindowId) {
        self.platform.overlay().untrack(w);
    }

    pub fn overlay_cfg(&self) -> clave_core::BorderCfg {
        self.policy.load().overlay.border_cfg()
    }

    pub fn route_flow(&self, proc: &ProcId, host: &str) -> Route {
        let blocked = self.policy.load().network.is_blocked(host);
        self.platform.network().route(proc, blocked)
    }

    pub fn open_flow(&self, id: FlowId, proc: &ProcId, host: &str) -> FlowDisposition {
        let blocked = self.policy.load().network.is_blocked(host);
        self.router
            .lock()
            .unwrap()
            .open_flow(id, proc, &self.zones, blocked)
    }

    pub fn flow_outbound(&self, id: FlowId, ip_packet: &[u8]) -> Outbound {
        self.router.lock().unwrap().outbound(id, ip_packet)
    }

    pub fn flow_inbound(&self, datagram: &[u8]) -> Inbound {
        self.router.lock().unwrap().inbound(datagram)
    }

    pub fn tunnel_poll_outgoing(&self) -> Option<Vec<u8>> {
        self.router.lock().unwrap().poll_outgoing()
    }

    pub fn tunnel_tick(&self) -> Option<Vec<u8>> {
        self.router.lock().unwrap().tick()
    }

    pub fn close_flow(&self, id: FlowId) {
        self.router.lock().unwrap().close_flow(id);
    }

    pub fn handle_shim_msg(&self, msg: ShimMsg, now: UnixTime) -> Option<DaemonMsg> {
        match msg {
            ShimMsg::RequestDecision { req_id, action } => Some(DaemonMsg::Decision {
                req_id,
                verdict: self.decide_action(&action, now),
            }),
            ShimMsg::WindowCreated { window } => {
                self.on_work_window_created(window);
                None
            }
            ShimMsg::WindowDestroyed { window } => {
                self.on_work_window_destroyed(window);
                None
            }
            ShimMsg::Heartbeat | ShimMsg::Hello { .. } => None,
        }
    }

    pub fn handle_launcher_request(&self, req: LauncherRequest, now: UnixTime) -> LauncherReply {
        match req {
            LauncherRequest::Hello { .. } => LauncherReply::Welcome {
                proto: clave_ipc::PROTO_VERSION,
            },
            LauncherRequest::ListApps => LauncherReply::Apps {
                apps: self.launchable_apps(),
            },
            LauncherRequest::PrepareLaunch { app_id } => LauncherReply::LaunchSpec {
                spec: self.prepare_launch(&app_id),
            },
            LauncherRequest::Launch { app_id } => LauncherReply::Launched {
                pid: self.launch(&app_id, now).ok().map(|l| l.pid),
            },
            LauncherRequest::Enforcement => LauncherReply::Enforcement {
                caps: self
                    .enforcement_report()
                    .entries()
                    .iter()
                    .map(|(cap, status)| (cap.to_string(), status.to_string()))
                    .collect(),
            },
        }
    }

    pub fn update_policy(&self, next: PolicyBundle) -> Result<(), PolicyError> {
        let current = self.policy.load().version;
        if next.version < current {
            return Err(PolicyError::Rollback {
                current,
                offered: next.version,
            });
        }
        self.policy.store(Arc::new(next));
        Ok(())
    }

    pub fn unlock_volume(&self, now: UnixTime) -> Result<(), VolumeError> {
        self.volume.lock().unwrap().unlock()?;
        self.audit.emit(AuditEvent::new(
            now,
            AuditAction::VolumeMounted,
            Verdict::allow(Reason::Default),
        ));
        Ok(())
    }

    pub fn lock_volume(&self, now: UnixTime) {
        self.volume.lock().unwrap().lock();
        self.audit.emit(AuditEvent::new(
            now,
            AuditAction::VolumeUnmounted,
            Verdict::allow(Reason::Default),
        ));
    }

    pub fn volume_is_unlocked(&self) -> bool {
        self.volume.lock().unwrap().is_unlocked()
    }

    pub fn volume_handle(&self) -> Arc<Mutex<ClaveVolume>> {
        Arc::clone(&self.volume)
    }

    pub fn volume_read(
        &self,
        caller: &ProcId,
        first_sector: u64,
        out: &mut [u8],
    ) -> Result<(), VolumeError> {
        self.volume.lock().unwrap().read(caller, first_sector, out)
    }

    pub fn volume_write(
        &self,
        caller: &ProcId,
        first_sector: u64,
        data: &[u8],
    ) -> Result<(), VolumeError> {
        self.volume
            .lock()
            .unwrap()
            .write(caller, first_sector, data)
    }

    pub fn wipe(&self, now: UnixTime) -> Result<(), VolumeError> {
        self.volume.lock().unwrap().wipe()?;
        let _ = self.platform.volume().request_wipe();
        self.audit.emit(AuditEvent::new(
            now,
            AuditAction::Wiped,
            Verdict::allow(Reason::Default),
        ));
        Ok(())
    }

    pub fn apply_gateway_command(
        &self,
        signed: &SignedCommand,
        now: UnixTime,
    ) -> Result<(), GatewayError> {
        let command = self
            .gateway
            .lock()
            .unwrap()
            .verify(signed, now)
            .map_err(GatewayError::Rejected)?;
        match command {
            GatewayCommand::UpdatePolicy(bundle) => {
                self.update_policy(bundle).map_err(GatewayError::Policy)?;
            }
            GatewayCommand::Lock { .. } => self.lock_volume(now),
            GatewayCommand::Wipe { container, .. } => {
                let ours = self.volume.lock().unwrap().container_id().0;
                if container != ours {
                    return Err(GatewayError::WrongContainer);
                }
                self.wipe(now).map_err(GatewayError::Volume)?;
            }
        }
        Ok(())
    }

    pub fn peek_audit(&self) -> (Vec<SpoolEntry>, ChainHash) {
        self.audit.peek()
    }

    pub fn confirm_audit(&self, through_seq: u64) {
        self.audit.confirm_through(through_seq);
    }

    pub fn audit_checkpoint(&self) -> (u64, ChainHash) {
        (self.audit.seq(), self.audit.head())
    }

    pub fn gateway_high_water(&self) -> u64 {
        self.gateway.lock().unwrap().high_water()
    }

    pub fn checkpoint(&self) -> Checkpoint {
        let (audit_seq, audit_head) = self.audit_checkpoint();
        let (audit_pending, _) = self.audit.peek();
        Checkpoint {
            gateway_high_water: self.gateway_high_water(),
            audit_seq,
            audit_head,
            audit_pending,
        }
    }

    pub fn enforcement_report(&self) -> EnforcementReport {
        self.platform.enforcement_report()
    }
}

fn spawn_contained(spec: &LaunchSpec) -> std::io::Result<LaunchedApp> {
    use std::process::{Command, Stdio};

    for (key, value) in &spec.env {
        if (key == "HOME" || key == "TMPDIR") && !value.is_empty() {
            let _ = std::fs::create_dir_all(value);
        }
    }

    seed_contained_home(spec);

    let program = resolve_program(&spec.executable);
    let mut cmd = Command::new(program);
    cmd.args(&spec.args);
    for (key, value) in &spec.env {
        cmd.env(key, value);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd.spawn()?;
    let pid = child.id();
    Ok(LaunchedApp {
        pid,
        proc: proc_id_for_pid(pid),
    })
}

/// Expose a curated set of the user's real-home entries (shell config, toolchains) inside the
/// contained HOME so a launched dev tool has a working environment instead of a bare home. Each
/// requested path (relative to the real user home, per [`LaunchSpec::seed_home`]) is symlinked in
/// if it exists and isn't already present. Best-effort: a failed link never blocks the launch.
///
/// Note: a symlink crosses the enclave boundary — the work process gains access to the linked
/// real-home path. This is an intentional lab-only convenience for developer tools; a production
/// build over real FS redirection would seed copies (or nothing) instead.
fn seed_contained_home(spec: &LaunchSpec) {
    if spec.seed_home.is_empty() {
        return;
    }
    let Some(home) = spec
        .env
        .iter()
        .find(|(k, _)| k == "HOME")
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
    else {
        return;
    };
    let Ok(real_home) = std::env::var("HOME") else {
        return;
    };
    if home == real_home {
        return;
    }

    for rel in &spec.seed_home {
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() || rel.split('/').any(|c| c == "..") {
            continue;
        }
        let src = std::path::Path::new(&real_home).join(rel);
        if !src.exists() {
            continue;
        }
        let dst = std::path::Path::new(home).join(rel);
        if std::fs::symlink_metadata(&dst).is_ok() {
            continue;
        }
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(&src, &dst);
    }
}

fn resolve_program(executable: &str) -> std::path::PathBuf {
    let path = std::path::Path::new(executable);
    let is_bundle = path.extension().and_then(|e| e.to_str()) == Some("app");
    if is_bundle && path.is_dir() {
        let macos_dir = path.join("Contents").join("MacOS");
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            let named = macos_dir.join(stem);
            if named.exists() {
                return named;
            }
        }
        if let Some(Ok(entry)) = std::fs::read_dir(&macos_dir)
            .ok()
            .and_then(|mut e| e.next())
        {
            return entry.path();
        }
    }
    path.to_path_buf()
}

#[cfg(target_os = "macos")]
fn proc_id_for_pid(pid: u32) -> ProcId {
    let mut token = [0u32; 8];
    token[5] = pid;
    ProcId::macos(token)
}

#[cfg(not(target_os = "macos"))]
fn proc_id_for_pid(pid: u32) -> ProcId {
    ProcId::windows(pid, 0)
}

fn audit_action_for(a: &Action, verdict: &Verdict) -> Option<AuditAction> {
    match a {
        Action::ClipboardTransfer { .. } => Some(AuditAction::ClipboardBlocked),
        Action::FileOpen { .. } => Some(match verdict.reason {
            Reason::EnclaveIntrusion => AuditAction::EnclaveIntrusionBlocked,
            _ => AuditAction::FileSaveDenied,
        }),
        Action::NetConnect { .. } => Some(AuditAction::NetworkBlocked),
    }
}

pub enum DaemonEvent {
    ZoneJoin(ProcId, JoinReason),
    ZoneLeave(ProcId),
    WorkWindowCreated(WindowId),
    WorkWindowDestroyed(WindowId),
    Decision {
        action: Action,
        reply: tokio::sync::oneshot::Sender<Verdict>,
    },
    PolicyUpdate(PolicyBundle),
    VolumeUnlock,
    VolumeLock,
    GatewayControl(Box<SignedCommand>),
    Wipe,
    Shutdown,
}

impl Daemon {
    pub async fn run<C>(self: Arc<Self>, mut rx: tokio::sync::mpsc::Receiver<DaemonEvent>, clock: C)
    where
        C: Fn() -> UnixTime + Send,
    {
        while let Some(ev) = rx.recv().await {
            let now = clock();
            match ev {
                DaemonEvent::ZoneJoin(id, reason) => self.on_zone_join(id, reason, now),
                DaemonEvent::ZoneLeave(id) => self.on_zone_leave(id, now),
                DaemonEvent::WorkWindowCreated(w) => self.on_work_window_created(w),
                DaemonEvent::WorkWindowDestroyed(w) => self.on_work_window_destroyed(w),
                DaemonEvent::Decision { action, reply } => {
                    let _ = reply.send(self.decide_action(&action, now));
                }
                DaemonEvent::PolicyUpdate(p) => {
                    let _ = self.update_policy(p);
                }
                DaemonEvent::VolumeUnlock => {
                    let _ = self.unlock_volume(now);
                }
                DaemonEvent::VolumeLock => self.lock_volume(now),
                DaemonEvent::GatewayControl(signed) => {
                    let _ = self.apply_gateway_command(&signed, now);
                }
                DaemonEvent::Wipe => {
                    let _ = self.wipe(now);
                }
                DaemonEvent::Shutdown => break,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncReport {
    pub applied: usize,
    pub rejected: usize,
    pub audit_shipped: usize,
    pub audit_retained: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub gateway_high_water: u64,
    pub audit_seq: u64,
    pub audit_head: ChainHash,
    #[serde(default)]
    pub audit_pending: Vec<SpoolEntry>,
}

pub trait CheckpointStore: Send + Sync {
    fn load(&self) -> Option<Checkpoint>;
    fn save(&self, checkpoint: Checkpoint);
}

#[derive(Clone, Default)]
pub struct MemCheckpointStore {
    inner: Arc<Mutex<Option<Checkpoint>>>,
}

impl MemCheckpointStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CheckpointStore for MemCheckpointStore {
    fn load(&self) -> Option<Checkpoint> {
        self.inner.lock().unwrap().clone()
    }
    fn save(&self, checkpoint: Checkpoint) {
        *self.inner.lock().unwrap() = Some(checkpoint);
    }
}

pub struct FileCheckpointStore {
    path: std::path::PathBuf,
}

impl FileCheckpointStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn tmp_path(&self) -> std::path::PathBuf {
        let mut p = self.path.clone();
        let mut name = p.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        p.set_file_name(name);
        p
    }
}

impl CheckpointStore for FileCheckpointStore {
    fn load(&self) -> Option<Checkpoint> {
        let bytes = std::fs::read(&self.path).ok()?;
        postcard::from_bytes(&bytes).ok()
    }

    fn save(&self, checkpoint: Checkpoint) {
        let Ok(bytes) = postcard::to_allocvec(&checkpoint) else {
            return;
        };
        let tmp = self.tmp_path();
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

pub struct GatewaySync {
    link: Box<dyn GatewayLink>,
    device_key: DeviceSigningKey,
    store: Box<dyn CheckpointStore>,
}

impl GatewaySync {
    pub fn new(
        link: Box<dyn GatewayLink>,
        device_key: DeviceSigningKey,
        store: Box<dyn CheckpointStore>,
    ) -> Self {
        Self {
            link,
            device_key,
            store,
        }
    }

    pub fn sync_once(&mut self, daemon: &Daemon, now: UnixTime) -> SyncReport {
        let mut report = SyncReport::default();
        for command in self.link.poll_commands() {
            match daemon.apply_gateway_command(&command, now) {
                Ok(()) => report.applied += 1,
                Err(_) => report.rejected += 1,
            }
        }
        self.store.save(daemon.checkpoint());

        let (entries, head) = daemon.peek_audit();
        if let Some(through) = entries.last().map(|e| e.seq) {
            let n = entries.len();
            match self
                .link
                .push_audit(self.device_key.sign_batch(entries, head))
            {
                Ok(()) => {
                    daemon.confirm_audit(through);
                    report.audit_shipped = n;
                    self.store.save(daemon.checkpoint());
                }
                Err(LinkError::Unavailable) => {
                    report.audit_retained = n;
                }
            }
        }
        report
    }
}
