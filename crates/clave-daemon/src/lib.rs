//! # clave-daemon
//!
//! The privileged service that hosts the portable policy brain ([`clave_core`]) and drives a
//! single [`Platform`] (a real OS adapter in production, a mock in tests). It owns the zone
//! mirror and the active policy, turns intercepted events into [`Verdict`]s, and orchestrates
//! the overlay / screen / network / volume capabilities.
//!
//! The logic is synchronous and side-effect-explicit so it can be unit-tested directly; the
//! [`Daemon::run`] loop is a thin async driver over a channel of [`DaemonEvent`]s.
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
use clave_platform::{EnforcementReport, Platform, ProcId, Rgba, Route, WindowId};
use clave_proto::{
    AuditSpool, ChainHash, DeviceSigningKey, GatewayCommand, GatewayLink, GatewayVerifier,
    LinkError, ProtoError, SignedCommand, SpoolEntry,
};
use serde::{Deserialize, Serialize};
use clave_volume::{ClaveVolume, VolumeError};

mod enroll;
pub use enroll::{AcceptedEnrollment, DeviceEnrollment, DeviceVolumeKey, EnrollError};

/// Why a policy update was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Offered a bundle older than the one in force — rollback protection.
    Rollback { current: u64, offered: u64 },
}

/// Why a signed gateway command was not applied. Every variant means the
/// device's posture is unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    /// Failed signature / replay / freshness / tenant verification.
    Rejected(ProtoError),
    /// A wipe command targeted a different container than this device's enclave.
    WrongContainer,
    /// The command was an authentic but rolled-back policy update.
    Policy(PolicyError),
    /// An authentic wipe failed in the volume core.
    Volume(VolumeError),
}

/// The daemon. Cheap to share via `Arc`; every method takes `&self` (interior mutability via
/// the zone registry and an [`ArcSwap`] policy cell), so it is `Send + Sync`.
pub struct Daemon {
    zones: Arc<ZoneRegistry>,
    policy: ArcSwap<PolicyBundle>,
    platform: Box<dyn Platform>,
    /// The audit sink *is* the tamper-evident spool: events are hash-chained and
    /// buffered here, and [`Daemon::peek_audit`]/[`Daemon::confirm_audit`] hand them to the gateway
    /// sync loop (ack-based, so a dead link never loses them). The spool may forward to an inner
    /// sink (recording / metrics) — see `AuditSpool::with_sink`.
    audit: Arc<AuditSpool>,
    /// Split-tunnel data plane: classifies flows and pumps Tunnel-flow packets.
    router: Mutex<SplitRouter>,
    /// Encrypted Clave Disk crypto core: DEK/XTS lifecycle, the per-IO access gate, and
    /// crypto-shred wipe. Its gate is `zones`, so one membership set governs both
    /// routing and disk access. `Arc<Mutex<…>>` so the OS mount adapter (WinFsp/APFS) shares
    /// this *exact* instance — one DEK, one lock state — via [`Daemon::volume_handle`]; a remote
    /// wipe then instantly evicts the key the mount is serving from.
    volume: Arc<Mutex<ClaveVolume>>,
    /// Verifies signed gateway commands against the pinned tenant key and tracks the anti-replay
    /// high-water mark. Wrapped in a `Mutex` because verification advances that mark.
    gateway: Mutex<GatewayVerifier>,
}

impl Daemon {
    /// `zones` is shared with the platform's supervisor/network *and* the volume's access gate,
    /// so all consult one membership set. In production the driver/ESF feeds the registry; in
    /// tests the mock shares it. `volume` is the encrypted-disk core (built with `zones` as its
    /// gate) wrapped in `Arc<Mutex<…>>`; the *same* handle is given to the OS mount adapter (see
    /// [`Daemon::volume_handle`]). `gateway` pins the tenant key that authenticates remote
    /// commands.
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

    /// Classify a new exec from its code-signature + parent, joining the work zone if it is a
    /// vetted app (the signed allow-list) or inherits from a supervised parent. The OS layer
    /// (ES `AUTH_EXEC` / the process-notify driver) feeds this; the
    /// *decision* is the policy brain's. Returns the [`ExecVerdict`] for the caller to answer the
    /// OS authorization event with.
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
                // Unreachable: joining without a match ⇒ a supervised parent existed.
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

    /// Resolve a matched app's contained launch environment — HOME/temp redirected into the
    /// mounted Clave Disk, plus env / (Windows) hive + namespace prefix.
    /// `None` if the app is unknown to the policy or the volume isn't mounted. The launcher applies
    /// this; Phase-4 (injection / FS redirection) enforces it.
    pub fn resolve_launch(&self, app_id: &AppId) -> Option<ResolvedLaunch> {
        let mount = self.platform.volume().mount_point()?;
        let policy = self.policy.load();
        let rule = policy.apps.rule(app_id)?;
        Some(rule.launch.resolve(app_id, &mount))
    }

    /// Classify a path a supervised instance of `app_id` is touching: redirect work
    /// data into the Clave Disk, copy-on-write system data, or pass through. `None` if the app is
    /// unknown or the volume isn't mounted. A convenience over [`clave_core::classify_path`] for
    /// the launcher / learn-mode; the per-IO hot path runs the same function locally in the FS
    /// hook / ES gate.
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

    /// The work apps the user can launch from the Clave launcher — the policy's allow-listed apps
    /// that carry an executable. The launcher UI lists these; clicking one calls
    /// [`Daemon::prepare_launch`].
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

    /// Resolve everything to launch `app_id` contained: the executable plus the env /
    /// namespace pointing into the mounted Clave Disk. The OS layer then spawns it *suspended*, adds
    /// the PID to the supervised set, injects the shim / marks the audit token, and resumes — so the
    /// app boots into the redirected FS. `None` if the app is unknown / not launchable, or the
    /// volume isn't mounted.
    pub fn prepare_launch(&self, app_id: &AppId) -> Option<LaunchSpec> {
        let mount = self.platform.volume().mount_point()?;
        let policy = self.policy.load();
        let rule = policy.apps.rule(app_id)?;
        if !rule.is_launchable() {
            return None;
        }
        Some(rule.launch_spec(&mount))
    }

    /// Adjudicate an intercepted operation, auditing any non-allow outcome.
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
        self.platform.overlay().track(w, Rgba::CLAVE_EDGE);
        // Screen protection is best-effort: a failure degrades, never blocks.
        let _ = self.platform.screen().protect_window(w);
    }

    pub fn on_work_window_destroyed(&self, w: WindowId) {
        self.platform.overlay().untrack(w);
    }

    /// Route a flow: compute the policy denylist result, then delegate to the platform tunnel
    /// (which classifies by the shared zone set).
    pub fn route_flow(&self, proc: &ProcId, host: &str) -> Route {
        let blocked = self.policy.load().network.is_blocked(host);
        self.platform.network().route(proc, blocked)
    }

    /// Classify a newly opened flow and remember its disposition. The OS network adapter calls
    /// this on flow-open, then [`Daemon::flow_outbound`] per packet.
    pub fn open_flow(&self, id: FlowId, proc: &ProcId, host: &str) -> FlowDisposition {
        let blocked = self.policy.load().network.is_blocked(host);
        self.router
            .lock()
            .unwrap()
            .open_flow(id, proc, &self.zones, blocked)
    }

    /// Handle an outbound packet on a flow: tunnel it, pass it through, or drop it.
    pub fn flow_outbound(&self, id: FlowId, ip_packet: &[u8]) -> Outbound {
        self.router.lock().unwrap().outbound(id, ip_packet)
    }

    /// Decapsulate an inbound datagram from the gateway. The result is an inner packet for the
    /// work process, a control reply to send back to the gateway, or nothing (see [`Inbound`]).
    /// The OS data loop must forward an [`Inbound::ToGateway`] back over UDP — dropping it stalls
    /// the WireGuard handshake.
    pub fn flow_inbound(&self, datagram: &[u8]) -> Inbound {
        self.router.lock().unwrap().inbound(datagram)
    }

    /// Flush a control/data packet the tunnel has queued for the gateway (a handshake initiation
    /// queued behind the first packet, or data released once the session comes up). The data-plane
    /// driver loops on this until it returns `None`.
    pub fn tunnel_poll_outgoing(&self) -> Option<Vec<u8>> {
        self.router.lock().unwrap().poll_outgoing()
    }

    /// Advance the tunnel's session timers (handshake retransmit, rekey, keepalive, expiry) on the
    /// data-plane cadence; returns a control packet to send to the gateway if one is produced.
    pub fn tunnel_tick(&self) -> Option<Vec<u8>> {
        self.router.lock().unwrap().tick()
    }

    /// Forget a closed flow.
    pub fn close_flow(&self, id: FlowId) {
        self.router.lock().unwrap().close_flow(id);
    }

    /// Translate a shim request into the daemon's effect + optional reply. The clave-ipc
    /// `serve` loop calls this per message: decision requests are adjudicated by the policy
    /// brain; window events drive the overlay/screen subsystems.
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

    /// Answer a request from the Clave launcher UI. The clave-ipc `serve_launcher`
    /// loop calls this per message: it surfaces the launch catalog, resolves a contained launch
    /// spec, and reports the enforcement posture — all read-only views over the policy brain and
    /// the OS adapter. Unlike the shim, the launcher never adjudicates policy or claims a zone.
    pub fn handle_launcher_request(&self, req: LauncherRequest) -> LauncherReply {
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

    /// Apply a new bundle, rejecting rollbacks (monotonic version).
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

    /// Unlock (mount) the Clave Disk: drive the crypto core's DEK unwrap + XTS bring-up, then
    /// audit the mount. Fail-closed — a wiped or unprovisioned container errors and stays
    /// locked. In production the OS mount layer then exposes the decrypted view.
    pub fn unlock_volume(&self, now: UnixTime) -> Result<(), VolumeError> {
        self.volume.lock().unwrap().unlock()?;
        self.audit.emit(AuditEvent::new(
            now,
            AuditAction::VolumeMounted,
            Verdict::allow(Reason::Default),
        ));
        Ok(())
    }

    /// Lock (unmount) the Clave Disk: zeroize the DEK so reads fail closed; audit the unmount.
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

    /// A shared handle to the encrypted-volume core for the OS mount adapter (WinFsp / APFS).
    ///
    /// The mount layer's per-sector read/write callbacks run crypto through *this* `ClaveVolume`,
    /// and `unlock`/`lock`/`wipe` issued via the daemon act on the same instance — so a remote
    /// wipe instantly evicts the DEK the mount is using, with no second key left serving plaintext.
    /// The adapter must use this; it must never construct its own `ClaveVolume`.
    pub fn volume_handle(&self) -> Arc<Mutex<ClaveVolume>> {
        Arc::clone(&self.volume)
    }

    /// Read plaintext from the Clave Disk on behalf of `caller`, enforcing the supervised-only
    /// access gate in the crypto core: a personal caller gets
    /// [`VolumeError::AccessDenied`] even while the volume is mounted.
    ///
    /// In production per-IO crypto runs in the OS mount callback (WinFsp/APFS) over this same
    /// shared volume; this method lets the lifecycle owner — and the tests — drive gated I/O.
    pub fn volume_read(
        &self,
        caller: &ProcId,
        first_sector: u64,
        out: &mut [u8],
    ) -> Result<(), VolumeError> {
        self.volume.lock().unwrap().read(caller, first_sector, out)
    }

    /// Encrypt-and-write `data` to the Clave Disk on behalf of `caller`; same access gate as
    /// [`Daemon::volume_read`]. Plaintext never reaches the backing container.
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

    /// **Remote wipe**: crypto-shred the enclave via the volume core — destroy the
    /// wrapped DEK and set the marker, rendering the container unrecoverable in O(1) — then
    /// signal the OS adapter to tear down its mount. Personal data is never inside the container
    /// and is untouched. The crypto-shred is authoritative; the platform call is best-effort.
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

    /// Verify a signed gateway command against the pinned tenant key (rejecting replays, stale,
    /// and wrong-tenant), then dispatch it: a policy update, a remote lock, or a remote wipe.
    /// This is the **only** path by which the gateway changes the device's posture — an
    /// unverifiable or replayed command changes nothing and returns [`GatewayError`].
    ///
    /// A `Wipe` is honored only if it targets *this* device's container, so a wipe addressed to
    /// another enclave can never destroy this one.
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

    /// Snapshot the pending audit tail + current chain head for the sync loop to sign and ship
    /// — non-destructively. The entries stay in the spool until [`Daemon::confirm_audit`]
    /// acknowledges the gateway received them, so a failed ship retains them instead of losing them.
    pub fn peek_audit(&self) -> (Vec<SpoolEntry>, ChainHash) {
        self.audit.peek()
    }

    /// Acknowledge the gateway durably received every pending entry with `seq <= through_seq`;
    /// drop exactly those. Called only after a successful ship (see [`GatewaySync::sync_once`]).
    pub fn confirm_audit(&self, through_seq: u64) {
        self.audit.confirm_through(through_seq);
    }

    /// The audit chain checkpoint `(seq, head)` to persist (encrypted, in the volume) so the chain
    /// resumes unbroken across restarts — pair with `AuditSpool::resume`.
    pub fn audit_checkpoint(&self) -> (u64, ChainHash) {
        (self.audit.seq(), self.audit.head())
    }

    /// The gateway anti-replay high-water mark to persist alongside the audit checkpoint, so a
    /// restart cannot rewind it — pair with `GatewayVerifier::with_high_water`.
    pub fn gateway_high_water(&self) -> u64 {
        self.gateway.lock().unwrap().high_water()
    }

    /// The current posture [`Checkpoint`] to persist — the gateway anti-replay mark plus the audit
    /// chain position. The gateway sync loop saves this each cycle (see [`GatewaySync`]); on startup
    /// the daemon is rebuilt from a loaded checkpoint via `GatewayVerifier::with_high_water` +
    /// `AuditSpool::resume`, so neither anti-replay nor the audit chain rewinds across a restart.
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

    /// The per-capability enforcement posture: what is production-`Enforced` vs a
    /// `DevelopmentOnly` stand-in vs `Unavailable`. The product surfaces this, and a
    /// production CI gate asserts [`EnforcementReport::is_production_ready`] so a dev-only fallback
    /// can't ship silently.
    pub fn enforcement_report(&self) -> EnforcementReport {
        self.platform.enforcement_report()
    }
}

fn audit_action_for(a: &Action, verdict: &Verdict) -> Option<AuditAction> {
    match a {
        Action::ClipboardTransfer { .. } => Some(AuditAction::ClipboardBlocked),
        // A file-open denial is either a personal intrusion or a supervised escape; the reason
        // separates them so audit doesn't conflate a personal app probing the disk with a work
        // app trying to save out.
        Action::FileOpen { .. } => Some(match verdict.reason {
            Reason::EnclaveIntrusion => AuditAction::EnclaveIntrusionBlocked,
            _ => AuditAction::FileSaveDenied,
        }),
        Action::NetConnect { .. } => Some(AuditAction::NetworkBlocked),
    }
}

/// Events fed to the daemon's [`Daemon::run`] loop. In production these come from the
/// driver/ESF channel, the shim IPC, the overlay tracker, and the gateway sync.
pub enum DaemonEvent {
    ZoneJoin(ProcId, JoinReason),
    ZoneLeave(ProcId),
    WorkWindowCreated(WindowId),
    WorkWindowDestroyed(WindowId),
    /// A decision request with a one-shot reply channel (mirrors `ShimMsg::RequestDecision`).
    Decision {
        action: Action,
        reply: tokio::sync::oneshot::Sender<Verdict>,
    },
    PolicyUpdate(PolicyBundle),
    /// Unlock/mount the Clave Disk (e.g. after user/device auth).
    VolumeUnlock,
    /// Lock/unmount the Clave Disk (lock screen, logout, daemon quiesce).
    VolumeLock,
    /// A signed command from the gateway (policy / lock / wipe) — authenticated before it acts.
    GatewayControl(Box<SignedCommand>),
    Wipe,
    Shutdown,
}

impl Daemon {
    /// Drive the daemon until `Shutdown` or the channel closes. `clock` supplies `now` per
    /// event, keeping the core deterministic (and testable with a fixed clock).
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

/// One sync cycle's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncReport {
    /// Gateway commands verified and applied.
    pub applied: usize,
    /// Gateway commands rejected (bad signature / replay / stale / wrong tenant / wrong container).
    pub rejected: usize,
    /// Audit entries signed and shipped to the gateway (and acknowledged) this cycle.
    pub audit_shipped: usize,
    /// Audit entries that could not be shipped (link down) and were retained to retry. Their
    /// presence means the chain did **not** advance past unshipped audit — no gap is created.
    pub audit_retained: usize,
}

/// The durable posture checkpoint: the gateway anti-replay high-water mark, the audit chain
/// position `(seq, head)`, and the unshipped audit tail. Persisted (encrypted, in the Clave Disk)
/// so a daemon restart can neither rewind anti-replay nor break the audit
/// chain, and so audit entries not yet acknowledged by the gateway re-ship rather than
/// vanishing.
///
/// Note the residual window: entries are captured here only as often as the checkpoint is saved
/// (each sync cycle), so a crash between an emit and the next save can still lose the very newest
/// entries. Fully closing that requires per-emit persistence to the encrypted volume-backed spool
/// — the OS layer that does not exist yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub gateway_high_water: u64,
    pub audit_seq: u64,
    pub audit_head: ChainHash,
    /// The pending (recorded-but-unacknowledged) audit entries, so a restart re-ships them.
    #[serde(default)]
    pub audit_pending: Vec<SpoolEntry>,
}

/// Durable store for the [`Checkpoint`]. The production impl writes it encrypted inside the Clave
/// Disk (or hardware-protected metadata) so a reset cannot rewind it; tests use [`MemCheckpointStore`],
/// and [`FileCheckpointStore`] is a portable on-disk stand-in.
pub trait CheckpointStore: Send + Sync {
    /// Load the persisted checkpoint, if any (to rebuild the verifier + spool on startup).
    fn load(&self) -> Option<Checkpoint>;
    /// Persist the latest checkpoint (called during each gateway sync cycle).
    fn save(&self, checkpoint: Checkpoint);
}

/// In-memory [`CheckpointStore`] double for tests/dev. Clone-shares its cell.
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

/// A portable on-disk [`CheckpointStore`]: postcard-serializes the checkpoint to a file, writing
/// via a temp file + atomic rename so a crash mid-write can't corrupt or truncate it. This is the
/// dev/portable durable store — it makes anti-replay and the audit chain genuinely survive a
/// process restart without the encrypted volume. Production still replaces it with a
/// hardware-protected / volume-encrypted store so the mark cannot be rolled
/// back by wiping a plaintext file.
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
        // A corrupt/partial file is treated as "no checkpoint" — fail-closed to the restrictive
        // default rather than trusting a garbled mark.
        postcard::from_bytes(&bytes).ok()
    }

    fn save(&self, checkpoint: Checkpoint) {
        let Ok(bytes) = postcard::to_allocvec(&checkpoint) else {
            return;
        };
        let tmp = self.tmp_path();
        if std::fs::write(&tmp, &bytes).is_ok() {
            // Atomic replace: readers see either the old or the new file, never a partial one.
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

/// Drives the daemon↔gateway exchange over a [`GatewayLink`]: pull signed commands and apply them
/// (each authenticated by the daemon), then drain the audit spool, sign it with the device key,
/// and ship it. Owned by a dedicated task; the real mTLS transport implements
/// [`GatewayLink`]. [`GatewaySync::sync_once`] is synchronous and side-effect-explicit so it is
/// directly testable — the async timer that calls it on an interval is a thin wrapper.
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

    /// Run one pull → apply → ship cycle and report what happened. Each command is independently
    /// verified by [`Daemon::apply_gateway_command`]; a rejected one changes nothing and is counted,
    /// not propagated.
    ///
    /// Audit shipping is **ack-based**: the tail is snapshotted, signed, and shipped, and only
    /// dropped from the spool once the link confirms delivery. A dead link retains the entries to
    /// retry next cycle — it never advances the chain past unshipped audit, so the gateway never
    /// sees a spurious gap (the old drain-then-ship dropped the batch on a dead link and wedged the
    /// chain permanently).
    pub fn sync_once(&mut self, daemon: &Daemon, now: UnixTime) -> SyncReport {
        let mut report = SyncReport::default();
        for command in self.link.poll_commands() {
            match daemon.apply_gateway_command(&command, now) {
                Ok(()) => report.applied += 1,
                Err(_) => report.rejected += 1,
            }
        }
        // Persist the advanced anti-replay mark immediately after applying — before the fallible
        // audit ship — so a restart can never rewind it even if shipping fails.
        self.store.save(daemon.checkpoint());

        let (entries, head) = daemon.peek_audit();
        if let Some(through) = entries.last().map(|e| e.seq) {
            let n = entries.len();
            match self.link.push_audit(self.device_key.sign_batch(entries, head)) {
                Ok(()) => {
                    // Delivered: drop exactly the acknowledged entries and re-persist so the
                    // durable pending tail shrinks to match.
                    daemon.confirm_audit(through);
                    report.audit_shipped = n;
                    self.store.save(daemon.checkpoint());
                }
                Err(LinkError::Unavailable) => {
                    // Link down: keep the entries; the chain stays put and we retry next cycle.
                    report.audit_retained = n;
                }
            }
        }
        report
    }
}
