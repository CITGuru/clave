//! End-to-end daemon behaviour against the in-memory `MockPlatform` — no OS required.

use std::sync::{Arc, Mutex};

use clave_core::{
    Action, AppId, AppRule, AuditAction, BinaryMatch, JoinReason, LaunchProfile, PathClass,
    PolicyBundle,
};
use clave_daemon::{
    Checkpoint, CheckpointStore, Daemon, DaemonEvent, FileCheckpointStore, GatewayError,
    GatewaySync, MemCheckpointStore, PolicyError,
};
use clave_net::{FlowDisposition, LoopbackTunnel, Outbound};
use clave_platform::{
    Capability, ClipFormat, Decision, EnforcementStatus, ProcId, Route, WindowId, Zone,
};
use clave_proto::{
    verify_batch, AuditSpool, ControlReason, DeviceSigningKey, GatewayCommand, GatewaySigningKey,
    GatewayVerifier, LoopbackLink, ProtoError, TenantId, GENESIS,
};
use clave_testkit::{MockPlatform, RecordingAuditSink};
use clave_volume::{
    BackingStore, ClaveVolume, ContainerId, ContainerMeta, Dek, Kek, KeyStore, MemBacking,
    MemKeyStore, VolumeError, SECTOR_SIZE,
};

fn pid(n: u32) -> ProcId {
    ProcId::windows(n, 1)
}

/// Test handles: the volume's in-memory backends, the gateway signing key, and the daemon's audit
/// spool. Lets a test mint signed commands, assert on the crypto-shred after a wipe (the keystore
/// no longer holds the wrapped DEK, and the backing carries the wipe marker), and drain the
/// tamper-evident audit chain.
struct Kit {
    keystore: Arc<MemKeyStore>,
    backing: Arc<MemBacking>,
    id: ContainerId,
    signer: GatewaySigningKey,
    spool: Arc<AuditSpool>,
}

/// Build a daemon over a fresh mock, with a *provisioned* encrypted volume whose access gate is
/// the daemon's own zone registry (one membership set governs routing and disk access) and a
/// gateway verifier pinned to a test tenant key. Returns the daemon, a mock handle, the audit
/// sink, and the test [`Kit`] (volume backends + the matching gateway signer).
fn make_full() -> (Arc<Daemon>, MockPlatform, RecordingAuditSink, Kit) {
    let platform = MockPlatform::new();
    let handle = platform.clone(); // Arc-backed: shares state with the boxed platform
    let zones = Arc::clone(&platform.zones);
    // The daemon's audit sink is a tamper-evident spool that also forwards to the recording sink
    // the existing assertions read. Production drains the spool to the gateway.
    let recording = RecordingAuditSink::new();
    let spool = Arc::new(AuditSpool::with_sink(Arc::new(recording.clone())));

    let id = ContainerId(0xC1A5_ED15);
    let keystore = Arc::new(MemKeyStore::new());
    keystore.provision(
        id,
        Kek::from_bytes([0x4B; 32]),
        &Dek::from_bytes([0xDE; 64]),
    );
    let backing = Arc::new(MemBacking::zeroed(64));
    let volume = ClaveVolume::new(
        ContainerMeta::new(id),
        keystore.clone(),
        backing.clone(),
        zones.clone(),
    );

    // The gateway's signing key; the daemon pins only its public half (signature pinning).
    let signer = GatewaySigningKey::from_seed(TenantId(1), [0x6A; 32]);
    let gateway = GatewayVerifier::new(TenantId(1), signer.public_key()).unwrap();

    let daemon = Arc::new(Daemon::new(
        zones,
        Box::new(platform),
        spool.clone(),
        PolicyBundle::restrictive_default(),
        Box::new(LoopbackTunnel::new(0x5A)),
        Arc::new(Mutex::new(volume)),
        gateway,
    ));
    (
        daemon,
        handle,
        recording,
        Kit {
            keystore,
            backing,
            id,
            signer,
            spool,
        },
    )
}

/// The common case: most tests don't need the volume backends.
fn make() -> (Arc<Daemon>, MockPlatform, RecordingAuditSink) {
    let (daemon, handle, audit, _vol) = make_full();
    (daemon, handle, audit)
}

#[test]
fn work_window_is_tracked_by_clave_edge_and_screen_protected() {
    let (daemon, h, _audit) = make();
    daemon.on_work_window_created(WindowId(5));
    assert!(h.overlay.is_tracking(WindowId(5)));
    assert_eq!(h.screen.protected(), vec![WindowId(5)]);

    daemon.on_work_window_destroyed(WindowId(5));
    assert!(!h.overlay.is_tracking(WindowId(5)));
}

#[test]
fn zone_membership_drives_split_tunnel() {
    let (daemon, h, _audit) = make();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);

    // A supervised flow to a permitted host tunnels; a personal proc goes direct.
    assert_eq!(daemon.route_flow(&work, "good.example"), Route::Tunnel);
    assert_eq!(daemon.route_flow(&pid(99), "good.example"), Route::Direct);

    assert!(h.network.routes().contains(&(work, Route::Tunnel)));
    assert!(h.network.routes().contains(&(pid(99), Route::Direct)));
}

#[test]
fn work_egress_denylist_blocks() {
    let (daemon, _h, _audit) = make();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);

    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.network.blocked_hosts = vec!["evil.example".to_string()];
    daemon.update_policy(pol).unwrap();

    assert_eq!(daemon.route_flow(&work, "evil.example"), Route::Block);
    assert_eq!(daemon.route_flow(&work, "good.example"), Route::Tunnel);
}

#[test]
fn denied_decision_is_audited_allowed_is_not() {
    let (daemon, _h, audit) = make();

    let deny = Action::ClipboardTransfer {
        src: Zone::Work,
        dst: Zone::Personal,
        fmt: ClipFormat::Files,
    };
    assert_eq!(daemon.decide_action(&deny, 1).decision, Decision::Deny);
    assert_eq!(audit.count(), 1);
    assert_eq!(audit.events()[0].action, AuditAction::ClipboardBlocked);

    let allow = Action::ClipboardTransfer {
        src: Zone::Work,
        dst: Zone::Work,
        fmt: ClipFormat::Files,
    };
    assert_eq!(daemon.decide_action(&allow, 2).decision, Decision::Allow);
    assert_eq!(audit.count(), 1, "an allowed action must not be audited");
}

#[test]
fn policy_rollback_is_rejected() {
    let (daemon, _h, _audit) = make();

    let mut v2 = PolicyBundle::restrictive_default();
    v2.version = 2;
    daemon.update_policy(v2).unwrap();
    assert_eq!(daemon.policy_version(), 2);

    let mut v1 = PolicyBundle::restrictive_default();
    v1.version = 1;
    assert_eq!(
        daemon.update_policy(v1),
        Err(PolicyError::Rollback {
            current: 2,
            offered: 1
        })
    );
    assert_eq!(daemon.policy_version(), 2, "rollback must not take effect");
}

#[test]
fn wipe_invokes_volume_crypto_shred() {
    let (daemon, h, audit, vol) = make_full();
    daemon.unlock_volume(1).unwrap();
    assert!(daemon.volume_is_unlocked());
    assert!(vol.keystore.contains(vol.id));
    assert_eq!(h.volume.wipe_count(), 0);

    daemon.wipe(2).unwrap();

    // The crypto-shred is authoritative: DEK evicted, wrapped key destroyed, marker set.
    assert!(!daemon.volume_is_unlocked(), "DEK evicted on wipe");
    assert!(
        !vol.keystore.contains(vol.id),
        "wrapped key crypto-shredded"
    );
    assert!(vol.backing.is_wiped(), "wipe marker set on the container");
    // The OS adapter was also signalled to tear its mount down (best-effort).
    assert_eq!(
        h.volume.wipe_count(),
        1,
        "platform mount teardown signalled"
    );
    assert!(audit
        .events()
        .iter()
        .any(|e| e.action == AuditAction::Wiped));

    // Fail-closed forever: re-unlocking the lingering container refuses on the marker.
    assert_eq!(daemon.unlock_volume(3), Err(VolumeError::WipeMarkerSet));
}

#[test]
fn work_proc_reads_and_writes_the_disk_through_the_daemon() {
    let (daemon, _h, audit, _vol) = make_full();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);

    daemon.unlock_volume(2).unwrap();
    assert!(daemon.volume_is_unlocked());
    assert!(
        audit
            .events()
            .iter()
            .any(|e| e.action == AuditAction::VolumeMounted),
        "the mount is audited"
    );

    let mut sector = vec![0u8; SECTOR_SIZE];
    sector[..5].copy_from_slice(b"hello");
    daemon.volume_write(&work, 0, &sector).unwrap();

    let mut got = vec![0u8; SECTOR_SIZE];
    daemon.volume_read(&work, 0, &mut got).unwrap();
    assert_eq!(got, sector);
}

#[test]
fn personal_proc_is_denied_disk_access_even_when_mounted() {
    let (daemon, _h, _audit, _vol) = make_full();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);
    daemon.unlock_volume(2).unwrap();

    // Seed a sector as the work proc, then have an unsupervised proc try to read it.
    daemon
        .volume_write(&work, 0, &vec![0xAB; SECTOR_SIZE])
        .unwrap();
    let personal = pid(99); // never joined the zone
    let mut got = vec![0u8; SECTOR_SIZE];
    assert_eq!(
        daemon.volume_read(&personal, 0, &mut got),
        Err(VolumeError::AccessDenied)
    );
}

#[test]
fn locking_the_disk_fails_reads_closed_and_audits_unmount() {
    let (daemon, _h, audit, _vol) = make_full();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);
    daemon.unlock_volume(2).unwrap();

    daemon.lock_volume(3);
    assert!(!daemon.volume_is_unlocked());
    assert!(
        audit
            .events()
            .iter()
            .any(|e| e.action == AuditAction::VolumeUnmounted),
        "the unmount is audited"
    );
    let mut got = vec![0u8; SECTOR_SIZE];
    assert_eq!(
        daemon.volume_read(&work, 0, &mut got),
        Err(VolumeError::Locked)
    );
}

#[tokio::test]
async fn volume_unlock_drives_through_the_event_loop() {
    let (daemon, _h, _audit, _vol) = make_full();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let runner = Arc::clone(&daemon);
    let jh = tokio::spawn(async move { runner.run(rx, || 7u64).await });

    // Events are processed in order, so the unlock has taken effect by the time Shutdown breaks.
    tx.send(DaemonEvent::VolumeUnlock).await.unwrap();
    tx.send(DaemonEvent::Shutdown).await.unwrap();
    jh.await.unwrap();

    assert!(
        daemon.volume_is_unlocked(),
        "the VolumeUnlock event mounted the disk"
    );
}

#[tokio::test]
async fn async_event_loop_round_trips_a_decision() {
    let (daemon, _h, _audit) = make();
    let (tx, rx) = tokio::sync::mpsc::channel(8);

    let runner = Arc::clone(&daemon);
    let jh = tokio::spawn(async move { runner.run(rx, || 1u64).await });

    // Ask for a work->personal clipboard decision; expect Deny under the restrictive default.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    tx.send(DaemonEvent::Decision {
        action: Action::ClipboardTransfer {
            src: Zone::Work,
            dst: Zone::Personal,
            fmt: ClipFormat::PlainText,
        },
        reply: reply_tx,
    })
    .await
    .unwrap();

    assert_eq!(reply_rx.await.unwrap().decision, Decision::Deny);

    tx.send(DaemonEvent::Shutdown).await.unwrap();
    jh.await.unwrap();
}

#[test]
fn work_flow_is_pumped_through_the_tunnel() {
    let (daemon, _h, _a) = make();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);

    // A supervised flow to a permitted host is tunneled; its packets are encapsulated.
    assert_eq!(
        daemon.open_flow(1, &work, "intra.corp"),
        FlowDisposition::Tunnel
    );
    let plaintext = b"GET /secret HTTP/1.1".to_vec();
    match daemon.flow_outbound(1, &plaintext) {
        Outbound::ToGateway(d) => assert_ne!(d, plaintext, "must be obscured on the wire"),
        other => panic!("expected ToGateway, got {other:?}"),
    }

    // A personal flow passes through untouched.
    assert_eq!(
        daemon.open_flow(2, &pid(99), "news.example"),
        FlowDisposition::Direct
    );
    assert!(matches!(
        daemon.flow_outbound(2, b"x"),
        Outbound::PassThrough
    ));

    // After close, the flow's packets drop.
    daemon.close_flow(1);
    assert!(matches!(daemon.flow_outbound(1, b"x"), Outbound::Dropped));
}

#[test]
fn blocked_host_flow_drops_packets() {
    let (daemon, _h, _a) = make();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);

    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.network.blocked_hosts = vec!["evil.example".to_string()];
    daemon.update_policy(pol).unwrap();

    assert_eq!(
        daemon.open_flow(7, &work, "evil.example"),
        FlowDisposition::Block
    );
    assert!(matches!(daemon.flow_outbound(7, b"x"), Outbound::Dropped));
}

#[cfg(unix)]
struct AllowAll;
#[cfg(unix)]
impl clave_ipc::transport::PeerAuthenticator for AllowAll {
    fn authenticate(&self, _cred: &clave_ipc::transport::PeerCred, _nonce: u64) -> bool {
        true
    }
}

#[cfg(unix)]
#[tokio::test]
async fn daemon_serves_decisions_over_ipc() {
    use clave_ipc::transport::{client_handshake, serve, server_handshake, Connection, IpcServer};
    use clave_ipc::{DaemonMsg, ShimMsg};

    let (daemon, _h, _a) = make();
    let mut path = std::env::temp_dir();
    path.push(format!("clave-daemon-ipc-{}.sock", std::process::id()));
    let server = IpcServer::bind(&path).unwrap();

    let d = Arc::clone(&daemon);
    let srv = tokio::spawn(async move {
        let mut conn = server.accept().await.unwrap();
        server_handshake(&mut conn, &AllowAll).await.unwrap();
        serve(conn, move |msg| d.handle_shim_msg(msg, 1))
            .await
            .unwrap();
    });

    let mut client = Connection::connect(&path).await.unwrap();
    client_handshake(&mut client, 1).await.unwrap();
    client
        .write(&ShimMsg::RequestDecision {
            req_id: 3,
            action: Action::ClipboardTransfer {
                src: Zone::Work,
                dst: Zone::Personal,
                fmt: ClipFormat::Files,
            },
        })
        .await
        .unwrap();

    let reply: Option<DaemonMsg> = client.read().await.unwrap();
    assert!(
        matches!(reply, Some(DaemonMsg::Decision { req_id: 3, verdict }) if verdict.decision == Decision::Deny)
    );

    drop(client);
    srv.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[cfg(unix)]
#[tokio::test]
async fn daemon_serves_the_launcher_over_ipc() {
    use clave_ipc::transport::{serve_launcher, IpcServer, LauncherClient};

    // A daemon whose policy lists one launchable work app.
    let (daemon, _h, _a, _kit) = make_full();
    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.apps.allow.push(
        AppRule::new(AppId("excel-work".into()), chrome_work())
            .with_display_name("Excel (Work)")
            .with_executable("/Applications/Microsoft Excel.app"),
    );
    daemon.update_policy(pol).unwrap();

    let mut path = std::env::temp_dir();
    path.push(format!("clave-launcher-ipc-{}.sock", std::process::id()));
    let server = IpcServer::bind(&path).unwrap();

    let d = Arc::clone(&daemon);
    let srv = tokio::spawn(async move {
        let conn = server.accept().await.unwrap();
        serve_launcher(conn, move |req| d.handle_launcher_request(req))
            .await
            .unwrap();
    });

    // The Tauri backend's exact client path: connect + handshake, then typed round-trips.
    let mut client = LauncherClient::connect(&path).await.unwrap();

    let apps = client.list_apps().await.unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].app_id, AppId("excel-work".into()));
    assert_eq!(apps[0].label, "Excel (Work)");

    let spec = client
        .prepare_launch(AppId("excel-work".into()))
        .await
        .unwrap()
        .expect("launchable + mounted");
    assert_eq!(spec.executable, "/Applications/Microsoft Excel.app");
    assert!(client
        .prepare_launch(AppId("unknown".into()))
        .await
        .unwrap()
        .is_none());

    // The posture comes straight from the OS adapter; the mock reports development-only/unavailable.
    let caps = client.enforcement().await.unwrap();
    assert!(!caps.is_empty(), "posture should list capabilities");

    drop(client);
    srv.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

// gateway: authenticated control commands

#[test]
fn gateway_signed_wipe_crypto_shreds_the_enclave() {
    let (daemon, h, audit, kit) = make_full();
    daemon.unlock_volume(1).unwrap();
    let cmd = kit.signer.sign(
        1,
        100,
        GatewayCommand::Wipe {
            container: kit.id.0,
            reason: ControlReason::LostOrStolen,
        },
    );
    daemon.apply_gateway_command(&cmd, 100).unwrap();

    assert!(!daemon.volume_is_unlocked(), "DEK evicted");
    assert!(
        !kit.keystore.contains(kit.id),
        "wrapped key crypto-shredded"
    );
    assert!(kit.backing.is_wiped(), "wipe marker set");
    assert_eq!(h.volume.wipe_count(), 1, "OS mount teardown signalled");
    assert!(audit
        .events()
        .iter()
        .any(|e| e.action == AuditAction::Wiped));
}

#[test]
fn gateway_wipe_for_a_different_container_is_refused() {
    let (daemon, _h, _a, kit) = make_full();
    daemon.unlock_volume(1).unwrap();
    let cmd = kit.signer.sign(
        1,
        100,
        GatewayCommand::Wipe {
            container: 0xBADC0DE, // some other device's enclave
            reason: ControlReason::AdminRequest,
        },
    );
    assert_eq!(
        daemon.apply_gateway_command(&cmd, 100),
        Err(GatewayError::WrongContainer)
    );
    assert!(
        daemon.volume_is_unlocked(),
        "a wipe for another device must not touch this one"
    );
}

#[test]
fn forged_gateway_command_changes_nothing() {
    let (daemon, _h, _a, kit) = make_full();
    daemon.unlock_volume(1).unwrap();
    // An attacker (wrong key) signs a wipe for the right container.
    let attacker = GatewaySigningKey::from_seed(TenantId(1), [0xFF; 32]);
    let forged = attacker.sign(
        1,
        100,
        GatewayCommand::Wipe {
            container: kit.id.0,
            reason: ControlReason::Compromise,
        },
    );
    assert_eq!(
        daemon.apply_gateway_command(&forged, 100),
        Err(GatewayError::Rejected(ProtoError::BadSignature))
    );
    assert!(daemon.volume_is_unlocked(), "a forged command did not wipe");
}

#[test]
fn replayed_gateway_command_is_rejected() {
    let (daemon, _h, _a, kit) = make_full();
    let cmd = kit.signer.sign(
        1,
        100,
        GatewayCommand::Lock {
            reason: ControlReason::Compromise,
        },
    );
    daemon.apply_gateway_command(&cmd, 100).unwrap(); // first delivery: applied
    assert!(matches!(
        daemon.apply_gateway_command(&cmd, 100),
        Err(GatewayError::Rejected(ProtoError::Replay { .. }))
    ));
}

#[test]
fn gateway_signed_policy_update_applies_and_rejects_rollback() {
    let (daemon, _h, _a, kit) = make_full();

    let mut v2 = PolicyBundle::restrictive_default();
    v2.version = 2;
    daemon
        .apply_gateway_command(
            &kit.signer.sign(1, 100, GatewayCommand::UpdatePolicy(v2)),
            100,
        )
        .unwrap();
    assert_eq!(daemon.policy_version(), 2);

    // A later, authentic, but *older* bundle: rejected by version monotonicity.
    let mut v1 = PolicyBundle::restrictive_default();
    v1.version = 1;
    assert!(matches!(
        daemon.apply_gateway_command(
            &kit.signer.sign(2, 101, GatewayCommand::UpdatePolicy(v1)),
            101
        ),
        Err(GatewayError::Policy(_))
    ));
    assert_eq!(daemon.policy_version(), 2, "rollback rejected");
}

#[test]
fn gateway_lock_command_unmounts_the_disk() {
    let (daemon, _h, _a, kit) = make_full();
    daemon.unlock_volume(1).unwrap();
    assert!(daemon.volume_is_unlocked());
    let lock = kit.signer.sign(
        1,
        100,
        GatewayCommand::Lock {
            reason: ControlReason::AdminRequest,
        },
    );
    daemon.apply_gateway_command(&lock, 100).unwrap();
    assert!(
        !daemon.volume_is_unlocked(),
        "gateway Lock unmounted the disk"
    );
}

#[tokio::test]
async fn gateway_command_drives_through_the_event_loop() {
    let (daemon, _h, _a, kit) = make_full();
    daemon.unlock_volume(1).unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let runner = Arc::clone(&daemon);
    let jh = tokio::spawn(async move { runner.run(rx, || 100u64).await });

    let cmd = kit.signer.sign(
        1,
        100,
        GatewayCommand::Wipe {
            container: kit.id.0,
            reason: ControlReason::Offboarding,
        },
    );
    tx.send(DaemonEvent::GatewayControl(Box::new(cmd)))
        .await
        .unwrap();
    tx.send(DaemonEvent::Shutdown).await.unwrap();
    jh.await.unwrap();

    assert!(
        !daemon.volume_is_unlocked(),
        "the GatewayControl event wiped the enclave"
    );
}

#[test]
fn daemon_audit_drains_into_a_verifiable_signed_batch() {
    // The daemon's audit sink is an AuditSpool; the (future) sync loop drains it, the device signs
    // the batch, and the gateway verifies the tamper-evident chain end to end.
    let (daemon, _h, _a, kit) = make_full();
    daemon.unlock_volume(1).unwrap(); // emits VolumeMounted (seq 1)
    let wipe = kit.signer.sign(
        1,
        100,
        GatewayCommand::Wipe {
            container: kit.id.0,
            reason: ControlReason::Offboarding,
        },
    );
    daemon.apply_gateway_command(&wipe, 100).unwrap(); // emits Wiped (seq 2)

    let device = DeviceSigningKey::from_seed([0xD0; 32]);
    let (entries, head) = kit.spool.drain();
    assert!(
        entries.iter().any(|e| e.event.action == AuditAction::Wiped),
        "the wipe was recorded in the audit chain"
    );

    let batch = device.sign_batch(entries, head);
    verify_batch(GENESIS, 1, &batch, device.public_key())
        .expect("the daemon's audit chain verifies at the gateway");
}

#[test]
fn volume_handle_shares_one_instance_so_wipe_halts_the_mount() {
    // The OS mount adapter (WinFsp/APFS) holds this same `Arc<Mutex<ClaveVolume>>` and runs its
    // per-sector crypto through it — so there is exactly one DEK and one lock state, not a second
    // copy that could keep serving plaintext after a wipe.
    let (daemon, _h, _audit, _vol) = make_full();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);
    daemon.unlock_volume(1).unwrap();

    let mount = daemon.volume_handle();
    assert!(
        mount.lock().unwrap().is_unlocked(),
        "the mount holds the same unlocked volume the daemon does"
    );

    // A remote wipe via the daemon must instantly affect the SHARED instance the mount serves —
    // the very point of the Arc seam.
    daemon.wipe(2).unwrap();
    assert!(
        !mount.lock().unwrap().is_unlocked(),
        "wipe evicted the DEK the mount was using"
    );
    let mut buf = vec![0u8; SECTOR_SIZE];
    assert_eq!(
        mount.lock().unwrap().read(&work, 0, &mut buf),
        Err(VolumeError::Locked),
        "I/O through the mount handle now fails closed"
    );
}

#[test]
fn gateway_sync_applies_pulled_commands_and_ships_signed_audit() {
    let (daemon, _h, _a, kit) = make_full();
    daemon.unlock_volume(1).unwrap(); // VolumeMounted (seq 1)

    // The gateway pushes a signed wipe onto the link; the daemon device-signs the audit it drains.
    let link = LoopbackLink::new();
    link.enqueue_command(kit.signer.sign(
        1,
        100,
        GatewayCommand::Wipe {
            container: kit.id.0,
            reason: ControlReason::Offboarding,
        },
    ));
    let device = DeviceSigningKey::from_seed([0xD0; 32]);
    let store = MemCheckpointStore::new();
    let mut sync = GatewaySync::new(
        Box::new(link.clone()),
        DeviceSigningKey::from_seed([0xD0; 32]),
        Box::new(store.clone()),
    );

    let report = sync.sync_once(&daemon, 100);

    assert_eq!(report.applied, 1);
    assert_eq!(report.rejected, 0);
    assert!(!daemon.volume_is_unlocked(), "the pulled wipe was applied");

    // The drained audit (VolumeMounted + Wiped) was signed, shipped, and verifies as a chain.
    let batches = link.pushed_batches();
    assert_eq!(batches.len(), 1);
    verify_batch(GENESIS, 1, &batches[0], device.public_key())
        .expect("the shipped audit batch verifies at the gateway");

    // The cycle persisted the advanced posture so a restart can't rewind it.
    let saved = store.load().expect("a checkpoint was persisted");
    assert_eq!(
        saved.gateway_high_water, 1,
        "the anti-replay mark advanced and was saved"
    );
}

#[test]
fn audit_survives_a_dead_link_and_never_wedges_the_chain() {
    // Regression (review finding): the old drain-then-ship removed entries then dropped the batch
    // when the link was down — advancing the chain past entries the gateway never received, so
    // every later batch failed with a permanent gap. The ack-based ship retains entries on failure
    // and re-ships the whole tail intact once the link recovers.
    let (daemon, _h, _a, _kit) = make_full();
    daemon.unlock_volume(1).unwrap(); // VolumeMounted (seq 1)

    let device = DeviceSigningKey::from_seed([0xD0; 32]);
    let link = LoopbackLink::new();
    link.set_online(false); // the link is DOWN
    let store = MemCheckpointStore::new();
    let mut sync = GatewaySync::new(
        Box::new(link.clone()),
        DeviceSigningKey::from_seed([0xD0; 32]),
        Box::new(store.clone()),
    );

    // Cycle 1: nothing ships; the entry is retained, not lost.
    let r1 = sync.sync_once(&daemon, 100);
    assert_eq!(r1.audit_shipped, 0);
    assert!(r1.audit_retained >= 1, "the undelivered entry is retained");
    assert!(link.pushed_batches().is_empty(), "a dead link delivers nothing");

    // More audit accrues while still offline.
    daemon.on_zone_join(pid(10), JoinReason::Launcher, 101); // ProcessJoinedZone (seq 2)
    let r2 = sync.sync_once(&daemon, 101);
    assert_eq!(r2.audit_shipped, 0, "still offline, still nothing shipped");

    // Link recovers → the next cycle ships the FULL retained tail as one continuous chain.
    link.set_online(true);
    let r3 = sync.sync_once(&daemon, 102);
    assert!(
        r3.audit_shipped >= 2,
        "the whole retained tail ships once the link is back"
    );

    let batches = link.pushed_batches();
    assert_eq!(
        batches.len(),
        1,
        "exactly one batch delivered — nothing lost, nothing duplicated"
    );
    verify_batch(GENESIS, 1, &batches[0], device.public_key())
        .expect("the recovered batch verifies as an unbroken chain from genesis");

    // A subsequent cycle with no new audit ships nothing — the tail was acknowledged and dropped.
    let r4 = sync.sync_once(&daemon, 103);
    assert_eq!(r4.audit_shipped, 0);
    assert_eq!(r4.audit_retained, 0);
}

#[test]
fn a_crash_before_ack_re_ships_pending_audit_via_the_file_checkpoint() {
    // Durability across a real restart: with a dead link the entries are retained in memory AND
    // captured in the persisted checkpoint. A fresh daemon restored from that on-disk checkpoint
    // resumes the pending tail and ships it — so a crash before the gateway acknowledged does not
    // leave a permanent gap.
    let dir = std::env::temp_dir().join(format!("clave-cp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("checkpoint.bin");
    let device = DeviceSigningKey::from_seed([0xD0; 32]);

    // -- lifetime 1: emit audit, fail to ship (link down), but persist to the file store.
    let tenant_pubkey = {
        let (daemon, _h, _a, kit) = make_full();
        daemon.unlock_volume(1).unwrap(); // VolumeMounted (seq 1)
        let link = LoopbackLink::new();
        link.set_online(false);
        let mut sync = GatewaySync::new(
            Box::new(link),
            DeviceSigningKey::from_seed([0xD0; 32]),
            Box::new(FileCheckpointStore::new(&path)),
        );
        let r = sync.sync_once(&daemon, 100);
        assert_eq!(r.audit_shipped, 0);
        assert!(r.audit_retained >= 1);
        kit.signer.public_key()
    };

    // The on-disk checkpoint captured the unshipped tail.
    let cp = FileCheckpointStore::new(&path)
        .load()
        .expect("checkpoint persisted to disk");
    assert!(
        !cp.audit_pending.is_empty(),
        "the unshipped audit tail was persisted"
    );

    // -- lifetime 2: a fresh daemon restored from the on-disk checkpoint, now with a live link.
    let daemon = restored_daemon(cp, tenant_pubkey);
    let link = LoopbackLink::new(); // online by default
    let mut sync = GatewaySync::new(
        Box::new(link.clone()),
        DeviceSigningKey::from_seed([0xD0; 32]),
        Box::new(FileCheckpointStore::new(&path)),
    );
    let r = sync.sync_once(&daemon, 200);
    assert!(r.audit_shipped >= 1, "the resumed tail ships after the restart");

    let batches = link.pushed_batches();
    assert_eq!(batches.len(), 1);
    verify_batch(GENESIS, 1, &batches[0], device.public_key())
        .expect("the resumed audit chain verifies unbroken from genesis");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn gateway_sync_counts_a_forged_command_as_rejected_and_changes_nothing() {
    let (daemon, _h, _a, kit) = make_full();
    daemon.unlock_volume(1).unwrap();

    let attacker = GatewaySigningKey::from_seed(TenantId(1), [0xFF; 32]);
    let link = LoopbackLink::new();
    link.enqueue_command(attacker.sign(
        1,
        100,
        GatewayCommand::Wipe {
            container: kit.id.0,
            reason: ControlReason::Compromise,
        },
    ));
    let mut sync = GatewaySync::new(
        Box::new(link.clone()),
        DeviceSigningKey::from_seed([1u8; 32]),
        Box::new(MemCheckpointStore::new()),
    );

    let report = sync.sync_once(&daemon, 100);

    assert_eq!(report.applied, 0);
    assert_eq!(report.rejected, 1);
    assert!(
        daemon.volume_is_unlocked(),
        "the forged wipe changed nothing"
    );
}

// platform enforcement posture

#[test]
fn enforcement_report_marks_the_mock_as_development_only() {
    let (daemon, _h, _a, _kit) = make_full();
    let report = daemon.enforcement_report();
    assert!(
        !report.is_production_ready(),
        "the mock platform is never production-ready"
    );
    let blockers = report.production_blockers();
    assert_eq!(blockers.len(), Capability::COUNT);
    assert!(
        blockers
            .iter()
            .all(|(_, s)| *s == EnforcementStatus::DevelopmentOnly),
        "every mock capability is a development stand-in"
    );
}

#[test]
fn a_fully_enforced_platform_passes_the_production_gate() {
    let (daemon, h, _a, _kit) = make_full();
    h.set_all_enforced();
    let report = daemon.enforcement_report();
    assert!(report.is_production_ready());
    assert!(report.require_production().is_ok());
}

#[test]
fn one_unavailable_capability_blocks_production() {
    let (daemon, h, _a, _kit) = make_full();
    h.set_all_enforced();
    h.set_enforcement(Capability::Network, EnforcementStatus::Unavailable);

    let report = daemon.enforcement_report();
    assert!(!report.is_production_ready());
    assert_eq!(
        report.require_production().unwrap_err(),
        vec![(Capability::Network, EnforcementStatus::Unavailable)]
    );
}

/// Rebuild a daemon from a persisted [`Checkpoint`], as production would on startup: the gateway
/// verifier is restored with the saved high-water mark and the audit spool resumes from the saved
/// `(seq, head)` — so neither anti-replay nor the audit chain rewinds.
fn restored_daemon(cp: Checkpoint, tenant_pubkey: [u8; 32]) -> Arc<Daemon> {
    let platform = MockPlatform::new();
    let zones = Arc::clone(&platform.zones);
    let id = ContainerId(0xC1A5_ED15);
    let keystore = Arc::new(MemKeyStore::new());
    keystore.provision(
        id,
        Kek::from_bytes([0x4B; 32]),
        &Dek::from_bytes([0xDE; 64]),
    );
    let backing = Arc::new(MemBacking::zeroed(64));
    let volume = ClaveVolume::new(ContainerMeta::new(id), keystore, backing, zones.clone());
    let gateway = GatewayVerifier::new(TenantId(1), tenant_pubkey)
        .unwrap()
        .with_high_water(cp.gateway_high_water);
    let spool = Arc::new(AuditSpool::resume_with(
        cp.audit_seq,
        cp.audit_head,
        cp.audit_pending.clone(),
    ));
    Arc::new(Daemon::new(
        zones,
        Box::new(platform),
        spool,
        PolicyBundle::restrictive_default(),
        Box::new(LoopbackTunnel::new(0x5A)),
        Arc::new(Mutex::new(volume)),
        gateway,
    ))
}

#[test]
fn gateway_high_water_survives_a_restart_via_the_checkpoint_store() {
    // -- lifetime 1: apply a gateway command at counter 5; the sync cycle persists the checkpoint.
    let (daemon, _h, _a, kit) = make_full();
    let store = MemCheckpointStore::new();
    let link = LoopbackLink::new();
    link.enqueue_command(kit.signer.sign(
        5,
        100,
        GatewayCommand::Lock {
            reason: ControlReason::AdminRequest,
        },
    ));
    let mut sync = GatewaySync::new(
        Box::new(link.clone()),
        DeviceSigningKey::from_seed([0xD0; 32]),
        Box::new(store.clone()),
    );
    assert_eq!(sync.sync_once(&daemon, 100).applied, 1);

    // The sync cycle persisted the advanced anti-replay mark.
    let cp = store.load().expect("the sync cycle persisted a checkpoint");
    assert_eq!(
        cp.gateway_high_water, 5,
        "the advanced anti-replay mark was saved"
    );

    // -- lifetime 2: a fresh daemon RESTORED from the persisted checkpoint (the "restart").
    let restored = restored_daemon(cp, kit.signer.public_key());

    // A replay at or below the restored mark is rejected — the restart did NOT rewind it.
    let replay = kit.signer.sign(
        5,
        101,
        GatewayCommand::Lock {
            reason: ControlReason::AdminRequest,
        },
    );
    assert!(matches!(
        restored.apply_gateway_command(&replay, 101),
        Err(GatewayError::Rejected(ProtoError::Replay { .. }))
    ));

    // A genuinely new command (higher counter) is still accepted, continuing from the restored mark.
    let next = kit.signer.sign(
        6,
        101,
        GatewayCommand::Lock {
            reason: ControlReason::AdminRequest,
        },
    );
    assert!(restored.apply_gateway_command(&next, 101).is_ok());
}

// process supervision: exec classification via the app allow-list

fn chrome_work() -> BinaryMatch {
    BinaryMatch::Macos {
        team_id: "ABCDE12345".into(),
        signing_id: "com.google.Chrome".into(),
    }
}

#[test]
fn allowlisted_exec_joins_the_zone_and_is_audited() {
    let (daemon, _h, audit, _kit) = make_full();
    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.apps
        .allow
        .push(AppRule::new(AppId("chrome-work".into()), chrome_work()));
    daemon.update_policy(pol).unwrap();

    let proc = pid(50);
    let verdict = daemon.on_exec(proc, None, &chrome_work(), 1);

    assert!(verdict.joins_zone);
    assert_eq!(verdict.matched, Some(AppId("chrome-work".into())));
    assert!(daemon.zones().is_supervised(&proc));
    assert!(audit
        .events()
        .iter()
        .any(|e| e.action == AuditAction::ProcessJoinedZone));
}

#[test]
fn unlisted_exec_stays_personal() {
    let (daemon, _h, _a, _kit) = make_full();
    let personal = BinaryMatch::Macos {
        team_id: "ZZZ".into(),
        signing_id: "com.personal.app".into(),
    };
    let proc = pid(51);
    let verdict = daemon.on_exec(proc, None, &personal, 1);

    assert!(!verdict.joins_zone);
    assert!(
        !daemon.zones().is_supervised(&proc),
        "personal apps are never supervised"
    );
}

#[test]
fn child_of_a_supervised_process_inherits_membership() {
    let (daemon, _h, _a, _kit) = make_full();
    let parent = pid(60);
    daemon.on_zone_join(parent, JoinReason::Launcher, 1); // parent is a work process
    let child = pid(61);
    let helper = BinaryMatch::Macos {
        team_id: "ZZZ".into(),
        signing_id: "com.unlisted.helper".into(),
    };

    let verdict = daemon.on_exec(child, Some(parent), &helper, 2);
    assert!(
        verdict.joins_zone,
        "a child of a supervised process inherits"
    );
    assert!(daemon.zones().is_supervised(&child));
}

#[test]
fn resolve_launch_redirects_a_matched_app_into_the_clave_disk() {
    let (daemon, _h, _a, _kit) = make_full();
    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.apps.allow.push(
        AppRule::new(AppId("chrome-work".into()), chrome_work()).with_launch(LaunchProfile {
            home_subdir: "chrome-work".into(),
            ..Default::default()
        }),
    );
    daemon.update_policy(pol).unwrap();

    // The mock volume mounts at /Volumes/ClaveDisk — so the app's HOME lands inside the enclave.
    let resolved = daemon
        .resolve_launch(&AppId("chrome-work".into()))
        .expect("a known app + mounted volume resolves");
    assert_eq!(resolved.home, "/Volumes/ClaveDisk/profiles/chrome-work");
    assert!(resolved
        .env
        .iter()
        .any(|(k, v)| k == "HOME" && v == &resolved.home));
}

#[test]
fn resolve_launch_is_none_for_an_unknown_app() {
    let (daemon, _h, _a, _kit) = make_full();
    assert!(daemon
        .resolve_launch(&AppId("not-enrolled".into()))
        .is_none());
}

#[test]
fn classify_path_redirects_work_data_and_respects_passthrough() {
    let (daemon, _h, _a, _kit) = make_full();
    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.files.work_data_roots = vec!["/Users/alice/Documents".into()];
    pol.apps.allow.push(
        AppRule::new(AppId("chrome-work".into()), chrome_work()).with_launch(LaunchProfile {
            passthrough_paths: vec!["/Users/alice/Documents/shared".into()],
            ..Default::default()
        }),
    );
    daemon.update_policy(pol).unwrap();

    let app = AppId("chrome-work".into());
    // Work data → redirect into the enclave; an explicit pass-through under it → left alone.
    assert_eq!(
        daemon.classify_path(&app, "/Users/alice/Documents/q3.xlsx"),
        Some(PathClass::WorkData)
    );
    assert_eq!(
        daemon.classify_path(&app, "/Users/alice/Documents/shared/logo.png"),
        Some(PathClass::PassThrough)
    );
    // Already inside the mounted disk → pass-through; unknown app → None.
    assert_eq!(
        daemon.classify_path(&app, "/Volumes/ClaveDisk/profiles/chrome-work/Prefs"),
        Some(PathClass::PassThrough)
    );
    assert_eq!(daemon.classify_path(&AppId("nope".into()), "/x"), None);
}

// the Clave launcher

#[test]
fn launchable_apps_lists_only_apps_with_an_executable() {
    let (daemon, _h, _a, _kit) = make_full();
    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.apps.allow.push(
        AppRule::new(AppId("excel-work".into()), chrome_work())
            .with_display_name("Excel (Work)")
            .with_executable("/Applications/Microsoft Excel.app"),
    );
    // An authorization-only rule (no executable): recognized if it runs, but not launcher-launchable.
    pol.apps.allow.push(AppRule::new(
        AppId("auth-only".into()),
        BinaryMatch::Macos {
            team_id: "T".into(),
            signing_id: "x".into(),
        },
    ));
    daemon.update_policy(pol).unwrap();

    let apps = daemon.launchable_apps();
    assert_eq!(apps.len(), 1, "only the app with an executable is launchable");
    assert_eq!(apps[0].app_id, AppId("excel-work".into()));
    assert_eq!(apps[0].label, "Excel (Work)");
}

#[test]
fn prepare_launch_resolves_the_contained_spawn_spec() {
    let (daemon, _h, _a, _kit) = make_full();
    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.apps.allow.push(
        AppRule::new(AppId("excel-work".into()), chrome_work())
            .with_executable("/Applications/Microsoft Excel.app"),
    );
    daemon.update_policy(pol).unwrap();

    let spec = daemon
        .prepare_launch(&AppId("excel-work".into()))
        .expect("a launchable app + a mounted volume");
    assert_eq!(spec.executable, "/Applications/Microsoft Excel.app");
    // HOME lands inside the mounted Clave Disk, so the app's profile persists encrypted.
    assert!(spec
        .env
        .iter()
        .any(|(k, v)| k == "HOME" && v == "/Volumes/ClaveDisk/profiles/excel-work"));

    // Unknown / non-launchable app → None.
    assert!(daemon.prepare_launch(&AppId("nope".into())).is_none());
}
