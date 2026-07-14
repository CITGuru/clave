use std::sync::{Arc, Mutex};

use clave_core::{
    Action, AppId, AppRule, AuditAction, BinaryMatch, DnsDecision, DnsSteering, ForwardMode,
    JoinReason, LaunchProfile, NetworkProvider, OverlayPolicy, PathClass, PolicyBundle, WebAppRule,
    WebPolicy,
};
use clave_daemon::{
    Checkpoint, CheckpointStore, Daemon, DaemonEvent, FileCheckpointStore, GatewayError,
    GatewaySync, MemCheckpointStore, PolicyError,
};
use clave_net::{FlowDisposition, Inbound, LoopbackTunnel, Outbound, Tunnel, TunnelOut};
use clave_platform::{
    Capability, ClipFormat, Decision, EnforcementStatus, ProcId, Rgba, Route, WindowId, Zone,
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

struct Kit {
    keystore: Arc<MemKeyStore>,
    backing: Arc<MemBacking>,
    id: ContainerId,
    signer: GatewaySigningKey,
    spool: Arc<AuditSpool>,
}

fn make_full() -> (Arc<Daemon>, MockPlatform, RecordingAuditSink, Kit) {
    let platform = MockPlatform::new();
    let handle = platform.clone();
    let zones = Arc::clone(&platform.zones);
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

fn make() -> (Arc<Daemon>, MockPlatform, RecordingAuditSink) {
    let (daemon, handle, audit, _vol) = make_full();
    (daemon, handle, audit)
}

struct OfflineTunnel;

impl Tunnel for OfflineTunnel {
    fn encapsulate(&mut self, ip_packet: &[u8]) -> TunnelOut {
        if ip_packet.is_empty() {
            TunnelOut::Idle
        } else {
            TunnelOut::SendToGateway(vec![0xFF])
        }
    }
    fn decapsulate(&mut self, _datagram: &[u8]) -> Inbound {
        Inbound::Idle
    }
    fn is_established(&self) -> bool {
        false
    }
}

fn offline_daemon() -> Arc<Daemon> {
    let platform = MockPlatform::new();
    let zones = Arc::clone(&platform.zones);
    let spool = Arc::new(AuditSpool::with_sink(Arc::new(RecordingAuditSink::new())));
    let id = ContainerId(0xC1A5_ED15);
    let keystore = Arc::new(MemKeyStore::new());
    keystore.provision(
        id,
        Kek::from_bytes([0x4B; 32]),
        &Dek::from_bytes([0xDE; 64]),
    );
    let backing = Arc::new(MemBacking::zeroed(64));
    let volume = ClaveVolume::new(ContainerMeta::new(id), keystore, backing, zones.clone());
    let signer = GatewaySigningKey::from_seed(TenantId(1), [0x6A; 32]);
    let gateway = GatewayVerifier::new(TenantId(1), signer.public_key()).unwrap();
    Arc::new(Daemon::new(
        zones,
        Box::new(platform),
        spool,
        PolicyBundle::restrictive_default(),
        Box::new(OfflineTunnel),
        Arc::new(Mutex::new(volume)),
        gateway,
    ))
}

#[test]
fn repeated_denials_are_coalesced_in_the_audit_chain() {
    let (daemon, _h, _audit) = make();
    let leak = Action::ClipboardTransfer {
        src: Zone::Work,
        dst: Zone::Personal,
        fmt: ClipFormat::Files,
    };

    for _ in 0..50 {
        assert_eq!(daemon.decide_action(&leak, 1_000).decision, Decision::Deny);
    }
    assert_eq!(
        daemon.peek_audit().0.len(),
        1,
        "a tight denial loop within the window audits once"
    );

    daemon.decide_action(&leak, 1_005);
    assert_eq!(
        daemon.peek_audit().0.len(),
        2,
        "a denial after the coalesce window is audited afresh"
    );
}

#[test]
fn web_apps_resolve_to_a_contained_browser_window() {
    let (daemon, _h, _audit) = make();
    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.web = WebPolicy {
        browser: "/Applications/Google Chrome.app".into(),
        apps: vec![WebAppRule::new("jira-work", "https://jira.corp").with_display_name("Jira")],
    };
    daemon.update_policy(pol).unwrap();

    let apps = daemon.web_apps();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].label, "Jira");
    assert_eq!(apps[0].url, "https://jira.corp");

    let spec = daemon
        .prepare_web_launch(&AppId("jira-work".into()))
        .expect("resolves to a launch spec");
    assert_eq!(spec.executable, "/Applications/Google Chrome.app");
    assert!(spec.args.iter().any(|a| a == "--app=https://jira.corp"));
    assert!(spec
        .args
        .iter()
        .any(|a| a.starts_with("--user-data-dir=") && a.ends_with("/profiles/web-jira-work")));
}

#[test]
fn no_web_browser_means_no_web_apps() {
    let (daemon, _h, _audit) = make();
    assert!(daemon.web_apps().is_empty());
    assert!(daemon
        .prepare_web_launch(&AppId("jira-work".into()))
        .is_none());
}

#[test]
fn launcher_status_reports_enrollment_and_volume_state() {
    let daemon = offline_daemon();
    let status = daemon.launcher_status();
    assert_eq!(status.tenant, 1);
    assert_eq!(status.policy_version, daemon.policy_version());
    assert_eq!(status.gateway_high_water, 0);
    assert_eq!(status.volume_unlocked, daemon.volume_is_unlocked());
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
fn clave_edge_appearance_follows_policy_live() {
    let (daemon, _h, _audit) = make();
    let cfg = daemon.overlay_cfg();
    assert_eq!(cfg.color, Rgba::CLAVE_EDGE);
    assert_eq!(cfg.thickness, 3);

    let brand = Rgba {
        r: 0xFF,
        g: 0x8C,
        b: 0x00,
        a: 0xFF,
    };
    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.overlay = OverlayPolicy {
        color: brand,
        thickness: 8,
    };
    daemon.update_policy(pol).unwrap();

    let cfg = daemon.overlay_cfg();
    assert_eq!(cfg.color, brand);
    assert_eq!(cfg.thickness, 8);
}

#[test]
fn zone_membership_drives_split_tunnel() {
    let (daemon, h, _audit) = make();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);

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
fn dns_steering_follows_the_provider_policy() {
    let (daemon, _h, _audit) = make();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);

    assert_eq!(
        daemon.dns_decision(&work, "intra.corp"),
        DnsDecision::Personal
    );

    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.network.providers = vec![NetworkProvider {
        id: "cisco-umbrella".into(),
        display_name: "Cisco Umbrella (DNS)".into(),
        mode: ForwardMode::Dns,
        endpoints: Vec::new(),
        static_egress_ip: None,
        dns: Some(DnsSteering {
            resolvers: vec!["208.67.222.222".into()],
            match_domains: Vec::new(),
            steer_all: true,
        }),
        params: Default::default(),
    }];
    daemon.update_policy(pol).unwrap();

    assert_eq!(daemon.dns_decision(&work, "intra.corp"), DnsDecision::Steer);
    assert_eq!(
        daemon.dns_decision(&pid(99), "intra.corp"),
        DnsDecision::Personal
    );
}

#[test]
fn split_horizon_dns_flow_tunnels_work_names_only() {
    let (daemon, _h, _audit) = make();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);

    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.network.providers = vec![NetworkProvider {
        id: "corp-dns".into(),
        display_name: "Corporate split-horizon resolver".into(),
        mode: ForwardMode::Dns,
        endpoints: Vec::new(),
        static_egress_ip: None,
        dns: Some(DnsSteering {
            resolvers: vec!["10.0.0.53".into()],
            match_domains: vec!["corp.example".into()],
            steer_all: false,
        }),
        params: Default::default(),
    }];
    daemon.update_policy(pol).unwrap();

    assert_eq!(
        daemon.open_dns_flow(1, &work, "git.corp.example"),
        FlowDisposition::Tunnel
    );
    assert!(matches!(
        daemon.flow_outbound(1, b"dns-query"),
        Outbound::ToGateway(_)
    ));

    assert_eq!(
        daemon.open_dns_flow(2, &work, "news.example.com"),
        FlowDisposition::Direct
    );
    assert!(matches!(
        daemon.flow_outbound(2, b"dns-query"),
        Outbound::PassThrough
    ));

    assert_eq!(
        daemon.open_dns_flow(3, &pid(99), "git.corp.example"),
        FlowDisposition::Direct
    );
}

#[test]
fn work_flows_fail_closed_when_the_tunnel_is_down() {
    let daemon = offline_daemon();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);

    assert!(!daemon.network_link_is_up());

    assert_eq!(
        daemon.open_flow(1, &work, "intra.corp"),
        FlowDisposition::HeldOffline
    );
    assert!(matches!(
        daemon.flow_outbound(1, b"work-data"),
        Outbound::ToGateway(_)
    ));

    assert_eq!(
        daemon.open_dns_flow(2, &work, "intra.corp"),
        FlowDisposition::HeldOffline
    );

    assert_eq!(
        daemon.open_flow(3, &pid(99), "news.example"),
        FlowDisposition::Direct
    );
    assert!(matches!(
        daemon.flow_outbound(3, b"portal-auth"),
        Outbound::PassThrough
    ));
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
fn policy_update_notifies_the_observer() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let (daemon, _h, _audit) = make();

    let seen = Arc::new(AtomicU64::new(0));
    let recorder = Arc::clone(&seen);
    daemon.set_policy_observer(Box::new(move |bundle| {
        recorder.store(bundle.version, Ordering::SeqCst);
    }));

    let mut v3 = PolicyBundle::restrictive_default();
    v3.version = 3;
    daemon.update_policy(v3).unwrap();
    assert_eq!(
        seen.load(Ordering::SeqCst),
        3,
        "the observer sees the applied policy"
    );

    let mut stale = PolicyBundle::restrictive_default();
    stale.version = 1;
    assert!(daemon.update_policy(stale).is_err());
    assert_eq!(
        seen.load(Ordering::SeqCst),
        3,
        "a rejected rollback must not notify the observer"
    );
}

#[test]
fn wipe_invokes_volume_crypto_shred() {
    let (daemon, h, audit, vol) = make_full();
    daemon.unlock_volume(1).unwrap();
    assert!(daemon.volume_is_unlocked());
    assert!(vol.keystore.contains(vol.id));
    assert_eq!(h.volume.wipe_count(), 0);

    daemon.wipe(2).unwrap();

    assert!(!daemon.volume_is_unlocked(), "DEK evicted on wipe");
    assert!(
        !vol.keystore.contains(vol.id),
        "wrapped key crypto-shredded"
    );
    assert!(vol.backing.is_wiped(), "wipe marker set on the container");
    assert_eq!(
        h.volume.wipe_count(),
        1,
        "platform mount teardown signalled"
    );
    assert!(audit
        .events()
        .iter()
        .any(|e| e.action == AuditAction::Wiped));

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

    daemon
        .volume_write(&work, 0, &vec![0xAB; SECTOR_SIZE])
        .unwrap();
    let personal = pid(99);
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

    assert_eq!(
        daemon.open_flow(1, &work, "intra.corp"),
        FlowDisposition::Tunnel
    );
    let plaintext = b"GET /secret HTTP/1.1".to_vec();
    match daemon.flow_outbound(1, &plaintext) {
        Outbound::ToGateway(d) => assert_ne!(d, plaintext, "must be obscured on the wire"),
        other => panic!("expected ToGateway, got {other:?}"),
    }

    assert_eq!(
        daemon.open_flow(2, &pid(99), "news.example"),
        FlowDisposition::Direct
    );
    assert!(matches!(
        daemon.flow_outbound(2, b"x"),
        Outbound::PassThrough
    ));

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
        serve_launcher(conn, move |req| d.handle_launcher_request(req, 1))
            .await
            .unwrap();
    });

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

    let caps = client.enforcement().await.unwrap();
    assert!(!caps.is_empty(), "posture should list capabilities");

    drop(client);
    srv.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[cfg(unix)]
#[test]
fn launch_spawns_the_process_and_seeds_supervision() {
    let (daemon, _h, _audit) = make();
    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.apps.allow.push(
        AppRule::new(AppId("echo-work".into()), chrome_work())
            .with_display_name("Echo (Work)")
            .with_executable("/bin/echo"),
    );
    daemon.update_policy(pol).unwrap();

    let launched = daemon
        .launch(&AppId("echo-work".into()), 1)
        .expect("spawn + supervise");
    assert!(launched.pid > 0, "a real pid was assigned");
    assert!(
        daemon.zones().is_supervised(&launched.proc),
        "the launched process joined the work zone (launcher-seeded membership)"
    );

    assert!(matches!(
        daemon.launch(&AppId("does-not-exist".into()), 1),
        Err(clave_daemon::LaunchError::NotLaunchable)
    ));
}

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
            container: 0xBADC0DE,
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
    daemon.apply_gateway_command(&cmd, 100).unwrap();
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
            &kit.signer
                .sign(1, 100, GatewayCommand::UpdatePolicy(Box::new(v2))),
            100,
        )
        .unwrap();
    assert_eq!(daemon.policy_version(), 2);

    let mut v1 = PolicyBundle::restrictive_default();
    v1.version = 1;
    assert!(matches!(
        daemon.apply_gateway_command(
            &kit.signer
                .sign(2, 101, GatewayCommand::UpdatePolicy(Box::new(v1))),
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
    let (daemon, _h, _a, kit) = make_full();
    daemon.unlock_volume(1).unwrap();
    let wipe = kit.signer.sign(
        1,
        100,
        GatewayCommand::Wipe {
            container: kit.id.0,
            reason: ControlReason::Offboarding,
        },
    );
    daemon.apply_gateway_command(&wipe, 100).unwrap();

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
    let (daemon, _h, _audit, _vol) = make_full();
    let work = pid(10);
    daemon.on_zone_join(work, JoinReason::Launcher, 1);
    daemon.unlock_volume(1).unwrap();

    let mount = daemon.volume_handle();
    assert!(
        mount.lock().unwrap().is_unlocked(),
        "the mount holds the same unlocked volume the daemon does"
    );

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
    daemon.unlock_volume(1).unwrap();

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

    let batches = link.pushed_batches();
    assert_eq!(batches.len(), 1);
    verify_batch(GENESIS, 1, &batches[0], device.public_key())
        .expect("the shipped audit batch verifies at the gateway");

    let saved = store.load().expect("a checkpoint was persisted");
    assert_eq!(
        saved.gateway_high_water, 1,
        "the anti-replay mark advanced and was saved"
    );
}

#[test]
fn audit_survives_a_dead_link_and_never_wedges_the_chain() {
    let (daemon, _h, _a, _kit) = make_full();
    daemon.unlock_volume(1).unwrap();

    let device = DeviceSigningKey::from_seed([0xD0; 32]);
    let link = LoopbackLink::new();
    link.set_online(false);
    let store = MemCheckpointStore::new();
    let mut sync = GatewaySync::new(
        Box::new(link.clone()),
        DeviceSigningKey::from_seed([0xD0; 32]),
        Box::new(store.clone()),
    );

    let r1 = sync.sync_once(&daemon, 100);
    assert_eq!(r1.audit_shipped, 0);
    assert!(r1.audit_retained >= 1, "the undelivered entry is retained");
    assert!(
        link.pushed_batches().is_empty(),
        "a dead link delivers nothing"
    );

    daemon.on_zone_join(pid(10), JoinReason::Launcher, 101);
    let r2 = sync.sync_once(&daemon, 101);
    assert_eq!(r2.audit_shipped, 0, "still offline, still nothing shipped");

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

    let r4 = sync.sync_once(&daemon, 103);
    assert_eq!(r4.audit_shipped, 0);
    assert_eq!(r4.audit_retained, 0);
}

#[test]
fn a_crash_before_ack_re_ships_pending_audit_via_the_file_checkpoint() {
    let dir = std::env::temp_dir().join(format!("clave-cp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("checkpoint.bin");
    let device = DeviceSigningKey::from_seed([0xD0; 32]);

    let tenant_pubkey = {
        let (daemon, _h, _a, kit) = make_full();
        daemon.unlock_volume(1).unwrap();
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

    let cp = FileCheckpointStore::new(&path)
        .load()
        .expect("checkpoint persisted to disk");
    assert!(
        !cp.audit_pending.is_empty(),
        "the unshipped audit tail was persisted"
    );

    let daemon = restored_daemon(cp, tenant_pubkey);
    let link = LoopbackLink::new();
    let mut sync = GatewaySync::new(
        Box::new(link.clone()),
        DeviceSigningKey::from_seed([0xD0; 32]),
        Box::new(FileCheckpointStore::new(&path)),
    );
    let r = sync.sync_once(&daemon, 200);
    assert!(
        r.audit_shipped >= 1,
        "the resumed tail ships after the restart"
    );

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

    let cp = store.load().expect("the sync cycle persisted a checkpoint");
    assert_eq!(
        cp.gateway_high_water, 5,
        "the advanced anti-replay mark was saved"
    );

    let restored = restored_daemon(cp, kit.signer.public_key());

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

    let next = kit.signer.sign(
        6,
        101,
        GatewayCommand::Lock {
            reason: ControlReason::AdminRequest,
        },
    );
    assert!(restored.apply_gateway_command(&next, 101).is_ok());
}

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
    let verdict = daemon.on_exec(proc, None, &chrome_work(), false, 1);

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
    let verdict = daemon.on_exec(proc, None, &personal, false, 1);

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
    daemon.on_zone_join(parent, JoinReason::Launcher, 1);
    let child = pid(61);
    let helper = BinaryMatch::Macos {
        team_id: "ZZZ".into(),
        signing_id: "com.unlisted.helper".into(),
    };

    let verdict = daemon.on_exec(child, Some(parent), &helper, false, 2);
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
            profile_subdir: "chrome-work".into(),
            ..Default::default()
        }),
    );
    daemon.update_policy(pol).unwrap();

    let resolved = daemon
        .resolve_launch(&AppId("chrome-work".into()))
        .expect("a known app + mounted volume resolves");
    assert!(
        resolved.home.starts_with("/Volumes/ClaveDisk/") && resolved.home != "/Volumes/ClaveDisk/"
    );
    assert_eq!(
        resolved.profile_dir,
        format!("{}/profiles/chrome-work", resolved.home)
    );
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
    assert_eq!(
        daemon.classify_path(&app, "/Users/alice/Documents/q3.xlsx"),
        Some(PathClass::WorkData)
    );
    assert_eq!(
        daemon.classify_path(&app, "/Users/alice/Documents/shared/logo.png"),
        Some(PathClass::PassThrough)
    );
    assert_eq!(
        daemon.classify_path(&app, "/Volumes/ClaveDisk/profiles/chrome-work/Prefs"),
        Some(PathClass::PassThrough)
    );
    assert_eq!(daemon.classify_path(&AppId("nope".into()), "/x"), None);
}

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
    pol.apps.allow.push(AppRule::new(
        AppId("auth-only".into()),
        BinaryMatch::Macos {
            team_id: "T".into(),
            signing_id: "x".into(),
        },
    ));
    daemon.update_policy(pol).unwrap();

    let apps = daemon.launchable_apps();
    assert_eq!(
        apps.len(),
        1,
        "only the app with an executable is launchable"
    );
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
    assert!(spec.env.iter().any(|(k, v)| k == "HOME"
        && v.starts_with("/Volumes/ClaveDisk/")
        && v.as_str() != "/Volumes/ClaveDisk/"));

    assert!(daemon.prepare_launch(&AppId("nope".into())).is_none());
}
