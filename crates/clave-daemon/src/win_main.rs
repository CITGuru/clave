use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clave_core::{JoinReason, ZoneRegistry};
use clave_net::LoopbackTunnel;
use clave_platform::{Capability, EnforcementStatus, Platform, ProcessContainment, Zone};
use clave_win::NetVerdict;
use clave_proto::{AuditSpool, GatewaySigningKey, GatewayVerifier, TenantId};
use clave_volume::{ClaveVolume, ContainerId, ContainerMeta, Dek, Kek, MemBacking, MemKeyStore};

use crate::{proc_id_for_pid, Daemon};

/// How often the supervisor reconciles the work zone with the Job Object's live process tree.
const SUPERVISE_INTERVAL: Duration = Duration::from_millis(500);

/// The Clave Disk mount point on Windows. Until the WinFsp mount lands this is only used to
/// resolve each app's contained launch spec (redirected HOME/temp), not a live volume.
const MOUNT_POINT: &str = "X:";

const CONTAINER_ID: u128 = 0xC1A5_0057;

/// Runs the Windows daemon: hosts the policy brain, drives the `clave-win` adapter, and serves
/// the launcher UI over a named pipe. Blocks until the process is stopped.
pub fn run_windows() {
    let zones = Arc::new(ZoneRegistry::new());
    let mut platform = clave_win::WindowsPlatform::new(Arc::clone(&zones));
    platform.configure_volume(MOUNT_POINT);
    // A real clipboard guard runs (EmptyClipboard genuinely clears the payload), but it is
    // poll-based rather than the delayed-render broker, so its honest posture is development-only.
    platform.set_enforcement(Capability::Clipboard, EnforcementStatus::DevelopmentOnly);

    // Job Object containment for launched work apps: `launch` assigns each app to the job, and a
    // supervisor thread reconciles the work zone with the job's live process tree.
    let containment: Option<Arc<dyn ProcessContainment>> = match clave_win::ContainmentJob::new() {
        Ok(job) => {
            let job = Arc::new(job);
            platform.configure_containment(job.clone());
            Some(job)
        }
        Err(e) => {
            eprintln!("clave-daemon: Job Object containment unavailable ({e:?}); launched apps will not be contained");
            None
        }
    };

    let report = platform.enforcement_report();
    println!("platform: Windows adapter (clave-win)");
    print!("{report}");
    if !report.is_production_ready() {
        println!(
            "lab build: not production-ready — a capability reaches `enforced` only with\n\
             Microsoft-signed drivers on a Secure-Boot machine."
        );
    }

    let container = ContainerId(CONTAINER_ID);
    let keystore = Arc::new(MemKeyStore::new());
    keystore.provision(
        container,
        Kek::from_bytes([0x4B; 32]),
        &Dek::from_bytes([0xDE; 64]),
    );
    let volume = ClaveVolume::new(
        ContainerMeta::new(container),
        keystore,
        Arc::new(MemBacking::zeroed(64)),
        zones.clone(),
    );

    let signer = GatewaySigningKey::from_seed(TenantId(1), [0x6A; 32]);
    let gateway = GatewayVerifier::new(TenantId(1), signer.public_key()).expect("valid pinned key");

    let daemon = Arc::new(Daemon::new(
        Arc::clone(&zones),
        Box::new(platform),
        Arc::new(AuditSpool::new()),
        demo_policy(),
        Box::new(LoopbackTunnel::new(0x5A)),
        Arc::new(Mutex::new(volume)),
        gateway,
    ));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    spawn_clipboard_guard(Arc::clone(&daemon), Arc::clone(&zones));
    if let Some(containment) = containment {
        spawn_zone_supervisor(Arc::clone(&zones), containment);
    }
    spawn_split_tunnel(Arc::clone(&daemon), Arc::clone(&zones));

    if let Err(e) = rt.block_on(serve_launcher_loop(daemon)) {
        // `first_pipe_instance(true)` (which stops a rogue process from pre-creating the pipe and
        // hijacking launcher connections) surfaces a second daemon as ACCESS_DENIED on bind.
        if matches!(&e, clave_ipc::transport::TransportError::Io(io) if io.raw_os_error() == Some(5))
        {
            eprintln!(
                "clave-daemon: another clave-daemon already owns the launcher pipe \
                 ({}). Stop it first.",
                clave_ipc::transport::default_launcher_endpoint().display()
            );
        } else {
            eprintln!("clave-daemon: launcher IPC server stopped: {e}");
        }
    }
}

/// Keeps the work zone in step with the process tree the OS is holding in the Job Object:
/// children a work app spawns join the zone, and pids that leave the job (exit) are dropped —
/// so a reused pid cannot inherit a departed app's work membership.
fn spawn_zone_supervisor(zones: Arc<ZoneRegistry>, containment: Arc<dyn ProcessContainment>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(SUPERVISE_INTERVAL);

        let live: HashSet<u32> = containment.contained_pids().into_iter().collect();
        for pid in &live {
            zones.join(proc_id_for_pid(*pid), JoinReason::Launcher);
        }
        for pid in zones.supervised_pids() {
            if !live.contains(&pid) {
                zones.leave(&proc_id_for_pid(pid));
            }
        }
    });
}

/// Enforces the network split-tunnel with WinDivert: outbound connects from a work-zone process
/// to a policy-blocked IP are dropped before they establish. Needs the daemon running elevated
/// with `WinDivert.dll` beside it; otherwise it logs and leaves the loopback data plane in place.
fn spawn_split_tunnel(daemon: Arc<Daemon>, zones: Arc<ZoneRegistry>) {
    let blocked: HashSet<IpAddr> = daemon
        .policy_snapshot()
        .network
        .blocked_hosts
        .iter()
        .filter_map(|h| h.parse::<IpAddr>().ok())
        .collect();

    std::thread::spawn(move || {
        let decide = move |zone: Zone, ip: IpAddr, _port: u16| {
            if zone == Zone::Work && blocked.contains(&ip) {
                NetVerdict::Block
            } else {
                NetVerdict::Allow
            }
        };
        if let Err(e) = clave_win::run_split_tunnel(zones, decide) {
            eprintln!(
                "clave-win: WinDivert split-tunnel inactive ({e}); network stays loopback \
                 development-only."
            );
        }
    });
}

fn spawn_clipboard_guard(daemon: Arc<Daemon>, zones: Arc<ZoneRegistry>) {
    std::thread::spawn(move || {
        clave_win::run_clipboard_guard(zones, move |src, dst, fmt| {
            daemon
                .decide_action(
                    &clave_core::Action::ClipboardTransfer { src, dst, fmt },
                    unix_now(),
                )
                .decision
        });
    });
}

async fn serve_launcher_loop(
    daemon: Arc<Daemon>,
) -> Result<(), clave_ipc::transport::TransportError> {
    use clave_ipc::transport::{default_launcher_endpoint, serve_launcher, IpcServer};

    let path = default_launcher_endpoint();
    let server = IpcServer::bind(&path)?;
    println!("clave-daemon: launcher IPC listening on {}", path.display());

    loop {
        let conn = server.accept().await?;
        let d = Arc::clone(&daemon);
        tokio::spawn(async move {
            if let Err(e) =
                serve_launcher(conn, move |req| d.handle_launcher_request(req, unix_now())).await
            {
                eprintln!("clave-daemon: launcher connection ended: {e}");
            }
        });
    }
}

fn unix_now() -> clave_core::UnixTime {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn demo_policy() -> clave_core::PolicyBundle {
    use clave_core::{AppId, AppPolicy, AppRule, BinaryMatch, LaunchProfile, PolicyBundle};

    fn app(id: &str, publisher: &str, product: &str, name: &str, exec: &str) -> AppRule {
        AppRule::new(
            AppId(id.into()),
            BinaryMatch::Windows {
                publisher: publisher.into(),
                product: product.into(),
            },
        )
        .with_display_name(name)
        .with_executable(exec)
    }

    fn chromium_app(id: &str, publisher: &str, product: &str, name: &str, exec: &str) -> AppRule {
        app(id, publisher, product, name, exec).with_launch(LaunchProfile::chromium())
    }

    let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    let program_files_x86 =
        std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
    let local_appdata =
        std::env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\Users\Public\AppData\Local".into());

    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    // A safe, demonstrable block target: RFC 5737 TEST-NET-1 is never globally routed, so the
    // WinDivert split-tunnel can prove it drops a work-zone connect without affecting real traffic.
    pol.network.blocked_hosts = vec!["192.0.2.1".to_string()];
    pol.apps = AppPolicy {
        allow: vec![
            chromium_app(
                "chrome-work",
                "CN=Google LLC",
                "Google Chrome",
                "Google Chrome",
                &format!(r"{program_files}\Google\Chrome\Application\chrome.exe"),
            ),
            chromium_app(
                "edge-work",
                "CN=Microsoft Corporation",
                "Microsoft Edge",
                "Microsoft Edge",
                &format!(r"{program_files_x86}\Microsoft\Edge\Application\msedge.exe"),
            ),
            app(
                "excel-work",
                "CN=Microsoft Corporation",
                "Microsoft Excel",
                "Excel",
                &format!(r"{program_files}\Microsoft Office\root\Office16\EXCEL.EXE"),
            ),
            app(
                "word-work",
                "CN=Microsoft Corporation",
                "Microsoft Word",
                "Word",
                &format!(r"{program_files}\Microsoft Office\root\Office16\WINWORD.EXE"),
            ),
            app(
                "outlook-work",
                "CN=Microsoft Corporation",
                "Microsoft Outlook",
                "Outlook",
                &format!(r"{program_files}\Microsoft Office\root\Office16\OUTLOOK.EXE"),
            ),
            app(
                "powerpoint-work",
                "CN=Microsoft Corporation",
                "Microsoft PowerPoint",
                "PowerPoint",
                &format!(r"{program_files}\Microsoft Office\root\Office16\POWERPNT.EXE"),
            ),
            chromium_app(
                "teams-work",
                "CN=Microsoft Corporation",
                "Microsoft Teams",
                "Teams",
                &format!(r"{local_appdata}\Microsoft\Teams\current\Teams.exe"),
            ),
            chromium_app(
                "slack-work",
                "CN=Slack Technologies, LLC",
                "Slack",
                "Slack",
                &format!(r"{local_appdata}\slack\slack.exe"),
            ),
            app(
                "vscode-work",
                "CN=Microsoft Corporation",
                "Visual Studio Code",
                "Visual Studio Code",
                &format!(r"{local_appdata}\Programs\Microsoft VS Code\Code.exe"),
            ),
            app(
                "notepad-work",
                "CN=Microsoft Windows",
                "Microsoft Windows Operating System",
                "Notepad",
                r"C:\Windows\System32\notepad.exe",
            ),
        ],
    };
    pol
}
