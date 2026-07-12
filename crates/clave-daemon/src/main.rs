//! Entry point: selects this target's OS [`Platform`](clave_platform::Platform) adapter, surfaces
//! its enforcement posture, and — on macOS — runs the launcher IPC server so the Clave launcher UI
//! talks to a live daemon instead of its embedded demo policy.
//!
//! This is a lab build: a local demo policy, an in-memory volume core with a dev mount point, and a
//! gateway verifier pinned to a locally-generated key.

fn main() {
    println!("clave-daemon — IPC proto v{}", clave_ipc::PROTO_VERSION);

    #[cfg(target_os = "macos")]
    run_macos();

    #[cfg(not(target_os = "macos"))]
    report_platform();
}

/// macOS: construct the real adapter, print what it actually enforces vs a development-only
/// stand-in or unavailable, then serve the launcher UI over the authenticated Unix-socket IPC.
#[cfg(target_os = "macos")]
fn run_macos() {
    use std::sync::{Arc, Mutex};

    use clave_core::ZoneRegistry;
    use clave_daemon::Daemon;
    use clave_net::LoopbackTunnel;
    use clave_platform::Platform;
    use clave_proto::{AuditSpool, GatewaySigningKey, GatewayVerifier, TenantId};
    use clave_volume::{
        ClaveVolume, ContainerId, ContainerMeta, Dek, Kek, MemBacking, MemKeyStore,
    };

    // One membership set governs process supervision, split-tunnel routing, and the volume gate.
    let zones = Arc::new(ZoneRegistry::new());

    // The real macOS adapter — honest posture (nothing reaches `Enforced`). A lab dev mount point
    // lets contained launch specs resolve before the encrypted-APFS mount exists.
    let mut platform = clave_mac::MacPlatform::new(Arc::clone(&zones));
    platform.set_dev_mount_point(dev_mount_point());

    // Reconcile the ES/NE posture with the machine's live SIP state: SIP-disabled → the unsigned dev
    // path is viable (`DevelopmentOnly`); SIP-enabled without an entitled extension → `Unavailable`.
    let sip = platform.detect_and_apply_sip_posture();
    println!("SIP: {sip}");

    let report = platform.enforcement_report();
    println!("platform: macOS adapter (clave-mac)");
    print!("{report}");
    if !report.is_production_ready() {
        println!(
            "lab build: not production-ready — a capability reaches `enforced` only on a stock,\n\
             entitled, SIP-enabled Mac."
        );
    }

    // A provisioned in-memory encrypted-volume core (dev backends); the crypto core is identical to
    // production, which swaps in the real OS mount + hardware key store.
    let container = ContainerId(0xC1A5_ED15);
    let keystore = Arc::new(MemKeyStore::new());
    keystore.provision(container, Kek::from_bytes([0x4B; 32]), &Dek::from_bytes([0xDE; 64]));
    let volume = ClaveVolume::new(
        ContainerMeta::new(container),
        keystore,
        Arc::new(MemBacking::zeroed(64)),
        zones.clone(),
    );

    // A dev gateway verifier pinned to a locally-generated key — no real control plane in a lab
    // build, so nothing can actually change device posture over the wire.
    let signer = GatewaySigningKey::from_seed(TenantId(1), [0x6A; 32]);
    let gateway = GatewayVerifier::new(TenantId(1), signer.public_key()).expect("valid pinned key");

    // Grab the overlay's tracked-window handle before the platform is moved into the daemon; the
    // native Clave Edge drawer reads it (and `zones`) to frame supervised windows.
    let overlay_tracked = platform.overlay_tracked();

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

    // The Clave Edge overlay owns the process **main thread** (AppKit is main-thread-only), so the
    // launcher IPC server runs on a worker thread. `CLAVE_EDGE=0` skips the overlay and serves the
    // IPC loop directly on the main thread (useful for headless / SSH runs with no window server).
    if std::env::var("CLAVE_EDGE").as_deref() == Ok("0") {
        if let Err(e) = rt.block_on(serve_launcher_loop(daemon)) {
            eprintln!("clave-daemon: launcher IPC server stopped: {e}");
        }
        return;
    }

    let server_daemon = Arc::clone(&daemon);
    std::thread::spawn(move || {
        if let Err(e) = rt.block_on(serve_launcher_loop(server_daemon)) {
            eprintln!("clave-daemon: launcher IPC server stopped: {e}");
        }
    });

    println!("clave-daemon: Clave Edge overlay active — framing supervised windows per policy");
    println!("  (set CLAVE_EDGE=0 to disable, CLAVE_EDGE_CAPTURE=1 to show it in screenshots)");
    let cfg_daemon = Arc::clone(&daemon);
    clave_mac::run_clave_edge(zones, overlay_tracked, move || cfg_daemon.overlay_cfg());
}

/// Accept launcher connections forever, serving each over the `clave-ipc` launcher protocol against
/// the daemon's read-only launcher view (catalog / launch spec / enforcement posture).
#[cfg(target_os = "macos")]
async fn serve_launcher_loop(
    daemon: std::sync::Arc<clave_daemon::Daemon>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use clave_ipc::transport::{serve_launcher, IpcServer};

    let path = socket_path();
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

/// Wall-clock seconds since the Unix epoch, for audit timestamps in a live run.
#[cfg(target_os = "macos")]
fn unix_now() -> clave_core::UnixTime {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The launcher socket path, matching the launcher UI: `$CLAVE_LAUNCHER_SOCK`, else
/// `<temp>/clave-launcher.sock`.
#[cfg(target_os = "macos")]
fn socket_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CLAVE_LAUNCHER_SOCK") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::temp_dir();
    p.push("clave-launcher.sock");
    p
}

/// The dev Clave Disk mount point: `$CLAVE_DEV_MOUNT`, else a writable `<temp>/clave-disk` — a real
/// directory so a spawned work app's redirected `HOME`/`TMPDIR` actually exist in a lab build.
#[cfg(target_os = "macos")]
fn dev_mount_point() -> String {
    if let Ok(p) = std::env::var("CLAVE_DEV_MOUNT") {
        return p;
    }
    std::env::temp_dir()
        .join("clave-disk")
        .to_string_lossy()
        .into_owned()
}

/// A stand-in for the tenant-signed policy the gateway would supply — a representative set of
/// allow-listed work apps so the launcher grid is populated in a lab build.
#[cfg(target_os = "macos")]
fn demo_policy() -> clave_core::PolicyBundle {
    use clave_core::{AppId, AppPolicy, AppRule, BinaryMatch, LaunchProfile, PolicyBundle};

    fn app(id: &str, signing: &str, name: &str, exec: &str) -> AppRule {
        AppRule::new(
            AppId(id.into()),
            BinaryMatch::Macos {
                team_id: "DEMO000000".into(),
                signing_id: signing.into(),
            },
        )
        .with_display_name(name)
        .with_executable(exec)
    }

    // Chromium/Electron apps hand a second launch off to the user's personal instance, so launch
    // them with a private --user-data-dir: contained profile + a window we supervise (and frame).
    fn chromium_app(id: &str, signing: &str, name: &str, exec: &str) -> AppRule {
        app(id, signing, name, exec).with_launch(LaunchProfile::chromium())
    }

    let mut pol = PolicyBundle::restrictive_default();
    pol.version = 1;
    pol.apps = AppPolicy {
        allow: vec![
            chromium_app("chrome-work", "com.google.Chrome", "Google Chrome", "/Applications/Google Chrome.app"),
            app("excel-work", "com.microsoft.Excel", "Excel", "/Applications/Microsoft Excel.app"),
            app("word-work", "com.microsoft.Word", "Word", "/Applications/Microsoft Word.app"),
            app("outlook-work", "com.microsoft.Outlook", "Outlook", "/Applications/Microsoft Outlook.app"),
            app("files-work", "com.apple.finder", "Files", "/System/Library/CoreServices/Finder.app"),
            app("powerpoint-work", "com.microsoft.Powerpoint", "PowerPoint", "/Applications/Microsoft PowerPoint.app"),
            chromium_app("edge-work", "com.microsoft.edgemac", "Edge", "/Applications/Microsoft Edge.app"),
            app("acrobat-work", "com.adobe.Acrobat.Pro", "Adobe Acrobat", "/Applications/Adobe Acrobat.app"),
            chromium_app("teams-work", "com.microsoft.teams2", "Teams", "/Applications/Microsoft Teams.app"),
            chromium_app("slack-work", "com.tinyspeck.slackmacgap", "Slack", "/Applications/Slack.app"),
            // Stock macOS apps that are always present, so a live "Launch" actually spawns and
            // supervises a real, visible window in a lab build.
            app("calculator-work", "com.apple.calculator", "Calculator", "/System/Applications/Calculator.app"),
            app("textedit-work", "com.apple.TextEdit", "TextEdit", "/System/Applications/TextEdit.app"),
        ],
    };
    pol
}

/// Windows: construct the real adapter and print its enforcement posture. The launcher IPC server
/// is Unix-only (the named-pipe transport is a future scaffold), so this reports and exits.
#[cfg(target_os = "windows")]
fn report_platform() {
    use clave_platform::Platform;
    use std::sync::Arc;

    // The process-notify driver feeds this zone mirror over the IOCTL channel in production.
    let zones = Arc::new(clave_core::ZoneRegistry::new());
    let platform = clave_win::WindowsPlatform::new(zones);
    let report = platform.enforcement_report();

    println!("platform: Windows adapter (clave-win)");
    print!("{report}");
    if !report.is_production_ready() {
        println!(
            "lab build: not production-ready — a capability reaches `enforced` only with\n\
             Microsoft-signed drivers on a Secure-Boot machine."
        );
    }
}

/// No OS adapter is linked for other targets yet.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn report_platform() {
    println!("no OS platform adapter for this target yet; run `cargo test` for daemon logic.");
}
