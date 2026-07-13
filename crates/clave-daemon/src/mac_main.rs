//! macOS daemon startup, entered from `main.rs` (the unsigned `cargo run` binary) or from
//! `clave-daemon-host`'s FFI shim (the signed `ClaveDaemonHost.app`). See [`Profile`].

use std::sync::{Arc, Mutex};

use clave_core::ZoneRegistry;
use clave_mac::Custody;
use clave_net::LoopbackTunnel;
use clave_platform::{Platform, VolumeMount};
use clave_proto::{AuditSpool, GatewaySigningKey, GatewayVerifier, TenantId};
use clave_volume::{ClaveVolume, ContainerId, ContainerMeta, Dek, Kek, MemBacking, MemKeyStore};

use crate::Daemon;

/// Which binary is running the daemon. They differ in one way that matters — whether they can reach
/// the Secure Enclave — so each owns a **separate Clave Disk**: custody is fixed at container
/// creation, so a shared container would lock one binary out or silently downgrade the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// `cargo run -p clave-daemon` — unsigned, so the Secure Enclave is unreachable. Throwaway disk
    /// with a plain-Keychain passphrase.
    Dev,
    /// `ClaveDaemonHost.app` — signed and provisioned. Its disk must be Secure-Enclave-sealed.
    SignedHost,
}

impl Profile {
    /// Keys the daemon's `ClaveVolume`, the OS mount, and a gateway wipe.
    fn container(self) -> u128 {
        match self {
            Profile::Dev => 0xC1A5_DE11,
            Profile::SignedHost => 0xC1A5_ED15,
        }
    }

    fn custody(self) -> Custody {
        match self {
            Profile::Dev => Custody::AllowPlainFallback,
            Profile::SignedHost => Custody::RequireHardware,
        }
    }

    /// Distinct bundles and mount points, so the two profiles' disks never collide.
    fn bundle_name(self) -> &'static str {
        match self {
            Profile::Dev => "ClaveDisk-dev.sparsebundle",
            Profile::SignedHost => "ClaveDisk.sparsebundle",
        }
    }

    fn default_mount_point(self) -> &'static str {
        match self {
            Profile::Dev => "/Volumes/ClaveDisk-dev",
            Profile::SignedHost => "/Volumes/ClaveDisk",
        }
    }

    fn banner(self) -> &'static str {
        match self {
            Profile::Dev => {
                "profile: dev (unsigned `cargo run`) — plain-Keychain disk, no Secure Enclave.\n\
                   Run ClaveDaemonHost.app for the hardware-sealed disk."
            }
            Profile::SignedHost => {
                "profile: signed host — Secure-Enclave-sealed disk (hardware-rooted key custody)."
            }
        }
    }
}

/// Mount the Clave Disk, report the honest enforcement posture, and serve the launcher over IPC.
/// Runs until killed.
pub fn run_macos(profile: Profile) {
    println!("clave-daemon: {}", profile.banner());

    let container_id = profile.container();
    let zones = Arc::new(ZoneRegistry::new());

    let mut platform = clave_mac::MacPlatform::new(Arc::clone(&zones));
    platform.configure_volume(container_id, disk_bundle_path(profile), profile.custody());
    let volume_mount = platform.volume_mac();
    match volume_mount.attach(mount_point(profile)) {
        Ok(()) => println!(
            "clave-daemon: Clave Disk mounted at {}",
            volume_mount.mount_point().unwrap_or_default()
        ),
        Err(e) => println!("clave-daemon: Clave Disk mount failed (continuing unmounted): {e:?}"),
    }

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

    let container = ContainerId(container_id);
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
async fn serve_launcher_loop(daemon: Arc<Daemon>) -> Result<(), Box<dyn std::error::Error>> {
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
fn unix_now() -> clave_core::UnixTime {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The launcher socket path, matching the launcher UI: `$CLAVE_LAUNCHER_SOCK`, else
/// `<temp>/clave-launcher.sock`.
fn socket_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CLAVE_LAUNCHER_SOCK") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::temp_dir();
    p.push("clave-launcher.sock");
    p
}

/// Where the `hdiutil`-mounted Clave Disk appears: `$CLAVE_DEV_MOUNT`, else the profile's default.
/// The signed host's `/Volumes/ClaveDisk` is the production path (doc 04 §4) and is what the ES
/// `AUTH_OPEN` client checks against (`macos/ClaveESExtension/main.swift`'s `claveDiskPrefix`).
fn mount_point(profile: Profile) -> String {
    std::env::var("CLAVE_DEV_MOUNT").unwrap_or_else(|_| profile.default_mount_point().to_string())
}

/// Where the encrypted sparsebundle container itself lives (the opaque blob "on personal disk" in
/// doc 04's diagram — distinct from the mount point above): `$CLAVE_DISK_BUNDLE`, else a stable
/// per-user Application Support path, named per profile so the two never share a container.
fn disk_bundle_path(profile: Profile) -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CLAVE_DISK_BUNDLE") {
        return std::path::PathBuf::from(p);
    }
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("Library/Application Support/Clave")
        .join(profile.bundle_name())
}

/// A stand-in for the tenant-signed policy the gateway would supply — a representative set of
/// allow-listed work apps so the launcher grid is populated in a lab build.
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
            chromium_app(
                "chrome-work",
                "com.google.Chrome",
                "Google Chrome",
                "/Applications/Google Chrome.app",
            ),
            app(
                "excel-work",
                "com.microsoft.Excel",
                "Excel",
                "/Applications/Microsoft Excel.app",
            ),
            app(
                "word-work",
                "com.microsoft.Word",
                "Word",
                "/Applications/Microsoft Word.app",
            ),
            app(
                "outlook-work",
                "com.microsoft.Outlook",
                "Outlook",
                "/Applications/Microsoft Outlook.app",
            ),
            app(
                "files-work",
                "com.apple.finder",
                "Files",
                "/System/Library/CoreServices/Finder.app",
            ),
            app(
                "powerpoint-work",
                "com.microsoft.Powerpoint",
                "PowerPoint",
                "/Applications/Microsoft PowerPoint.app",
            ),
            chromium_app(
                "edge-work",
                "com.microsoft.edgemac",
                "Edge",
                "/Applications/Microsoft Edge.app",
            ),
            app(
                "academy-work",
                "com.clave.academy",
                "Clave Academy",
                "/Applications/Clave Academy.app",
            ),
            app(
                "acrobat-work",
                "com.adobe.Acrobat.Pro",
                "Adobe Acrobat",
                "/Applications/Adobe Acrobat.app",
            ),
            app(
                "clavework-work",
                "com.clave.work",
                "Clave Work",
                "/Applications/Clave Work.app",
            ),
            chromium_app(
                "teams-work",
                "com.microsoft.teams2",
                "Teams",
                "/Applications/Microsoft Teams.app",
            ),
            chromium_app(
                "slack-work",
                "com.tinyspeck.slackmacgap",
                "Slack",
                "/Applications/Slack.app",
            ),
            chromium_app(
                "vscode-work",
                "com.microsoft.VSCode",
                "Visual Studio Code",
                "/Applications/Visual Studio Code.app",
            ),
            chromium_app(
                "cursor-work",
                "com.todesktop.230313mzl4w4u92",
                "Cursor",
                "/Applications/Cursor.app",
            ),
            // Stock macOS apps that are always present, so a live "Launch" actually spawns and
            // supervises a real, visible window in a lab build.
            app(
                "calculator-work",
                "com.apple.calculator",
                "Calculator",
                "/System/Applications/Calculator.app",
            ),
            app(
                "textedit-work",
                "com.apple.TextEdit",
                "TextEdit",
                "/System/Applications/TextEdit.app",
            ),
        ],
    };
    pol
}
