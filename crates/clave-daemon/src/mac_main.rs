use std::sync::{Arc, Mutex, OnceLock};

use clave_core::ZoneRegistry;
use clave_mac::Custody;
use clave_net::LoopbackTunnel;
use clave_platform::{Platform, VolumeMount};
use clave_proto::{AuditSpool, GatewaySigningKey, GatewayVerifier, TenantId};
use clave_volume::{ClaveVolume, ContainerId, ContainerMeta, Dek, Kek, MemBacking, MemKeyStore};

use crate::Daemon;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Dev,
    SignedHost,
}

impl Profile {
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

    let policy = demo_policy();
    publish_es_policy(&policy, profile);

    let daemon = Arc::new(Daemon::new(
        Arc::clone(&zones),
        Box::new(platform),
        Arc::new(AuditSpool::new()),
        policy,
        Box::new(LoopbackTunnel::new(0x5A)),
        Arc::new(Mutex::new(volume)),
        gateway,
    ));

    daemon.set_policy_observer(Box::new(move |bundle| {
        let updated = bundle.clone();
        std::thread::spawn(move || publish_es_policy(&updated, profile));
    }));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    spawn_clipboard_guard(Arc::clone(&daemon), Arc::clone(&zones));
    spawn_screen_watch(Arc::clone(&daemon), Arc::clone(&zones));
    spawn_input_watch(Arc::clone(&daemon), Arc::clone(&zones));

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

fn spawn_clipboard_guard(daemon: Arc<Daemon>, zones: Arc<ZoneRegistry>) {
    std::thread::spawn(move || {
        clave_mac::run_clipboard_guard(zones, move |src, dst, fmt| {
            daemon
                .decide_action(
                    &clave_core::Action::ClipboardTransfer { src, dst, fmt },
                    unix_now(),
                )
                .decision
        });
    });
}

fn spawn_screen_watch(daemon: Arc<Daemon>, zones: Arc<ZoneRegistry>) {
    std::thread::spawn(move || {
        clave_mac::run_screen_watch(zones, move |capturer| {
            let verdict = daemon.decide_action(
                &clave_core::Action::ScreenCapture {
                    proc: Some(crate::proc_id_for_pid(capturer.pid)),
                    exe: capturer.exe.clone(),
                },
                unix_now(),
            );
            if !verdict.is_allow() {
                eprintln!(
                    "clave-daemon: {} (pid {}) captured the screen over work content — audited, \
                     not blocked (macOS cannot exclude third-party windows from capture)",
                    capturer.exe, capturer.pid
                );
            }
        });
    });
}

fn spawn_input_watch(daemon: Arc<Daemon>, zones: Arc<ZoneRegistry>) {
    std::thread::spawn(move || {
        clave_mac::run_input_watch(zones, move |tapper| {
            let verdict = daemon.decide_action(
                &clave_core::Action::InputTap {
                    proc: Some(crate::proc_id_for_pid(tapper.pid)),
                    exe: tapper.exe.clone(),
                },
                unix_now(),
            );
            if !verdict.is_allow() {
                eprintln!(
                    "clave-daemon: {} (pid {}) is reading the keyboard while a work app is focused \
                     — audited, not blocked (macOS ships no kernel input filter)",
                    tapper.exe, tapper.pid
                );
            }
        });
    });
}

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

fn unix_now() -> clave_core::UnixTime {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn socket_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CLAVE_LAUNCHER_SOCK") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::temp_dir();
    p.push("clave-launcher.sock");
    p
}

fn mount_point(profile: Profile) -> String {
    std::env::var("CLAVE_DEV_MOUNT").unwrap_or_else(|_| profile.default_mount_point().to_string())
}

pub type PolicyPublisher = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

static POLICY_PUBLISHER: OnceLock<Mutex<Option<PolicyPublisher>>> = OnceLock::new();

fn policy_publisher() -> &'static Mutex<Option<PolicyPublisher>> {
    POLICY_PUBLISHER.get_or_init(|| Mutex::new(None))
}

pub fn register_policy_publisher(publisher: PolicyPublisher) {
    *policy_publisher()
        .lock()
        .expect("policy publisher lock poisoned") = Some(publisher);
}

fn publish_es_policy(policy: &clave_core::PolicyBundle, profile: Profile) {
    let mount = mount_point(profile);

    let json = match serde_json::to_string_pretty(policy) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("clave-daemon: failed to serialize ES policy: {e}");
            return;
        }
    };

    let publisher = policy_publisher()
        .lock()
        .expect("policy publisher lock poisoned")
        .clone();
    if let Some(publisher) = publisher {
        if publisher(json.as_bytes()) {
            println!("clave-daemon: ES policy pushed to the ES client over XPC (mount {mount})");
        } else {
            eprintln!("clave-daemon: ES policy XPC push failed");
        }
        return;
    }

    write_es_policy_file(&json, &mount);
}

fn write_es_policy_file(json: &str, mount: &str) {
    use std::path::PathBuf;

    let path = std::env::var("CLAVE_POLICY_JSON")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/Users/Shared/Clave/policy.json"));
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, json) {
        eprintln!("clave-daemon: failed to write ES policy snapshot: {e}");
    } else {
        println!(
            "clave-daemon: ES policy snapshot → {} (mount {mount})",
            path.display()
        );
    }
}

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

    fn apple_app(id: &str, signing: &str, name: &str, exec: &str) -> AppRule {
        AppRule::new(
            AppId(id.into()),
            BinaryMatch::Macos {
                team_id: String::new(),
                signing_id: signing.into(),
            },
        )
        .with_display_name(name)
        .with_executable(exec)
    }

    fn chromium_app(id: &str, signing: &str, name: &str, exec: &str) -> AppRule {
        app(id, signing, name, exec).with_launch(LaunchProfile::chromium())
    }

    fn editor_app(id: &str, signing: &str, name: &str, exec: &str) -> AppRule {
        app(id, signing, name, exec).with_launch(LaunchProfile::chromium().with_seed_home([
            ".zshenv",
            ".zprofile",
            ".zshrc",
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".gitconfig",
            ".local",
            ".cargo",
            ".nvm",
            ".bun",
        ]))
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
            apple_app(
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
            editor_app(
                "vscode-work",
                "com.microsoft.VSCode",
                "Visual Studio Code",
                "/Applications/Visual Studio Code.app",
            ),
            editor_app(
                "cursor-work",
                "com.todesktop.230313mzl4w4u92",
                "Cursor",
                "/Applications/Cursor.app",
            ),
            apple_app(
                "calculator-work",
                "com.apple.calculator",
                "Calculator",
                "/System/Applications/Calculator.app",
            ),
            apple_app(
                "textedit-work",
                "com.apple.TextEdit",
                "TextEdit",
                "/System/Applications/TextEdit.app",
            ),
        ],
    };
    pol
}
