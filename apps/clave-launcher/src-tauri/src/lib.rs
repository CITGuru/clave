//! Clave launcher desktop app (Tauri) — backend.
//!
//! Thin Tauri commands that ask the privileged **`clave-daemon`** for the launch catalog, a
//! contained launch spec, and the OS adapter's enforcement posture, over the authenticated
//! Unix-socket IPC link (`clave_ipc::transport::LauncherClient`). The frontend (React +
//! Tailwind + shadcn/ui, in `../src`) calls these via `invoke`.
//!
//! **Fallback.** When the daemon is not running — a dev machine with no enrolled enclave, or the
//! Windows build before the named-pipe transport lands — each command falls back to an embedded
//! **demo policy** + fixed mount so the UI stays runnable end-to-end. The socket path is
//! `$CLAVE_LAUNCHER_SOCK`, else `<temp>/clave-launcher.sock`. The *actual* launch (OS spawn+inject)
//! remains the OS layer; these commands resolve and surface the spec the daemon vetted.

use clave_core::{AppId, AppPolicy, AppRule, BinaryMatch, PolicyBundle};
use serde::Serialize;

/// Demo mount point used only by the fallback. With the daemon connected, the spec's env already
/// points into the real `platform.volume().mount_point()`.
const MOUNT: &str = "/Volumes/ClaveDisk";

/// The daemon's launcher socket: `$CLAVE_LAUNCHER_SOCK`, else `<temp>/clave-launcher.sock`.
#[cfg(unix)]
fn socket_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CLAVE_LAUNCHER_SOCK") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::temp_dir();
    p.push("clave-launcher.sock");
    p
}

/// Connect + handshake to the daemon, or `None` if it isn't reachable (→ caller uses the fallback).
#[cfg(unix)]
async fn daemon() -> Option<clave_ipc::transport::LauncherClient> {
    clave_ipc::transport::LauncherClient::connect(socket_path())
        .await
        .ok()
}

#[derive(Serialize)]
pub struct AppInfo {
    id: String,
    label: String,
}

#[derive(Serialize)]
pub struct LaunchInfo {
    executable: String,
    env: Vec<(String, String)>,
    namespace_prefix: Option<String>,
}

#[derive(Serialize)]
pub struct CapStatus {
    capability: String,
    status: String,
}

/// Build one allow-listed work app (demo). Team id is a placeholder; production rules carry the
/// real code-signing identity the daemon vetted.
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

/// A stand-in for the signed policy the daemon would supply — a representative set of work apps so
/// the launcher grid is populated on a dev machine.
fn demo_policy() -> PolicyBundle {
    let mut pol = PolicyBundle::restrictive_default();
    pol.apps = AppPolicy {
        allow: vec![
            app("chrome-work", "com.google.Chrome", "Google Chrome", "/Applications/Google Chrome.app"),
            app("excel-work", "com.microsoft.Excel", "Excel", "/Applications/Microsoft Excel.app"),
            app("word-work", "com.microsoft.Word", "Word", "/Applications/Microsoft Word.app"),
            app("outlook-work", "com.microsoft.Outlook", "Outlook", "/Applications/Microsoft Outlook.app"),
            app("files-work", "com.apple.finder", "Files", "/System/Library/CoreServices/Finder.app"),
            app("powerpoint-work", "com.microsoft.Powerpoint", "PowerPoint", "/Applications/Microsoft PowerPoint.app"),
            app("edge-work", "com.microsoft.edgemac", "Edge", "/Applications/Microsoft Edge.app"),
            app("academy-work", "ai.finic.academy", "Clave Academy", "/Applications/Clave Academy.app"),
            app("acrobat-work", "com.adobe.Acrobat.Pro", "Adobe Acrobat", "/Applications/Adobe Acrobat.app"),
            app("clavework-work", "ai.finic.work", "Clave Work", "/Applications/Clave Work.app"),
            app("teams-work", "com.microsoft.teams2", "Teams", "/Applications/Microsoft Teams.app"),
            app("slack-work", "com.tinyspeck.slackmacgap", "Slack", "/Applications/Slack.app"),
        ],
    };
    pol
}

/// The launcher catalog: the daemon's allow-listed work apps, or the demo set when
/// the daemon isn't running.
#[tauri::command]
async fn list_apps() -> Vec<AppInfo> {
    #[cfg(unix)]
    if let Some(mut client) = daemon().await {
        if let Ok(apps) = client.list_apps().await {
            return apps
                .into_iter()
                .map(|a| AppInfo {
                    id: a.app_id.0,
                    label: a.label,
                })
                .collect();
        }
    }
    demo_apps()
}

/// Resolve the contained spawn spec for an app. The real launch (spawn suspended +
/// inject/mark + resume) is the OS layer; this returns what it would execute. With the daemon
/// connected, the daemon is authoritative — an unknown app yields `None`, not the demo spec.
#[tauri::command]
async fn launch_spec(app_id: String) -> Option<LaunchInfo> {
    #[cfg(unix)]
    if let Some(mut client) = daemon().await {
        if let Ok(spec) = client.prepare_launch(AppId(app_id.clone())).await {
            return spec.map(to_launch_info);
        }
    }
    demo_launch_spec(&app_id)
}

/// This target's OS-adapter enforcement posture: the daemon's live report, or a
/// locally-constructed adapter posture as a fallback.
#[tauri::command]
async fn enforcement() -> Vec<CapStatus> {
    #[cfg(unix)]
    if let Some(mut client) = daemon().await {
        if let Ok(caps) = client.enforcement().await {
            return caps
                .into_iter()
                .map(|(capability, status)| CapStatus { capability, status })
                .collect();
        }
    }
    report()
        .into_iter()
        .map(|(capability, status)| CapStatus { capability, status })
        .collect()
}

fn to_launch_info(s: clave_core::LaunchSpec) -> LaunchInfo {
    LaunchInfo {
        executable: s.executable,
        env: s.env,
        namespace_prefix: s.namespace_prefix,
    }
}

fn demo_apps() -> Vec<AppInfo> {
    demo_policy()
        .apps
        .allow
        .iter()
        .filter(|r| r.is_launchable())
        .map(|r| AppInfo {
            id: r.app_id.0.clone(),
            label: r.label().to_string(),
        })
        .collect()
}

fn demo_launch_spec(app_id: &str) -> Option<LaunchInfo> {
    let pol = demo_policy();
    let rule = pol.apps.rule(&AppId(app_id.to_string()))?;
    if !rule.is_launchable() {
        return None;
    }
    Some(to_launch_info(rule.launch_spec(MOUNT)))
}

#[cfg(target_os = "macos")]
fn report() -> Vec<(String, String)> {
    use clave_platform::Platform;
    use std::sync::Arc;
    let p = clave_mac::MacPlatform::new(Arc::new(clave_core::ZoneRegistry::new()));
    p.enforcement_report()
        .entries()
        .iter()
        .map(|(c, s)| (c.to_string(), s.to_string()))
        .collect()
}

#[cfg(target_os = "windows")]
fn report() -> Vec<(String, String)> {
    use clave_platform::Platform;
    use std::sync::Arc;
    let p = clave_win::WindowsPlatform::new(Arc::new(clave_core::ZoneRegistry::new()));
    p.enforcement_report()
        .entries()
        .iter()
        .map(|(c, s)| (c.to_string(), s.to_string()))
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn report() -> Vec<(String, String)> {
    Vec::new()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![list_apps, launch_spec, enforcement])
        .run(tauri::generate_context!())
        .expect("error while running the Clave app");
}
