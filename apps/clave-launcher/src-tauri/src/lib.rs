use clave_core::{AppId, AppPolicy, AppRule, BinaryMatch, LaunchProfile, PolicyBundle};
use serde::Serialize;

const MOUNT: &str = "/Volumes/ClaveDisk";

#[cfg(any(unix, windows))]
async fn daemon() -> Option<clave_ipc::transport::LauncherClient> {
    clave_ipc::transport::LauncherClient::connect(
        clave_ipc::transport::default_launcher_endpoint(),
    )
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
    args: Vec<String>,
    env: Vec<(String, String)>,
    namespace_prefix: Option<String>,
}

#[derive(Serialize)]
pub struct CapStatus {
    capability: String,
    status: String,
}

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

fn chromium_app(id: &str, signing: &str, name: &str, exec: &str) -> AppRule {
    app(id, signing, name, exec).with_launch(LaunchProfile::chromium())
}

fn demo_policy() -> PolicyBundle {
    let mut pol = PolicyBundle::restrictive_default();
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
            chromium_app("vscode-work", "com.microsoft.VSCode", "Visual Studio Code", "/Applications/Visual Studio Code.app"),
            chromium_app("cursor-work", "com.todesktop.230313mzl4w4u92", "Cursor", "/Applications/Cursor.app"),
            app("calculator-work", "com.apple.calculator", "Calculator", "/System/Applications/Calculator.app"),
            app("textedit-work", "com.apple.TextEdit", "TextEdit", "/System/Applications/TextEdit.app"),
        ],
    };
    pol
}

#[tauri::command]
async fn list_apps() -> Vec<AppInfo> {
    #[cfg(any(unix, windows))]
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

#[tauri::command]
async fn launch_spec(app_id: String) -> Option<LaunchInfo> {
    #[cfg(any(unix, windows))]
    if let Some(mut client) = daemon().await {
        if let Ok(spec) = client.prepare_launch(AppId(app_id.clone())).await {
            return spec.map(to_launch_info);
        }
    }
    demo_launch_spec(&app_id)
}

#[tauri::command]
async fn launch_app(app_id: String) -> Result<u32, String> {
    #[cfg(any(unix, windows))]
    if let Some(mut client) = daemon().await {
        return match client.launch(AppId(app_id)).await {
            Ok(Some(pid)) => Ok(pid),
            Ok(None) => Err("launch returned no pid".into()),
            Err(clave_ipc::transport::TransportError::LaunchFailed(e)) => Err(e),
            Err(e) => Err(e.to_string()),
        };
    }
    #[cfg(any(unix, windows))]
    {
        let _ = app_id;
        Err("daemon not running".into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = app_id;
        Err("launch is not supported on this platform".into())
    }
}

#[tauri::command]
async fn enforcement() -> Vec<CapStatus> {
    #[cfg(any(unix, windows))]
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
        args: s.args,
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
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
    Some(to_launch_info(rule.launch_spec(MOUNT, &user)))
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
        .invoke_handler(tauri::generate_handler![
            list_apps,
            launch_spec,
            launch_app,
            enforcement
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Clave app");
}
