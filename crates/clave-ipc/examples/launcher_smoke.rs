#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("launcher_smoke requires a Unix-domain socket or a Windows named pipe");
}

#[cfg(any(unix, windows))]
#[tokio::main]
async fn main() {
    use clave_core::AppId;
    use clave_ipc::transport::{default_launcher_endpoint, LauncherClient};

    let path = std::env::var("CLAVE_LAUNCHER_SOCK")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| default_launcher_endpoint());

    let mut client = LauncherClient::connect(&path)
        .await
        .expect("connect to clave-daemon launcher endpoint");

    let apps = client.list_apps().await.expect("list apps");
    println!("catalog ({} apps):", apps.len());
    for a in &apps {
        println!("  {} — {}", a.app_id.0, a.label);
    }

    if let Some(first) = apps.first() {
        let spec = client
            .prepare_launch(first.app_id.clone())
            .await
            .expect("prepare launch");
        println!("launch spec for {}: {:?}", first.app_id.0, spec);
    }

    let unknown = client
        .prepare_launch(AppId("does-not-exist".into()))
        .await
        .expect("prepare launch (unknown)");
    println!("unknown app spec (want None): {unknown:?}");

    let caps = client.enforcement().await.expect("enforcement");
    println!("enforcement:");
    for (cap, status) in caps {
        println!("  {cap}: {status}");
    }

    if let Ok(app_id) = std::env::var("CLAVE_SMOKE_LAUNCH") {
        let pid = client.launch(AppId(app_id.clone())).await.expect("launch");
        println!("launched {app_id}: pid {pid:?}");
    }
}
