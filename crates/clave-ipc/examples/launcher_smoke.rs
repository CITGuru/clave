//! Manual smoke check: connect to a running `clave-daemon` as the launcher UI would and print the
//! catalog, one launch spec, and the enforcement posture. Run with `CLAVE_LAUNCHER_SOCK` set.
//!
//! `cargo run -p clave-ipc --example launcher_smoke`

use clave_core::AppId;
use clave_ipc::transport::LauncherClient;

#[tokio::main]
async fn main() {
    let path = std::env::var("CLAVE_LAUNCHER_SOCK")
        .unwrap_or_else(|_| format!("{}/clave-launcher.sock", std::env::temp_dir().display()));

    let mut client = LauncherClient::connect(&path)
        .await
        .expect("connect to clave-daemon launcher socket");

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

    // Opt-in: actually spawn a work app (pops a real window). Set CLAVE_SMOKE_LAUNCH to an app id,
    // e.g. `CLAVE_SMOKE_LAUNCH=calculator-work`.
    if let Ok(app_id) = std::env::var("CLAVE_SMOKE_LAUNCH") {
        let pid = client
            .launch(AppId(app_id.clone()))
            .await
            .expect("launch");
        println!("launched {app_id}: pid {pid:?}");
    }
}
