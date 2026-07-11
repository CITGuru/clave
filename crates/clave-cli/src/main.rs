//! clave-cli — admin / diagnostics for Clave.
//!
//! Portable operator tooling: surface the platform's **enforcement posture** and
//! **dry-run** the policy brain's classifiers (`classify_exec`, `classify_path`) so an admin can
//! test policy before shipping it. The dispatch is a pure `run(args) -> Result<String, String>`
//! so it is unit-testable with no real OS.

use clave_core::{
    classify_exec, classify_path, AppId, AppPolicy, AppRule, BinaryMatch, FilePolicy, PolicyBundle,
};

const USAGE: &str = "\
clave-cli — Clave admin / diagnostics

usage:
  clave-cli version
  clave-cli enforcement
  clave-cli classify-exec <team_id> <signing_id> [allowed_team:allowed_signing ...]
  clave-cli classify-path <mount_point> <path> [work_data_root ...]
  clave-cli apps   <policy.json>
  clave-cli launch <policy.json> <app_id> <mount_point>
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) => print!("{out}"),
        Err(e) => {
            eprintln!("error: {e}\n");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
}

/// Dispatch a command line into output text (or an error message). Pure for every subcommand
/// except `enforcement`, which queries this target's OS adapter.
fn run(args: &[String]) -> Result<String, String> {
    let (cmd, rest) = args.split_first().ok_or("no command given")?;
    match cmd.as_str() {
        "version" => Ok(format!(
            "ipc proto v{}\ngateway proto v{}\n",
            clave_ipc::PROTO_VERSION,
            clave_proto::GATEWAY_PROTO_VERSION
        )),
        "enforcement" => Ok(enforcement_text()),
        "classify-exec" => classify_exec_cmd(rest),
        "classify-path" => classify_path_cmd(rest),
        "apps" => {
            let path = rest.first().ok_or("apps needs <policy.json>")?;
            Ok(launchable_list(&load_policy(path)?))
        }
        "launch" => {
            let path = rest.first().ok_or("launch needs <policy.json>")?;
            let app = rest.get(1).ok_or("launch needs <app_id>")?;
            let mount = rest.get(2).ok_or("launch needs <mount_point>")?;
            launch_text(&load_policy(path)?, app, mount)
        }
        other => Err(format!("unknown command: {other}")),
    }
}

/// Load a signed policy bundle from a JSON file (its signature/transport is the gateway's concern;
/// this is the decoded bundle for local inspection).
fn load_policy(path: &str) -> Result<PolicyBundle, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing {path}: {e}"))
}

/// The launcher catalog: allow-listed work apps that carry an executable.
fn launchable_list(pol: &PolicyBundle) -> String {
    let mut out = String::new();
    for rule in pol.apps.allow.iter().filter(|r| r.is_launchable()) {
        out.push_str(&format!("{}\t{}\n", rule.app_id.0, rule.label()));
    }
    if out.is_empty() {
        out.push_str("(no launchable apps in this policy)\n");
    }
    out
}

/// Resolve a contained spawn spec for `app_id` against the Clave Disk at `mount`.
fn launch_text(pol: &PolicyBundle, app_id: &str, mount: &str) -> Result<String, String> {
    let id = AppId(app_id.to_string());
    let rule = pol.apps.rule(&id).ok_or_else(|| format!("unknown app: {app_id}"))?;
    if !rule.is_launchable() {
        return Err(format!("{app_id} has no executable (authorization-only)"));
    }
    let spec = rule.launch_spec(mount);
    let mut out = format!("exec: {}\n", spec.executable);
    for (k, v) in &spec.env {
        out.push_str(&format!("  {k}={v}\n"));
    }
    if let Some(ns) = &spec.namespace_prefix {
        out.push_str(&format!("  namespace: {ns}\n"));
    }
    out.push_str("(spawn + inject = OS layer, deferred)\n");
    Ok(out)
}

/// `classify-exec <team_id> <signing_id> [allowed_team:allowed_signing ...]` — does this signed
/// binary join the work zone under the given allow-list? (Parent assumed personal.)
fn classify_exec_cmd(args: &[String]) -> Result<String, String> {
    let team = args.first().ok_or("classify-exec needs <team_id>")?;
    let signing = args.get(1).ok_or("classify-exec needs <signing_id>")?;
    let mut allow = Vec::new();
    for spec in args.get(2..).unwrap_or(&[]) {
        let (t, s) = spec
            .split_once(':')
            .ok_or_else(|| format!("bad allow entry '{spec}', want team:signing"))?;
        allow.push(AppRule::new(
            AppId(format!("{t}:{s}")),
            BinaryMatch::Macos {
                team_id: t.to_string(),
                signing_id: s.to_string(),
            },
        ));
    }
    let presented = BinaryMatch::Macos {
        team_id: team.clone(),
        signing_id: signing.clone(),
    };
    let v = classify_exec(&presented, false, &AppPolicy { allow });
    Ok(format!(
        "joins_zone={} matched={:?}\n",
        v.joins_zone,
        v.matched.map(|a| a.0)
    ))
}

/// `classify-path <mount_point> <path> [work_data_root ...]` — where does this path map for a
/// supervised app?
fn classify_path_cmd(args: &[String]) -> Result<String, String> {
    let mount = args.first().ok_or("classify-path needs <mount_point>")?;
    let path = args.get(1).ok_or("classify-path needs <path>")?;
    let files = FilePolicy {
        allow_save_outside_enclave: false,
        work_data_roots: args.get(2..).unwrap_or(&[]).to_vec(),
        cow_roots: Vec::new(),
    };
    Ok(format!("{:?}\n", classify_path(path, mount, &[], &files)))
}

/// This target's OS adapter enforcement report.
#[cfg(target_os = "macos")]
fn enforcement_text() -> String {
    use clave_platform::Platform;
    use std::sync::Arc;
    let p = clave_mac::MacPlatform::new(Arc::new(clave_core::ZoneRegistry::new()));
    format!("{}", p.enforcement_report())
}

#[cfg(target_os = "windows")]
fn enforcement_text() -> String {
    use clave_platform::Platform;
    use std::sync::Arc;
    let p = clave_win::WindowsPlatform::new(Arc::new(clave_core::ZoneRegistry::new()));
    format!("{}", p.enforcement_report())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn enforcement_text() -> String {
    "no OS platform adapter for this target\n".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn version_lists_proto_versions() {
        let out = run(&args(&["version"])).unwrap();
        assert!(out.contains("ipc proto v"));
        assert!(out.contains("gateway proto v"));
    }

    #[test]
    fn classify_exec_matches_the_allow_list() {
        let yes = run(&args(&[
            "classify-exec",
            "TEAM",
            "com.acme.app",
            "TEAM:com.acme.app",
        ]))
        .unwrap();
        assert!(yes.contains("joins_zone=true"));

        let no = run(&args(&[
            "classify-exec",
            "TEAM",
            "com.evil.app",
            "TEAM:com.acme.app",
        ]))
        .unwrap();
        assert!(no.contains("joins_zone=false"));
    }

    #[test]
    fn classify_path_dry_run() {
        let work = run(&args(&[
            "classify-path",
            "/Volumes/ClaveDisk",
            "/Users/a/Documents/x",
            "/Users/a/Documents",
        ]))
        .unwrap();
        assert!(work.contains("WorkData"));

        let inside = run(&args(&[
            "classify-path",
            "/Volumes/ClaveDisk",
            "/Volumes/ClaveDisk/x",
            "/Users/a/Documents",
        ]))
        .unwrap();
        assert!(inside.contains("PassThrough"));
    }

    #[test]
    fn missing_args_and_unknown_commands_error() {
        assert!(run(&args(&["frobnicate"])).is_err());
        assert!(run(&[]).is_err());
        assert!(run(&args(&["classify-path", "/mnt"])).is_err()); // missing <path>
    }

    fn policy_with_excel() -> PolicyBundle {
        let mut pol = PolicyBundle::restrictive_default();
        pol.apps.allow.push(
            AppRule::new(
                AppId("excel-work".into()),
                BinaryMatch::Macos {
                    team_id: "T".into(),
                    signing_id: "com.microsoft.Excel".into(),
                },
            )
            .with_display_name("Excel (Work)")
            .with_executable("/Applications/Microsoft Excel.app"),
        );
        pol
    }

    #[test]
    fn launcher_lists_and_resolves_from_a_policy() {
        let pol = policy_with_excel();

        let list = launchable_list(&pol);
        assert!(list.contains("excel-work"));
        assert!(list.contains("Excel (Work)"));

        let spec = launch_text(&pol, "excel-work", "/Volumes/ClaveDisk").unwrap();
        assert!(spec.contains("exec: /Applications/Microsoft Excel.app"));
        assert!(spec.contains("HOME=/Volumes/ClaveDisk/profiles/excel-work"));

        assert!(launch_text(&pol, "nope", "/m").is_err());
    }

    #[test]
    fn policy_round_trips_through_json() {
        // The `apps`/`launch` subcommands load a JSON policy; ensure the bundle serializes cleanly.
        let pol = policy_with_excel();
        let json = serde_json::to_string(&pol).unwrap();
        let back: PolicyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pol);
        assert!(launchable_list(&back).contains("Excel (Work)"));
    }
}
