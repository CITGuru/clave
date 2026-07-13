use clave_core::{
    decide, path::is_under_mount, Access, Action, PolicyBundle, UnixTime, ZoneRegistry,
};
use clave_platform::{Decision, ProcId};
use std::sync::{OnceLock, RwLock};

#[derive(Clone, Debug)]
pub struct EsGateConfig {
    pub mount_prefix: String,
    pub allow_save_outside_enclave: bool,
}

impl Default for EsGateConfig {
    fn default() -> Self {
        Self {
            mount_prefix: "/Volumes/ClaveDisk".into(),
            allow_save_outside_enclave: false,
        }
    }
}

static ES_GATE: OnceLock<RwLock<EsGateConfig>> = OnceLock::new();

fn es_gate() -> &'static RwLock<EsGateConfig> {
    ES_GATE.get_or_init(|| RwLock::new(EsGateConfig::default()))
}

pub fn set_mount_prefix(prefix: &str) {
    let mut g = es_gate().write().expect("es gate lock poisoned");
    g.mount_prefix = prefix.trim_end_matches('/').to_string();
}

pub fn set_allow_save_outside_enclave(allow: bool) {
    es_gate()
        .write()
        .expect("es gate lock poisoned")
        .allow_save_outside_enclave = allow;
}

pub fn apply_file_policy(files: &clave_core::FilePolicy) {
    let mut g = es_gate().write().expect("es gate lock poisoned");
    g.allow_save_outside_enclave = files.allow_save_outside_enclave;
}

fn policy_for_config(config: &EsGateConfig) -> PolicyBundle {
    let mut pol = PolicyBundle::restrictive_default();
    pol.files.allow_save_outside_enclave = config.allow_save_outside_enclave;
    pol
}

pub fn authorize_open_with(
    zones: &ZoneRegistry,
    proc: ProcId,
    path: &str,
    write: bool,
    config: &EsGateConfig,
) -> bool {
    let inside = is_under_mount(path, &config.mount_prefix);
    let access = if write { Access::Write } else { Access::Read };
    let verdict = decide(
        &Action::FileOpen {
            proc,
            inside_enclave: inside,
            access,
        },
        zones,
        &policy_for_config(config),
        UnixTime::MAX,
    );
    matches!(verdict.decision, Decision::Allow)
}

pub fn authorize_open(zones: &ZoneRegistry, proc: ProcId, path: &str, write: bool) -> bool {
    let config = es_gate().read().expect("es gate lock poisoned").clone();
    authorize_open_with(zones, proc, path, write, &config)
}

pub fn authorize_clone_with(
    zones: &ZoneRegistry,
    proc: ProcId,
    source: &str,
    target: &str,
    config: &EsGateConfig,
) -> bool {
    authorize_open_with(zones, proc, source, false, config)
        && authorize_open_with(zones, proc, target, true, config)
}

pub fn authorize_clone(zones: &ZoneRegistry, proc: ProcId, source: &str, target: &str) -> bool {
    let config = es_gate().read().expect("es gate lock poisoned").clone();
    authorize_clone_with(zones, proc, source, target, &config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clave_core::JoinReason;

    fn token(n: u32) -> ProcId {
        let mut t = [0u32; 8];
        t[5] = n;
        ProcId::macos(t)
    }

    fn config(mount: &str) -> EsGateConfig {
        EsGateConfig {
            mount_prefix: mount.into(),
            allow_save_outside_enclave: false,
        }
    }

    #[test]
    fn supervised_write_outside_mount_is_denied() {
        let cfg = config("/Volumes/ClaveDisk");
        let zones = ZoneRegistry::new();
        let p = token(42);
        zones.join(p, JoinReason::Launcher);

        assert!(authorize_open_with(
            &zones,
            p,
            "/Volumes/ClaveDisk/ada/doc.pdf",
            true,
            &cfg,
        ));
        assert!(!authorize_open_with(
            &zones,
            p,
            "/Users/alice/Desktop/doc.pdf",
            true,
            &cfg,
        ));
        assert!(authorize_open_with(
            &zones,
            p,
            "/Users/alice/Desktop/doc.pdf",
            false,
            &cfg,
        ));
    }

    #[test]
    fn clone_from_enclave_to_desktop_is_denied() {
        let cfg = config("/Volumes/ClaveDisk-dev");
        let zones = ZoneRegistry::new();
        let p = token(7);
        zones.join(p, JoinReason::Launcher);

        assert!(!authorize_clone_with(
            &zones,
            p,
            "/Volumes/ClaveDisk-dev/ada/secret.pdf",
            "/Users/alice/Desktop/secret.pdf",
            &cfg,
        ));
    }

    #[test]
    fn non_supervised_clone_out_of_enclave_is_denied() {
        let cfg = config("/Volumes/ClaveDisk");
        let zones = ZoneRegistry::new();
        let p = token(99);

        assert!(!authorize_clone_with(
            &zones,
            p,
            "/Volumes/ClaveDisk/ada/secret.pdf",
            "/Users/alice/Desktop/secret.pdf",
            &cfg,
        ));
    }

    #[test]
    fn supervised_clone_into_enclave_is_allowed() {
        let cfg = config("/Volumes/ClaveDisk");
        let zones = ZoneRegistry::new();
        let p = token(11);
        zones.join(p, JoinReason::Launcher);

        assert!(authorize_clone_with(
            &zones,
            p,
            "/Users/alice/Downloads/report.pdf",
            "/Volumes/ClaveDisk/ada/report.pdf",
            &cfg,
        ));
    }
}
