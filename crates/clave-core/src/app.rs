//! The signed app allow-list and exec classification.
//!
//! A *work* process is one Clave **supervises**. A binary becomes supervised when it is
//! launched by the Clave launcher, inherits membership from a supervised parent, or **matches the
//! signed app allow-list** — a binary whose code-signature is on the policy's vetted list. This
//! module is the portable, OS-free half: the allow-list data and the pure [`classify_exec`]
//! decision the OS layers (macOS Endpoint Security `AUTH_EXEC`, the Windows process-notify driver)
//! feed with a presented binary identity. It is the analog of [`classify_flow`](crate::net) for
//! processes.

use serde::{Deserialize, Serialize};

/// A stable label for an allow-listed app (e.g. `"chrome-work"`), used for audit and (Phase 4)
/// launch-profile selection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppId(pub String);

/// A binary's **code-signature identity** — the thing that must match for it to be a vetted work
/// app (the *required* code-sign identity, never a path or name alone, which are
/// forgeable). Exact match for Phase 1; path/glob criteria slot in later.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinaryMatch {
    /// macOS Developer ID: Team ID + signing identifier.
    Macos { team_id: String, signing_id: String },
    /// Windows Authenticode: publisher subject + product name.
    Windows { publisher: String, product: String },
}

/// One allow-list entry: an [`AppId`], the [`BinaryMatch`] a binary must satisfy to be it, how it
/// launches contained ([`LaunchProfile`]), and the launcher metadata (label + executable) the Clave
/// launcher uses to present and spawn it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRule {
    pub app_id: AppId,
    pub binary: BinaryMatch,
    /// How the app launches contained. Default: HOME under `profiles/<app_id>`.
    pub launch: LaunchProfile,
    /// Human label for the launcher UI (e.g. `"Excel (Work)"`). Empty ⇒ falls back to the app id.
    pub display_name: String,
    /// What the launcher spawns (executable path / bundle). Empty ⇒ authorization-only (the rule
    /// recognizes the app if it runs, but the launcher can't start it).
    pub executable: String,
}

impl AppRule {
    /// A rule with the default launch profile and no launcher metadata (authorization-only until
    /// an executable is attached).
    pub fn new(app_id: AppId, binary: BinaryMatch) -> Self {
        Self {
            app_id,
            binary,
            launch: LaunchProfile::default(),
            display_name: String::new(),
            executable: String::new(),
        }
    }

    /// Attach a custom [`LaunchProfile`].
    pub fn with_launch(mut self, launch: LaunchProfile) -> Self {
        self.launch = launch;
        self
    }

    /// Set the launcher label.
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    /// Set the executable the launcher spawns (makes the app launchable).
    pub fn with_executable(mut self, executable: impl Into<String>) -> Self {
        self.executable = executable.into();
        self
    }

    /// The launcher label — `display_name`, or the app id if unset.
    pub fn label(&self) -> &str {
        if self.display_name.is_empty() {
            &self.app_id.0
        } else {
            &self.display_name
        }
    }

    /// Whether the launcher can spawn this app (it has an executable).
    pub fn is_launchable(&self) -> bool {
        !self.executable.is_empty()
    }

    /// Resolve the contained spawn instructions against the Clave Disk at `mount_point`: the
    /// executable plus the env / namespace pointing into the encrypted volume.
    pub fn launch_spec(&self, mount_point: &str) -> LaunchSpec {
        let resolved = self.launch.resolve(&self.app_id, mount_point);
        LaunchSpec {
            app_id: self.app_id.clone(),
            executable: self.executable.clone(),
            env: resolved.env,
            namespace_prefix: resolved.namespace_prefix,
        }
    }
}

/// A work app the user can launch from the Clave launcher — what the launcher UI
/// lists. Produced by `Daemon::launchable_apps` and carried to the launcher UI over `clave-ipc`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchableApp {
    pub app_id: AppId,
    pub label: String,
}

/// The resolved instructions to spawn a contained work app. The OS layer executes it:
/// spawn `executable` **suspended**, add the PID to the supervised set, inject the shim (Windows) or
/// mark the audit token (macOS), apply `env`, then resume — so the app boots into the redirected FS
/// on the encrypted volume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchSpec {
    pub app_id: AppId,
    pub executable: String,
    /// `HOME`/`TMPDIR` redirected into the Clave Disk, plus the profile's overrides.
    pub env: Vec<(String, String)>,
    /// (Windows) object-namespace prefix so work/personal instances coexist.
    pub namespace_prefix: Option<String>,
}

/// How a matched work app launches **contained**: its profile/HOME and temp
/// redirected into the Clave Disk so everything it persists is encrypted at rest, plus
/// env overrides and — on Windows — a copy-on-write registry hive seed and an object-namespace
/// prefix. Portable data; the OS layer *applies* it (Phase 4 — injection / FS
/// redirection on Windows, a distinct container HOME + ES on macOS).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LaunchProfile {
    /// Subdirectory under the Clave Disk's `profiles/` for this app's HOME/container.
    /// Empty ⇒ defaults to the rule's [`AppId`].
    pub home_subdir: String,
    /// Extra environment overrides, applied after the redirected `HOME`/`TMPDIR`.
    pub env: Vec<(String, String)>,
    /// (Windows) object-namespace prefix so work/personal instances don't collide.
    pub namespace_prefix: Option<String>,
    /// (Windows) copy-on-write registry hive seed under the Clave Disk's `registry/`.
    pub hive_seed: Option<String>,
    /// Paths the app may reach unredirected — e.g. shared read-only system data.
    pub passthrough_paths: Vec<String>,
}

/// The concrete launch environment for a contained work app, resolved against the mounted Clave
/// Disk — every path points **inside** the encrypted volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedLaunch {
    /// The app's HOME / container directory (under the Clave Disk's `profiles/`).
    pub home: String,
    /// Environment to launch with: `HOME` + `TMPDIR` redirected into the volume, then the
    /// profile's overrides.
    pub env: Vec<(String, String)>,
    /// (Windows) the COW hive file to `RegLoadKey`, if any.
    pub hive_path: Option<String>,
    /// (Windows) the object-namespace prefix, if any.
    pub namespace_prefix: Option<String>,
}

impl LaunchProfile {
    /// Resolve against the Clave Disk mounted at `mount_point` for `app_id`. `HOME` and `TMPDIR`
    /// are redirected inside the encrypted volume; the profile's `env` overrides are applied last
    /// (so a profile can deliberately override even `HOME`). Paths use `/`; the OS adapter
    /// normalizes separators (a Windows mount is e.g. `X:`).
    pub fn resolve(&self, app_id: &AppId, mount_point: &str) -> ResolvedLaunch {
        let sub = if self.home_subdir.is_empty() {
            app_id.0.as_str()
        } else {
            self.home_subdir.as_str()
        };
        let home = format!("{mount_point}/profiles/{sub}");
        let mut env = vec![
            ("HOME".to_string(), home.clone()),
            ("TMPDIR".to_string(), format!("{mount_point}/tmp")),
        ];
        env.extend(self.env.iter().cloned());
        let hive_path = self
            .hive_seed
            .as_ref()
            .map(|h| format!("{mount_point}/registry/{h}"));
        ResolvedLaunch {
            home,
            env,
            hive_path,
            namespace_prefix: self.namespace_prefix.clone(),
        }
    }
}

/// The set of binaries permitted to run as supervised work apps. **Default-empty**: with no rules,
/// no binary auto-joins the zone by signature — only the launcher and inheritance do, so an
/// un-synced or restrictive policy supervises nothing it wasn't explicitly told to (fail-safe).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPolicy {
    pub allow: Vec<AppRule>,
}

impl AppPolicy {
    /// The conservative default: no allow-listed apps.
    pub fn empty() -> Self {
        Self { allow: Vec::new() }
    }

    /// The [`AppId`] a presented binary signature matches, if any.
    pub fn match_app(&self, presented: &BinaryMatch) -> Option<&AppId> {
        self.allow
            .iter()
            .find(|r| &r.binary == presented)
            .map(|r| &r.app_id)
    }

    /// The rule for an [`AppId`], if present — to resolve its launch profile after a match.
    pub fn rule(&self, app_id: &AppId) -> Option<&AppRule> {
        self.allow.iter().find(|r| &r.app_id == app_id)
    }
}

/// The outcome of classifying an exec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecVerdict {
    /// Whether to permit the exec. Clave **classifies** execs into work/personal rather than
    /// allow-listing the whole machine, so this is currently always `true`; it is kept for the
    /// OS-API contract (ES `AUTH_EXEC` demands a verdict) and a future strict mode.
    pub allow: bool,
    /// Whether the new process is supervised — joins the work zone.
    pub joins_zone: bool,
    /// The allow-list entry it matched, if any (drives audit + Phase-4 launch profiles).
    pub matched: Option<AppId>,
}

/// Classify a new exec into work (supervised) or personal, from its code-signature and whether its
/// parent is supervised. **Pure & deterministic**:
///
/// * a binary on the signed allow-list → joins (a vetted work app);
/// * else a child of a supervised process → joins (inheritance);
/// * else → personal (not supervised, never instrumented or logged).
///
/// A binary that merely *names* a work app but whose signature is absent from the list simply
/// doesn't match — it runs personal, never as a spoofed work app.
pub fn classify_exec(
    binary: &BinaryMatch,
    parent_supervised: bool,
    apps: &AppPolicy,
) -> ExecVerdict {
    if let Some(app) = apps.match_app(binary) {
        ExecVerdict {
            allow: true,
            joins_zone: true,
            matched: Some(app.clone()),
        }
    } else {
        ExecVerdict {
            allow: true,
            joins_zone: parent_supervised,
            matched: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome() -> BinaryMatch {
        BinaryMatch::Macos {
            team_id: "ABCDE12345".into(),
            signing_id: "com.google.Chrome".into(),
        }
    }

    fn policy() -> AppPolicy {
        AppPolicy {
            allow: vec![AppRule::new(AppId("chrome-work".into()), chrome())],
        }
    }

    #[test]
    fn allowlisted_binary_joins_the_zone() {
        let v = classify_exec(&chrome(), false, &policy());
        assert!(v.joins_zone);
        assert_eq!(v.matched, Some(AppId("chrome-work".into())));
    }

    #[test]
    fn unlisted_binary_with_personal_parent_stays_personal() {
        let other = BinaryMatch::Macos {
            team_id: "ZZZ".into(),
            signing_id: "com.evil.app".into(),
        };
        let v = classify_exec(&other, false, &policy());
        assert!(!v.joins_zone);
        assert_eq!(v.matched, None);
    }

    #[test]
    fn unlisted_binary_inherits_from_a_supervised_parent() {
        let other = BinaryMatch::Macos {
            team_id: "ZZZ".into(),
            signing_id: "com.evil.app".into(),
        };
        let v = classify_exec(&other, true, &policy());
        assert!(v.joins_zone, "a child of a supervised process inherits");
        assert_eq!(v.matched, None);
    }

    #[test]
    fn signature_mismatch_does_not_masquerade_as_a_work_app() {
        // The same product but a different signing id (a tampered / repackaged binary) → no match.
        let fake = BinaryMatch::Macos {
            team_id: "ABCDE12345".into(),
            signing_id: "com.google.Chrome.evil".into(),
        };
        assert_eq!(policy().match_app(&fake), None);
        assert!(!classify_exec(&fake, false, &policy()).joins_zone);
    }

    #[test]
    fn empty_policy_allowlists_nothing() {
        assert!(!classify_exec(&chrome(), false, &AppPolicy::empty()).joins_zone);
    }

    #[test]
    fn windows_authenticode_match() {
        let bin = BinaryMatch::Windows {
            publisher: "CN=Google LLC".into(),
            product: "Google Chrome".into(),
        };
        let apps = AppPolicy {
            allow: vec![AppRule::new(AppId("chrome-work".into()), bin.clone())],
        };
        assert_eq!(apps.match_app(&bin), Some(&AppId("chrome-work".into())));
    }

    #[test]
    fn launch_profile_redirects_home_into_the_clave_disk() {
        let rule = AppRule::new(AppId("chrome-work".into()), chrome());
        let r = rule.launch.resolve(&rule.app_id, "/Volumes/ClaveDisk");
        assert_eq!(r.home, "/Volumes/ClaveDisk/profiles/chrome-work");
        assert!(r
            .env
            .iter()
            .any(|(k, v)| k == "HOME" && v == "/Volumes/ClaveDisk/profiles/chrome-work"));
        assert!(r
            .env
            .iter()
            .any(|(k, v)| k == "TMPDIR" && v == "/Volumes/ClaveDisk/tmp"));
    }

    #[test]
    fn custom_launch_profile_overrides_and_seeds_windows_bits() {
        let profile = LaunchProfile {
            home_subdir: "office".into(),
            env: vec![("CLAVE_ZONE".into(), "work".into())],
            namespace_prefix: Some("Clave-work\\".into()),
            hive_seed: Some("zone-default.hiv".into()),
            passthrough_paths: vec![],
        };
        let r = profile.resolve(&AppId("office".into()), "X:");
        assert_eq!(r.home, "X:/profiles/office");
        assert_eq!(r.hive_path.as_deref(), Some("X:/registry/zone-default.hiv"));
        assert_eq!(r.namespace_prefix.as_deref(), Some("Clave-work\\"));
        assert!(r.env.iter().any(|(k, v)| k == "CLAVE_ZONE" && v == "work"));
    }
}
