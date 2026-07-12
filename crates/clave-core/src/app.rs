//! The signed app allow-list and exec classification: allow-list data plus the pure
//! [`classify_exec`] decision the OS layers feed with a presented binary identity.

use serde::{Deserialize, Serialize};

/// A stable label for an allow-listed app (e.g. `"chrome-work"`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppId(pub String);

/// A binary's code-signature identity — never a path or name alone, which are forgeable.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinaryMatch {
    /// macOS Developer ID: Team ID + signing identifier.
    Macos { team_id: String, signing_id: String },
    /// Windows Authenticode: publisher subject + product name.
    Windows { publisher: String, product: String },
}

/// One allow-list entry: the app id, the signature a binary must match, how it launches contained,
/// and the launcher's label + executable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRule {
    pub app_id: AppId,
    pub binary: BinaryMatch,
    /// How the app launches contained. Default: HOME under `profiles/<app_id>`.
    pub launch: LaunchProfile,
    /// Launcher UI label. Empty ⇒ falls back to the app id.
    pub display_name: String,
    /// Executable/bundle the launcher spawns. Empty ⇒ authorization-only (not launchable).
    pub executable: String,
}

impl AppRule {
    /// A rule with the default launch profile and no launcher metadata (not yet launchable).
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

    /// Resolve the contained spawn spec against the Clave Disk at `mount_point`.
    pub fn launch_spec(&self, mount_point: &str) -> LaunchSpec {
        let resolved = self.launch.resolve(&self.app_id, mount_point);
        LaunchSpec {
            app_id: self.app_id.clone(),
            executable: self.executable.clone(),
            args: resolved.args,
            env: resolved.env,
            namespace_prefix: resolved.namespace_prefix,
        }
    }
}

/// How the OS layer must start the app to get a fresh, isolated instance whose profile lives in the
/// Clave Disk rather than joining the user's personal one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ContainerKind {
    /// Env-only redirect (`HOME`/`TMPDIR`) — for well-behaved native apps.
    #[default]
    Native,
    /// Chromium/Electron apps: also pass a private `--user-data-dir` so they run contained instead
    /// of joining the user's personal instance.
    Chromium,
}

/// A launchable work app as listed by the launcher UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchableApp {
    pub app_id: AppId,
    pub label: String,
}

/// The resolved instructions to spawn a contained work app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchSpec {
    pub app_id: AppId,
    pub executable: String,
    /// Launch arguments — e.g. a Chromium `--user-data-dir` into the Clave Disk. Empty for native.
    #[serde(default)]
    pub args: Vec<String>,
    /// `HOME`/`TMPDIR` redirected into the Clave Disk, plus the profile's overrides.
    pub env: Vec<(String, String)>,
    /// (Windows) object-namespace prefix so work/personal instances coexist.
    pub namespace_prefix: Option<String>,
}

/// How a matched work app launches contained: HOME/TMPDIR redirected into the Clave Disk, plus env
/// overrides and — on Windows — a registry hive seed and object-namespace prefix.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LaunchProfile {
    /// Subdirectory under the Clave Disk's `profiles/` for this app's HOME/container.
    /// Empty ⇒ defaults to the rule's [`AppId`].
    pub home_subdir: String,
    /// How to start the app so it runs a fresh, contained instance (see [`ContainerKind`]).
    #[serde(default)]
    pub container: ContainerKind,
    /// Extra launch arguments, appended after any [`ContainerKind`]-derived flags.
    #[serde(default)]
    pub args: Vec<String>,
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
/// Disk — every path points inside the encrypted volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedLaunch {
    /// The app's HOME / container directory (under the Clave Disk's `profiles/`).
    pub home: String,
    /// Launch arguments: [`ContainerKind`]-derived flags followed by the profile's extra `args`.
    pub args: Vec<String>,
    /// `HOME` + `TMPDIR` redirected into the volume, then the profile's overrides.
    pub env: Vec<(String, String)>,
    /// (Windows) the COW hive file to `RegLoadKey`, if any.
    pub hive_path: Option<String>,
    /// (Windows) the object-namespace prefix, if any.
    pub namespace_prefix: Option<String>,
}

impl LaunchProfile {
    /// Resolve against the Clave Disk at `mount_point` for `app_id`. `HOME`/`TMPDIR` are redirected
    /// into the volume; the profile's `env` overrides apply last. Paths use `/`.
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
        let mut args = match self.container {
            ContainerKind::Native => Vec::new(),
            // A private --user-data-dir forces a fresh, contained instance whose window-owning
            // process we supervise, instead of joining the user's personal one.
            ContainerKind::Chromium => vec![
                format!("--user-data-dir={home}"),
                "--no-first-run".to_string(),
                "--no-default-browser-check".to_string(),
            ],
        };
        args.extend(self.args.iter().cloned());
        let hive_path = self
            .hive_seed
            .as_ref()
            .map(|h| format!("{mount_point}/registry/{h}"));
        ResolvedLaunch {
            home,
            args,
            env,
            hive_path,
            namespace_prefix: self.namespace_prefix.clone(),
        }
    }

    /// A profile for a Chromium/Electron app (see [`ContainerKind::Chromium`]).
    pub fn chromium() -> Self {
        Self {
            container: ContainerKind::Chromium,
            ..Self::default()
        }
    }
}

/// The set of binaries permitted to run as supervised work apps. Default-empty: with no rules, only
/// the launcher and inheritance can supervise a process (fail-safe).
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

    /// The rule for an [`AppId`], if present.
    pub fn rule(&self, app_id: &AppId) -> Option<&AppRule> {
        self.allow.iter().find(|r| &r.app_id == app_id)
    }
}

/// The outcome of classifying an exec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecVerdict {
    /// Whether to permit the exec. Always `true` today (Clave classifies rather than allow-lists the
    /// machine); kept for the OS-API contract and a future strict mode.
    pub allow: bool,
    /// Whether the new process is supervised — joins the work zone.
    pub joins_zone: bool,
    /// The allow-list entry it matched, if any.
    pub matched: Option<AppId>,
}

/// Classify a new exec into work (supervised) or personal, from its code-signature and whether its
/// parent is supervised: allow-listed → joins; else a child of a supervised process → joins; else
/// personal.
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
            container: ContainerKind::Native,
            args: vec![],
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
        assert!(r.args.is_empty(), "a native profile passes no launch args");
    }

    #[test]
    fn chromium_profile_isolates_the_profile_into_the_clave_disk() {
        let mut profile = LaunchProfile::chromium();
        profile.args = vec!["--restore-last-session".into()];
        let r = profile.resolve(&AppId("chrome-work".into()), "/Volumes/ClaveDisk");
        assert_eq!(
            r.args[0], "--user-data-dir=/Volumes/ClaveDisk/profiles/chrome-work",
            "the private profile dir points into the Clave Disk"
        );
        assert!(r.args.iter().any(|a| a == "--no-first-run"));
        assert!(
            r.args.iter().any(|a| a == "--restore-last-session"),
            "profile's extra args are appended after the container flags"
        );
    }

    #[test]
    fn launch_spec_carries_the_container_args() {
        let rule = AppRule::new(AppId("chrome-work".into()), chrome())
            .with_launch(LaunchProfile::chromium())
            .with_executable("/Applications/Google Chrome.app");
        let spec = rule.launch_spec("/Volumes/ClaveDisk");
        assert!(spec
            .args
            .iter()
            .any(|a| a == "--user-data-dir=/Volumes/ClaveDisk/profiles/chrome-work"));
    }

    #[test]
    fn container_kind_missing_in_json_defaults_to_native() {
        // Older policy bundles that predate the `container`/`args` fields still deserialize.
        let json = r#"{"home_subdir":"","env":[],"namespace_prefix":null,"hive_seed":null,"passthrough_paths":[]}"#;
        let profile: LaunchProfile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.container, ContainerKind::Native);
        assert!(profile.args.is_empty());
    }
}
