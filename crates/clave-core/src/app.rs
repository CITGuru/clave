use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinaryMatch {
    Macos { team_id: String, signing_id: String },
    Windows { publisher: String, product: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRule {
    pub app_id: AppId,
    pub binary: BinaryMatch,
    pub launch: LaunchProfile,
    pub display_name: String,
    pub executable: String,
}

impl AppRule {
    pub fn new(app_id: AppId, binary: BinaryMatch) -> Self {
        Self {
            app_id,
            binary,
            launch: LaunchProfile::default(),
            display_name: String::new(),
            executable: String::new(),
        }
    }

    pub fn with_launch(mut self, launch: LaunchProfile) -> Self {
        self.launch = launch;
        self
    }

    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    pub fn with_executable(mut self, executable: impl Into<String>) -> Self {
        self.executable = executable.into();
        self
    }

    pub fn label(&self) -> &str {
        if self.display_name.is_empty() {
            &self.app_id.0
        } else {
            &self.display_name
        }
    }

    pub fn is_launchable(&self) -> bool {
        !self.executable.is_empty()
    }

    pub fn launch_spec(&self, mount_point: &str) -> LaunchSpec {
        let resolved = self.launch.resolve(&self.app_id, mount_point);
        LaunchSpec {
            app_id: self.app_id.clone(),
            executable: self.executable.clone(),
            args: resolved.args,
            env: resolved.env,
            namespace_prefix: resolved.namespace_prefix,
            seed_home: resolved.seed_home,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ContainerKind {
    #[default]
    Native,
    Chromium,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchableApp {
    pub app_id: AppId,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchSpec {
    pub app_id: AppId,
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub namespace_prefix: Option<String>,
    /// Paths (relative to the real user home) to make available inside the contained HOME — the
    /// OS layer symlinks each existing one at launch. Empty ⇒ a pristine home.
    #[serde(default)]
    pub seed_home: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LaunchProfile {
    pub home_subdir: String,
    #[serde(default)]
    pub container: ContainerKind,
    #[serde(default)]
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub namespace_prefix: Option<String>,
    pub hive_seed: Option<String>,
    pub passthrough_paths: Vec<String>,
    /// Paths under the real user home (e.g. `.zshrc`, `.local`, `.cargo`) to expose inside the
    /// contained HOME so a launched dev tool sees the user's shell config / toolchains instead of
    /// an empty home. The daemon symlinks each existing entry at launch. Empty ⇒ a pristine home.
    #[serde(default)]
    pub seed_home: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedLaunch {
    pub home: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub hive_path: Option<String>,
    pub namespace_prefix: Option<String>,
    pub seed_home: Vec<String>,
}

impl LaunchProfile {
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
            seed_home: self.seed_home.clone(),
        }
    }

    pub fn chromium() -> Self {
        Self {
            container: ContainerKind::Chromium,
            ..Self::default()
        }
    }

    /// Expose paths (relative to the real user home) inside the contained HOME at launch — see
    /// [`LaunchProfile::seed_home`].
    pub fn with_seed_home<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.seed_home = paths.into_iter().map(Into::into).collect();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPolicy {
    pub allow: Vec<AppRule>,
}

impl AppPolicy {
    pub fn empty() -> Self {
        Self { allow: Vec::new() }
    }

    pub fn match_app(&self, presented: &BinaryMatch) -> Option<&AppId> {
        self.allow
            .iter()
            .find(|r| &r.binary == presented)
            .map(|r| &r.app_id)
    }

    pub fn rule(&self, app_id: &AppId) -> Option<&AppRule> {
        self.allow.iter().find(|r| &r.app_id == app_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecVerdict {
    pub allow: bool,
    pub joins_zone: bool,
    pub matched: Option<AppId>,
}

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
            seed_home: vec![],
        };
        let r = profile.resolve(&AppId("office".into()), "X:");
        assert_eq!(r.home, "X:/profiles/office");
        assert_eq!(r.hive_path.as_deref(), Some("X:/registry/zone-default.hiv"));
        assert_eq!(r.namespace_prefix.as_deref(), Some("Clave-work\\"));
        assert!(r.env.iter().any(|(k, v)| k == "CLAVE_ZONE" && v == "work"));
        assert!(r.args.is_empty(), "a native profile passes no launch args");
    }

    #[test]
    fn seed_home_flows_through_resolve_and_launch_spec() {
        let rule = AppRule::new(AppId("vscode-work".into()), chrome())
            .with_executable("/Applications/Visual Studio Code.app")
            .with_launch(LaunchProfile::chromium().with_seed_home([".zshrc", ".local"]));
        let r = rule.launch.resolve(&rule.app_id, "/Volumes/ClaveDisk");
        assert_eq!(
            r.seed_home,
            vec![".zshrc".to_string(), ".local".to_string()]
        );
        let spec = rule.launch_spec("/Volumes/ClaveDisk");
        assert_eq!(
            spec.seed_home,
            vec![".zshrc".to_string(), ".local".to_string()]
        );
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
        let json = r#"{"home_subdir":"","env":[],"namespace_prefix":null,"hive_seed":null,"passthrough_paths":[]}"#;
        let profile: LaunchProfile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.container, ContainerKind::Native);
        assert!(profile.args.is_empty());
    }
}
