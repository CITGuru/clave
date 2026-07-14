use serde::{Deserialize, Serialize};

use crate::app::{ContainerKind, LaunchProfile, LaunchSpec};
use crate::AppId;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAppRule {
    pub id: AppId,
    #[serde(default)]
    pub display_name: String,
    pub url: String,
    #[serde(default)]
    pub persona: Option<String>,
}

impl WebAppRule {
    pub fn new(id: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            id: AppId(id.into()),
            display_name: String::new(),
            url: url.into(),
            persona: None,
        }
    }

    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    pub fn with_persona(mut self, persona: impl Into<String>) -> Self {
        self.persona = Some(persona.into());
        self
    }

    pub fn label(&self) -> &str {
        if self.display_name.is_empty() {
            &self.id.0
        } else {
            &self.display_name
        }
    }

    pub fn launch_spec(&self, browser: &str, mount_point: &str, user: &str) -> LaunchSpec {
        let subdir = self
            .persona
            .clone()
            .unwrap_or_else(|| format!("web-{}", self.id.0));
        let profile = LaunchProfile {
            profile_subdir: subdir,
            container: ContainerKind::Chromium,
            args: vec![format!("--app={}", self.url)],
            ..LaunchProfile::default()
        };
        let resolved = profile.resolve(&self.id, mount_point, user);
        LaunchSpec {
            app_id: self.id.clone(),
            executable: browser.to_string(),
            args: resolved.args,
            env: resolved.env,
            namespace_prefix: resolved.namespace_prefix,
            seed_home: resolved.seed_home,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WebPolicy {
    #[serde(default)]
    pub browser: String,
    #[serde(default)]
    pub apps: Vec<WebAppRule>,
}

impl WebPolicy {
    pub fn is_launchable(&self) -> bool {
        !self.browser.is_empty()
    }

    pub fn rule(&self, id: &AppId) -> Option<&WebAppRule> {
        self.apps.iter().find(|r| &r.id == id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAppInfo {
    pub app_id: AppId,
    pub label: String,
    pub url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_web_app_resolves_to_a_contained_app_window() {
        let rule = WebAppRule::new("jira-work", "https://jira.corp.example").with_display_name("Jira");
        let spec = rule.launch_spec("/Applications/Google Chrome.app", "/Volumes/ClaveDisk", "ada");

        assert_eq!(spec.executable, "/Applications/Google Chrome.app");
        assert!(spec
            .args
            .contains(&"--app=https://jira.corp.example".to_string()));
        assert!(spec
            .args
            .contains(&"--user-data-dir=/Volumes/ClaveDisk/ada/profiles/web-jira-work".to_string()));
        assert!(spec
            .env
            .iter()
            .any(|(k, v)| k == "HOME" && v == "/Volumes/ClaveDisk/ada"));
    }

    #[test]
    fn a_persona_groups_web_apps_into_one_profile() {
        let a = WebAppRule::new("gmail", "https://mail.google.com").with_persona("google");
        let b = WebAppRule::new("drive", "https://drive.google.com").with_persona("google");
        let sa = a.launch_spec("/b", "/mnt", "ada");
        let sb = b.launch_spec("/b", "/mnt", "ada");
        assert!(sa.args.contains(&"--user-data-dir=/mnt/ada/profiles/google".to_string()));
        assert!(sb.args.contains(&"--user-data-dir=/mnt/ada/profiles/google".to_string()));
    }

    #[test]
    fn an_empty_browser_is_not_launchable() {
        assert!(!WebPolicy::default().is_launchable());
        let pol = WebPolicy {
            browser: "/b".into(),
            apps: vec![WebAppRule::new("x", "https://x.example")],
        };
        assert!(pol.is_launchable());
        assert!(pol.rule(&AppId("x".into())).is_some());
    }
}
