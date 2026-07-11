//! "Learn mode": discover an app's footprint to synthesize a candidate launch profile.
//!
//! App-compat is "the unglamorous 60%". Rather than hand-author every [`LaunchProfile`], run a new
//! app in **notify-only** mode — the OS layer reports what it touches without redirecting or
//! denying — and accumulate the accesses here. [`LearnSession::synthesize`] turns them into a
//! *candidate* the admin curates: the directories it wrote to become
//! [`FilePolicy::work_data_roots`](crate::policy::FilePolicy), and a named-object sighting suggests
//! the work instance needs a namespace prefix to coexist with personal. Portable and
//! OS-free; the OS layer only supplies the [`Observation`]s.

use crate::app::{AppId, LaunchProfile};
use crate::path::under;
use serde::{Deserialize, Serialize};

/// One thing a watched app touched while running in notify-only learn mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Observation {
    /// A filesystem access. `write` distinguishes data the app *persists* (a work-data-root
    /// candidate) from reads (which pass through by default, so they need no profile entry).
    PathAccess { path: String, write: bool },
    /// A named kernel object (mutex / event / section). Its presence implies the app expects a
    /// singleton, so the work instance needs a namespace prefix to coexist.
    NamedObject { name: String },
}

/// A learn-mode session accumulating one app's observations.
#[derive(Clone, Debug)]
pub struct LearnSession {
    app_id: AppId,
    observations: Vec<Observation>,
}

/// A synthesized candidate — *suggestions* an admin reviews, never auto-applied policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearnedProfile {
    pub app_id: AppId,
    /// Parent directories of files the app wrote outside the Clave Disk — candidate
    /// [`FilePolicy::work_data_roots`](crate::policy::FilePolicy).
    pub work_data_roots: Vec<String>,
    /// The candidate launch profile (container HOME + a namespace prefix if it used named objects).
    pub launch: LaunchProfile,
}

impl LearnSession {
    pub fn new(app_id: AppId) -> Self {
        Self {
            app_id,
            observations: Vec::new(),
        }
    }

    /// Record one observed access (fed by the OS notify-mode hook / ES-notify client).
    pub fn record(&mut self, obs: Observation) {
        self.observations.push(obs);
    }

    pub fn len(&self) -> usize {
        self.observations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// Synthesize candidates from what was observed, relative to the Clave Disk at `mount_point`.
    /// Writes already inside the disk and reads are ignored; the rest yield work-data-root
    /// suggestions (deduped, sorted) plus a namespace prefix if any named object was seen.
    pub fn synthesize(&self, mount_point: &str) -> LearnedProfile {
        let mut work_data_roots: Vec<String> = Vec::new();
        let mut uses_named_objects = false;

        for obs in &self.observations {
            match obs {
                Observation::PathAccess { path, write: true } => {
                    // Already-contained writes need no redirection; only escapes do.
                    if !under(path, mount_point) {
                        if let Some(dir) = parent_dir(path) {
                            if !work_data_roots.iter().any(|r| r == dir) {
                                work_data_roots.push(dir.to_string());
                            }
                        }
                    }
                }
                Observation::PathAccess { write: false, .. } => {} // reads pass through by default
                Observation::NamedObject { .. } => uses_named_objects = true,
            }
        }
        work_data_roots.sort();

        let namespace_prefix = uses_named_objects.then(|| format!("Clave-{}\\", self.app_id.0));
        let launch = LaunchProfile {
            home_subdir: self.app_id.0.clone(),
            env: Vec::new(),
            namespace_prefix,
            hive_seed: None,
            passthrough_paths: Vec::new(),
        };
        LearnedProfile {
            app_id: self.app_id.clone(),
            work_data_roots,
            launch,
        }
    }
}

/// The directory portion of `path` (everything before the last `/` or `\`), or `None` for a
/// top-level path with no usable parent.
fn parent_dir(path: &str) -> Option<&str> {
    path.rfind(['/', '\\'])
        .map(|i| &path[..i])
        .filter(|d| !d.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::{classify_path, PathClass};
    use crate::policy::FilePolicy;

    fn write(path: &str) -> Observation {
        Observation::PathAccess {
            path: path.into(),
            write: true,
        }
    }

    #[test]
    fn synthesizes_work_data_roots_from_writes_only() {
        let mut s = LearnSession::new(AppId("acme".into()));
        s.record(write("/Users/alice/Documents/a.txt"));
        s.record(write("/Users/alice/Documents/b.txt")); // same dir → deduped
        s.record(write("/Users/alice/Library/Acme/state")); // a second dir
        s.record(Observation::PathAccess {
            path: "/usr/lib/x.dylib".into(),
            write: false,
        }); // a read → ignored
        s.record(write("/Volumes/ClaveDisk/profiles/acme/c")); // already inside → ignored

        let learned = s.synthesize("/Volumes/ClaveDisk");
        assert_eq!(
            learned.work_data_roots,
            vec![
                "/Users/alice/Documents".to_string(),
                "/Users/alice/Library/Acme".to_string()
            ]
        );
        assert_eq!(learned.launch.home_subdir, "acme");
        assert_eq!(learned.launch.namespace_prefix, None);
    }

    #[test]
    fn named_objects_suggest_a_namespace_prefix() {
        let mut s = LearnSession::new(AppId("acme".into()));
        s.record(Observation::NamedObject {
            name: "AcmeSingletonMutex".into(),
        });
        let learned = s.synthesize("/Volumes/ClaveDisk");
        assert_eq!(learned.launch.namespace_prefix.as_deref(), Some("Clave-acme\\"));
    }

    #[test]
    fn learned_roots_then_drive_classify_path() {
        // The loop closes: what learn mode discovers, applied as policy, makes classify_path
        // redirect the app's future writes into the enclave.
        let mut s = LearnSession::new(AppId("acme".into()));
        s.record(write("/Users/alice/Documents/a.txt"));
        let learned = s.synthesize("/Volumes/ClaveDisk");

        let files = FilePolicy {
            allow_save_outside_enclave: false,
            work_data_roots: learned.work_data_roots,
            cow_roots: Vec::new(),
        };
        assert_eq!(
            classify_path("/Users/alice/Documents/new.txt", "/Volumes/ClaveDisk", &[], &files),
            PathClass::WorkData
        );
    }
}
