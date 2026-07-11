//! Filesystem-path classification for app virtualization.
//!
//! The portable, OS-free decision the file-redirection layers consult: the Windows user-mode
//! `Nt*` FS hook (to remap a path) and — read the same way — the macOS ES file gate. Given a path
//! a *supervised* app is touching, decide whether it is **work data** (redirect into the encrypted
//! Clave Disk), **system data it writes** (copy-on-write so the base system is untouched), or
//! **pass-through** (leave it alone). It is the filesystem analog of
//! [`classify_flow`](crate::net) and [`classify_exec`](crate::app).
//!
//! This classifier is *app-compat*, not the security boundary: an unknown path defaults to
//! pass-through, and if a supervised app then writes work data somewhere unredirected, the
//! authoritative gate ([`decide`](crate::decide) on `FileOpen`, backed by the kernel
//! minifilter / ES `AUTH_OPEN`) still denies the escape. "Hooks make it work; the
//! kernel makes it safe."

use crate::policy::FilePolicy;

/// How a supervised app's path access should be handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathClass {
    /// Work data — redirect into the Clave Disk (it persists encrypted).
    WorkData,
    /// A system path the app writes to — copy-on-write so the base system is never mutated.
    SystemCow,
    /// Leave the path unchanged (already inside the enclave, an explicit pass-through, or unknown).
    PassThrough,
}

/// Whether the configured `prefix` looks like a Windows path — a drive-letter root (`C:`) or any
/// backslash separator. Windows filesystems compare paths case-insensitively, so a root configured
/// this way must match regardless of case; Unix-style roots stay case-sensitive.
fn is_windows_style(s: &str) -> bool {
    s.contains('\\')
        || (s.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && s.as_bytes().get(1) == Some(&b':'))
}

/// Whether `path` is at or under `prefix`, on a path-component boundary (so `/Users/alice` does
/// **not** match `/Users/alice-other`). Accepts both `/` and `\` separators interchangeably (so
/// `C:/Users` and `C:\Users` are the same), and folds ASCII case for Windows-style roots (so
/// `C:\USERS\...` is not a redirection bypass). An empty prefix never matches.
///
/// Unix roots stay case-sensitive by default; a case-insensitive macOS volume is a possible future
/// refinement, but the concrete bypass here was Windows, where case-insensitivity is the rule.
pub(crate) fn under(path: &str, prefix: &str) -> bool {
    let fold = is_windows_style(prefix);
    let norm = |s: &str| -> String {
        let s = s.replace('\\', "/");
        let s = s.trim_end_matches('/');
        if fold {
            s.to_ascii_lowercase()
        } else {
            s.to_string()
        }
    };
    let prefix = norm(prefix);
    if prefix.is_empty() {
        return false;
    }
    let path = norm(path);
    path == prefix || path.strip_prefix(&prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// Classify a path a supervised work app is accessing. `mount_point` is where the
/// Clave Disk is mounted; `passthrough` is the app's [`LaunchProfile`](crate::LaunchProfile)
/// pass-through list; `files` carries the work-data / COW roots.
///
/// Precedence: already-inside-the-disk → explicit pass-through → work-data root → COW root →
/// default pass-through.
pub fn classify_path(
    path: &str,
    mount_point: &str,
    passthrough: &[String],
    files: &FilePolicy,
) -> PathClass {
    // Already inside the encrypted volume — nothing to redirect (the access gate guards it).
    if under(path, mount_point) {
        return PathClass::PassThrough;
    }
    // Explicit per-app pass-throughs win over redirection.
    if passthrough.iter().any(|p| under(path, p)) {
        return PathClass::PassThrough;
    }
    // Work-data locations redirect into the encrypted volume.
    if files.work_data_roots.iter().any(|p| under(path, p)) {
        return PathClass::WorkData;
    }
    // System paths the app writes to get copy-on-write.
    if files.cow_roots.iter().any(|p| under(path, p)) {
        return PathClass::SystemCow;
    }
    // Unknown: leave it alone — the minifilter / ES gate is the security backstop.
    PathClass::PassThrough
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> FilePolicy {
        FilePolicy {
            allow_save_outside_enclave: false,
            work_data_roots: vec!["/Users/alice/Documents".into(), "C:\\Users\\alice\\Documents".into()],
            cow_roots: vec!["C:\\ProgramData\\Acme".into()],
        }
    }

    const MOUNT: &str = "/Volumes/ClaveDisk";

    #[test]
    fn work_data_paths_redirect_into_the_enclave() {
        assert_eq!(
            classify_path("/Users/alice/Documents/q3.xlsx", MOUNT, &[], &files()),
            PathClass::WorkData
        );
    }

    #[test]
    fn cow_paths_are_copy_on_write() {
        assert_eq!(
            classify_path("C:\\ProgramData\\Acme\\config.ini", "X:", &[], &files()),
            PathClass::SystemCow
        );
    }

    #[test]
    fn paths_already_inside_the_disk_pass_through() {
        assert_eq!(
            classify_path("/Volumes/ClaveDisk/profiles/chrome-work/Prefs", MOUNT, &[], &files()),
            PathClass::PassThrough
        );
    }

    #[test]
    fn explicit_passthrough_overrides_work_data() {
        let pass = vec!["/Users/alice/Documents/shared".to_string()];
        assert_eq!(
            classify_path("/Users/alice/Documents/shared/logo.png", MOUNT, &pass, &files()),
            PathClass::PassThrough
        );
        // ...but a sibling that isn't pass-through is still work data.
        assert_eq!(
            classify_path("/Users/alice/Documents/secret.txt", MOUNT, &pass, &files()),
            PathClass::WorkData
        );
    }

    #[test]
    fn unknown_paths_pass_through() {
        assert_eq!(
            classify_path("/usr/lib/libSystem.dylib", MOUNT, &[], &files()),
            PathClass::PassThrough
        );
    }

    #[test]
    fn windows_roots_match_case_insensitively() {
        // A miscased Windows path must still classify as work data — byte-exact matching let
        // `C:\USERS\ALICE\DOCUMENTS\...` escape redirection (dropping encryption-at-rest).
        assert_eq!(
            classify_path("C:\\USERS\\ALICE\\DOCUMENTS\\q3.xlsx", "X:", &[], &files()),
            PathClass::WorkData
        );
    }

    #[test]
    fn windows_roots_match_across_separator_styles() {
        // Win32 accepts forward slashes; `C:/Users/...` must match a `C:\Users\...` root.
        assert_eq!(
            classify_path("C:/Users/alice/Documents/q3.xlsx", "X:", &[], &files()),
            PathClass::WorkData
        );
    }

    #[test]
    fn unix_roots_stay_case_sensitive() {
        // Unix/macOS roots are treated case-sensitively (the Windows case-fold is scoped to
        // Windows-style roots); a miscased Unix path does not spuriously match.
        assert_eq!(
            classify_path("/USERS/alice/Documents/q3.xlsx", MOUNT, &[], &files()),
            PathClass::PassThrough
        );
    }

    #[test]
    fn prefix_match_respects_component_boundaries() {
        // `/Users/alice-other` must not be captured by the `/Users/alice/Documents` root, and a
        // bare sibling of a root is not under it.
        assert_eq!(
            classify_path("/Users/alice-other/Documents/x", MOUNT, &[], &files()),
            PathClass::PassThrough
        );
        assert_eq!(
            classify_path("/Users/alice/DocumentsExtra/x", MOUNT, &[], &files()),
            PathClass::PassThrough
        );
    }
}
