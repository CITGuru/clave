use crate::policy::FilePolicy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathClass {
    WorkData,
    SystemCow,
    PassThrough,
}

fn is_windows_style(s: &str) -> bool {
    s.contains('\\')
        || (s.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && s.as_bytes().get(1) == Some(&b':'))
}

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
    path == prefix
        || path
            .strip_prefix(&prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub fn is_under_mount(path: &str, mount_point: &str) -> bool {
    under(path, mount_point)
}

pub fn classify_path(
    path: &str,
    mount_point: &str,
    passthrough: &[String],
    files: &FilePolicy,
) -> PathClass {
    if under(path, mount_point) {
        return PathClass::PassThrough;
    }
    if passthrough.iter().any(|p| under(path, p)) {
        return PathClass::PassThrough;
    }
    if files.work_data_roots.iter().any(|p| under(path, p)) {
        return PathClass::WorkData;
    }
    if files.cow_roots.iter().any(|p| under(path, p)) {
        return PathClass::SystemCow;
    }
    PathClass::PassThrough
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> FilePolicy {
        FilePolicy {
            allow_save_outside_enclave: false,
            work_data_roots: vec![
                "/Users/alice/Documents".into(),
                "C:\\Users\\alice\\Documents".into(),
            ],
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
            classify_path(
                "/Volumes/ClaveDisk/profiles/chrome-work/Prefs",
                MOUNT,
                &[],
                &files()
            ),
            PathClass::PassThrough
        );
    }

    #[test]
    fn explicit_passthrough_overrides_work_data() {
        let pass = vec!["/Users/alice/Documents/shared".to_string()];
        assert_eq!(
            classify_path(
                "/Users/alice/Documents/shared/logo.png",
                MOUNT,
                &pass,
                &files()
            ),
            PathClass::PassThrough
        );
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
        assert_eq!(
            classify_path("C:\\USERS\\ALICE\\DOCUMENTS\\q3.xlsx", "X:", &[], &files()),
            PathClass::WorkData
        );
    }

    #[test]
    fn windows_roots_match_across_separator_styles() {
        assert_eq!(
            classify_path("C:/Users/alice/Documents/q3.xlsx", "X:", &[], &files()),
            PathClass::WorkData
        );
    }

    #[test]
    fn unix_roots_stay_case_sensitive() {
        assert_eq!(
            classify_path("/USERS/alice/Documents/q3.xlsx", MOUNT, &[], &files()),
            PathClass::PassThrough
        );
    }

    #[test]
    fn prefix_match_respects_component_boundaries() {
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
