#![cfg(target_os = "macos")]
#![allow(deprecated)]

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use cocoa::base::{id, nil};
use cocoa::foundation::{NSString, NSUInteger};
use objc::{class, msg_send, sel, sel_impl};

pub fn bundle_identifier(app_bundle: &Path) -> Option<String> {
    let plist = app_bundle.join("Contents/Info.plist");
    let out = Command::new("/usr/bin/plutil")
        .args(["-extract", "CFBundleIdentifier", "raw", "-o", "-"])
        .arg(plist)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!id.is_empty()).then_some(id)
}

pub fn running_pids_for_bundle(bundle_id: &str) -> Vec<u32> {
    unsafe {
        let nsid = NSString::alloc(nil).init_str(bundle_id);
        let apps: id = msg_send![
            class!(NSRunningApplication),
            runningApplicationsWithBundleIdentifier: nsid
        ];
        if apps == nil {
            return Vec::new();
        }
        let count: NSUInteger = msg_send![apps, count];
        let mut pids = Vec::with_capacity(count as usize);
        for i in 0..count {
            let app: id = msg_send![apps, objectAtIndex: i];
            let pid: i32 = msg_send![app, processIdentifier];
            if let Ok(pid) = u32::try_from(pid) {
                pids.push(pid);
            }
        }
        pids.sort_unstable();
        pids.dedup();
        pids
    }
}

pub fn wait_for_new_app_pid(
    app_bundle: &Path,
    exclude: &HashSet<u32>,
    timeout: Duration,
) -> Option<u32> {
    let bundle_id = bundle_identifier(app_bundle)?;
    let deadline = Instant::now() + timeout;
    loop {
        let current = running_pids_for_bundle(&bundle_id);
        if let Some(pid) = first_new(&current, exclude) {
            return Some(pid);
        }
        if Instant::now() >= deadline {
            return current.last().copied();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn first_new(current: &[u32], exclude: &HashSet<u32>) -> Option<u32> {
    current.iter().copied().find(|pid| !exclude.contains(pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finder_bundle_id_is_readable() {
        let id = bundle_identifier(Path::new("/System/Library/CoreServices/Finder.app"));
        assert_eq!(id.as_deref(), Some("com.apple.finder"));
    }

    #[test]
    fn the_new_instance_wins_over_a_preexisting_personal_one() {
        let preexisting = HashSet::from([100]);
        assert_eq!(first_new(&[100, 205], &preexisting), Some(205));
    }

    #[test]
    fn no_new_instance_yet_reports_none_so_the_wait_keeps_polling() {
        let preexisting = HashSet::from([100]);
        assert_eq!(first_new(&[100], &preexisting), None);
    }

    #[test]
    fn a_fresh_launch_with_nothing_preexisting_picks_the_only_instance() {
        assert_eq!(first_new(&[205], &HashSet::new()), Some(205));
    }
}
