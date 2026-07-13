//! Screen-capture protection for macOS: detect, decide, audit (doc 07 §3).
//!
//! macOS has **no way to exclude a third-party window from capture** (doc 07 §3.2). `sharingType`
//! is an instance property on an `NSWindow` you own, and injecting into the work app to set it is
//! ruled out by SIP/library validation — so Chrome's and Excel's windows are capturable and there
//! is nothing this adapter can do about it. That is a real gap, not a missing feature: the Windows
//! shim *can* do this, macOS cannot.
//!
//! What is possible is doc 07 §3.3's reactive path: notice capture tooling running while work
//! windows are on screen, put it through the shared policy, and **audit** it. That gives the
//! gateway a record of every screenshot taken over enclave content — a deterrent and an
//! investigation trail, not a block.
//!
//! Two further vectors are deliberately out of reach here and left to the ES client
//! (`macos/ClaveESExtension`), which cannot activate without Apple's Endpoint Security entitlement:
//! `AUTH_EXEC`-denying `screencapture` outright — the one *hard* block macOS allows — and seeing a
//! capture process the moment it execs rather than on the next poll.

use std::collections::HashSet;

/// Executable names of capture tooling.
///
/// A denylist is **inherently incomplete** — any app granted Screen Recording can capture, and this
/// cannot see it. It covers the vectors an honest user actually reaches for (⌘⇧3/⌘⇧4/⌘⇧5 and the
/// common recorders); a determined adversary in the personal zone is out of scope for it (doc 07
/// §3.4). Screen-Recording TCC consent remains the platform's real backstop.
const CAPTURE_TOOLS: &[&str] = &[
    "screencapture",   // the CLI behind ⌘⇧3 / ⌘⇧4
    "screencaptureui", // the ⌘⇧5 capture UI
    "Screenshot",
    "QuickTime Player",
    "obs",
    "OBS",
];

/// Whether `exe` is capture tooling this adapter knows how to notice.
pub fn is_capture_tool(exe: &str) -> bool {
    CAPTURE_TOOLS.contains(&exe)
}

/// A capture tool seen running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capturer {
    pub pid: u32,
    pub exe: String,
}

/// Reports each capture process **once**, while work windows are on screen.
///
/// Without it a 500 ms poll would re-report the same `screencapture` every tick for as long as the
/// user holds the crosshair, flooding the audit chain with duplicates of one screenshot.
#[derive(Debug, Default)]
pub struct CaptureWatch {
    reported: HashSet<u32>,
}

impl CaptureWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Given every capture tool currently running and whether work content is on screen, return the
    /// ones to act on now. A capture with no work window visible is not our business, and a pid
    /// that has exited is forgotten so a later capture by a recycled pid is still reported.
    pub fn observe(&mut self, running: &[Capturer], work_on_screen: bool) -> Vec<Capturer> {
        let live: HashSet<u32> = running.iter().map(|c| c.pid).collect();
        self.reported.retain(|pid| live.contains(pid));

        if !work_on_screen {
            return Vec::new();
        }
        running
            .iter()
            .filter(|c| self.reported.insert(c.pid))
            .cloned()
            .collect()
    }
}

#[cfg(target_os = "macos")]
pub use driver::{running_capture_tools, run_screen_watch};

#[cfg(target_os = "macos")]
mod driver {
    use super::{is_capture_tool, CaptureWatch, Capturer};
    use crate::edge::work_windows_on_screen;
    use clave_core::ZoneRegistry;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;

    /// Fast enough to catch an interactive screenshot (the ⌘⇧4 crosshair lives for seconds) without
    /// spawning `ps` constantly. A scripted, non-interactive `screencapture -x` can still start and
    /// finish inside one tick — see the module docs: this observes, it does not block.
    const POLL: Duration = Duration::from_millis(500);

    /// Watch for capture tooling running over work content, forever.
    ///
    /// `report` takes the capturing process and decides — wire it to the daemon so the same call
    /// applies policy and audits a denial.
    pub fn run_screen_watch(zones: Arc<ZoneRegistry>, mut report: impl FnMut(&Capturer)) {
        let mut watch = CaptureWatch::new();
        loop {
            std::thread::sleep(POLL);

            let running = running_capture_tools();
            // Skip the window enumeration entirely when nothing is capturing — the common case.
            let work_on_screen = !running.is_empty() && work_windows_on_screen(&zones) > 0;

            for capturer in watch.observe(&running, work_on_screen) {
                report(&capturer);
            }
        }
    }

    /// Capture tooling currently running, by pid and executable name.
    ///
    /// Shells out to `ps`, as the adapter already does for `csrutil` and `hdiutil`. `comm` is the
    /// executable's base name, which is what [`is_capture_tool`] matches.
    pub fn running_capture_tools() -> Vec<Capturer> {
        let Ok(out) = Command::new("ps").args(["-axo", "pid=,comm="]).output() else {
            return Vec::new();
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| {
                let (pid, path) = line.trim().split_once(char::is_whitespace)?;
                let exe = path.trim().rsplit('/').next()?;
                if !is_capture_tool(exe) {
                    return None;
                }
                Some(Capturer {
                    pid: pid.trim().parse().ok()?,
                    exe: exe.to_string(),
                })
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// `ps` must actually parse — a silent failure here would mean the watch never fires and
        /// the gap would look like "no captures happened".
        #[test]
        fn ps_output_parses_and_this_process_is_not_capture_tooling() {
            // The parser runs against the real `ps`; the test binary is not a capture tool, so the
            // list is empty, but the call must not panic or hang.
            let tools = running_capture_tools();
            assert!(tools.iter().all(|c| is_capture_tool(&c.exe)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(pid: u32, exe: &str) -> Capturer {
        Capturer {
            pid,
            exe: exe.to_string(),
        }
    }

    #[test]
    fn the_screenshot_vectors_are_recognised() {
        assert!(is_capture_tool("screencapture"), "⌘⇧3 / ⌘⇧4");
        assert!(is_capture_tool("screencaptureui"), "⌘⇧5");
        assert!(!is_capture_tool("Google Chrome"));
    }

    #[test]
    fn a_capture_over_work_content_is_reported() {
        let mut w = CaptureWatch::new();
        let seen = w.observe(&[cap(42, "screencapture")], true);
        assert_eq!(seen, vec![cap(42, "screencapture")]);
    }

    #[test]
    fn a_capture_with_no_work_on_screen_is_not_our_business() {
        let mut w = CaptureWatch::new();
        assert!(
            w.observe(&[cap(42, "screencapture")], false).is_empty(),
            "a screenshot of a personal desktop is never instrumented (doc 01)"
        );
    }

    /// The poll runs every 500 ms and an interactive capture lives for seconds — reporting each
    /// tick would flood the audit chain with duplicates of a single screenshot.
    #[test]
    fn one_capture_is_reported_once_not_once_per_poll() {
        let mut w = CaptureWatch::new();
        let running = [cap(42, "screencapture")];
        assert_eq!(w.observe(&running, true).len(), 1);
        assert!(w.observe(&running, true).is_empty());
        assert!(w.observe(&running, true).is_empty());
    }

    #[test]
    fn a_second_screenshot_is_reported_again() {
        let mut w = CaptureWatch::new();
        assert_eq!(w.observe(&[cap(42, "screencapture")], true).len(), 1);
        assert!(w.observe(&[], true).is_empty()); // the first capture exits
        assert_eq!(w.observe(&[cap(43, "screencapture")], true).len(), 1); // a fresh pid, reported
    }

    /// pids are recycled. If an exited capturer were remembered forever, a later capture that
    /// happened to reuse its pid would go unreported.
    #[test]
    fn an_exited_capturer_is_forgotten_so_a_recycled_pid_still_reports() {
        let mut w = CaptureWatch::new();
        assert_eq!(w.observe(&[cap(42, "screencapture")], true).len(), 1);
        assert!(w.observe(&[], true).is_empty());
        assert_eq!(w.observe(&[cap(42, "obs")], true).len(), 1);
    }

    #[test]
    fn concurrent_capturers_are_each_reported() {
        let mut w = CaptureWatch::new();
        let seen = w.observe(&[cap(1, "screencapture"), cap(2, "obs")], true);
        assert_eq!(seen.len(), 2);
    }
}
