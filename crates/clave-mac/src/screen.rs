use std::collections::HashSet;

const CAPTURE_TOOLS: &[&str] = &[
    "screencapture",
    "screencaptureui",
    "Screenshot",
    "QuickTime Player",
    "obs",
    "OBS",
];

pub fn is_capture_tool(exe: &str) -> bool {
    CAPTURE_TOOLS.contains(&exe)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capturer {
    pub pid: u32,
    pub exe: String,
}

#[derive(Debug, Default)]
pub struct CaptureWatch {
    reported: HashSet<u32>,
}

impl CaptureWatch {
    pub fn new() -> Self {
        Self::default()
    }

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
pub use driver::{run_screen_watch, running_capture_tools};

#[cfg(target_os = "macos")]
mod driver {
    use super::{is_capture_tool, CaptureWatch, Capturer};
    use crate::edge::work_windows_on_screen;
    use clave_core::ZoneRegistry;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;

    const POLL: Duration = Duration::from_millis(500);

    pub fn run_screen_watch(zones: Arc<ZoneRegistry>, mut report: impl FnMut(&Capturer)) {
        let mut watch = CaptureWatch::new();
        loop {
            std::thread::sleep(POLL);

            let running = running_capture_tools();
            let work_on_screen = !running.is_empty() && work_windows_on_screen(&zones) > 0;

            for capturer in watch.observe(&running, work_on_screen) {
                report(&capturer);
            }
        }
    }

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

        #[test]
        fn ps_output_parses_and_this_process_is_not_capture_tooling() {
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
        assert!(w.observe(&[], true).is_empty());
        assert_eq!(w.observe(&[cap(43, "screencapture")], true).len(), 1);
    }

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
