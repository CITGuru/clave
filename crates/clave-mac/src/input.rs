use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tapper {
    pub pid: u32,
    pub exe: String,
}

#[derive(Debug, Default)]
pub struct TapWatch {
    reported: HashSet<u32>,
}

impl TapWatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, tapping: &[Tapper], work_focused: bool) -> Vec<Tapper> {
        let live: HashSet<u32> = tapping.iter().map(|t| t.pid).collect();
        self.reported.retain(|pid| live.contains(pid));

        if !work_focused {
            return Vec::new();
        }
        tapping
            .iter()
            .filter(|t| self.reported.insert(t.pid))
            .cloned()
            .collect()
    }
}

#[cfg(target_os = "macos")]
pub use driver::{raw_keyboard_taps, run_input_watch};

#[cfg(target_os = "macos")]
mod driver {
    use super::{TapWatch, Tapper};
    use crate::clipboard::frontmost_app_pid;
    use clave_core::ZoneRegistry;
    use std::os::raw::c_void;
    use std::sync::Arc;
    use std::time::Duration;

    const POLL: Duration = Duration::from_millis(1000);

    const KEYBOARD_MASK: u64 = (1 << 10) | (1 << 11) | (1 << 12);

    #[repr(C)]
    struct CGEventTapInformation {
        event_tap_id: u32,
        tap_point: u32,
        options: u32,
        events_of_interest: u64,
        tapping_process: i32,
        _enabling_process: i32,
        _min_usec: f32,
        _avg_usec: f32,
        _max_usec: f32,
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGGetEventTapList(
            max: u32,
            tap_list: *mut CGEventTapInformation,
            count: *mut u32,
        ) -> c_void;
    }

    pub fn run_input_watch(zones: Arc<ZoneRegistry>, mut report: impl FnMut(&Tapper)) {
        let mut watch = TapWatch::new();
        loop {
            std::thread::sleep(POLL);

            let tapping = keyboard_tappers(&zones);
            let work_focused =
                frontmost_app_pid().is_some_and(|pid| zones.supervised_pids().contains(&pid));

            for tapper in watch.observe(&tapping, work_focused) {
                report(&tapper);
            }
        }
    }

    fn keyboard_tappers(zones: &ZoneRegistry) -> Vec<Tapper> {
        let supervised: std::collections::HashSet<u32> =
            zones.supervised_pids().into_iter().collect();
        let own = std::process::id();

        raw_keyboard_taps()
            .into_iter()
            .filter(|pid| *pid != own && !supervised.contains(pid))
            .filter_map(|pid| {
                Some(Tapper {
                    pid,
                    exe: exe_name(pid)?,
                })
            })
            .collect()
    }

    pub fn raw_keyboard_taps() -> Vec<u32> {
        unsafe {
            let mut count: u32 = 0;
            CGGetEventTapList(0, std::ptr::null_mut(), &mut count);
            if count == 0 {
                return Vec::new();
            }
            let mut taps: Vec<CGEventTapInformation> = Vec::with_capacity(count as usize);
            let mut written: u32 = 0;
            CGGetEventTapList(count, taps.as_mut_ptr(), &mut written);
            taps.set_len(written as usize);

            taps.iter()
                .filter(|t| t.events_of_interest & KEYBOARD_MASK != 0 && t.tapping_process > 0)
                .map(|t| t.tapping_process as u32)
                .collect()
        }
    }

    fn exe_name(pid: u32) -> Option<String> {
        let out = std::process::Command::new("ps")
            .args(["-o", "comm=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let path = String::from_utf8_lossy(&out.stdout);
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        Some(path.rsplit('/').next()?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tap(pid: u32, exe: &str) -> Tapper {
        Tapper {
            pid,
            exe: exe.to_string(),
        }
    }

    #[test]
    fn a_tap_while_a_work_app_is_focused_is_reported() {
        let mut w = TapWatch::new();
        assert_eq!(
            w.observe(&[tap(9, "keylogger")], true),
            vec![tap(9, "keylogger")]
        );
    }

    #[test]
    fn a_tap_with_no_work_app_focused_is_not_our_business() {
        let mut w = TapWatch::new();
        assert!(
            w.observe(&[tap(9, "keylogger")], false).is_empty(),
            "what a tapper reads from personal apps is not policed (doc 01)"
        );
    }

    #[test]
    fn a_persistent_tap_is_reported_once() {
        let mut w = TapWatch::new();
        let taps = [tap(9, "keylogger")];
        assert_eq!(w.observe(&taps, true).len(), 1);
        assert!(w.observe(&taps, true).is_empty());
        assert!(w.observe(&taps, true).is_empty());
    }

    #[test]
    fn a_dropped_and_recreated_tap_is_reported_again() {
        let mut w = TapWatch::new();
        assert_eq!(w.observe(&[tap(9, "keylogger")], true).len(), 1);
        assert!(w.observe(&[], true).is_empty());
        assert_eq!(w.observe(&[tap(9, "keylogger")], true).len(), 1);
    }

    #[test]
    fn an_exited_tapper_is_forgotten_so_a_recycled_pid_still_reports() {
        let mut w = TapWatch::new();
        assert_eq!(w.observe(&[tap(9, "a")], true).len(), 1);
        assert!(w.observe(&[], true).is_empty());
        assert_eq!(w.observe(&[tap(9, "b")], true).len(), 1);
    }
}
