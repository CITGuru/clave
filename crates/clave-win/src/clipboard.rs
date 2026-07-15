use clave_platform::{ClipFormat, Decision, Zone};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardAction {
    Nothing,
    ClearClipboard,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Tagged {
    sequence: i64,
    formats: Vec<ClipFormat>,
}

/// The portable clipboard-guard state machine: it tags a payload copied while a work app owns
/// the foreground and decides whether to clear it once a personal app takes over. Pure and
/// OS-agnostic so it is fully unit-testable; the Win32 polling that drives it lives in `driver`.
#[derive(Debug, Default)]
pub struct ClipboardGuard {
    tagged: Option<Tagged>,
}

impl ClipboardGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn holds_work_payload(&self) -> bool {
        self.tagged.is_some()
    }

    pub fn on_copy(&mut self, sequence: i64, by: Zone, formats: Vec<ClipFormat>) {
        self.tagged = match by {
            Zone::Work => Some(Tagged { sequence, formats }),
            Zone::Personal => None,
        };
    }

    pub fn on_front(
        &mut self,
        front: Zone,
        sequence: i64,
        mut decide: impl FnMut(Zone, Zone, ClipFormat) -> Decision,
    ) -> GuardAction {
        if front == Zone::Work {
            return GuardAction::Nothing;
        }
        let Some(tagged) = &self.tagged else {
            return GuardAction::Nothing;
        };
        // If the clipboard changed since we tagged it, the payload is no longer ours to clear.
        if tagged.sequence != sequence {
            self.tagged = None;
            return GuardAction::Nothing;
        }

        let denied = tagged
            .formats
            .iter()
            .map(|fmt| decide(Zone::Work, Zone::Personal, *fmt))
            .any(|d| d != Decision::Allow);

        if denied {
            self.tagged = None;
            GuardAction::ClearClipboard
        } else {
            GuardAction::Nothing
        }
    }
}

#[cfg(windows)]
pub use driver::run_clipboard_guard;

#[cfg(windows)]
#[allow(unsafe_code)]
mod driver {
    use super::{ClipboardGuard, GuardAction};
    use clave_core::ZoneRegistry;
    use clave_platform::{ClipFormat, Decision, Zone};
    use std::sync::Arc;
    use std::time::Duration;
    use windows::core::w;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, EnumClipboardFormats, GetClipboardSequenceNumber,
        OpenClipboard, RegisterClipboardFormatW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

    const POLL: Duration = Duration::from_millis(200);

    // Standard clipboard format IDs (stable Win32 values; see `winuser.h`).
    const CF_TEXT: u32 = 1;
    const CF_BITMAP: u32 = 2;
    const CF_DIB: u32 = 8;
    const CF_UNICODETEXT: u32 = 13;
    const CF_HDROP: u32 = 15;
    const CF_DIBV5: u32 = 17;

    /// Polls the clipboard and the foreground window's owning process, tags a payload copied by a
    /// supervised (work) app, and empties the clipboard when a personal app takes the foreground
    /// and policy denies the work→personal transfer. A real control — `EmptyClipboard` genuinely
    /// removes the data — but poll-based, so a paste inside the poll window can still win (the
    /// leak window is narrowed, not closed; the delayed-render broker in doc 05 §2 closes it).
    pub fn run_clipboard_guard(
        zones: Arc<ZoneRegistry>,
        mut decide: impl FnMut(Zone, Zone, ClipFormat) -> Decision,
    ) {
        let mut guard = ClipboardGuard::new();
        let mut last = sequence();

        loop {
            std::thread::sleep(POLL);

            let front = frontmost_zone(&zones);
            let seq = sequence();

            if seq != last {
                last = seq;
                guard.on_copy(seq, front, formats());
            }

            if guard.on_front(front, seq, &mut decide) == GuardAction::ClearClipboard {
                clear_clipboard();
                last = sequence();
                eprintln!(
                    "clave-win: cleared a work-copied payload from the clipboard \
                     (work→personal denied by policy)"
                );
            }
        }
    }

    fn sequence() -> i64 {
        unsafe { GetClipboardSequenceNumber() as i64 }
    }

    fn frontmost_zone(zones: &ZoneRegistry) -> Zone {
        match foreground_pid() {
            Some(pid) if zones.supervised_pids().contains(&pid) => Zone::Work,
            _ => Zone::Personal,
        }
    }

    fn foreground_pid() -> Option<u32> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return None;
            }
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            (pid != 0).then_some(pid)
        }
    }

    fn formats() -> Vec<ClipFormat> {
        let mut out = Vec::new();
        unsafe {
            if OpenClipboard(None).is_err() {
                return out;
            }
            let html = RegisterClipboardFormatW(w!("HTML Format"));
            let rtf = RegisterClipboardFormatW(w!("Rich Text Format"));

            let mut fmt = EnumClipboardFormats(0);
            while fmt != 0 {
                let class = classify_format(fmt, html, rtf);
                if !out.contains(&class) {
                    out.push(class);
                }
                fmt = EnumClipboardFormats(fmt);
            }
            let _ = CloseClipboard();
        }
        out
    }

    fn classify_format(fmt: u32, html: u32, rtf: u32) -> ClipFormat {
        match fmt {
            CF_UNICODETEXT | CF_TEXT => ClipFormat::PlainText,
            CF_HDROP => ClipFormat::Files,
            CF_BITMAP | CF_DIB | CF_DIBV5 => ClipFormat::Image,
            f if html != 0 && f == html => ClipFormat::Html,
            f if rtf != 0 && f == rtf => ClipFormat::RichText,
            _ => ClipFormat::Other,
        }
    }

    fn clear_clipboard() {
        unsafe {
            if OpenClipboard(None).is_ok() {
                let _ = EmptyClipboard();
                let _ = CloseClipboard();
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn standard_formats_map_onto_policy_classes() {
            assert_eq!(classify_format(CF_UNICODETEXT, 0, 0), ClipFormat::PlainText);
            assert_eq!(classify_format(CF_TEXT, 0, 0), ClipFormat::PlainText);
            assert_eq!(classify_format(CF_HDROP, 0, 0), ClipFormat::Files);
            assert_eq!(classify_format(CF_DIB, 0, 0), ClipFormat::Image);
            assert_eq!(classify_format(0xC1FF, 0xC1FF, 0), ClipFormat::Html);
            assert_eq!(classify_format(0xC200, 0, 0xC200), ClipFormat::RichText);
            assert_eq!(classify_format(0xDEAD, 0xC1FF, 0xC200), ClipFormat::Other);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny_work_to_personal(src: Zone, dst: Zone, _fmt: ClipFormat) -> Decision {
        match (src, dst) {
            (Zone::Work, Zone::Personal) => Decision::Deny,
            _ => Decision::Allow,
        }
    }

    fn allow_all(_: Zone, _: Zone, _: ClipFormat) -> Decision {
        Decision::Allow
    }

    #[test]
    fn work_copy_then_personal_app_clears_the_clipboard() {
        let mut g = ClipboardGuard::new();
        g.on_copy(1, Zone::Work, vec![ClipFormat::PlainText]);
        assert!(g.holds_work_payload());

        assert_eq!(
            g.on_front(Zone::Personal, 1, deny_work_to_personal),
            GuardAction::ClearClipboard
        );
        assert!(!g.holds_work_payload());
        assert_eq!(
            g.on_front(Zone::Personal, 1, deny_work_to_personal),
            GuardAction::Nothing
        );
    }

    #[test]
    fn work_to_work_is_never_touched() {
        let mut g = ClipboardGuard::new();
        g.on_copy(1, Zone::Work, vec![ClipFormat::Files]);
        assert_eq!(
            g.on_front(Zone::Work, 1, deny_work_to_personal),
            GuardAction::Nothing,
            "copying between work apps is normal productivity"
        );
        assert!(g.holds_work_payload(), "and the payload stays available");
    }

    #[test]
    fn a_personal_copy_is_never_tagged_or_cleared() {
        let mut g = ClipboardGuard::new();
        g.on_copy(1, Zone::Personal, vec![ClipFormat::PlainText]);
        assert!(!g.holds_work_payload());
        assert_eq!(
            g.on_front(Zone::Personal, 1, deny_work_to_personal),
            GuardAction::Nothing,
            "the user's own clipboard is not our business (doc 05 §1)"
        );
    }

    #[test]
    fn a_personal_copy_replaces_a_work_payload_and_drops_the_tag() {
        let mut g = ClipboardGuard::new();
        g.on_copy(1, Zone::Work, vec![ClipFormat::PlainText]);
        g.on_copy(2, Zone::Personal, vec![ClipFormat::PlainText]);
        assert!(!g.holds_work_payload());
        assert_eq!(
            g.on_front(Zone::Personal, 2, deny_work_to_personal),
            GuardAction::Nothing,
            "clearing here would destroy the user's own clipboard"
        );
    }

    #[test]
    fn a_stale_tag_is_dropped_rather_than_clearing_someone_elses_payload() {
        let mut g = ClipboardGuard::new();
        g.on_copy(1, Zone::Work, vec![ClipFormat::PlainText]);
        assert_eq!(
            g.on_front(Zone::Personal, 7, deny_work_to_personal),
            GuardAction::Nothing
        );
        assert!(!g.holds_work_payload());
    }

    #[test]
    fn policy_may_permit_a_format_across_the_boundary() {
        let mut g = ClipboardGuard::new();
        g.on_copy(1, Zone::Work, vec![ClipFormat::PlainText]);
        assert_eq!(
            g.on_front(Zone::Personal, 1, allow_all),
            GuardAction::Nothing,
            "a policy that allows plain text work→personal must not have it cleared"
        );
    }

    #[test]
    fn one_denied_format_clears_a_multi_format_payload() {
        let mut g = ClipboardGuard::new();
        g.on_copy(1, Zone::Work, vec![ClipFormat::PlainText, ClipFormat::Files]);
        let allow_text_only = |_: Zone, _: Zone, fmt: ClipFormat| match fmt {
            ClipFormat::PlainText => Decision::Allow,
            _ => Decision::Deny,
        };
        assert_eq!(
            g.on_front(Zone::Personal, 1, allow_text_only),
            GuardAction::ClearClipboard
        );
    }
}
