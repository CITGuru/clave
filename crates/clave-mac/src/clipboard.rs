use clave_platform::{ClipFormat, Decision, Zone};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardAction {
    Nothing,
    ClearPasteboard,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Tagged {
    change_count: i64,
    formats: Vec<ClipFormat>,
}

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

    pub fn on_copy(&mut self, change_count: i64, by: Zone, formats: Vec<ClipFormat>) {
        self.tagged = match by {
            Zone::Work => Some(Tagged {
                change_count,
                formats,
            }),
            Zone::Personal => None,
        };
    }

    pub fn on_front(
        &mut self,
        front: Zone,
        change_count: i64,
        mut decide: impl FnMut(Zone, Zone, ClipFormat) -> Decision,
    ) -> GuardAction {
        if front == Zone::Work {
            return GuardAction::Nothing;
        }
        let Some(tagged) = &self.tagged else {
            return GuardAction::Nothing;
        };
        if tagged.change_count != change_count {
            self.tagged = None;
            return GuardAction::Nothing;
        }

        let decisions: Vec<Decision> = tagged
            .formats
            .iter()
            .map(|fmt| decide(Zone::Work, Zone::Personal, *fmt))
            .collect();

        if decisions.iter().any(|d| *d != Decision::Allow) {
            self.tagged = None;
            GuardAction::ClearPasteboard
        } else {
            GuardAction::Nothing
        }
    }
}

#[cfg(target_os = "macos")]
pub use driver::{frontmost_app_pid, run_clipboard_guard};

#[cfg(target_os = "macos")]
#[allow(deprecated)]
mod driver {
    use super::{ClipboardGuard, GuardAction};
    use clave_core::ZoneRegistry;
    use clave_platform::{ClipFormat, Decision, Zone};
    use cocoa::base::{id, nil};
    use cocoa::foundation::NSUInteger;
    use objc::{class, msg_send, sel, sel_impl};
    use std::sync::Arc;
    use std::time::Duration;

    const POLL: Duration = Duration::from_millis(200);

    pub fn run_clipboard_guard(
        zones: Arc<ZoneRegistry>,
        mut decide: impl FnMut(Zone, Zone, ClipFormat) -> Decision,
    ) {
        let mut guard = ClipboardGuard::new();
        let mut last_count = unsafe { change_count() };

        loop {
            std::thread::sleep(POLL);

            let front = frontmost_zone(&zones);
            let count = unsafe { change_count() };

            if count != last_count {
                last_count = count;
                guard.on_copy(count, front, unsafe { formats() });
            }

            if guard.on_front(front, count, &mut decide) == GuardAction::ClearPasteboard {
                last_count = unsafe { clear_pasteboard() };
                eprintln!(
                    "clave-mac: cleared a work-copied payload from the clipboard \
                     (work→personal denied by policy)"
                );
            }
        }
    }

    fn frontmost_zone(zones: &ZoneRegistry) -> Zone {
        match unsafe { frontmost_pid() } {
            Some(pid) if zones.supervised_pids().contains(&pid) => Zone::Work,
            _ => Zone::Personal,
        }
    }

    unsafe fn general_pasteboard() -> id {
        msg_send![class!(NSPasteboard), generalPasteboard]
    }

    unsafe fn change_count() -> i64 {
        msg_send![general_pasteboard(), changeCount]
    }

    unsafe fn clear_pasteboard() -> i64 {
        msg_send![general_pasteboard(), clearContents]
    }

    pub fn frontmost_app_pid() -> Option<u32> {
        unsafe { frontmost_pid() }
    }

    unsafe fn frontmost_pid() -> Option<u32> {
        let workspace: id = msg_send![class!(NSWorkspace), sharedWorkspace];
        let app: id = msg_send![workspace, frontmostApplication];
        if app == nil {
            return None;
        }
        let pid: i32 = msg_send![app, processIdentifier];
        u32::try_from(pid).ok()
    }

    unsafe fn formats() -> Vec<ClipFormat> {
        let types: id = msg_send![general_pasteboard(), types];
        if types == nil {
            return Vec::new();
        }
        let count: NSUInteger = msg_send![types, count];
        let mut out: Vec<ClipFormat> = Vec::new();
        for i in 0..count {
            let ty: id = msg_send![types, objectAtIndex: i];
            let utf8: *const std::os::raw::c_char = msg_send![ty, UTF8String];
            if utf8.is_null() {
                continue;
            }
            let uti = std::ffi::CStr::from_ptr(utf8).to_string_lossy();
            let fmt = classify_uti(&uti);
            if !out.contains(&fmt) {
                out.push(fmt);
            }
        }
        out
    }

    fn classify_uti(uti: &str) -> ClipFormat {
        match uti {
            "public.utf8-plain-text" | "public.plain-text" | "NSStringPboardType" => {
                ClipFormat::PlainText
            }
            "public.rtf" | "NeXT Rich Text Format v1.0 pasteboard type" => ClipFormat::RichText,
            "public.html" | "Apple HTML pasteboard type" => ClipFormat::Html,
            "public.tiff" | "public.png" | "public.jpeg" | "NSTIFFPboardType" => ClipFormat::Image,
            "public.file-url" | "NSFilenamesPboardType" => ClipFormat::Files,
            _ => ClipFormat::Other,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn utis_map_onto_policy_format_classes() {
            assert_eq!(
                classify_uti("public.utf8-plain-text"),
                ClipFormat::PlainText
            );
            assert_eq!(classify_uti("public.rtf"), ClipFormat::RichText);
            assert_eq!(classify_uti("public.html"), ClipFormat::Html);
            assert_eq!(classify_uti("public.png"), ClipFormat::Image);
            assert_eq!(classify_uti("public.file-url"), ClipFormat::Files);
            assert_eq!(classify_uti("NSFilenamesPboardType"), ClipFormat::Files);
            assert_eq!(classify_uti("com.acme.private"), ClipFormat::Other);
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
    fn work_copy_then_personal_app_clears_the_pasteboard() {
        let mut g = ClipboardGuard::new();
        g.on_copy(1, Zone::Work, vec![ClipFormat::PlainText]);
        assert!(g.holds_work_payload());

        assert_eq!(
            g.on_front(Zone::Personal, 1, deny_work_to_personal),
            GuardAction::ClearPasteboard
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
        g.on_copy(
            1,
            Zone::Work,
            vec![ClipFormat::PlainText, ClipFormat::Files],
        );
        let allow_text_only = |_: Zone, _: Zone, fmt: ClipFormat| match fmt {
            ClipFormat::PlainText => Decision::Allow,
            _ => Decision::Deny,
        };
        assert_eq!(
            g.on_front(Zone::Personal, 1, allow_text_only),
            GuardAction::ClearPasteboard
        );
    }

    #[test]
    fn every_format_is_reported_for_audit() {
        let mut g = ClipboardGuard::new();
        g.on_copy(
            1,
            Zone::Work,
            vec![ClipFormat::Files, ClipFormat::Image, ClipFormat::PlainText],
        );
        let mut seen = Vec::new();
        g.on_front(Zone::Personal, 1, |_, _, fmt| {
            seen.push(fmt);
            Decision::Deny
        });
        assert_eq!(
            seen,
            vec![ClipFormat::Files, ClipFormat::Image, ClipFormat::PlainText]
        );
    }
}
