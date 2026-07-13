//! Clipboard DLP for macOS: monitor, tag, reactive-clear, audit (doc 05 §3).
//!
//! macOS has no supported way to intercept a paste — `NSPasteboard` exposes no "before paste"
//! callback, and SIP/library validation rules out injecting a gate into the pasting app. So this is
//! **deliberately not a hard control** (doc 05 §3.3): it polls the general pasteboard, tags a
//! payload copied by a work app, and clears it when a personal app comes to the front and policy
//! denies the transfer. A paste timed inside the poll window still wins the race — the leak window
//! is narrowed, not closed — so every observed work→personal transition is audited whether or not
//! the clear beat the paste.
//!
//! [`ClipboardGuard`] holds that logic with no AppKit involved, so the state machine is tested
//! directly; [`run_clipboard_guard`] is the polling driver that feeds it. The *decision* is never
//! made here — it comes from `clave-core`'s `clip_decision` via the `decide` callback, so macOS and
//! Windows enforce one policy.

use clave_platform::{ClipFormat, Decision, Zone};

/// What the guard wants the OS layer to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardAction {
    Nothing,
    /// A work-tagged payload is exposed to a personal app and policy denies at least one of its
    /// formats — clear the general pasteboard.
    ClearPasteboard,
}

/// A payload copied by a work app, pinned to the pasteboard generation it arrived on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Tagged {
    /// `NSPasteboard.changeCount` at the copy. If the live count has moved past this, the payload
    /// is gone and the tag is stale.
    change_count: i64,
    formats: Vec<ClipFormat>,
}

/// Tracks whether the pasteboard currently holds work-copied data, and decides when to clear it.
#[derive(Debug, Default)]
pub struct ClipboardGuard {
    tagged: Option<Tagged>,
}

impl ClipboardGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the pasteboard currently holds a payload copied by a work app.
    pub fn holds_work_payload(&self) -> bool {
        self.tagged.is_some()
    }

    /// A new payload landed on the pasteboard. `by` is the zone of the frontmost app, which is who
    /// copied it. A personal copy clears any tag — its payload replaced the work one.
    pub fn on_copy(&mut self, change_count: i64, by: Zone, formats: Vec<ClipFormat>) {
        self.tagged = match by {
            Zone::Work => Some(Tagged {
                change_count,
                formats,
            }),
            Zone::Personal => None,
        };
    }

    /// The frontmost app is now in `front`, with the pasteboard at generation `change_count`.
    ///
    /// `decide` answers a single (src, dst, format) transfer — wire it to the daemon so the same
    /// call both applies policy and audits a denial. It is consulted for **every** format of a
    /// work-tagged payload, so the audit records each denied format, not just the first.
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
        // The payload the tag refers to is gone; nothing of ours is exposed.
        if tagged.change_count != change_count {
            self.tagged = None;
            return GuardAction::Nothing;
        }

        // Collected, not short-circuited: `decide` is also the audit hook, so every format must be
        // offered even once one has already been denied.
        let decisions: Vec<Decision> = tagged
            .formats
            .iter()
            .map(|fmt| decide(Zone::Work, Zone::Personal, *fmt))
            .collect();

        if decisions.iter().any(|d| *d != Decision::Allow) {
            // Clearing bumps the change count, so the tag can never match again.
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
// The `cocoa` crate is deprecated in favour of `objc2`; `edge.rs` already carries this allow, and
// migrating both is its own change.
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

    /// Doc 05 §3.2's 150–300 ms band: short enough that an app switch is caught at human speed,
    /// long enough not to spin.
    const POLL: Duration = Duration::from_millis(200);

    /// Poll the general pasteboard and the frontmost app forever, driving [`ClipboardGuard`].
    ///
    /// Runs on its own thread — the Clave Edge overlay owns the main thread (AppKit is
    /// main-thread-only), and these reads do not require it.
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

    /// A supervised (work-zone) frontmost app means the copy came from, or the paste is going to,
    /// the enclave. Anything else — including no frontmost app — is personal.
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

    /// Clear the pasteboard, returning the new change count (clearing bumps it).
    unsafe fn clear_pasteboard() -> i64 {
        msg_send![general_pasteboard(), clearContents]
    }

    /// The pid of the app the user is currently in front of, if any.
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

    /// The pasteboard's declared UTIs, mapped onto the policy's format classes. One copy declares
    /// several (a text copy carries plain text *and* RTF/HTML), and policy is per-format, so all of
    /// them are reported — a payload is only allowed across the boundary if every format is.
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
            // The file formats are the ones that move whole documents — they must never fall
            // through to `Other`, which a policy may treat differently.
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
        // The tag is spent: a second look must not try to clear again.
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
        // The pasteboard moved on without us seeing who wrote it (a fast copy between polls).
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

    /// Every format is offered to `decide`, not just up to the first denial — the daemon audits
    /// through that callback, so short-circuiting would under-report what was blocked.
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
