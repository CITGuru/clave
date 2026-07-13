use clave_core::{
    clip_decision, decide, Access, Action, JoinReason, PolicyBundle, Reason, ZoneRegistry,
};
use clave_platform::{ClipFormat, Decision, ProcId, Zone};
use proptest::prelude::*;

fn pid(n: u32) -> ProcId {
    ProcId::windows(n, 1)
}

#[test]
fn work_to_work_clipboard_always_allows() {
    let pol = PolicyBundle::restrictive_default();
    for fmt in ClipFormat::ALL {
        assert_eq!(
            clip_decision(Zone::Work, Zone::Work, fmt, &pol),
            Decision::Allow,
            "work->work must always allow {fmt:?}"
        );
    }
}

#[test]
fn work_to_personal_denied_by_default() {
    let pol = PolicyBundle::restrictive_default();
    for fmt in ClipFormat::ALL {
        assert_eq!(
            clip_decision(Zone::Work, Zone::Personal, fmt, &pol),
            Decision::Deny,
            "restrictive default must block exfil of {fmt:?}"
        );
    }
}

#[test]
fn work_to_personal_text_allowed_when_policy_permits() {
    let mut pol = PolicyBundle::restrictive_default();
    pol.clipboard.work_to_personal_allow = vec![ClipFormat::PlainText];

    assert_eq!(
        clip_decision(Zone::Work, Zone::Personal, ClipFormat::PlainText, &pol),
        Decision::Allow
    );
    assert_eq!(
        clip_decision(Zone::Work, Zone::Personal, ClipFormat::Files, &pol),
        Decision::Deny
    );
}

#[test]
fn personal_to_work_sanitizes_listed_formats() {
    let mut pol = PolicyBundle::restrictive_default();
    pol.clipboard.personal_to_work_sanitize = vec![ClipFormat::Html, ClipFormat::RichText];

    assert_eq!(
        clip_decision(Zone::Personal, Zone::Work, ClipFormat::Html, &pol),
        Decision::Sanitize
    );
    assert_eq!(
        clip_decision(Zone::Personal, Zone::Work, ClipFormat::PlainText, &pol),
        Decision::Allow
    );
}

#[test]
fn expired_policy_fails_closed_even_for_normally_allowed_action() {
    let mut pol = PolicyBundle::restrictive_default();
    pol.not_after = 1_000;
    let zones = ZoneRegistry::new();

    let act = Action::ClipboardTransfer {
        src: Zone::Work,
        dst: Zone::Work,
        fmt: ClipFormat::PlainText,
    };
    let v = decide(&act, &zones, &pol, 2_000);
    assert_eq!(v.decision, Decision::Deny);
    assert_eq!(v.reason, Reason::PolicyExpired);
}

#[test]
fn supervised_write_outside_enclave_is_denied() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();
    let p = pid(42);
    zones.join(p, JoinReason::Launcher);

    let escaping = Action::FileOpen {
        proc: p,
        inside_enclave: false,
        access: Access::Write,
    };
    let v = decide(&escaping, &zones, &pol, 1);
    assert_eq!(v.decision, Decision::Deny);
    assert_eq!(v.reason, Reason::FileWrite);

    let contained = Action::FileOpen {
        proc: p,
        inside_enclave: true,
        access: Access::Write,
    };
    assert_eq!(
        decide(&contained, &zones, &pol, 1).decision,
        Decision::Allow
    );
}

#[test]
fn supervised_read_outside_enclave_is_allowed() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();
    let p = pid(42);
    zones.join(p, JoinReason::Launcher);

    let act = Action::FileOpen {
        proc: p,
        inside_enclave: false,
        access: Access::Read,
    };
    assert_eq!(decide(&act, &zones, &pol, 1).decision, Decision::Allow);
}

#[test]
fn personal_process_cannot_open_the_enclave() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();

    for access in [Access::Read, Access::Write] {
        let act = Action::FileOpen {
            proc: pid(99),
            inside_enclave: true,
            access,
        };
        let v = decide(&act, &zones, &pol, 1);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "personal {access:?} of the disk must be denied"
        );
        assert_eq!(v.reason, Reason::EnclaveIntrusion);
    }
}

#[test]
fn personal_process_file_writes_outside_enclave_are_not_gated() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();

    let act = Action::FileOpen {
        proc: pid(99),
        inside_enclave: false,
        access: Access::Write,
    };
    let v = decide(&act, &zones, &pol, 1);
    assert_eq!(
        v.decision,
        Decision::Allow,
        "we never touch personal activity outside the enclave"
    );
    assert_eq!(v.reason, Reason::NotSupervised);
}

#[test]
fn save_outside_enclave_allowed_when_policy_opts_in() {
    let mut pol = PolicyBundle::restrictive_default();
    pol.files.allow_save_outside_enclave = true;
    let zones = ZoneRegistry::new();
    let p = pid(42);
    zones.join(p, JoinReason::Launcher);

    let act = Action::FileOpen {
        proc: p,
        inside_enclave: false,
        access: Access::Write,
    };
    assert_eq!(decide(&act, &zones, &pol, 1).decision, Decision::Allow);

    let intruder = Action::FileOpen {
        proc: pid(99),
        inside_enclave: true,
        access: Access::Write,
    };
    assert_eq!(decide(&intruder, &zones, &pol, 1).decision, Decision::Deny);
}

#[test]
fn personal_network_is_allowed_and_unsupervised() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();
    let act = Action::NetConnect {
        proc: pid(7),
        host: "example.com".to_string(),
    };
    let v = decide(&act, &zones, &pol, 1);
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.reason, Reason::NotSupervised);
}

#[test]
fn work_network_blocklist_is_enforced() {
    let mut pol = PolicyBundle::restrictive_default();
    pol.network.blocked_hosts = vec!["evil.example".to_string()];
    let zones = ZoneRegistry::new();
    let p = pid(7);
    zones.join(p, JoinReason::Launcher);

    let blocked = Action::NetConnect {
        proc: p,
        host: "evil.example".to_string(),
    };
    assert_eq!(decide(&blocked, &zones, &pol, 1).decision, Decision::Deny);

    let ok = Action::NetConnect {
        proc: p,
        host: "good.example".to_string(),
    };
    assert_eq!(decide(&ok, &zones, &pol, 1).decision, Decision::Allow);
}

#[test]
fn zone_membership_join_leave_and_pid_reuse() {
    let zones = ZoneRegistry::new();
    let original = ProcId::windows(100, 5_000);
    zones.join(original, JoinReason::Launcher);
    assert!(zones.is_supervised(&original));

    zones.leave(&original);
    assert!(!zones.is_supervised(&original));

    let reused = ProcId::windows(100, 9_000);
    assert!(!zones.is_supervised(&reused));
}

fn zone_strat() -> impl Strategy<Value = Zone> {
    prop_oneof![Just(Zone::Work), Just(Zone::Personal)]
}

fn fmt_strat() -> impl Strategy<Value = ClipFormat> {
    prop_oneof![
        Just(ClipFormat::PlainText),
        Just(ClipFormat::RichText),
        Just(ClipFormat::Html),
        Just(ClipFormat::Image),
        Just(ClipFormat::Files),
        Just(ClipFormat::Other),
    ]
}

proptest! {
    #[test]
    fn prop_same_zone_clipboard_always_allowed(fmt in fmt_strat()) {
        let pol = PolicyBundle::restrictive_default();
        prop_assert_eq!(clip_decision(Zone::Work, Zone::Work, fmt, &pol), Decision::Allow);
        prop_assert_eq!(clip_decision(Zone::Personal, Zone::Personal, fmt, &pol), Decision::Allow);
    }

    #[test]
    fn prop_restrictive_default_blocks_all_exfil(fmt in fmt_strat()) {
        let pol = PolicyBundle::restrictive_default();
        prop_assert_eq!(clip_decision(Zone::Work, Zone::Personal, fmt, &pol), Decision::Deny);
    }

    #[test]
    fn prop_expired_denies_everything(
        src in zone_strat(),
        dst in zone_strat(),
        fmt in fmt_strat(),
        now in 1_001u64..u64::MAX,
    ) {
        let mut pol = PolicyBundle::restrictive_default();
        pol.not_after = 1_000;
        let zones = ZoneRegistry::new();
        let act = Action::ClipboardTransfer { src, dst, fmt };
        let v = decide(&act, &zones, &pol, now);
        prop_assert_eq!(v.decision, Decision::Deny);
        prop_assert_eq!(v.reason, Reason::PolicyExpired);
    }

    #[test]
    fn prop_personal_net_never_denied(host in "[a-z]{1,12}\\.example", n in 1u32..10_000) {
        let mut pol = PolicyBundle::restrictive_default();
        pol.network.blocked_hosts = vec![host.clone()];
        let zones = ZoneRegistry::new();
        let act = Action::NetConnect { proc: pid(n), host };
        prop_assert!(decide(&act, &zones, &pol, 1).is_allow());
    }
}

#[test]
fn screen_capture_over_work_is_denied_by_default() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();
    let act = Action::ScreenCapture {
        proc: Some(pid(9)),
        exe: "screencapture".into(),
    };
    let v = decide(&act, &zones, &pol, 1);
    assert_eq!(v.decision, Decision::Deny);
    assert_eq!(v.reason, Reason::ScreenCapture);
}

#[test]
fn a_work_process_may_capture_its_own_zone() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();
    let work = pid(9);
    zones.join(work, JoinReason::Launcher);
    let act = Action::ScreenCapture {
        proc: Some(work),
        exe: "screencapture".into(),
    };
    assert!(decide(&act, &zones, &pol, 1).is_allow());
}

#[test]
fn policy_may_sanction_a_capture_tool() {
    let mut pol = PolicyBundle::restrictive_default();
    pol.screen.allowed_capturers = vec!["zoom.us".into()];
    let zones = ZoneRegistry::new();

    let sanctioned = Action::ScreenCapture {
        proc: Some(pid(9)),
        exe: "zoom.us".into(),
    };
    assert!(decide(&sanctioned, &zones, &pol, 1).is_allow());

    let other = Action::ScreenCapture {
        proc: Some(pid(9)),
        exe: "obs".into(),
    };
    assert_eq!(decide(&other, &zones, &pol, 1).decision, Decision::Deny);
}

/// An unidentifiable capturer must not slip through as "not a work process, so allow" — it is the
/// most suspicious case, not the least.
#[test]
fn an_unidentified_capturer_is_still_denied() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();
    let act = Action::ScreenCapture {
        proc: None,
        exe: String::new(),
    };
    assert_eq!(decide(&act, &zones, &pol, 1).decision, Decision::Deny);
}

#[test]
fn input_tap_over_work_is_denied_by_default() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();
    let act = Action::InputTap {
        proc: Some(pid(9)),
        exe: "keylogger".into(),
    };
    let v = decide(&act, &zones, &pol, 1);
    assert_eq!(v.decision, Decision::Deny);
    assert_eq!(v.reason, Reason::InputTap);
}

#[test]
fn a_work_process_may_tap_its_own_input() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new();
    let work = pid(9);
    zones.join(work, JoinReason::Launcher);
    let act = Action::InputTap {
        proc: Some(work),
        exe: "keylogger".into(),
    };
    assert!(decide(&act, &zones, &pol, 1).is_allow());
}

#[test]
fn policy_may_sanction_an_input_tapper() {
    let mut pol = PolicyBundle::restrictive_default();
    pol.input.allowed_tappers = vec!["TextExpander".into()];
    let zones = ZoneRegistry::new();
    let ok = Action::InputTap {
        proc: Some(pid(9)),
        exe: "TextExpander".into(),
    };
    assert!(decide(&ok, &zones, &pol, 1).is_allow());
    let bad = Action::InputTap {
        proc: Some(pid(9)),
        exe: "keylogger".into(),
    };
    assert_eq!(decide(&bad, &zones, &pol, 1).decision, Decision::Deny);
}
