//! Behavioural tests for the policy brain.
//!
//! These run with no OS, no driver, no entitlements — the whole point of Phase 1. The
//! property tests assert the *security invariants* the docs promise, not just examples.

use clave_core::{
    clip_decision, decide, Access, Action, JoinReason, PolicyBundle, Reason, ZoneRegistry,
};
use clave_platform::{ClipFormat, Decision, ProcId, Zone};
use proptest::prelude::*;

fn pid(n: u32) -> ProcId {
    ProcId::windows(n, 1)
}

// Clipboard matrix

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
    // Files remain denied — granular per-format policy.
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

// Fail-closed

#[test]
fn expired_policy_fails_closed_even_for_normally_allowed_action() {
    let mut pol = PolicyBundle::restrictive_default();
    pol.not_after = 1_000;
    let zones = ZoneRegistry::new();

    // work->work clipboard is normally an unconditional Allow...
    let act = Action::ClipboardTransfer {
        src: Zone::Work,
        dst: Zone::Work,
        fmt: ClipFormat::PlainText,
    };
    // ...but past expiry it must be denied.
    let v = decide(&act, &zones, &pol, 2_000);
    assert_eq!(v.decision, Decision::Deny);
    assert_eq!(v.reason, Reason::PolicyExpired);
}

// File-write containment

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
    // A work app reading a system path (a shared library, a font) is not an escape.
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
    // The intrusion invariant: a personal (unsupervised) process may neither read nor write the
    // Clave Disk. Under the old escape-only model this fell through to Allow.
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new(); // pid(99) never joins → personal

    for access in [Access::Read, Access::Write] {
        let act = Action::FileOpen {
            proc: pid(99),
            inside_enclave: true,
            access,
        };
        let v = decide(&act, &zones, &pol, 1);
        assert_eq!(v.decision, Decision::Deny, "personal {access:?} of the disk must be denied");
        assert_eq!(v.reason, Reason::EnclaveIntrusion);
    }
}

#[test]
fn personal_process_file_writes_outside_enclave_are_not_gated() {
    let pol = PolicyBundle::restrictive_default();
    let zones = ZoneRegistry::new(); // pid(99) never joins → personal

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

    // ...but opt-in to save-outside must NOT open the enclave to a personal process.
    let intruder = Action::FileOpen {
        proc: pid(99),
        inside_enclave: true,
        access: Access::Write,
    };
    assert_eq!(decide(&intruder, &zones, &pol, 1).decision, Decision::Deny);
}

// Network split-tunnel decisions

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

// Zone registry semantics

#[test]
fn zone_membership_join_leave_and_pid_reuse() {
    let zones = ZoneRegistry::new();
    let original = ProcId::windows(100, 5_000); // pid 100, created at t=5000
    zones.join(original, JoinReason::Launcher);
    assert!(zones.is_supervised(&original));

    zones.leave(&original);
    assert!(!zones.is_supervised(&original));

    // A *different* process reusing pid 100 (later create time) is NOT supervised — the
    // create-time disambiguator defeats PID reuse.
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
    /// Invariant: same-zone clipboard transfers are ALWAYS allowed, for any format.
    #[test]
    fn prop_same_zone_clipboard_always_allowed(fmt in fmt_strat()) {
        let pol = PolicyBundle::restrictive_default();
        prop_assert_eq!(clip_decision(Zone::Work, Zone::Work, fmt, &pol), Decision::Allow);
        prop_assert_eq!(clip_decision(Zone::Personal, Zone::Personal, fmt, &pol), Decision::Allow);
    }

    /// Invariant: under the restrictive default, NO work→personal format is ever allowed.
    #[test]
    fn prop_restrictive_default_blocks_all_exfil(fmt in fmt_strat()) {
        let pol = PolicyBundle::restrictive_default();
        prop_assert_eq!(clip_decision(Zone::Work, Zone::Personal, fmt, &pol), Decision::Deny);
    }

    /// Invariant: an expired policy denies EVERY action, for any zones/format/time-after.
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

    /// Invariant: a personal (unsupervised) process is never denied a network connection by
    /// the enclave — we don't govern personal traffic.
    #[test]
    fn prop_personal_net_never_denied(host in "[a-z]{1,12}\\.example", n in 1u32..10_000) {
        let mut pol = PolicyBundle::restrictive_default();
        pol.network.blocked_hosts = vec![host.clone()]; // even if it's on the work denylist
        let zones = ZoneRegistry::new();                 // ...the proc is personal
        let act = Action::NetConnect { proc: pid(n), host };
        prop_assert!(decide(&act, &zones, &pol, 1).is_allow());
    }
}
