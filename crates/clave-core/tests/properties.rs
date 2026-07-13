use clave_core::{
    classify_exec, classify_flow, classify_path, clip_decision, decide, Access, Action, AppId,
    AppPolicy, AppRule, BinaryMatch, FilePolicy, JoinReason, PathClass, PolicyBundle, Reason,
    ZoneRegistry,
};
use clave_platform::{ClipFormat, Decision, ProcId, Route, Zone};
use proptest::prelude::*;

fn clip_format() -> impl Strategy<Value = ClipFormat> {
    prop::sample::select(ClipFormat::ALL.to_vec())
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        (clip_format(), any::<bool>(), any::<bool>()).prop_map(|(fmt, a, b)| {
            Action::ClipboardTransfer {
                src: if a { Zone::Work } else { Zone::Personal },
                dst: if b { Zone::Work } else { Zone::Personal },
                fmt,
            }
        }),
        (any::<u32>(), any::<bool>(), any::<bool>()).prop_map(|(n, inside, write)| {
            Action::FileOpen {
                proc: ProcId::windows(n, 1),
                inside_enclave: inside,
                access: if write { Access::Write } else { Access::Read },
            }
        }),
        (any::<u32>(), "[a-z]{1,12}").prop_map(|(n, host)| Action::NetConnect {
            proc: ProcId::windows(n, 1),
            host,
        }),
    ]
}

proptest! {
    #[test]
    fn expired_policy_denies_every_action(
        act in action(),
        not_after in 0u64..1_000_000,
        gap in 1u64..1_000,
    ) {
        let zones = ZoneRegistry::new();
        let mut pol = PolicyBundle::restrictive_default();
        pol.not_after = not_after;
        let now = not_after + gap;
        prop_assert_eq!(decide(&act, &zones, &pol, now).decision, Decision::Deny);
    }

    #[test]
    fn personal_process_never_opens_the_enclave(
        n in any::<u32>(),
        write in any::<bool>(),
        allow_outside in any::<bool>(),
    ) {
        let zones = ZoneRegistry::new();
        let mut pol = PolicyBundle::restrictive_default();
        pol.files.allow_save_outside_enclave = allow_outside;
        let act = Action::FileOpen {
            proc: ProcId::windows(n, 1),
            inside_enclave: true,
            access: if write { Access::Write } else { Access::Read },
        };
        let v = decide(&act, &zones, &pol, 1);
        prop_assert_eq!(v.decision, Decision::Deny);
        prop_assert_eq!(v.reason, Reason::EnclaveIntrusion);
    }

    #[test]
    fn same_zone_clipboard_always_allows(fmt in clip_format()) {
        let pol = PolicyBundle::restrictive_default();
        prop_assert_eq!(clip_decision(Zone::Work, Zone::Work, fmt, &pol), Decision::Allow);
        prop_assert_eq!(clip_decision(Zone::Personal, Zone::Personal, fmt, &pol), Decision::Allow);
    }

    #[test]
    fn personal_flow_always_routes_direct(n in any::<u32>(), blocked in any::<bool>()) {
        let zones = ZoneRegistry::new();
        prop_assert_eq!(classify_flow(&ProcId::windows(n, 1), &zones, blocked), Route::Direct);
    }

    #[test]
    fn work_flow_blocks_iff_denylisted(n in any::<u32>(), blocked in any::<bool>()) {
        let zones = ZoneRegistry::new();
        let p = ProcId::windows(n, 1);
        zones.join(p, JoinReason::Launcher);
        let expect = if blocked { Route::Block } else { Route::Tunnel };
        prop_assert_eq!(classify_flow(&p, &zones, blocked), expect);
    }

    #[test]
    fn allowlisted_binary_always_joins(
        team in "[A-Z0-9]{1,12}",
        signing in "[a-z.]{1,24}",
        parent in any::<bool>(),
    ) {
        let bin = BinaryMatch::Macos { team_id: team, signing_id: signing };
        let apps = AppPolicy { allow: vec![AppRule::new(AppId("x".into()), bin.clone())] };
        let v = classify_exec(&bin, false, parent, &apps);
        prop_assert!(v.joins_zone);
        prop_assert_eq!(v.matched, Some(AppId("x".into())));
    }

    #[test]
    fn unlisted_binary_joins_iff_parent_supervised(
        team in "[A-Z]{1,8}",
        signing in "[a-z]{1,8}",
        parent in any::<bool>(),
    ) {
        let bin = BinaryMatch::Macos { team_id: team, signing_id: signing };
        let v = classify_exec(&bin, false, parent, &AppPolicy::empty());
        prop_assert_eq!(v.joins_zone, parent);
        prop_assert!(v.matched.is_none());
    }

    #[test]
    fn paths_under_the_disk_always_pass_through(
        mount in "/[a-z]{1,8}",
        suffix in "(/[a-z]{1,8}){0,3}",
        roots in prop::collection::vec("/[a-z]{1,8}", 0..4),
    ) {
        let path = format!("{mount}{suffix}");
        let files = FilePolicy {
            allow_save_outside_enclave: false,
            work_data_roots: roots,
            cow_roots: Vec::new(),
        };
        prop_assert_eq!(classify_path(&path, &mount, &[], &files), PathClass::PassThrough);
    }

    #[test]
    fn passthrough_overrides_work_data(root in "/[a-z]{2,8}", leaf in "[a-z]{1,8}") {
        let path = format!("{root}/{leaf}");
        let files = FilePolicy {
            allow_save_outside_enclave: false,
            work_data_roots: vec![root.clone()],
            cow_roots: Vec::new(),
        };
        prop_assert_eq!(
            classify_path(&path, "/Volumes/ClaveDisk", std::slice::from_ref(&root), &files),
            PathClass::PassThrough
        );
        prop_assert_eq!(
            classify_path(&path, "/Volumes/ClaveDisk", &[], &files),
            PathClass::WorkData
        );
    }
}
