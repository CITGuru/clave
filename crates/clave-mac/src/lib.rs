#![allow(unexpected_cfgs)]

use clave_core::{classify_exec, AppPolicy, BinaryMatch, JoinReason, ZoneRegistry};
use clave_platform::{ProcId, Route};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::{OnceLock, RwLock};

mod platform;
mod sip;
pub use platform::{MacPlatform, TrackedWindows};
pub use sip::SipStatus;

#[cfg(target_os = "macos")]
mod edge;
#[cfg(target_os = "macos")]
pub use edge::run_clave_edge;

mod clipboard;
#[cfg(target_os = "macos")]
pub use clipboard::{frontmost_app_pid, run_clipboard_guard};
pub use clipboard::{ClipboardGuard, GuardAction};

#[cfg(target_os = "macos")]
mod se_seal;

#[cfg(target_os = "macos")]
mod volume;
#[cfg(target_os = "macos")]
pub use volume::{Custody, MacVolumeMount};

static ZONES: OnceLock<ZoneRegistry> = OnceLock::new();

fn zones() -> &'static ZoneRegistry {
    ZONES.get_or_init(ZoneRegistry::new)
}

static POLICY: OnceLock<RwLock<AppPolicy>> = OnceLock::new();

fn policy() -> &'static RwLock<AppPolicy> {
    POLICY.get_or_init(|| RwLock::new(AppPolicy::empty()))
}

unsafe fn read_cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .unwrap_or_default()
        .to_owned()
}

fn classify(token: [u32; 8], zones: &ZoneRegistry, dst_blocked: bool) -> Route {
    clave_net::route(&ProcId::macos(token), zones, dst_blocked)
}

fn route_code(r: Route) -> u8 {
    match r {
        Route::Direct => 0,
        Route::Tunnel => 1,
        Route::Block => 2,
    }
}

unsafe fn read_token(token_ptr: *const u32) -> Option<[u32; 8]> {
    if token_ptr.is_null() {
        return None;
    }
    let mut t = [0u32; 8];
    let slice = unsafe { std::slice::from_raw_parts(token_ptr, 8) };
    t.copy_from_slice(slice);
    Some(t)
}

/// # Safety
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s (a macOS `audit_token_t`).
#[no_mangle]
pub unsafe extern "C" fn clave_mac_route_flow(token_ptr: *const u32, dst_blocked: bool) -> u8 {
    match unsafe { read_token(token_ptr) } {
        Some(t) => route_code(classify(t, zones(), dst_blocked)),
        None => route_code(Route::Direct),
    }
}

/// # Safety
/// `ptr` must be null or point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_load_policy_json(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() {
        return false;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    match serde_json::from_slice::<AppPolicy>(bytes) {
        Ok(parsed) => {
            *policy().write().expect("policy lock poisoned") = parsed;
            true
        }
        Err(_) => false,
    }
}

/// # Safety
/// `parent_token`/`target_token` must each be null or point to 8 readable, aligned `u32`s;
/// `team_id`/`signing_id` must each be null or a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_authorize_exec(
    parent_token: *const u32,
    target_token: *const u32,
    team_id: *const c_char,
    signing_id: *const c_char,
) -> bool {
    let parent_supervised = match unsafe { read_token(parent_token) } {
        Some(t) => zones().is_supervised(&ProcId::macos(t)),
        None => false,
    };
    let binary = BinaryMatch::Macos {
        team_id: unsafe { read_cstr(team_id) },
        signing_id: unsafe { read_cstr(signing_id) },
    };
    let verdict = classify_exec(
        &binary,
        parent_supervised,
        &policy().read().expect("policy lock poisoned"),
    );
    if verdict.joins_zone {
        if let Some(t) = unsafe { read_token(target_token) } {
            let reason = match &verdict.matched {
                Some(_) => JoinReason::AllowList,
                None => JoinReason::Child(ProcId::macos(
                    unsafe { read_token(parent_token) }.unwrap_or([0; 8]),
                )),
            };
            zones().join(ProcId::macos(t), reason);
        }
    }
    verdict.allow
}

/// # Safety
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_zone_join(token_ptr: *const u32) {
    if let Some(t) = unsafe { read_token(token_ptr) } {
        zones().join(ProcId::macos(t), JoinReason::Launcher);
    }
}

/// # Safety
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_zone_leave(token_ptr: *const u32) {
    if let Some(t) = unsafe { read_token(token_ptr) } {
        zones().leave(&ProcId::macos(t));
    }
}

/// # Safety
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_can_access_volume(token_ptr: *const u32) -> bool {
    match unsafe { read_token(token_ptr) } {
        Some(t) => zones().is_supervised(&ProcId::macos(t)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_token_classification() {
        let zones = ZoneRegistry::new();
        let token = [1, 2, 3, 4, 5, 6, 7, 8];

        assert_eq!(classify(token, &zones, true), Route::Direct);

        zones.join(ProcId::macos(token), JoinReason::Launcher);
        assert_eq!(classify(token, &zones, false), Route::Tunnel);
        assert_eq!(classify(token, &zones, true), Route::Block);
    }

    #[test]
    fn route_codes_are_stable() {
        assert_eq!(route_code(Route::Direct), 0);
        assert_eq!(route_code(Route::Tunnel), 1);
        assert_eq!(route_code(Route::Block), 2);
    }

    #[test]
    fn ffi_null_token_is_safe_and_routes_direct() {
        let code = unsafe { clave_mac_route_flow(std::ptr::null(), false) };
        assert_eq!(code, route_code(Route::Direct));
    }

    #[test]
    fn authorize_exec_joins_allow_listed_binary() {
        let target = [0xB0u32, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7];
        let policy_json = br#"{"allow":[{"app_id":"chrome-work",
            "binary":{"Macos":{"team_id":"EQHXZ8M8AV","signing_id":"com.google.Chrome"}},
            "launch":{"home_subdir":"","env":[],"namespace_prefix":null,"hive_seed":null,
            "passthrough_paths":[]},"display_name":"Chrome","executable":""}]}"#;
        assert!(unsafe { clave_mac_load_policy_json(policy_json.as_ptr(), policy_json.len()) });

        let team = std::ffi::CString::new("EQHXZ8M8AV").unwrap();
        let sig = std::ffi::CString::new("com.google.Chrome").unwrap();
        let allow = unsafe {
            clave_mac_authorize_exec(
                std::ptr::null(),
                target.as_ptr(),
                team.as_ptr(),
                sig.as_ptr(),
            )
        };
        assert!(allow, "exec is always allowed");
        assert!(
            zones().is_supervised(&ProcId::macos(target)),
            "an allow-listed binary joins the zone"
        );

        let other = [0xB8u32, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF];
        let bad = std::ffi::CString::new("com.evil.app").unwrap();
        unsafe {
            clave_mac_authorize_exec(
                std::ptr::null(),
                other.as_ptr(),
                team.as_ptr(),
                bad.as_ptr(),
            )
        };
        assert!(
            !zones().is_supervised(&ProcId::macos(other)),
            "an unknown binary stays personal"
        );
    }

    #[test]
    fn load_policy_rejects_garbage_and_keeps_prior() {
        let garbage = b"not json";
        assert!(!unsafe { clave_mac_load_policy_json(garbage.as_ptr(), garbage.len()) });
        assert!(!unsafe { clave_mac_load_policy_json(std::ptr::null(), 0) });
    }

    #[test]
    fn auth_open_gate_allows_only_supervised_callers() {
        let token = [0xA0u32, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
        let ptr = token.as_ptr();
        assert!(
            !unsafe { clave_mac_can_access_volume(ptr) },
            "a personal caller is denied"
        );
        zones().join(ProcId::macos(token), JoinReason::Launcher);
        assert!(
            unsafe { clave_mac_can_access_volume(ptr) },
            "a supervised caller is allowed"
        );
        assert!(
            !unsafe { clave_mac_can_access_volume(std::ptr::null()) },
            "a null token denies"
        );
    }
}
