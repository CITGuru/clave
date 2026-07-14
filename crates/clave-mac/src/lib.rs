#![allow(unexpected_cfgs)]

use clave_core::{classify_exec, AppPolicy, BinaryMatch, JoinReason, ZoneRegistry};
#[cfg(target_os = "macos")]
use clave_core::PolicyBundle;
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

mod screen;
#[cfg(target_os = "macos")]
pub use edge::work_windows_on_screen;
#[cfg(target_os = "macos")]
pub use screen::{run_screen_watch, running_capture_tools};
pub use screen::{CaptureWatch, Capturer};

mod input;
#[cfg(target_os = "macos")]
pub use input::{raw_keyboard_taps, run_input_watch};
pub use input::{TapWatch, Tapper};

#[cfg(target_os = "macos")]
mod launch;
#[cfg(target_os = "macos")]
pub use launch::{bundle_identifier, running_pids_for_bundle, wait_for_app_pid};

#[cfg(target_os = "macos")]
mod es_gate;
#[cfg(target_os = "macos")]
pub use es_gate::{
    apply_file_policy, authorize_clone, authorize_open, set_allow_save_outside_enclave,
    set_mount_prefix,
};

#[cfg(target_os = "macos")]
mod keychain;
#[cfg(target_os = "macos")]
pub use keychain::provision_contained_keychain;

#[cfg(target_os = "macos")]
mod se_seal;

#[cfg(target_os = "macos")]
mod volume;
// Stub so `MacPlatform` (and the rest of this crate) still compiles on
// Linux/Windows CI; the real `hdiutil` + Keychain + SE mount is macOS-only.
#[cfg(not(target_os = "macos"))]
mod volume {
    use std::path::PathBuf;

    use clave_platform::{PResult, VolumeMount};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Custody {
        RequireHardware,
        AllowPlainFallback,
    }

    #[derive(Default)]
    pub struct MacVolumeMount;

    impl MacVolumeMount {
        pub fn new(
            _container: u128,
            _bundle_path: impl Into<PathBuf>,
            _custody: Custody,
        ) -> Self {
            Self
        }
    }

    impl VolumeMount for MacVolumeMount {
        fn is_mounted(&self) -> bool {
            false
        }
        fn mount_point(&self) -> Option<String> {
            None
        }
        fn request_wipe(&self) -> PResult<()> {
            Ok(())
        }
    }
}
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
/// `ptr` must be null, or point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_load_policy_json(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() {
        return false;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    #[cfg(target_os = "macos")]
    if let Ok(bundle) = serde_json::from_slice::<PolicyBundle>(bytes) {
        *policy().write().expect("policy lock poisoned") = bundle.apps;
        crate::es_gate::apply_file_policy(&bundle.files);
        return true;
    }
    match serde_json::from_slice::<AppPolicy>(bytes) {
        Ok(parsed) => {
            *policy().write().expect("policy lock poisoned") = parsed;
            true
        }
        Err(_) => false,
    }
}

/// # Safety
/// `parent_token` and `target_token` must each be null or point to 8 readable, aligned `u32`s
/// (a macOS `audit_token_t`). `team_id` and `signing_id` must each be null or a NUL-terminated
/// C string.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_authorize_exec(
    parent_token: *const u32,
    target_token: *const u32,
    team_id: *const c_char,
    signing_id: *const c_char,
    is_platform_binary: bool,
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
        is_platform_binary,
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
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s (a macOS `audit_token_t`).
#[no_mangle]
pub unsafe extern "C" fn clave_mac_zone_join(token_ptr: *const u32) {
    if let Some(t) = unsafe { read_token(token_ptr) } {
        zones().join(ProcId::macos(t), JoinReason::Launcher);
    }
}

/// # Safety
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s (a macOS `audit_token_t`).
#[no_mangle]
pub unsafe extern "C" fn clave_mac_zone_leave(token_ptr: *const u32) {
    if let Some(t) = unsafe { read_token(token_ptr) } {
        zones().leave(&ProcId::macos(t));
    }
}

/// # Safety
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s (a macOS `audit_token_t`).
#[no_mangle]
pub unsafe extern "C" fn clave_mac_can_access_volume(token_ptr: *const u32) -> bool {
    match unsafe { read_token(token_ptr) } {
        Some(t) => zones().is_supervised(&ProcId::macos(t)),
        None => false,
    }
}

/// # Safety
/// `ptr` must be null or a NUL-terminated C string.
#[cfg(target_os = "macos")]
#[no_mangle]
pub unsafe extern "C" fn clave_mac_set_mount_prefix(ptr: *const c_char) -> bool {
    if ptr.is_null() {
        return false;
    }
    let prefix = unsafe { read_cstr(ptr) };
    if prefix.is_empty() {
        return false;
    }
    crate::es_gate::set_mount_prefix(&prefix);
    true
}

/// # Safety
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s (a macOS `audit_token_t`).
/// `path_ptr` must be null or a NUL-terminated C string.
#[cfg(target_os = "macos")]
#[no_mangle]
pub unsafe extern "C" fn clave_mac_authorize_open(
    token_ptr: *const u32,
    path_ptr: *const c_char,
    write: bool,
) -> bool {
    let Some(t) = (unsafe { read_token(token_ptr) }) else {
        return false;
    };
    if path_ptr.is_null() {
        return false;
    }
    let path = unsafe { read_cstr(path_ptr) };
    if path.is_empty() {
        return false;
    }
    crate::es_gate::authorize_open(zones(), ProcId::macos(t), &path, write)
}

/// # Safety
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s (a macOS `audit_token_t`).
/// `source_ptr` and `target_ptr` must each be null or a NUL-terminated C string.
#[cfg(target_os = "macos")]
#[no_mangle]
pub unsafe extern "C" fn clave_mac_authorize_clone(
    token_ptr: *const u32,
    source_ptr: *const c_char,
    target_ptr: *const c_char,
) -> bool {
    let Some(t) = (unsafe { read_token(token_ptr) }) else {
        return false;
    };
    if source_ptr.is_null() || target_ptr.is_null() {
        return false;
    }
    let source = unsafe { read_cstr(source_ptr) };
    let target = unsafe { read_cstr(target_ptr) };
    if source.is_empty() || target.is_empty() {
        return false;
    }
    crate::es_gate::authorize_clone(zones(), ProcId::macos(t), &source, &target)
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
            "launch":{"profile_subdir":"","env":[],"namespace_prefix":null,"hive_seed":null,
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
                false,
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
                false,
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

    #[test]
    #[cfg(target_os = "macos")]
    fn authorize_open_denies_supervised_writes_outside_the_mount() {
        crate::es_gate::set_mount_prefix("/Volumes/ClaveDisk");
        crate::es_gate::set_allow_save_outside_enclave(false);
        let token = [0xC0u32, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7];
        zones().join(ProcId::macos(token), JoinReason::Launcher);
        let ptr = token.as_ptr();
        let desktop = std::ffi::CString::new("/Users/alice/Desktop/leak.pdf").unwrap();
        assert!(
            !unsafe { clave_mac_authorize_open(ptr, desktop.as_ptr(), true) },
            "supervised write outside the mount is denied"
        );
        assert!(
            unsafe { clave_mac_authorize_open(ptr, desktop.as_ptr(), false) },
            "supervised read outside the mount is allowed"
        );
    }
}
