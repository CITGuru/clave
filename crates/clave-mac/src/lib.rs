//! # clave-mac — macOS platform adapter
//!
//! macOS enforcement runs in two Swift System Extensions that link this crate as a `staticlib` and
//! call the C ABI below: an Endpoint Security client (→ [`clave_mac_zone_join`] /
//! [`clave_mac_zone_leave`]) and a `NETransparentProxyProvider` (→ [`clave_mac_route_flow`]). Those
//! need Apple entitlements + notarization and are not built in CI; what is built and tested here is
//! this Rust core (audit-token → zone classification and the stable C ABI). `unsafe` is confined to
//! the FFI boundary.
// The `objc` 0.2 macros expand to `cfg(cargo-clippy)` checks that trip `unexpected_cfgs`.
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

/// Process-global zone mirror, fed by the ES client at exec/exit. (A production adapter would
/// scope this to the daemon connection; a `OnceLock` keeps the scaffold simple.)
static ZONES: OnceLock<ZoneRegistry> = OnceLock::new();

fn zones() -> &'static ZoneRegistry {
    ZONES.get_or_init(ZoneRegistry::new)
}

/// The signed app allow-list the ES client consults at `AUTH_EXEC`. Fed by the daemon from the
/// tenant-signed policy bundle; defaults to empty (fail-safe: only launcher/inheritance supervise).
static POLICY: OnceLock<RwLock<AppPolicy>> = OnceLock::new();

fn policy() -> &'static RwLock<AppPolicy> {
    POLICY.get_or_init(|| RwLock::new(AppPolicy::empty()))
}

/// Read a NUL-terminated UTF-8 C string into an owned `String` (empty if null / not UTF-8).
///
/// # Safety
/// `p` must be null or point to a NUL-terminated C string valid for the read.
unsafe fn read_cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: caller guarantees a NUL-terminated string at `p`.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .unwrap_or_default()
        .to_owned()
}

/// Safe core: classify a flow given an `audit_token`. Delegates to the shared `clave-net`
/// routing (which delegates to `clave-core`), so macOS and Windows share one decision.
fn classify(token: [u32; 8], zones: &ZoneRegistry, dst_blocked: bool) -> Route {
    clave_net::route(&ProcId::macos(token), zones, dst_blocked)
}

/// Stable ABI encoding of [`Route`].
fn route_code(r: Route) -> u8 {
    match r {
        Route::Direct => 0,
        Route::Tunnel => 1,
        Route::Block => 2,
    }
}

/// Read a macOS `audit_token_t` (8 × `u32`) from a C pointer.
///
/// # Safety
/// `token_ptr` must be null or point to 8 readable, aligned `u32`s.
unsafe fn read_token(token_ptr: *const u32) -> Option<[u32; 8]> {
    if token_ptr.is_null() {
        return None;
    }
    let mut t = [0u32; 8];
    // SAFETY: the caller guarantees 8 readable u32s at `token_ptr` (the contract above).
    let slice = unsafe { std::slice::from_raw_parts(token_ptr, 8) };
    t.copy_from_slice(slice);
    Some(t)
}

/// C ABI for the `NETransparentProxyProvider`'s `handleNewFlow`: classify a flow by the
/// originating app's audit token. Returns `0 = Direct` (let the system route it), `1 = Tunnel`
/// (the provider handles it → boringtun → gateway), `2 = Block`.
///
/// # Safety
/// `token_ptr` must satisfy [`read_token`]'s contract.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_route_flow(token_ptr: *const u32, dst_blocked: bool) -> u8 {
    // SAFETY: forwarded contract.
    match unsafe { read_token(token_ptr) } {
        Some(t) => route_code(classify(t, zones(), dst_blocked)),
        None => route_code(Route::Direct),
    }
}

/// C ABI: load/replace the signed app allow-list from a JSON [`AppPolicy`] bundle. The daemon
/// calls this on startup and on every gateway policy update. Returns `true` on a successful parse;
/// on failure the previous policy is kept (fail-safe). `ptr`/`len` describe the UTF-8 JSON bytes.
///
/// # Safety
/// `ptr` must be null or point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_load_policy_json(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees `len` readable bytes at `ptr`.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    match serde_json::from_slice::<AppPolicy>(bytes) {
        Ok(parsed) => {
            *policy().write().expect("policy lock poisoned") = parsed;
            true
        }
        Err(_) => false,
    }
}

/// C ABI for the ES client's `AUTH_EXEC` handler: given the executing process's audit token, the
/// new image's audit token, and the new image's code-signature (Team ID + signing id), decide via
/// the portable [`classify_exec`] whether the process joins the work zone — and, if so, record it.
/// Returns the allow verdict (always `true` today; Clave classifies rather than allow-lists the
/// machine). A binary matching the signed allow-list joins; otherwise a child of a supervised
/// process inherits membership; otherwise it stays personal.
///
/// # Safety
/// Both token pointers must satisfy [`read_token`]'s contract; `team_id`/`signing_id` must satisfy
/// [`read_cstr`]'s contract.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_authorize_exec(
    parent_token: *const u32,
    target_token: *const u32,
    team_id: *const c_char,
    signing_id: *const c_char,
) -> bool {
    // SAFETY: forwarded contract.
    let parent_supervised = match unsafe { read_token(parent_token) } {
        Some(t) => zones().is_supervised(&ProcId::macos(t)),
        None => false,
    };
    let binary = BinaryMatch::Macos {
        // SAFETY: forwarded contract.
        team_id: unsafe { read_cstr(team_id) },
        signing_id: unsafe { read_cstr(signing_id) },
    };
    let verdict = classify_exec(
        &binary,
        parent_supervised,
        &policy().read().expect("policy lock poisoned"),
    );
    if verdict.joins_zone {
        // SAFETY: forwarded contract.
        if let Some(t) = unsafe { read_token(target_token) } {
            let reason = match &verdict.matched {
                Some(_) => JoinReason::AllowList,
                None => JoinReason::Child(ProcId::macos(
                    // SAFETY: forwarded contract; parent token re-read for the inheritance record.
                    unsafe { read_token(parent_token) }.unwrap_or([0; 8]),
                )),
            };
            zones().join(ProcId::macos(t), reason);
        }
    }
    verdict.allow
}

/// C ABI for the ES client: seed work-zone membership directly (the Clave launcher's spawn path,
/// [`JoinReason::Launcher`]) — distinct from [`clave_mac_authorize_exec`]'s allow-list matching.
///
/// # Safety
/// `token_ptr` must satisfy [`read_token`]'s contract.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_zone_join(token_ptr: *const u32) {
    // SAFETY: forwarded contract.
    if let Some(t) = unsafe { read_token(token_ptr) } {
        zones().join(ProcId::macos(t), JoinReason::Launcher);
    }
}

/// C ABI for the ES client: a supervised process exited (`NOTIFY_EXIT`).
///
/// # Safety
/// `token_ptr` must satisfy [`read_token`]'s contract.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_zone_leave(token_ptr: *const u32) {
    // SAFETY: forwarded contract.
    if let Some(t) = unsafe { read_token(token_ptr) } {
        zones().leave(&ProcId::macos(t));
    }
}

/// C ABI for the ES client's `AUTH_OPEN` handler on the Clave Disk: may this caller
/// read the encrypted volume? Returns `true` to allow, `false` to deny. Only supervised (work-zone)
/// processes may open the disk — a personal process is denied even while the volume is mounted,
/// mirroring the kernel-authoritative gate. Fail-closed: a null or unknown token denies.
///
/// # Safety
/// `token_ptr` must satisfy [`read_token`]'s contract.
#[no_mangle]
pub unsafe extern "C" fn clave_mac_can_access_volume(token_ptr: *const u32) -> bool {
    // SAFETY: forwarded contract.
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

        // Unknown token → personal → Direct (and never inspected).
        assert_eq!(classify(token, &zones, true), Route::Direct);

        // After joining the zone → work → Tunnel, or Block if the host is denylisted.
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
        // SAFETY: null is explicitly handled by read_token.
        let code = unsafe { clave_mac_route_flow(std::ptr::null(), false) };
        assert_eq!(code, route_code(Route::Direct));
    }

    #[test]
    fn authorize_exec_joins_allow_listed_binary() {
        // A distinct token space avoids racing the process-global zone mirror in other tests.
        let target = [0xB0u32, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7];
        let policy_json = br#"{"allow":[{"app_id":"chrome-work",
            "binary":{"Macos":{"team_id":"EQHXZ8M8AV","signing_id":"com.google.Chrome"}},
            "launch":{"home_subdir":"","env":[],"namespace_prefix":null,"hive_seed":null,
            "passthrough_paths":[]},"display_name":"Chrome","executable":""}]}"#;
        // SAFETY: valid byte slice.
        assert!(unsafe { clave_mac_load_policy_json(policy_json.as_ptr(), policy_json.len()) });

        let team = std::ffi::CString::new("EQHXZ8M8AV").unwrap();
        let sig = std::ffi::CString::new("com.google.Chrome").unwrap();
        // SAFETY: valid tokens + NUL-terminated strings; no parent (personal parent).
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

        // An unknown binary with no supervised parent stays personal.
        let other = [0xB8u32, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF];
        let bad = std::ffi::CString::new("com.evil.app").unwrap();
        // SAFETY: same contract.
        unsafe {
            clave_mac_authorize_exec(std::ptr::null(), other.as_ptr(), team.as_ptr(), bad.as_ptr())
        };
        assert!(
            !zones().is_supervised(&ProcId::macos(other)),
            "an unknown binary stays personal"
        );
    }

    #[test]
    fn load_policy_rejects_garbage_and_keeps_prior() {
        let garbage = b"not json";
        // SAFETY: valid byte slice.
        assert!(!unsafe { clave_mac_load_policy_json(garbage.as_ptr(), garbage.len()) });
        // SAFETY: null is handled (fail-closed).
        assert!(!unsafe { clave_mac_load_policy_json(std::ptr::null(), 0) });
    }

    #[test]
    fn auth_open_gate_allows_only_supervised_callers() {
        // Uses the process-global zone mirror; a token unique to this test avoids cross-test races.
        let token = [0xA0u32, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
        let ptr = token.as_ptr();
        // SAFETY: `ptr` points to 8 readable, aligned u32s.
        assert!(
            !unsafe { clave_mac_can_access_volume(ptr) },
            "a personal caller is denied"
        );
        zones().join(ProcId::macos(token), JoinReason::Launcher);
        // SAFETY: same contract.
        assert!(
            unsafe { clave_mac_can_access_volume(ptr) },
            "a supervised caller is allowed"
        );
        // SAFETY: null is handled (fail-closed).
        assert!(
            !unsafe { clave_mac_can_access_volume(std::ptr::null()) },
            "a null token denies"
        );
    }
}
