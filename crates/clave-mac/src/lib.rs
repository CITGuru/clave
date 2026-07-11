//! # clave-mac — macOS platform adapter (Phase 2 scaffold)
//!
//! macOS enforcement runs in two **Swift System Extensions** that link this
//! crate as a `staticlib` and call the C ABI below:
//!
//! * an **Endpoint Security** client (exec/file authorization) → [`clave_mac_zone_join`] /
//!   [`clave_mac_zone_leave`];
//! * a **`NETransparentProxyProvider`** (split tunnel) → [`clave_mac_route_flow`].
//!
//! Building/running those Swift extensions needs the Endpoint Security + Network Extension
//! entitlements (Apple approval) and notarization — they are **not** built in CI here.
//! What *is* built and tested here is this Rust core: the audit-token → zone classification and
//! the stable C ABI. The Swift host skeleton is in `swift/`.
//!
//! `unsafe` is confined to the thin FFI boundary (unsafe lives in OS adapters).

use clave_core::{JoinReason, ZoneRegistry};
use clave_platform::{ProcId, Route};
use std::sync::OnceLock;

mod platform;
pub use platform::MacPlatform;

/// Process-global zone mirror, fed by the ES client at exec/exit. (A production adapter would
/// scope this to the daemon connection; a `OnceLock` keeps the scaffold simple.)
static ZONES: OnceLock<ZoneRegistry> = OnceLock::new();

fn zones() -> &'static ZoneRegistry {
    ZONES.get_or_init(ZoneRegistry::new)
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

/// C ABI for the ES client: a binary joined the work zone (matched the signed allow-list at
/// `AUTH_EXEC`).
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
