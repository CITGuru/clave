//! # clave-ipc
//!
//! The message contracts that cross Clave's trust boundaries, plus the wire framing.
//!
//! Transport is per-link (named pipes / XPC / Unix sockets); this crate is
//! transport-agnostic. It defines:
//!
//! * the message enums ([`ShimMsg`], [`DaemonMsg`]), and
//! * a compact, **panic-free** length-prefixed [`postcard`] codec ([`encode`], [`try_decode`]).
//!
//! ## Security note
//!
//! [`try_decode`] parses bytes from the semi-trusted shim (potentially hostile input): it must never
//! panic, never over-allocate without bound, and reject malformed frames cleanly. [`MAX_FRAME`]
//! bounds per-frame allocation; `tests/framing.rs` asserts panic-freedom over arbitrary bytes.
#![forbid(unsafe_code)]

use clave_core::{Action, AppId, LaunchSpec, LaunchableApp, Verdict};
use clave_platform::WindowId;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Authenticated socket transport (Unix-domain sockets). See [`transport`]. Unix-only; the
/// Windows named-pipe equivalent is future work.
#[cfg(unix)]
pub mod transport;

/// Bumped on any wire-incompatible change. Exchanged in the handshake so a daemon and a shim
/// of mismatched versions refuse rather than misparse.
pub const PROTO_VERSION: u16 = 3;

/// Hard cap on a single frame's body. Bounds the allocation an attacker can induce via the
/// length prefix. 1 MiB is generous for control messages; bulk data never crosses this link.
pub const MAX_FRAME: usize = 1 << 20;

/// Messages the (semi-trusted) shim sends to the daemon. The shim *requests*; the daemon
/// *decides* using kernel-authoritative identity — it never trusts a zone claim from here.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ShimMsg {
    /// First message after connect; carries the per-launch nonce handed to the shim at
    /// injection time so the daemon can bind this channel to that launch.
    Hello { proto: u16, nonce: u64 },
    /// Ask the daemon to adjudicate an intercepted operation.
    RequestDecision { req_id: u64, action: Action },
    /// A new top-level work window appeared (for overlay + screen protection).
    WindowCreated { window: WindowId },
    /// A work window went away.
    WindowDestroyed { window: WindowId },
    /// Liveness ping.
    Heartbeat,
}

/// Messages the daemon sends back to a shim.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DaemonMsg {
    /// Accepts the handshake.
    Welcome { proto: u16 },
    /// The verdict for a prior [`ShimMsg::RequestDecision`].
    Decision { req_id: u64, verdict: Verdict },
    /// Notifies of a policy version change (the shim may re-request affected decisions).
    PolicyVersion { version: u64 },
    /// Tear down: the enclave is being wiped/locked.
    Wipe,
}

/// Requests the Clave launcher UI sends to the daemon — a separate channel from [`ShimMsg`]. The
/// launcher only ever asks for the catalog, a launch spec, a launch, or the enforcement posture; it
/// never adjudicates policy. The daemon authenticates it by peer credentials at accept time.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LauncherRequest {
    /// First message: negotiate the protocol version (mirrors [`ShimMsg::Hello`] without a nonce —
    /// the UI is identified by its peer uid, not a per-launch injection token).
    Hello { proto: u16 },
    /// List the allow-listed work apps that carry an executable (the launcher grid).
    ListApps,
    /// Resolve the contained spawn spec for one app (executable + redirected env).
    PrepareLaunch { app_id: AppId },
    /// Spawn one app **contained** and seed it into the supervised zone set. Unlike
    /// [`LauncherRequest::PrepareLaunch`] (which only resolves the spec), this actually launches the
    /// process — the daemon is authoritative.
    Launch { app_id: AppId },
    /// This OS adapter's enforcement posture, for the UI's honest status display.
    Enforcement,
}

/// Replies the daemon sends back to the launcher UI, answering a [`LauncherRequest`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LauncherReply {
    /// Accepts the handshake.
    Welcome { proto: u16 },
    /// The launch catalog for [`LauncherRequest::ListApps`].
    Apps { apps: Vec<LaunchableApp> },
    /// The resolved spec for [`LauncherRequest::PrepareLaunch`] — `None` if the app is unknown / not
    /// launchable, or the Clave Disk is not mounted.
    LaunchSpec { spec: Option<LaunchSpec> },
    /// The result of [`LauncherRequest::Launch`]: the spawned pid, or `None` if the launch was
    /// refused (unknown / not launchable / disk unmounted) or the spawn failed.
    Launched { pid: Option<u32> },
    /// `capability → status` posture pairs for [`LauncherRequest::Enforcement`].
    Enforcement { caps: Vec<(String, String)> },
}

/// Framing errors. `Malformed`/`TooLarge` are protocol violations — the caller should drop
/// the peer. (Incomplete is represented as `Ok(None)`, not an error.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Length prefix exceeded [`MAX_FRAME`].
    TooLarge,
    /// The body did not deserialize to the expected type.
    Malformed,
}

/// Serialize `msg` into a `[u32 little-endian length][postcard body]` frame.
pub fn encode<T: Serialize>(msg: &T) -> Vec<u8> {
    // postcard serialization of our own POD types is infallible; a failure here is a bug.
    let body = postcard::to_allocvec(msg).expect("postcard serialize of a control message");
    debug_assert!(
        body.len() <= MAX_FRAME,
        "control message exceeded MAX_FRAME"
    );
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Try to decode exactly one frame from the front of `buf`.
///
/// * `Ok(Some((msg, consumed)))` — a complete frame was decoded; advance the buffer by
///   `consumed` bytes.
/// * `Ok(None)` — the buffer holds a partial frame; read more bytes and retry.
/// * `Err(_)` — a protocol violation; drop the connection.
///
/// Panic-free for **all** inputs (it reads untrusted bytes).
pub fn try_decode<T: DeserializeOwned>(buf: &[u8]) -> Result<Option<(T, usize)>, FrameError> {
    if buf.len() < 4 {
        return Ok(None); // not even a full length prefix yet
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    let end = 4 + len;
    if buf.len() < end {
        return Ok(None); // body not fully arrived
    }
    match postcard::from_bytes::<T>(&buf[4..end]) {
        Ok(msg) => Ok(Some((msg, end))),
        Err(_) => Err(FrameError::Malformed),
    }
}
