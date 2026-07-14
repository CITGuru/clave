#![forbid(unsafe_code)]

use clave_core::{Action, AppId, LaunchSpec, LaunchableApp, Verdict, WebAppInfo};
use clave_platform::WindowId;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(any(unix, windows))]
pub mod transport;

pub const PROTO_VERSION: u16 = 6;

pub const MAX_FRAME: usize = 1 << 20;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ShimMsg {
    Hello { proto: u16, nonce: u64 },
    RequestDecision { req_id: u64, action: Action },
    WindowCreated { window: WindowId },
    WindowDestroyed { window: WindowId },
    Heartbeat,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DaemonMsg {
    Welcome { proto: u16 },
    Decision { req_id: u64, verdict: Verdict },
    PolicyVersion { version: u64 },
    Wipe,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LauncherRequest {
    Hello { proto: u16 },
    ListApps,
    PrepareLaunch { app_id: AppId },
    Launch { app_id: AppId },
    Enforcement,
    Status,
    ListWebApps,
    LaunchWeb { app_id: AppId },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LauncherReply {
    Welcome { proto: u16 },
    Apps { apps: Vec<LaunchableApp> },
    LaunchSpec { spec: Option<LaunchSpec> },
    Launched { pid: Option<u32> },
    LaunchFailed { error: String },
    Enforcement { caps: Vec<(String, String)> },
    Status { status: LauncherStatus },
    WebApps { apps: Vec<WebAppInfo> },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LauncherStatus {
    pub tenant: u64,
    pub policy_version: u64,
    pub volume_unlocked: bool,
    pub mount_point: Option<String>,
    pub gateway_high_water: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooLarge,
    Malformed,
}

pub fn encode<T: Serialize>(msg: &T) -> Vec<u8> {
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

pub fn try_decode<T: DeserializeOwned>(buf: &[u8]) -> Result<Option<(T, usize)>, FrameError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    let end = 4 + len;
    if buf.len() < end {
        return Ok(None);
    }
    match postcard::from_bytes::<T>(&buf[4..end]) {
        Ok(msg) => Ok(Some((msg, end))),
        Err(_) => Err(FrameError::Malformed),
    }
}
