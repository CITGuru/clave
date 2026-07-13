use crate::decide::Verdict;
use crate::policy::UnixTime;
use clave_platform::Zone;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: UnixTime,
    pub zone: Zone,
    pub action: AuditAction,
    pub verdict: Verdict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    ClipboardBlocked,
    ClipboardSanitized,
    FileSaveDenied,
    EnclaveIntrusionBlocked,
    NetworkBlocked,
    ScreenCaptureOverWork,
    ProcessJoinedZone,
    ProcessLeftZone,
    VolumeMounted,
    VolumeUnmounted,
    Wiped,
}

impl AuditEvent {
    pub fn new(ts: UnixTime, action: AuditAction, verdict: Verdict) -> Self {
        Self {
            ts,
            zone: Zone::Work,
            action,
            verdict,
        }
    }
}

pub trait AuditSink: Send + Sync {
    fn emit(&self, event: AuditEvent);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn emit(&self, _event: AuditEvent) {}
}
