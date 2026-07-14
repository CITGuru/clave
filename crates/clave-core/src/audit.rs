use crate::app::AppId;
use crate::decide::Verdict;
use crate::policy::UnixTime;
use clave_platform::Zone;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: UnixTime,
    pub zone: Zone,
    pub action: AuditAction,
    pub verdict: Verdict,
    #[serde(default)]
    pub app_id: Option<AppId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    ClipboardBlocked,
    ClipboardSanitized,
    FileSaveDenied,
    EnclaveIntrusionBlocked,
    NetworkBlocked,
    ScreenCaptureOverWork,
    InputTapOverWork,
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
            app_id: None,
        }
    }

    pub fn with_app_id(mut self, app_id: AppId) -> Self {
        self.app_id = Some(app_id);
        self
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::Reason;

    #[test]
    fn app_id_is_optional_and_survives_json() {
        let base = AuditEvent::new(
            7,
            AuditAction::ClipboardBlocked,
            Verdict::deny(Reason::Clipboard),
        );
        assert_eq!(base.app_id, None);

        let tagged = base.clone().with_app_id(AppId("excel-work".into()));
        assert_eq!(tagged.app_id, Some(AppId("excel-work".into())));
        assert_ne!(base, tagged);

        let json = serde_json::to_string(&tagged).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tagged);
    }
}
