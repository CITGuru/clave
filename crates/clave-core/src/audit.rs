//! Privacy-by-schema audit events.
//!
//! The audit log is simultaneously the company's record *and* the user's privacy guarantee.
//! We enforce the guarantee structurally: there is **no field** in [`AuditEvent`] that can
//! hold a personal path, URL, keystroke, or clipboard *content*. A future contributor cannot
//! accidentally log personal data because the type system gives them nowhere to put it.

use crate::decide::Verdict;
use crate::policy::UnixTime;
use clave_platform::Zone;
use serde::{Deserialize, Serialize};

/// A single enforcement event, destined for the tamper-evident spool and the gateway.
///
/// Invariant: only **work-zone** enforcement is ever represented. Personal activity emits
/// nothing — there is no code path and no schema field for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: UnixTime,
    /// Always [`Zone::Work`] for emitted events; encoded for explicitness and forward-compat.
    pub zone: Zone,
    pub action: AuditAction,
    pub verdict: Verdict,
}

/// What happened. Note every variant names a *category* of work-side enforcement — never a
/// concrete resource. No `path`, `url`, `host`, or `content` payloads are carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    ClipboardBlocked,
    ClipboardSanitized,
    FileSaveDenied,
    /// A non-supervised (personal) process was denied access to the Clave Disk. Distinct
    /// from `FileSaveDenied` (a supervised escape) so the two failure modes are separable in audit.
    EnclaveIntrusionBlocked,
    NetworkBlocked,
    ScreenCaptureOverWork,
    ProcessJoinedZone,
    ProcessLeftZone,
    /// The encrypted Clave Disk was unlocked/mounted. A lifecycle event — it
    /// records *that* the enclave came up, never which files or paths it holds.
    VolumeMounted,
    /// The Clave Disk was locked/unmounted (DEK zeroized; reads now fail closed).
    VolumeUnmounted,
    Wiped,
}

impl AuditEvent {
    /// Construct a work-zone audit event. The `zone` is fixed to `Work` by construction so a
    /// personal event is unrepresentable.
    pub fn new(ts: UnixTime, action: AuditAction, verdict: Verdict) -> Self {
        Self {
            ts,
            zone: Zone::Work,
            action,
            verdict,
        }
    }
}

/// Where audit events go. The production sink hash-chains and spools them into the encrypted
/// volume, then drains to the gateway; tests use a recording sink.
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: AuditEvent);
}

/// Discards events. Useful as a default and in unit tests that don't assert on audit.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn emit(&self, _event: AuditEvent) {}
}
