//! Capability traits — the behaviours each OS adapter must provide.
//!
//! `clave-core` programs against these, never against a concrete OS type. A `MockPlatform`
//! (in `clave-testkit`, a later milestone) implements them with in-memory state so the whole
//! daemon can be integration-tested with no driver installed.

use crate::enforcement::{Capability, EnforcementReport, EnforcementStatus};
use crate::types::{ClipFormat, Decision, ProcId, Rgba, Route, WindowId, Zone};

/// Minimal, portable error surface for platform operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    AccessDenied,
    NotFound,
    Unsupported,
    Io(String),
}

pub type PResult<T> = Result<T, PlatformError>;

/// Who is in the work zone. The authoritative copy lives in the kernel driver (Windows) /
/// Endpoint Security client (macOS); this trait is how the core asks.
pub trait ProcessSupervisor: Send + Sync {
    fn is_supervised(&self, p: &ProcId) -> bool;
    fn supervised_count(&self) -> usize;
}

/// The **OS mount / presentation layer** for the encrypted Clave Disk — distinct from the crypto
/// core (`clave_volume::ClaveVolume`, owned by the daemon). This exposes the *decrypted view* at a
/// path/drive-letter and tears it down; the per-sector crypto runs through the shared `ClaveVolume`.
/// Windows: WinFsp. macOS: encrypted APFS / sparsebundle.
pub trait VolumeMount: Send + Sync {
    /// Whether the decrypted filesystem view is mounted/visible to apps. This is the *OS mount*
    /// state — distinct from `ClaveVolume::is_unlocked` (whether the DEK is loaded).
    fn is_mounted(&self) -> bool;
    /// Where the view is mounted (drive letter / `/Volumes/ClaveDisk`), if mounted.
    fn mount_point(&self) -> Option<String>;
    /// Tear down the mount and unlink the container blob. The **authoritative** crypto-shred is
    /// the volume core's `ClaveVolume::wipe` (destroy the wrapped key); this is the best-effort
    /// OS-side cleanup the daemon calls alongside it.
    fn request_wipe(&self) -> PResult<()>;
}

/// Clipboard / drag-drop gating. The concrete impl enforces; the *decision* is the core's
/// `clip_decision`.
pub trait ClipboardBroker: Send + Sync {
    fn classify_and_gate(&self, src: Zone, dst: Zone, fmt: ClipFormat) -> Decision;
}

/// Per-flow split-tunnel routing.
pub trait NetworkTunnel: Send + Sync {
    /// `dst_blocked` is the policy allowlist result, computed by the core.
    fn route(&self, proc: &ProcId, dst_blocked: bool) -> Route;
}

/// Screen-capture protection for a work window.
pub trait ScreenGuard: Send + Sync {
    fn protect_window(&self, w: WindowId) -> PResult<()>;
}

/// The Clave Edge overlay tracker.
pub trait WindowOverlay: Send + Sync {
    fn track(&self, w: WindowId, color: Rgba);
    fn untrack(&self, w: WindowId);
}

/// Anti-keylogging posture.
pub trait InputGuard: Send + Sync {
    fn protect_input_enabled(&self) -> bool;
}

/// The aggregate a `clave-daemon` is handed: one object exposing every capability.
///
/// Accessors return `&dyn` so the daemon can hold a single `Box<dyn Platform>` chosen at
/// startup by target OS (or a mock in tests).
pub trait Platform: Send + Sync + 'static {
    fn supervisor(&self) -> &dyn ProcessSupervisor;
    fn volume(&self) -> &dyn VolumeMount;
    fn clipboard(&self) -> &dyn ClipboardBroker;
    fn network(&self) -> &dyn NetworkTunnel;
    fn screen(&self) -> &dyn ScreenGuard;
    fn overlay(&self) -> &dyn WindowOverlay;
    fn input(&self) -> &dyn InputGuard;

    /// Report a capability's enforcement posture: production-`Enforced`, a
    /// `DevelopmentOnly` stand-in, or `Unavailable`. A mock answers `DevelopmentOnly`; a real
    /// adapter inspects entitlements / driver signing / TCC grants / SIP at runtime.
    fn enforcement(&self, cap: Capability) -> EnforcementStatus;

    /// Aggregate posture across every [`Capability`]. The product surfaces this; a production CI
    /// gate asserts [`EnforcementReport::is_production_ready`] so a dev-only fallback can't ship
    /// silently.
    fn enforcement_report(&self) -> EnforcementReport {
        EnforcementReport::from_fn(|cap| self.enforcement(cap))
    }
}
