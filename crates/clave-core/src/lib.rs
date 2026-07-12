//! # clave-core
//!
//! The portable policy brain. Pure logic, **no OS calls**, `#![forbid(unsafe_code)]`. It
//! decides; the platform adapters enforce.
//!
//! * [`zone`] — the in-memory zone-membership mirror.
//! * [`policy`] — the signed, versioned policy model and its per-subsystem sub-policies.
//! * [`decide`] — the single, pure, fail-closed [`decide`](decide::decide) contract.
//! * [`audit`] — the privacy-by-schema audit event (no field can hold personal data).
#![forbid(unsafe_code)]

pub mod app;
pub mod audit;
pub mod decide;
pub mod learn;
pub mod net;
pub mod overlay;
pub mod path;
pub mod policy;
pub mod zone;

pub use app::{
    classify_exec, AppId, AppPolicy, AppRule, BinaryMatch, ContainerKind, ExecVerdict,
    LaunchProfile, LaunchSpec, LaunchableApp, ResolvedLaunch,
};
pub use audit::{AuditAction, AuditEvent, AuditSink, NoopAuditSink};
pub use decide::{clip_decision, decide, Access, Action, Reason, Verdict};
pub use learn::{LearnSession, LearnedProfile, Observation};
pub use net::classify_flow;
pub use overlay::{
    recompute_frames, recompute_frames_themed, BorderCfg, Frame, RectPx, WindowGeom,
};
pub use path::{classify_path, PathClass};
pub use policy::{
    ClipboardPolicy, FilePolicy, NetworkPolicy, OverlayPolicy, PolicyBundle, UnixTime,
};
pub use zone::{JoinReason, ZoneMember, ZoneRegistry};
