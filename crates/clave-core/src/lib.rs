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
pub use net::{
    classify_dns_flow, classify_flow, decide_dns, DnsDecision, DnsSteering, ForwardMode,
    Forwarding, NetworkProvider, ProviderError,
};
pub use overlay::{
    recompute_frames, recompute_frames_themed, BorderCfg, Frame, RectPx, WindowGeom,
};
pub use path::{classify_path, is_under_mount, PathClass};
pub use policy::{
    ClipboardPolicy, FilePolicy, NetworkPolicy, OverlayPolicy, PolicyBundle, UnixTime,
};
pub use zone::{JoinReason, ZoneMember, ZoneRegistry};
