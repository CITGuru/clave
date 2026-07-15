use crate::enforcement::{Capability, EnforcementReport, EnforcementStatus};
use crate::types::{ClipFormat, Decision, ProcId, Rgba, Route, WindowId, Zone};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    AccessDenied,
    NotFound,
    Unsupported,
    Io(String),
}

pub type PResult<T> = Result<T, PlatformError>;

pub trait ProcessSupervisor: Send + Sync {
    fn is_supervised(&self, p: &ProcId) -> bool;
    fn supervised_count(&self) -> usize;
}

/// OS-level containment of a launched process and its descendants (Windows Job Objects, doc
/// appendix A.1). `contain` places a process under the boundary; `contained_pids` reports the
/// live members so the daemon can reconcile the work zone with the process tree the OS is
/// actually holding — children a work app spawns join the zone without a separate exec hook.
pub trait ProcessContainment: Send + Sync {
    fn contain(&self, pid: u32) -> PResult<()>;
    fn contained_pids(&self) -> Vec<u32>;
}

pub trait VolumeMount: Send + Sync {
    fn is_mounted(&self) -> bool;
    fn mount_point(&self) -> Option<String>;
    fn request_wipe(&self) -> PResult<()>;
}

pub trait ClipboardBroker: Send + Sync {
    fn classify_and_gate(&self, src: Zone, dst: Zone, fmt: ClipFormat) -> Decision;
}

pub trait NetworkTunnel: Send + Sync {
    fn route(&self, proc: &ProcId, dst_blocked: bool) -> Route;
}

pub trait ScreenGuard: Send + Sync {
    fn protect_window(&self, w: WindowId) -> PResult<()>;
}

pub trait WindowOverlay: Send + Sync {
    fn track(&self, w: WindowId, color: Rgba);
    fn untrack(&self, w: WindowId);
}

pub trait InputGuard: Send + Sync {
    fn protect_input_enabled(&self) -> bool;
}

pub trait Platform: Send + Sync + 'static {
    fn supervisor(&self) -> &dyn ProcessSupervisor;
    fn volume(&self) -> &dyn VolumeMount;
    fn clipboard(&self) -> &dyn ClipboardBroker;
    fn network(&self) -> &dyn NetworkTunnel;
    fn screen(&self) -> &dyn ScreenGuard;
    fn overlay(&self) -> &dyn WindowOverlay;
    fn input(&self) -> &dyn InputGuard;

    fn enforcement(&self, cap: Capability) -> EnforcementStatus;

    /// OS process containment for launched work apps, if this platform provides one.
    /// `None` means the platform cannot contain a process tree (the daemon then relies only on
    /// the pid it spawned joining the zone).
    fn containment(&self) -> Option<&dyn ProcessContainment> {
        None
    }

    fn enforcement_report(&self) -> EnforcementReport {
        EnforcementReport::from_fn(|cap| self.enforcement(cap))
    }
}
