use crate::policy::{PolicyBundle, UnixTime};
use crate::zone::ZoneRegistry;
use clave_platform::{ClipFormat, Decision, ProcId, Zone};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    ClipboardTransfer {
        src: Zone,
        dst: Zone,
        fmt: ClipFormat,
    },
    FileOpen {
        proc: ProcId,
        inside_enclave: bool,
        access: Access,
    },
    NetConnect {
        proc: ProcId,
        host: String,
    },
    /// A process is capturing the screen. Only reported while work windows are actually visible —
    /// a screenshot of a purely personal desktop is never instrumented (doc 01).
    ScreenCapture {
        /// The capturing process, if it could be identified.
        proc: Option<ProcId>,
        /// Its executable name, matched against the policy's sanctioned capture tools.
        exe: String,
    },
    /// A process holds a keyboard event tap. Only reported while a work app has focus — what a
    /// keylogger reads from the user's own apps is not ours to police (doc 01).
    InputTap {
        proc: Option<ProcId>,
        exe: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    Clipboard,
    FileWrite,
    FileAccess,
    EnclaveIntrusion,
    Network,
    ScreenCapture,
    InputTap,
    PolicyExpired,
    NotSupervised,
    Default,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub decision: Decision,
    pub reason: Reason,
}

impl Verdict {
    pub fn of(decision: Decision, reason: Reason) -> Self {
        Self { decision, reason }
    }
    pub fn allow(reason: Reason) -> Self {
        Self::of(Decision::Allow, reason)
    }
    pub fn deny(reason: Reason) -> Self {
        Self::of(Decision::Deny, reason)
    }
    pub fn is_allow(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }
}

pub fn decide(act: &Action, zones: &ZoneRegistry, pol: &PolicyBundle, now: UnixTime) -> Verdict {
    if now > pol.not_after {
        return Verdict::deny(Reason::PolicyExpired);
    }

    match act {
        Action::ClipboardTransfer { src, dst, fmt } => {
            Verdict::of(clip_decision(*src, *dst, *fmt, pol), Reason::Clipboard)
        }

        Action::FileOpen {
            proc,
            inside_enclave,
            access,
        } => {
            let supervised = zones.is_supervised(proc);
            match (inside_enclave, supervised) {
                (true, false) => Verdict::deny(Reason::EnclaveIntrusion),
                (true, true) => Verdict::allow(Reason::FileAccess),
                (false, true)
                    if matches!(access, Access::Write) && !pol.files.allow_save_outside_enclave =>
                {
                    Verdict::deny(Reason::FileWrite)
                }
                (false, true) => Verdict::allow(Reason::FileAccess),
                (false, false) => Verdict::allow(Reason::NotSupervised),
            }
        }

        Action::NetConnect { proc, host } => {
            if !zones.is_supervised(proc) {
                Verdict::allow(Reason::NotSupervised)
            } else if pol.network.is_blocked(host) {
                Verdict::deny(Reason::Network)
            } else {
                Verdict::allow(Reason::Network)
            }
        }

        // Reported only while work content is on screen (the OS layer establishes that), so this is
        // always a capture *of the enclave*. A work process capturing its own zone is in-bounds; a
        // sanctioned tool is permitted by policy; anything else is the exfil case.
        Action::ScreenCapture { proc, exe } => {
            let in_zone = proc.is_some_and(|p| zones.is_supervised(&p));
            if in_zone || pol.screen.is_allowed_capturer(exe) {
                Verdict::allow(Reason::ScreenCapture)
            } else {
                Verdict::of(pol.screen.on_capture, Reason::ScreenCapture)
            }
        }

        // Reported only while a work app has focus, so the tap is reading enclave keystrokes. A work
        // process tapping inside its own zone is in-bounds; a sanctioned tool is permitted; anything
        // else is a keylogger as far as policy is concerned.
        Action::InputTap { proc, exe } => {
            let in_zone = proc.is_some_and(|p| zones.is_supervised(&p));
            if in_zone || pol.input.is_allowed_tapper(exe) {
                Verdict::allow(Reason::InputTap)
            } else {
                Verdict::of(pol.input.on_tap, Reason::InputTap)
            }
        }
    }
}

pub fn clip_decision(src: Zone, dst: Zone, fmt: ClipFormat, pol: &PolicyBundle) -> Decision {
    match (src, dst) {
        (Zone::Work, Zone::Work) => Decision::Allow,
        (Zone::Personal, Zone::Personal) => Decision::Allow,
        (Zone::Work, Zone::Personal) => pol.clipboard.work_to_personal(fmt),
        (Zone::Personal, Zone::Work) => pol.clipboard.personal_to_work(fmt),
    }
}
