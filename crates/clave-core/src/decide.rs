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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    Clipboard,
    FileWrite,
    FileAccess,
    EnclaveIntrusion,
    Network,
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
