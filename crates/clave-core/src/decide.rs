//! The decision contract — the single, pure, fail-closed entry point the whole system funnels
//! through.
//!
//! Properties this module guarantees:
//! * **Pure & deterministic** — no I/O, no ambient clock; `now` is a parameter.
//! * **Fail-closed** — an expired policy denies *everything*, before any per-action logic.
//! * **Explainable** — every [`Verdict`] carries a [`Reason`] for audit and user prompts.

use crate::policy::{PolicyBundle, UnixTime};
use crate::zone::ZoneRegistry;
use clave_platform::{ClipFormat, Decision, ProcId, Zone};
use serde::{Deserialize, Serialize};

/// Whether a file open is a read or a write. The enclave gate cares about **both** directions:
/// a personal process must not *read* the Clave Disk (data-at-rest confidentiality), and a work
/// process must not *write* work data outside it (containment).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Access {
    Read,
    Write,
}

/// An operation the policy brain adjudicates. Constructed by the platform adapters from
/// intercepted OS events and shipped over `clave-ipc` as decision requests (hence `Serialize`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// A clipboard or drag-drop transfer of `fmt` from `src` zone to `dst` zone.
    ClipboardTransfer {
        src: Zone,
        dst: Zone,
        fmt: ClipFormat,
    },
    /// A process opening a path. `inside_enclave` is whether the target lives on the Clave Disk;
    /// `access` is the direction. This is the single decision the minifilter / ES `AUTH_OPEN`
    /// consults, and it gates both directions: a personal (unsupervised)
    /// process may never touch the enclave, and a supervised process may not write work data
    /// outside it.
    FileOpen {
        proc: ProcId,
        inside_enclave: bool,
        access: Access,
    },
    /// A process initiating an outbound connection to `host`.
    NetConnect { proc: ProcId, host: String },
}

/// Why a [`Verdict`] came out the way it did. Surfaced in the audit log and user prompts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    Clipboard,
    /// A supervised process tried to write work data outside the enclave — fail-closed escape.
    FileWrite,
    /// A file access was permitted (a contained work access, or a supervised read outside).
    FileAccess,
    /// A non-supervised (personal) process tried to open the Clave Disk — denied. Personal apps
    /// can neither read nor write the enclave, ever.
    EnclaveIntrusion,
    Network,
    /// The policy bundle was past its `not_after` — fail-closed.
    PolicyExpired,
    /// The acting process is not in the work zone, so the enclave does not govern it.
    NotSupervised,
    Default,
}

/// A decision plus its justification.
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

/// The one function every enforcement point consults.
///
/// `zones` is the membership mirror, `pol` the active bundle, `now` the caller-supplied time.
/// Returns a fully-explained [`Verdict`].
pub fn decide(act: &Action, zones: &ZoneRegistry, pol: &PolicyBundle, now: UnixTime) -> Verdict {
    // Fail-closed gate first: an expired (or never-refreshed-and-since-expired) bundle denies
    // every action regardless of its nature. A device that loses contact with the gateway
    // long enough loses *new* capability but never silently fails open.
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
                // Intrusion: a personal (unsupervised) process may never read or write the
                // Clave Disk — "no process outside the zone can open the Clave Disk". This
                // is the read/open half the escape-only model was missing;
                // without it a personal app opening the disk fell through to Allow.
                (true, false) => Verdict::deny(Reason::EnclaveIntrusion),
                // A supervised work app using its own encrypted disk — allowed.
                (true, true) => Verdict::allow(Reason::FileAccess),
                // Outside the enclave, supervised: only a *write* of work data is an escape;
                // a read of a system path (a library, a font) is fine.
                (false, true)
                    if matches!(access, Access::Write) && !pol.files.allow_save_outside_enclave =>
                {
                    Verdict::deny(Reason::FileWrite)
                }
                (false, true) => Verdict::allow(Reason::FileAccess),
                // Personal process outside the enclave — not the enclave's business.
                (false, false) => Verdict::allow(Reason::NotSupervised),
            }
        }

        Action::NetConnect { proc, host } => {
            if !zones.is_supervised(proc) {
                // Personal flow — not the enclave's business; it will route direct.
                Verdict::allow(Reason::NotSupervised)
            } else if pol.network.is_blocked(host) {
                Verdict::deny(Reason::Network)
            } else {
                Verdict::allow(Reason::Network)
            }
        }
    }
}

/// The clipboard/drag matrix. Same-zone transfers are always allowed; cross-zone transfers
/// defer to policy. Kept separate (and public) so the platform `ClipboardBroker` and the
/// tests can exercise the matrix directly.
pub fn clip_decision(src: Zone, dst: Zone, fmt: ClipFormat, pol: &PolicyBundle) -> Decision {
    match (src, dst) {
        (Zone::Work, Zone::Work) => Decision::Allow,
        (Zone::Personal, Zone::Personal) => Decision::Allow,
        (Zone::Work, Zone::Personal) => pol.clipboard.work_to_personal(fmt),
        (Zone::Personal, Zone::Work) => pol.clipboard.personal_to_work(fmt),
    }
}
