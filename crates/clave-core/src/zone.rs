//! The in-memory zone-membership mirror. The authoritative set lives in the kernel driver
//! (Windows) / Endpoint Security client (macOS); this is the portable mirror the policy brain reads,
//! kept in sync via the driver/ESF event stream.

use clave_platform::{ProcId, ProcessSupervisor};
use std::collections::HashMap;
use std::sync::RwLock;

/// Why a process is in the zone — useful for audit and for the inheritance rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinReason {
    /// Seeded directly by the Clave launcher.
    Launcher,
    /// Inherited membership from a supervised parent.
    Child(ProcId),
    /// Matched a signed app allow-list entry.
    AllowList,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneMember {
    pub id: ProcId,
    pub reason: JoinReason,
}

/// Concurrent set of supervised processes.
#[derive(Default)]
pub struct ZoneRegistry {
    members: RwLock<HashMap<ProcId, ZoneMember>>,
}

impl ZoneRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a process to the zone (idempotent; re-join updates the reason).
    pub fn join(&self, id: ProcId, reason: JoinReason) {
        self.members
            .write()
            .expect("zone lock poisoned")
            .insert(id, ZoneMember { id, reason });
    }

    /// Remove a process (on exit). No-op if absent.
    pub fn leave(&self, id: &ProcId) {
        self.members.write().expect("zone lock poisoned").remove(id);
    }

    /// Hot-path membership test.
    pub fn is_supervised(&self, id: &ProcId) -> bool {
        self.members
            .read()
            .expect("zone lock poisoned")
            .contains_key(id)
    }

    pub fn member(&self, id: &ProcId) -> Option<ZoneMember> {
        self.members
            .read()
            .expect("zone lock poisoned")
            .get(id)
            .copied()
    }

    /// The OS process ids of every supervised process — the macOS Clave Edge overlay matches
    /// `CGWindowList` owner pids against this set. Deduplicated; order unspecified.
    pub fn supervised_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self
            .members
            .read()
            .expect("zone lock poisoned")
            .keys()
            .map(|id| id.pid())
            .collect();
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    pub fn len(&self) -> usize {
        self.members.read().expect("zone lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Replace the whole set (used on daemon restart / resync from the authoritative layer).
    pub fn reset_from<I: IntoIterator<Item = (ProcId, JoinReason)>>(&self, iter: I) {
        let mut g = self.members.write().expect("zone lock poisoned");
        g.clear();
        for (id, reason) in iter {
            g.insert(id, ZoneMember { id, reason });
        }
    }
}

/// The core's mirror can serve as a [`ProcessSupervisor`] for tests and the `MockPlatform`.
impl ProcessSupervisor for ZoneRegistry {
    fn is_supervised(&self, p: &ProcId) -> bool {
        ZoneRegistry::is_supervised(self, p)
    }
    fn supervised_count(&self) -> usize {
        self.len()
    }
}
