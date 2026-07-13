use clave_platform::{ProcId, ProcessSupervisor};
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinReason {
    Launcher,
    Child(ProcId),
    AllowList,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneMember {
    pub id: ProcId,
    pub reason: JoinReason,
}

#[derive(Default)]
pub struct ZoneRegistry {
    members: RwLock<HashMap<ProcId, ZoneMember>>,
}

impl ZoneRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn join(&self, id: ProcId, reason: JoinReason) {
        self.members
            .write()
            .expect("zone lock poisoned")
            .insert(id, ZoneMember { id, reason });
    }

    pub fn leave(&self, id: &ProcId) {
        self.members.write().expect("zone lock poisoned").remove(id);
    }

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

    pub fn reset_from<I: IntoIterator<Item = (ProcId, JoinReason)>>(&self, iter: I) {
        let mut g = self.members.write().expect("zone lock poisoned");
        g.clear();
        for (id, reason) in iter {
            g.insert(id, ZoneMember { id, reason });
        }
    }
}

impl ProcessSupervisor for ZoneRegistry {
    fn is_supervised(&self, p: &ProcId) -> bool {
        ZoneRegistry::is_supervised(self, p)
    }
    fn supervised_count(&self) -> usize {
        self.len()
    }
}
