use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use clave_core::PolicyBundle;
use clave_identity::{UnixTime, WorkspaceId};
use clave_proto::{GatewayCommand, GatewaySigningKey, SignedCommand};

use crate::GatewayError;

pub trait CounterStore: Send + Sync {
    fn next(&self) -> Result<u64, GatewayError>;
    fn current(&self) -> u64;
}

pub struct MemCounter(AtomicU64);

impl MemCounter {
    pub fn new(start: u64) -> Self {
        Self(AtomicU64::new(start))
    }
}

impl Default for MemCounter {
    fn default() -> Self {
        Self::new(0)
    }
}

impl CounterStore for MemCounter {
    fn next(&self) -> Result<u64, GatewayError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn current(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub struct FileCounter {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileCounter {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    fn read_current(&self) -> u64 {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }
}

impl CounterStore for FileCounter {
    fn next(&self) -> Result<u64, GatewayError> {
        let _g = self.lock.lock().expect("counter lock poisoned");
        let next = self.read_current() + 1;
        let mut tmp = self.path.clone();
        let mut name = tmp.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        tmp.set_file_name(name);
        std::fs::write(&tmp, next.to_string())
            .and_then(|()| std::fs::rename(&tmp, &self.path))
            .map_err(|e| GatewayError::Counter(format!("persist counter: {e}")))?;
        Ok(next)
    }
    fn current(&self) -> u64 {
        let _g = self.lock.lock().expect("counter lock poisoned");
        self.read_current()
    }
}

#[async_trait]
pub trait PolicyIssuer: Send + Sync {
    async fn issue_initial_policy(
        &self,
        workspace: WorkspaceId,
        now: UnixTime,
    ) -> Result<Option<SignedCommand>, GatewayError>;

    async fn current_policy(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Option<PolicyBundle>, GatewayError>;

    async fn author_policy(
        &self,
        workspace: WorkspaceId,
        bundle: PolicyBundle,
    ) -> Result<PolicyBundle, GatewayError>;

    async fn reissue_policy(
        &self,
        workspace: WorkspaceId,
        now: UnixTime,
    ) -> Result<Option<SignedCommand>, GatewayError>;

    async fn policy_versions(&self, workspace: WorkspaceId) -> Result<Vec<u64>, GatewayError>;
}

pub struct MemPolicyIssuer {
    signer: GatewaySigningKey,
    policies: Mutex<HashMap<WorkspaceId, Vec<PolicyBundle>>>,
    counter: Box<dyn CounterStore>,
}

impl MemPolicyIssuer {
    pub fn new(signer: GatewaySigningKey) -> Self {
        Self::with_counter(signer, Box::new(MemCounter::default()))
    }

    pub fn with_counter(signer: GatewaySigningKey, counter: Box<dyn CounterStore>) -> Self {
        Self {
            signer,
            policies: Mutex::new(HashMap::new()),
            counter,
        }
    }

    pub fn set_policy(&self, workspace: WorkspaceId, bundle: PolicyBundle) {
        self.policies.lock().unwrap().insert(workspace, vec![bundle]);
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    fn current(&self, workspace: WorkspaceId) -> Option<PolicyBundle> {
        self.policies
            .lock()
            .unwrap()
            .get(&workspace)
            .and_then(|h| h.last().cloned())
    }

    fn sign_current(
        &self,
        workspace: WorkspaceId,
        now: UnixTime,
    ) -> Result<Option<SignedCommand>, GatewayError> {
        let bundle = match self.current(workspace) {
            Some(b) => b,
            None => return Ok(None),
        };
        let counter = self.counter.next()?;
        Ok(Some(self.signer.sign(
            counter,
            now,
            GatewayCommand::UpdatePolicy(Box::new(bundle)),
        )))
    }
}

#[async_trait]
impl PolicyIssuer for MemPolicyIssuer {
    async fn issue_initial_policy(
        &self,
        workspace: WorkspaceId,
        now: UnixTime,
    ) -> Result<Option<SignedCommand>, GatewayError> {
        self.sign_current(workspace, now)
    }

    async fn current_policy(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Option<PolicyBundle>, GatewayError> {
        Ok(self.current(workspace))
    }

    async fn author_policy(
        &self,
        workspace: WorkspaceId,
        mut bundle: PolicyBundle,
    ) -> Result<PolicyBundle, GatewayError> {
        let mut policies = self.policies.lock().unwrap();
        let history = policies.entry(workspace).or_default();
        bundle.version = history.last().map(|b| b.version + 1).unwrap_or(1);
        history.push(bundle.clone());
        Ok(bundle)
    }

    async fn reissue_policy(
        &self,
        workspace: WorkspaceId,
        now: UnixTime,
    ) -> Result<Option<SignedCommand>, GatewayError> {
        self.sign_current(workspace, now)
    }

    async fn policy_versions(&self, workspace: WorkspaceId) -> Result<Vec<u64>, GatewayError> {
        Ok(self
            .policies
            .lock()
            .unwrap()
            .get(&workspace)
            .map(|h| h.iter().map(|b| b.version).collect())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_counter_increments_and_resumes_from_seed() {
        let c = MemCounter::new(0);
        assert_eq!(c.next().unwrap(), 1);
        assert_eq!(c.next().unwrap(), 2);
        assert_eq!(c.current(), 2);
        assert_eq!(MemCounter::new(2).next().unwrap(), 3);
    }

    #[test]
    fn file_counter_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("clave-counter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("counter");

        let c1 = FileCounter::new(&path);
        assert_eq!(c1.next().unwrap(), 1);
        assert_eq!(c1.next().unwrap(), 2);

        let c2 = FileCounter::new(&path);
        assert_eq!(c2.current(), 2);
        assert_eq!(
            c2.next().unwrap(),
            3,
            "the counter resumes above the persisted high-water"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
