//! The [`PolicyIssuer`] seam: the signed initial policy a device receives when it finishes enrolling.
//!
//! Enrollment proves *who* (WorkOS) and *whether* (`clave-identity`) and registers the device's
//! key; the last step is handing that device an authentic **policy bundle** so it boots governed.
//! The gateway is the only party that may change a device's posture, and it proves each command
//! with a tenant **Ed25519** signature (`clave-proto`); the device's pinned-key
//! [`GatewayVerifier`](clave_proto::GatewayVerifier) refuses anything else. So the bundle is issued
//! as a signed [`SignedCommand`]`::UpdatePolicy`, exactly like any later gateway command — the
//! initial sync is just the first one in the per-tenant counter sequence.
//!
//! This is a **seam** with an in-memory double ([`MemPolicyIssuer`]) so the control plane stays
//! testable with no HSM and no key material on disk. Production backs it with the tenant signing
//! key from the HSM and a DB-sourced, per-workspace policy bundle + a persistent monotonic counter.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use clave_core::PolicyBundle;
use clave_identity::{UnixTime, WorkspaceId};
use clave_proto::{GatewayCommand, GatewaySigningKey, SignedCommand};

use crate::GatewayError;

/// Durable source of the strictly-increasing per-tenant command counter — the anti-replay
/// primitive every signed command carries. Each [`next`](CounterStore::next) must
/// return a value strictly greater than every one previously returned **across the whole tenant
/// lifetime, including process restarts** — otherwise a device that has pinned a higher high-water
/// rejects the reissued command as a replay, and the device can never receive policy again.
pub trait CounterStore: Send + Sync {
    /// Allocate and durably persist the next counter, or fail closed if it cannot be persisted.
    fn next(&self) -> Result<u64, GatewayError>;
    /// The last value handed out (for diagnostics / persisting alongside other state).
    fn current(&self) -> u64;
}

/// In-memory counter for tests / the single-process bootstrap. **Not durable** — it rewinds to its
/// seed on restart, so a production deployment must supply a [`FileCounter`] or a DB/HSM-backed one.
pub struct MemCounter(AtomicU64);

impl MemCounter {
    /// Start above `start` (pass the last persisted high-water to resume without rewinding).
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

/// File-backed counter: reads the last value, increments, and **persists before returning** (temp
/// file + atomic rename), so a restart resumes above the persisted high-water instead of rewinding
/// to zero and colliding with the counters a device has already pinned. A portable stand-in for the
/// production durable sequence (a DB sequence or HSM monotonic counter). If the write fails, `next`
/// returns [`GatewayError::Counter`] and issues nothing — fail closed.
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

/// Issues the signed initial policy bundle a freshly-enrolled device receives.
/// Returning `None` means the workspace has no policy configured yet — enrollment still succeeds and
/// the device stays at its restrictive default until the first gateway sync delivers one.
#[async_trait]
pub trait PolicyIssuer: Send + Sync {
    /// Sign the current policy bundle for `workspace` as of `now` (the envelope's `issued_at`).
    async fn issue_initial_policy(
        &self,
        workspace: WorkspaceId,
        now: UnixTime,
    ) -> Result<Option<SignedCommand>, GatewayError>;
}

/// In-memory [`PolicyIssuer`] for tests/dev and the single-tenant bootstrap (mirrors
/// [`MockIdentityProvider`](crate::MockIdentityProvider) / [`MemStore`](crate::MemStore)). Holds one
/// tenant [`GatewaySigningKey`], a per-workspace bundle map, and a process-local monotonic counter.
///
/// One signing key ⇒ one tenant; the `workspace` argument only selects which bundle to sign. A
/// multi-tenant production issuer maps `workspace → tenant → key` and sources the counter from a
/// durable sequence so a restart can't rewind it.
pub struct MemPolicyIssuer {
    signer: GatewaySigningKey,
    policies: Mutex<HashMap<WorkspaceId, PolicyBundle>>,
    counter: Box<dyn CounterStore>,
}

impl MemPolicyIssuer {
    /// Build an issuer over a tenant signing key with an in-memory (non-durable) counter. No
    /// policies until [`MemPolicyIssuer::set_policy`]. For a deployment that must survive restart,
    /// prefer [`MemPolicyIssuer::with_counter`] and a [`FileCounter`] (or a DB/HSM-backed store).
    pub fn new(signer: GatewaySigningKey) -> Self {
        Self::with_counter(signer, Box::new(MemCounter::default()))
    }

    /// Build an issuer over a tenant signing key and an explicit durable [`CounterStore`], so the
    /// per-tenant command counter does not rewind across a gateway restart.
    pub fn with_counter(signer: GatewaySigningKey, counter: Box<dyn CounterStore>) -> Self {
        Self {
            signer,
            policies: Mutex::new(HashMap::new()),
            counter,
        }
    }

    /// Set (or replace) the policy bundle issued for `workspace`.
    pub fn set_policy(&self, workspace: WorkspaceId, bundle: PolicyBundle) {
        self.policies.lock().unwrap().insert(workspace, bundle);
    }

    /// The tenant public key to pin into the device's [`GatewayVerifier`](clave_proto::GatewayVerifier).
    pub fn public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    /// Allocate the next strictly-increasing per-tenant counter (the anti-replay primitive), failing
    /// closed if it cannot be durably persisted.
    fn next_counter(&self) -> Result<u64, GatewayError> {
        self.counter.next()
    }
}

#[async_trait]
impl PolicyIssuer for MemPolicyIssuer {
    async fn issue_initial_policy(
        &self,
        workspace: WorkspaceId,
        now: UnixTime,
    ) -> Result<Option<SignedCommand>, GatewayError> {
        let bundle = match self.policies.lock().unwrap().get(&workspace).cloned() {
            Some(b) => b,
            None => return Ok(None),
        };
        let counter = self.next_counter()?;
        Ok(Some(self.signer.sign(
            counter,
            now,
            GatewayCommand::UpdatePolicy(bundle),
        )))
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
        // Seeding from a persisted high-water continues above it (no reuse).
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

        // A fresh instance over the same file — the "restart" — must not rewind and reissue 1/2.
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
