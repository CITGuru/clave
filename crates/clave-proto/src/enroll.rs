use serde::{Deserialize, Serialize};

use crate::SignedCommand;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedVolumeKey {
    pub container: u128,
    pub wrapped_dek: Vec<u8>,
    pub ephemeral_pub: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EnrollmentGrant {
    pub policy: Option<SignedCommand>,
    pub volume_key: Option<WrappedVolumeKey>,
}

impl EnrollmentGrant {
    pub fn new(policy: Option<SignedCommand>, volume_key: Option<WrappedVolumeKey>) -> Self {
        Self { policy, volume_key }
    }
}
