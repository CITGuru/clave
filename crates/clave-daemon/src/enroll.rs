//! The **device-side enrollment client**: turns the gateway's
//! [`EnrollmentGrant`] into the runtime material the [`Daemon`](crate::Daemon) is built from.
//!
//! Enrollment is what *bootstraps* the device's gateway trust. The device holds three things
//! out-of-band — its pinned tenant key (from the MDM / enrollment token), the tenant id, and its
//! volume **wrapping key** (hardware-bound in production) — and the gateway returns a signed initial
//! policy + a wrapped volume key. [`DeviceEnrollment::accept`] combines them: it pins the tenant key
//! into a [`GatewayVerifier`], **verifies** the policy through it (so a forged or stale bundle never
//! installs), and **opens** the wrapped volume key with the device key to recover the Clave Disk
//! [`Dek`]. The result feeds straight into [`Daemon::new`](crate::Daemon::new): the verifier, the
//! initial [`PolicyBundle`], and the `(container, DEK)` to provision the volume's key store.

use clave_core::{PolicyBundle, UnixTime};
use clave_proto::{
    EnrollmentGrant, GatewayCommand, GatewayVerifier, ProtoError, TenantId, WrappedVolumeKey,
};
use clave_volume::{open_dek, ContainerId, Dek, DeviceSealingKey, Kek, SealedDek, WrappedDek};

/// How the device opens its wrapped volume key: the dev/bootstrap path holds a shared
/// symmetric KEK; the production path holds the device's X25519 **sealing key** whose secret never
/// leaves the Secure Enclave / TPM. [`DeviceEnrollment::accept`] picks the path from the grant.
pub enum DeviceVolumeKey {
    /// Shared symmetric AES-KW key (dev/bootstrap).
    Symmetric([u8; 32]),
    /// Hardware-bound X25519 sealing keypair (production).
    Sealed(DeviceSealingKey),
}

/// The device's enrollment secrets + the tenant pin, held before first boot. Used once to accept the
/// gateway's grant.
pub struct DeviceEnrollment {
    tenant: TenantId,
    pinned_tenant_key: [u8; 32],
    volume_key: DeviceVolumeKey,
}

/// The runtime material recovered from an accepted enrollment — exactly what [`Daemon::new`] needs:
/// a tenant-pinned [`GatewayVerifier`] (already advanced past the initial policy's counter), the
/// initial [`PolicyBundle`] if one was issued, and the `(container, DEK)` to provision the volume.
pub struct AcceptedEnrollment {
    verifier: GatewayVerifier,
    policy: Option<PolicyBundle>,
    volume: Option<(ContainerId, Dek)>,
}

/// Why an enrollment grant was refused. Every variant is fail-closed: nothing is installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollError {
    /// The pinned tenant key is not a valid Ed25519 public key.
    BadTenantKey,
    /// The signed policy failed verification (signature / replay / freshness / tenant).
    PolicyRejected(ProtoError),
    /// The signed command verified but was not a `GatewayCommand::UpdatePolicy`.
    NotAPolicyCommand,
    /// The wrapped volume key was the wrong length.
    MalformedVolumeKey,
    /// The device key could not open the wrapped volume key (wrong key or corrupt ciphertext).
    VolumeKeyUnwrap,
    /// The grant carried a *sealed* (asymmetric) volume key, but this enrollment holds only a
    /// symmetric KEK.
    UnexpectedSealedKey,
    /// The grant carried a *symmetric* volume key, but this enrollment holds an X25519 sealing key.
    UnexpectedSymmetricKey,
}

impl DeviceEnrollment {
    /// Hold the device's enrollment secrets: the tenant it pins, that tenant's public key, and the
    /// device's volume key (symmetric KEK or hardware sealing key).
    pub fn new(
        tenant: TenantId,
        pinned_tenant_key: [u8; 32],
        volume_key: DeviceVolumeKey,
    ) -> Self {
        Self {
            tenant,
            pinned_tenant_key,
            volume_key,
        }
    }

    /// Accept the gateway's [`EnrollmentGrant`] at time `now`, producing the daemon's runtime
    /// material. Verifies the signed policy against the pinned tenant key and opens the wrapped
    /// volume key with the device key; fail-closed on any check.
    pub fn accept(
        &self,
        grant: &EnrollmentGrant,
        now: UnixTime,
    ) -> Result<AcceptedEnrollment, EnrollError> {
        // Pin the tenant key: this verifier is the device's sole gateway-trust anchor from here on.
        let mut verifier = GatewayVerifier::new(self.tenant, self.pinned_tenant_key)
            .map_err(|_| EnrollError::BadTenantKey)?;

        // Verify the initial policy *through* that verifier, so a forged/stale bundle never installs
        // and the anti-replay high-water advances past it (the daemon continues from there).
        let policy = match &grant.policy {
            Some(signed) => match verifier
                .verify(signed, now)
                .map_err(EnrollError::PolicyRejected)?
            {
                GatewayCommand::UpdatePolicy(bundle) => Some(bundle),
                _ => return Err(EnrollError::NotAPolicyCommand),
            },
            None => None,
        };

        let volume = match &grant.volume_key {
            Some(vk) => Some(self.open_volume_key(vk)?),
            None => None,
        };

        Ok(AcceptedEnrollment {
            verifier,
            policy,
            volume,
        })
    }

    /// Recover the Clave Disk DEK from the wrapped volume key, choosing the path from the grant: a
    /// sealed key (carrying an ephemeral public key) is opened with the device's X25519 sealing key;
    /// a symmetric key is AES-KW-unwrapped under the device KEK. A grant/key-type mismatch is
    /// refused fail-closed.
    fn open_volume_key(&self, vk: &WrappedVolumeKey) -> Result<(ContainerId, Dek), EnrollError> {
        let wrapped = WrappedDek::from_bytes(
            vk.wrapped_dek
                .as_slice()
                .try_into()
                .map_err(|_| EnrollError::MalformedVolumeKey)?,
        );
        let dek = match (&self.volume_key, vk.ephemeral_pub) {
            // Production: sealed-box opened with the hardware sealing key.
            (DeviceVolumeKey::Sealed(sealing), Some(ephemeral_pub)) => open_dek(
                sealing,
                &SealedDek {
                    ephemeral_pub,
                    wrapped,
                },
            )
            .map_err(|_| EnrollError::VolumeKeyUnwrap)?,
            // Dev/bootstrap: symmetric AES-KW unwrap under the shared KEK.
            (DeviceVolumeKey::Symmetric(kek), None) => Kek::from_bytes(*kek)
                .unwrap(&wrapped)
                .map_err(|_| EnrollError::VolumeKeyUnwrap)?,
            // Mismatches: the grant's shape doesn't match the key the device holds.
            (DeviceVolumeKey::Symmetric(_), Some(_)) => return Err(EnrollError::UnexpectedSealedKey),
            (DeviceVolumeKey::Sealed(_), None) => {
                return Err(EnrollError::UnexpectedSymmetricKey)
            }
        };
        Ok((ContainerId(vk.container), dek))
    }
}

impl AcceptedEnrollment {
    /// The verified initial policy, if the grant carried one.
    pub fn policy(&self) -> Option<&PolicyBundle> {
        self.policy.as_ref()
    }

    /// The recovered `(container, DEK)` to provision the volume's key store, if a volume key was
    /// issued. The DEK stays in this crate's zeroizing custody until handed to the key store.
    pub fn volume(&self) -> Option<&(ContainerId, Dek)> {
        self.volume.as_ref()
    }

    /// Consume into the parts [`Daemon::new`](crate::Daemon::new) needs: the pinned verifier, the
    /// initial policy, and the recovered volume material.
    pub fn into_parts(
        self,
    ) -> (
        GatewayVerifier,
        Option<PolicyBundle>,
        Option<(ContainerId, Dek)>,
    ) {
        (self.verifier, self.policy, self.volume)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clave_proto::GatewaySigningKey;
    use clave_volume::{seal_dek, DEK_LEN};

    const TENANT: TenantId = TenantId(1);

    fn signed_policy(signer: &GatewaySigningKey, bundle: PolicyBundle) -> clave_proto::SignedCommand {
        signer.sign(1, 1_000, GatewayCommand::UpdatePolicy(bundle))
    }

    /// Build the grant a gateway would issue: a signed policy (counter 1) + a symmetric-wrapped DEK.
    fn issue(
        signer: &GatewaySigningKey,
        device_kek: [u8; 32],
        bundle: PolicyBundle,
        container: u128,
        dek: [u8; DEK_LEN],
    ) -> EnrollmentGrant {
        let wrapped = Kek::from_bytes(device_kek).wrap(&Dek::from_bytes(dek));
        EnrollmentGrant::new(
            Some(signed_policy(signer, bundle)),
            Some(WrappedVolumeKey {
                container,
                wrapped_dek: wrapped.as_bytes().to_vec(),
                ephemeral_pub: None,
            }),
        )
    }

    /// Prove a recovered DEK equals `expected` without reading key bytes: AES-KW is deterministic,
    /// so wrapping both under a common probe KEK yields identical ciphertext.
    fn assert_dek_eq(recovered: &Dek, expected: [u8; DEK_LEN]) {
        let probe = Kek::from_bytes([0x77; 32]);
        assert_eq!(
            probe.wrap(recovered).as_bytes(),
            probe.wrap(&Dek::from_bytes(expected)).as_bytes()
        );
    }

    fn sym(kek: [u8; 32]) -> DeviceVolumeKey {
        DeviceVolumeKey::Symmetric(kek)
    }

    #[test]
    fn accept_pins_key_verifies_policy_and_recovers_the_dek() {
        let signer = GatewaySigningKey::from_seed(TENANT, [0x5A; 32]);
        let device_kek = [0x11; 32];
        let mut bundle = PolicyBundle::restrictive_default();
        bundle.version = 9;
        let escrowed = [0xDE; DEK_LEN];
        let grant = issue(&signer, device_kek, bundle, 0xC1A5, escrowed);

        let enroll = DeviceEnrollment::new(TENANT, signer.public_key(), sym(device_kek));
        let accepted = enroll.accept(&grant, 1_000).expect("accept");

        // The initial policy verified and is available.
        assert_eq!(accepted.policy().unwrap().version, 9);

        // The volume material is the escrowed container + DEK.
        let (container, dek) = accepted.volume().expect("volume material");
        assert_eq!(*container, ContainerId(0xC1A5));
        assert_dek_eq(dek, escrowed);

        // The verifier is pinned and advanced: replaying the initial policy is now rejected.
        let (mut verifier, _, _) = accepted.into_parts();
        assert!(matches!(
            verifier.verify(grant.policy.as_ref().unwrap(), 1_000),
            Err(ProtoError::Replay { .. })
        ));
    }

    #[test]
    fn a_grant_signed_by_the_wrong_tenant_is_rejected() {
        let real = GatewaySigningKey::from_seed(TENANT, [0x5A; 32]);
        let device_kek = [0x11; 32];
        let grant = issue(
            &real,
            device_kek,
            PolicyBundle::restrictive_default(),
            1,
            [0xDE; DEK_LEN],
        );

        // The device pins a DIFFERENT key than the one that signed the grant.
        let wrong_pin = GatewaySigningKey::from_seed(TENANT, [0x01; 32]).public_key();
        let enroll = DeviceEnrollment::new(TENANT, wrong_pin, sym(device_kek));
        assert!(matches!(
            enroll.accept(&grant, 1_000),
            Err(EnrollError::PolicyRejected(_))
        ));
    }

    #[test]
    fn the_wrong_device_key_cannot_open_the_volume_key() {
        let signer = GatewaySigningKey::from_seed(TENANT, [0x5A; 32]);
        let grant = issue(
            &signer,
            [0x11; 32],
            PolicyBundle::restrictive_default(),
            1,
            [0xDE; DEK_LEN],
        );
        // Same tenant pin, but the device holds the wrong wrapping key.
        let enroll = DeviceEnrollment::new(TENANT, signer.public_key(), sym([0x22; 32]));
        assert!(matches!(
            enroll.accept(&grant, 1_000),
            Err(EnrollError::VolumeKeyUnwrap)
        ));
    }

    #[test]
    fn a_sealed_volume_key_is_refused_without_a_sealing_key() {
        let signer = GatewaySigningKey::from_seed(TENANT, [0x5A; 32]);
        let device_kek = [0x11; 32];
        let mut grant = issue(
            &signer,
            device_kek,
            PolicyBundle::restrictive_default(),
            1,
            [0xDE; DEK_LEN],
        );
        // Mark the volume key as sealed (asymmetric) — the symmetric client must refuse it.
        grant.volume_key.as_mut().unwrap().ephemeral_pub = Some([0xAB; 32]);
        let enroll = DeviceEnrollment::new(TENANT, signer.public_key(), sym(device_kek));
        assert!(matches!(
            enroll.accept(&grant, 1_000),
            Err(EnrollError::UnexpectedSealedKey)
        ));
    }

    #[test]
    fn accept_opens_a_sealed_volume_key_with_the_hardware_sealing_key() {
        // The production path: the gateway seals the DEK to the device's X25519 public key, and the
        // device opens it with its (here, software) sealing key — exactly the bytes
        // `SealedVolumeKeyService` produces.
        let signer = GatewaySigningKey::from_seed(TENANT, [0x5A; 32]);
        let device = DeviceSealingKey::generate();
        let escrowed = [0xDE; DEK_LEN];
        let sealed = seal_dek(device.public_key(), &Dek::from_bytes(escrowed)).expect("seal");
        let mut bundle = PolicyBundle::restrictive_default();
        bundle.version = 4;
        let grant = EnrollmentGrant::new(
            Some(signed_policy(&signer, bundle)),
            Some(WrappedVolumeKey {
                container: 0xC1A5,
                wrapped_dek: sealed.wrapped.as_bytes().to_vec(),
                ephemeral_pub: Some(sealed.ephemeral_pub),
            }),
        );

        let enroll =
            DeviceEnrollment::new(TENANT, signer.public_key(), DeviceVolumeKey::Sealed(device));
        let accepted = enroll.accept(&grant, 1_000).expect("accept sealed grant");
        assert_eq!(accepted.policy().unwrap().version, 4);
        let (container, dek) = accepted.volume().expect("volume material");
        assert_eq!(*container, ContainerId(0xC1A5));
        assert_dek_eq(dek, escrowed);
    }

    #[test]
    fn a_symmetric_volume_key_is_refused_by_a_sealing_device() {
        let signer = GatewaySigningKey::from_seed(TENANT, [0x5A; 32]);
        // A symmetric grant, but the device only holds a sealing key — a config mismatch.
        let grant = issue(
            &signer,
            [0x11; 32],
            PolicyBundle::restrictive_default(),
            1,
            [0xDE; DEK_LEN],
        );
        let enroll = DeviceEnrollment::new(
            TENANT,
            signer.public_key(),
            DeviceVolumeKey::Sealed(DeviceSealingKey::generate()),
        );
        assert!(matches!(
            enroll.accept(&grant, 1_000),
            Err(EnrollError::UnexpectedSymmetricKey)
        ));
    }
}
