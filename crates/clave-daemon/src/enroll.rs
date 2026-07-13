use clave_core::{PolicyBundle, UnixTime};
use clave_proto::{
    EnrollmentGrant, GatewayCommand, GatewayVerifier, ProtoError, TenantId, WrappedVolumeKey,
};
use clave_volume::{open_dek, ContainerId, Dek, DeviceSealingKey, Kek, SealedDek, WrappedDek};

pub enum DeviceVolumeKey {
    Symmetric([u8; 32]),
    Sealed(DeviceSealingKey),
}

pub struct DeviceEnrollment {
    tenant: TenantId,
    pinned_tenant_key: [u8; 32],
    volume_key: DeviceVolumeKey,
}

pub struct AcceptedEnrollment {
    verifier: GatewayVerifier,
    policy: Option<PolicyBundle>,
    volume: Option<(ContainerId, Dek)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollError {
    BadTenantKey,
    PolicyRejected(ProtoError),
    NotAPolicyCommand,
    MalformedVolumeKey,
    VolumeKeyUnwrap,
    UnexpectedSealedKey,
    UnexpectedSymmetricKey,
}

impl DeviceEnrollment {
    pub fn new(tenant: TenantId, pinned_tenant_key: [u8; 32], volume_key: DeviceVolumeKey) -> Self {
        Self {
            tenant,
            pinned_tenant_key,
            volume_key,
        }
    }

    pub fn accept(
        &self,
        grant: &EnrollmentGrant,
        now: UnixTime,
    ) -> Result<AcceptedEnrollment, EnrollError> {
        let mut verifier = GatewayVerifier::new(self.tenant, self.pinned_tenant_key)
            .map_err(|_| EnrollError::BadTenantKey)?;

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

    fn open_volume_key(&self, vk: &WrappedVolumeKey) -> Result<(ContainerId, Dek), EnrollError> {
        let wrapped = WrappedDek::from_bytes(
            vk.wrapped_dek
                .as_slice()
                .try_into()
                .map_err(|_| EnrollError::MalformedVolumeKey)?,
        );
        let dek = match (&self.volume_key, vk.ephemeral_pub) {
            (DeviceVolumeKey::Sealed(sealing), Some(ephemeral_pub)) => open_dek(
                sealing,
                &SealedDek {
                    ephemeral_pub,
                    wrapped,
                },
            )
            .map_err(|_| EnrollError::VolumeKeyUnwrap)?,
            (DeviceVolumeKey::Symmetric(kek), None) => Kek::from_bytes(*kek)
                .unwrap(&wrapped)
                .map_err(|_| EnrollError::VolumeKeyUnwrap)?,
            (DeviceVolumeKey::Symmetric(_), Some(_)) => {
                return Err(EnrollError::UnexpectedSealedKey)
            }
            (DeviceVolumeKey::Sealed(_), None) => return Err(EnrollError::UnexpectedSymmetricKey),
        };
        Ok((ContainerId(vk.container), dek))
    }
}

impl AcceptedEnrollment {
    pub fn policy(&self) -> Option<&PolicyBundle> {
        self.policy.as_ref()
    }

    pub fn volume(&self) -> Option<&(ContainerId, Dek)> {
        self.volume.as_ref()
    }

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

    fn signed_policy(
        signer: &GatewaySigningKey,
        bundle: PolicyBundle,
    ) -> clave_proto::SignedCommand {
        signer.sign(1, 1_000, GatewayCommand::UpdatePolicy(bundle))
    }

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

        assert_eq!(accepted.policy().unwrap().version, 9);

        let (container, dek) = accepted.volume().expect("volume material");
        assert_eq!(*container, ContainerId(0xC1A5));
        assert_dek_eq(dek, escrowed);

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
        grant.volume_key.as_mut().unwrap().ephemeral_pub = Some([0xAB; 32]);
        let enroll = DeviceEnrollment::new(TENANT, signer.public_key(), sym(device_kek));
        assert!(matches!(
            enroll.accept(&grant, 1_000),
            Err(EnrollError::UnexpectedSealedKey)
        ));
    }

    #[test]
    fn accept_opens_a_sealed_volume_key_with_the_hardware_sealing_key() {
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
