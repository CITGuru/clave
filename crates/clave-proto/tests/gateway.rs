use clave_core::PolicyBundle;
use clave_proto::{
    ControlReason, Envelope, GatewayCommand, GatewaySigningKey, GatewayVerifier, ProtoError,
    TenantId,
};

const TENANT: TenantId = TenantId(7);
const NOW: u64 = 1_000_000;

fn signer() -> GatewaySigningKey {
    GatewaySigningKey::from_seed(TENANT, [42u8; 32])
}

fn verifier(s: &GatewaySigningKey) -> GatewayVerifier {
    GatewayVerifier::new(TENANT, s.public_key()).unwrap()
}

fn wipe() -> GatewayCommand {
    GatewayCommand::Wipe {
        container: 0x00C0_FFEE,
        reason: ControlReason::LostOrStolen,
    }
}

#[test]
fn signed_command_verifies_and_returns_the_command() {
    let s = signer();
    let mut v = verifier(&s);
    let cmd = v
        .verify(&s.sign(1, NOW, wipe()), NOW)
        .expect("a valid command verifies");
    assert_eq!(cmd, wipe());
    assert_eq!(v.high_water(), 1);
}

#[test]
fn tampered_payload_is_rejected() {
    let s = signer();
    let mut v = verifier(&s);
    let mut signed = s.sign(1, NOW, wipe());
    let last = signed.envelope.len() - 1;
    signed.envelope[last] ^= 0x01;
    assert_eq!(v.verify(&signed, NOW), Err(ProtoError::BadSignature));
    assert_eq!(
        v.high_water(),
        0,
        "a rejected command must not advance the counter"
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let s = signer();
    let mut v = verifier(&s);
    let mut signed = s.sign(1, NOW, wipe());
    signed.signature[0] ^= 0x01;
    assert_eq!(v.verify(&signed, NOW), Err(ProtoError::BadSignature));
}

#[test]
fn command_signed_by_the_wrong_key_is_rejected() {
    let real = signer();
    let attacker = GatewaySigningKey::from_seed(TENANT, [99u8; 32]);
    let mut v = verifier(&real);
    let forged = attacker.sign(1, NOW, wipe());
    assert_eq!(v.verify(&forged, NOW), Err(ProtoError::BadSignature));
}

#[test]
fn replayed_command_is_rejected() {
    let s = signer();
    let mut v = verifier(&s);
    let cmd = s.sign(5, NOW, wipe());
    v.verify(&cmd, NOW).expect("first delivery accepted");
    assert_eq!(
        v.verify(&cmd, NOW),
        Err(ProtoError::Replay { last: 5, got: 5 })
    );
}

#[test]
fn out_of_order_lower_counter_is_rejected() {
    let s = signer();
    let mut v = verifier(&s);
    v.verify(&s.sign(10, NOW, wipe()), NOW).unwrap();
    let lock = GatewayCommand::Lock {
        reason: ControlReason::Compromise,
    };
    assert_eq!(
        v.verify(&s.sign(9, NOW, lock), NOW),
        Err(ProtoError::Replay { last: 10, got: 9 })
    );
}

#[test]
fn counters_must_strictly_increase() {
    let s = signer();
    let mut v = verifier(&s);
    v.verify(&s.sign(1, NOW, wipe()), NOW).unwrap();
    v.verify(&s.sign(2, NOW, wipe()), NOW).unwrap();
    v.verify(&s.sign(3, NOW, wipe()), NOW).unwrap();
    assert_eq!(v.high_water(), 3);
}

#[test]
fn stale_command_is_rejected() {
    let s = signer();
    let mut v = verifier(&s);
    let way_later = NOW + 31 * 24 * 60 * 60;
    assert!(matches!(
        v.verify(&s.sign(1, NOW, wipe()), way_later),
        Err(ProtoError::Stale { .. })
    ));
}

#[test]
fn future_dated_command_beyond_skew_is_rejected() {
    let s = signer();
    let mut v = verifier(&s);
    let issued = NOW + 3600;
    assert!(matches!(
        v.verify(&s.sign(1, issued, wipe()), NOW),
        Err(ProtoError::Stale { .. })
    ));
}

#[test]
fn freshness_window_is_configurable() {
    let s = signer();
    let mut v = GatewayVerifier::new(TENANT, s.public_key())
        .unwrap()
        .with_max_age(60);
    assert!(matches!(
        v.verify(&s.sign(1, NOW - 61, wipe()), NOW),
        Err(ProtoError::Stale { .. })
    ));
}

#[test]
fn wrong_tenant_is_rejected() {
    let s = signer();
    let mut v = GatewayVerifier::new(TenantId(8), s.public_key()).unwrap();
    let signed = s.sign_envelope(&Envelope::new(TenantId(7), 1, NOW, wipe()));
    assert_eq!(
        v.verify(&signed, NOW),
        Err(ProtoError::WrongTenant {
            pinned: TenantId(8),
            got: TenantId(7),
        })
    );
}

#[test]
fn high_water_can_be_restored_for_persistence() {
    let s = signer();
    let mut v = GatewayVerifier::new(TENANT, s.public_key())
        .unwrap()
        .with_high_water(100);
    assert_eq!(
        v.verify(&s.sign(100, NOW, wipe()), NOW),
        Err(ProtoError::Replay {
            last: 100,
            got: 100
        })
    );
    v.verify(&s.sign(101, NOW, wipe()), NOW)
        .expect("a counter past the restored mark is accepted");
    assert_eq!(v.high_water(), 101);
}

#[test]
fn signed_policy_update_round_trips() {
    let s = signer();
    let mut v = verifier(&s);
    let mut bundle = PolicyBundle::restrictive_default();
    bundle.version = 9;
    let cmd = v
        .verify(
            &s.sign(1, NOW, GatewayCommand::UpdatePolicy(bundle.clone())),
            NOW,
        )
        .unwrap();
    assert_eq!(cmd, GatewayCommand::UpdatePolicy(bundle));
}

#[test]
fn malformed_signature_length_is_rejected() {
    let s = signer();
    let mut v = verifier(&s);
    let mut signed = s.sign(1, NOW, wipe());
    signed.signature.truncate(10);
    assert_eq!(v.verify(&signed, NOW), Err(ProtoError::Malformed));
}

#[test]
fn signed_command_survives_serialization() {
    let s = signer();
    let mut v = verifier(&s);
    let signed = s.sign(1, NOW, wipe());
    let wire = postcard::to_allocvec(&signed).unwrap();
    let recovered: clave_proto::SignedCommand = postcard::from_bytes(&wire).unwrap();
    assert_eq!(v.verify(&recovered, NOW).unwrap(), wipe());
}
