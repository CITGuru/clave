#![cfg(feature = "device-link")]

use std::sync::Arc;

use clave_gateway::{
    AuthMethod, DeviceCaIssuer, EmailAddr, EnrollmentCompletion, Gateway, MemStore, Membership,
    MembershipStatus, MockIdentityProvider, Role, SsoMode, UserId, VerifiedUser, Workspace,
    WorkspaceId,
};
use clave_proto::mtls::{
    accept_device_session, connect_gateway_link, server_config, DeviceCa, Identity,
};

const WS: WorkspaceId = WorkspaceId(100);

#[tokio::test]
async fn an_enrolled_device_cert_lets_it_connect_and_binds_to_its_id() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let store = Arc::new(MemStore::new());
    store.seed_workspace(Workspace {
        id: WS,
        allowed_domains: vec![],
        sso: SsoMode::Optional,
    });
    store.seed_membership(Membership {
        workspace: WS,
        user: UserId(1),
        role: Role::Member,
        status: MembershipStatus::Active,
    });

    let vu = VerifiedUser {
        email: EmailAddr::parse("dev@acme.com").unwrap(),
        idp_user_id: "u".to_string(),
        workspace: WS,
        method: AuthMethod::Password,
        access_token: "a".to_string(),
        refresh_token: "r".to_string(),
    };
    let issuer = Arc::new(DeviceCaIssuer::new(
        DeviceCa::generate().unwrap(),
        "gateway.test",
        &addr,
    ));
    let gw = Gateway::new(MockIdentityProvider::new(vu, "approved-device"), store.clone())
        .with_device_ca(issuer.clone());

    let auth = gw.begin_enrollment(WS).await.unwrap();
    let completion = gw
        .complete_enrollment(WS, &auth.device_code, &[0xAB; 32], None, 1_000)
        .await
        .unwrap();
    let (device, tls) = match completion {
        EnrollmentCompletion::Approved { device, tls, .. } => (device, tls.expect("cert issued")),
        _ => panic!("expected approval"),
    };
    assert_eq!(tls.server_name, "gateway.test");
    assert_eq!(tls.gateway_addr, addr);

    let (server_cert, server_key) = issuer.issue_server("gateway.test").unwrap();
    let server_cfg = server_config(
        issuer.ca_pem(),
        Identity::from_pem(&server_cert, &server_key).unwrap(),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        accept_device_session(server_cfg, tcp).await.unwrap()
    });

    let _device_link = connect_gateway_link(
        &tls.gateway_addr,
        &tls.server_name,
        &tls.ca_pem,
        Identity::from_pem(&tls.cert_pem, &tls.key_pem).unwrap(),
    )
    .await
    .unwrap();
    let (_gw_link, fingerprint) = server.await.unwrap();

    assert_eq!(
        gw.device_for_fingerprint(&fingerprint).await.unwrap(),
        Some(device),
        "the presented cert binds the connection back to its device row"
    );
}
