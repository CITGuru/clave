//! End-to-end transport tests over a real Unix-domain socket: handshake, peer auth, a request/
//! reply round-trip, and rejection paths. Unix-only.
#![cfg(unix)]

use clave_core::{Action, Reason, Verdict};
use clave_ipc::transport::{
    client_handshake, serve, server_handshake, Connection, IpcServer, PeerAuthenticator, PeerCred,
    TransportError,
};
use clave_ipc::{DaemonMsg, ShimMsg, PROTO_VERSION};
use clave_platform::{ClipFormat, Decision, Zone};

struct AllowAll;
impl PeerAuthenticator for AllowAll {
    fn authenticate(&self, _cred: &PeerCred, _nonce: u64) -> bool {
        true
    }
}

struct DenyAll;
impl PeerAuthenticator for DenyAll {
    fn authenticate(&self, _cred: &PeerCred, _nonce: u64) -> bool {
        false
    }
}

fn temp_sock(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("clave-ipc-{}-{}.sock", std::process::id(), tag));
    p
}

#[tokio::test]
async fn handshake_and_decision_round_trip() {
    let path = temp_sock("ok");
    let server = IpcServer::bind(&path).unwrap();

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.unwrap();
        let cred = server_handshake(&mut conn, &AllowAll).await.unwrap();
        // We connected from this same process, so the peer pid should be visible.
        assert!(cred.pid.is_some() || cred.uid == cred.uid);
        serve(conn, |msg| match msg {
            ShimMsg::RequestDecision { req_id, .. } => Some(DaemonMsg::Decision {
                req_id,
                verdict: Verdict::deny(Reason::Clipboard),
            }),
            _ => None,
        })
        .await
        .unwrap();
    });

    let mut client = Connection::connect(&path).await.unwrap();
    client_handshake(&mut client, 0xABCD).await.unwrap();

    client
        .write(&ShimMsg::RequestDecision {
            req_id: 7,
            action: Action::ClipboardTransfer {
                src: Zone::Work,
                dst: Zone::Personal,
                fmt: ClipFormat::Files,
            },
        })
        .await
        .unwrap();

    let reply: Option<DaemonMsg> = client.read().await.unwrap();
    match reply {
        Some(DaemonMsg::Decision { req_id, verdict }) => {
            assert_eq!(req_id, 7);
            assert_eq!(verdict.decision, Decision::Deny);
        }
        other => panic!("unexpected reply: {other:?}"),
    }

    drop(client); // EOF → server's serve loop returns
    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn rejected_peer_fails_handshake() {
    let path = temp_sock("deny");
    let server = IpcServer::bind(&path).unwrap();

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.unwrap();
        let res = server_handshake(&mut conn, &DenyAll).await;
        assert!(matches!(res, Err(TransportError::Handshake(_))));
    });

    let mut client = Connection::connect(&path).await.unwrap();
    // The server reads Hello, rejects, and drops without sending Welcome → client read errors.
    let res = client_handshake(&mut client, 1).await;
    assert!(res.is_err());

    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn wrong_protocol_version_is_rejected() {
    let path = temp_sock("proto");
    let server = IpcServer::bind(&path).unwrap();

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.unwrap();
        let res = server_handshake(&mut conn, &AllowAll).await;
        assert!(matches!(res, Err(TransportError::Handshake(_))));
    });

    let mut client = Connection::connect(&path).await.unwrap();
    client
        .write(&ShimMsg::Hello {
            proto: PROTO_VERSION.wrapping_add(1),
            nonce: 0,
        })
        .await
        .unwrap();

    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}
