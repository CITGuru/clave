//! Codec round-trips, partial/oversized/garbage handling, and panic-freedom on hostile input.

use clave_core::{Action, Reason, Verdict};
use clave_ipc::{encode, try_decode, DaemonMsg, FrameError, ShimMsg, MAX_FRAME, PROTO_VERSION};
use clave_platform::{ClipFormat, WindowId, Zone};
use proptest::prelude::*;

#[test]
fn round_trip_shim_messages() {
    let msgs = vec![
        ShimMsg::Hello {
            proto: PROTO_VERSION,
            nonce: 0xDEAD_BEEF_CAFE_F00D,
        },
        ShimMsg::RequestDecision {
            req_id: 7,
            action: Action::ClipboardTransfer {
                src: Zone::Work,
                dst: Zone::Personal,
                fmt: ClipFormat::Files,
            },
        },
        ShimMsg::WindowCreated {
            window: WindowId(42),
        },
        ShimMsg::WindowDestroyed {
            window: WindowId(42),
        },
        ShimMsg::Heartbeat,
    ];
    for m in msgs {
        let bytes = encode(&m);
        let (decoded, consumed) = try_decode::<ShimMsg>(&bytes).unwrap().unwrap();
        assert_eq!(decoded, m);
        assert_eq!(consumed, bytes.len());
    }
}

#[test]
fn round_trip_daemon_messages() {
    let m = DaemonMsg::Decision {
        req_id: 7,
        verdict: Verdict::deny(Reason::Clipboard),
    };
    let bytes = encode(&m);
    let (d, consumed) = try_decode::<DaemonMsg>(&bytes).unwrap().unwrap();
    assert_eq!(d, m);
    assert_eq!(consumed, bytes.len());
}

#[test]
fn incomplete_frames_return_none() {
    let bytes = encode(&ShimMsg::WindowCreated {
        window: WindowId(1),
    });
    // Drop the final body byte → not enough bytes yet.
    assert_eq!(
        try_decode::<ShimMsg>(&bytes[..bytes.len() - 1]).unwrap(),
        None
    );
    // Only a partial length prefix.
    assert_eq!(try_decode::<ShimMsg>(&[0, 0]).unwrap(), None);
    // Empty.
    assert_eq!(try_decode::<ShimMsg>(&[]).unwrap(), None);
}

#[test]
fn oversized_length_prefix_is_rejected() {
    let mut buf = ((MAX_FRAME as u32) + 1).to_le_bytes().to_vec();
    buf.extend_from_slice(&[0u8; 16]);
    assert_eq!(try_decode::<ShimMsg>(&buf), Err(FrameError::TooLarge));
}

#[test]
fn garbage_body_is_malformed_not_panic() {
    // Valid length prefix (8), but the body is not a valid ShimMsg encoding.
    let mut buf = 8u32.to_le_bytes().to_vec();
    buf.extend_from_slice(&[0xFF; 8]);
    // Either Malformed, or (vanishingly unlikely) a valid decode — never a panic.
    let _ = try_decode::<ShimMsg>(&buf);
}

#[test]
fn two_frames_decode_sequentially() {
    let a = encode(&ShimMsg::Heartbeat);
    let b = encode(&ShimMsg::WindowCreated {
        window: WindowId(9),
    });
    let mut stream = a;
    stream.extend_from_slice(&b);

    let (m1, c1) = try_decode::<ShimMsg>(&stream).unwrap().unwrap();
    assert_eq!(m1, ShimMsg::Heartbeat);

    let (m2, c2) = try_decode::<ShimMsg>(&stream[c1..]).unwrap().unwrap();
    assert_eq!(
        m2,
        ShimMsg::WindowCreated {
            window: WindowId(9)
        }
    );
    assert_eq!(c1 + c2, stream.len());
}

proptest! {
    /// The decoder must never panic on arbitrary bytes (it parses untrusted shim input).
    #[test]
    fn prop_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = try_decode::<ShimMsg>(&bytes);
        let _ = try_decode::<DaemonMsg>(&bytes);
    }

    /// A well-formed frame wrapping a random body is always either decoded or cleanly
    /// `Malformed` — never `TooLarge` (the body is small) and never a panic.
    #[test]
    fn prop_random_body_is_decoded_or_malformed(body in prop::collection::vec(any::<u8>(), 0..1024)) {
        let mut buf = (body.len() as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(&body);
        match try_decode::<ShimMsg>(&buf) {
            Ok(_) | Err(FrameError::Malformed) => {}
            Err(FrameError::TooLarge) => prop_assert!(false, "small body wrongly flagged TooLarge"),
        }
    }

    /// Round-trip property: any encodable decision request survives encode→decode intact.
    #[test]
    fn prop_request_decision_round_trips(req_id in any::<u64>(), n in any::<u32>()) {
        let m = ShimMsg::RequestDecision {
            req_id,
            action: Action::NetConnect { proc: clave_platform::ProcId::windows(n, 1), host: "h.example".into() },
        };
        let bytes = encode(&m);
        let (decoded, _) = try_decode::<ShimMsg>(&bytes).unwrap().unwrap();
        prop_assert_eq!(decoded, m);
    }
}
