# 10 — Policy Engine, IPC & Audit

This is the brain (`clave-core`) and the nervous system (IPC) that the OS-specific subsystems
plug into. It is almost entirely portable Rust and is where you want the most test coverage,
because a policy bug is a silent security failure.

---

## 1. Policy model

Policy is a **signed, versioned bundle** delivered by the gateway, cached locally (inside the
encrypted volume), and evaluated by `clave-core`. It must be: declarative, diff-able,
fail-closed on parse error, and evaluable offline.

```rust
// clave-core/src/policy/mod.rs
#[derive(Deserialize)]   // serde; the wire form is signed JSON or CBOR
pub struct PolicyBundle {
    pub version:    u64,
    pub tenant:     TenantId,
    pub not_after:  UnixTime,                 // bundles expire → forces refresh / fail-closed
    pub zones:      Vec<ZoneDef>,
    pub apps:       Vec<AppRule>,             // which binaries may join the zone (signing reqs)
    pub clipboard:  ClipboardPolicy,          // doc 05 matrix
    pub screen:     ScreenPolicy,             // doc 07
    pub input:      InputPolicy,              // doc 06
    pub network:    NetworkPolicy,            // doc 08 egress allowlist, DNS, static-IP id
    pub files:      FilePolicy,               // allowed save targets, USB, print
    pub signature:  Signature,                // detached; verified against pinned gateway key
}

pub struct AppRule {
    pub app_id:      AppId,
    pub match_:      BinaryMatch,             // path glob + REQUIRED code-sign identity
    pub launch:      LaunchProfile,           // env, container/HOME, hive seed, namespace prefix
}
pub enum BinaryMatch {
    Windows { publisher: Authenticode, product: String },
    Macos   { team_id: String, signing_id: String },
}
```

### 1.1 Evaluation contract

- **Pure & deterministic:** `decide(action, context, &policy) -> Decision`. No I/O, no clock
  reads except a passed-in `now`. This makes it exhaustively testable and replayable for audit.
- **Fail-closed:** unknown action, unparseable bundle, expired `not_after`, or bad signature ⇒
  the most restrictive decision (deny enclave grants, deny cross-zone transfers) — never
  fail-open. A device with stale policy loses *new* capabilities but keeps existing data
  protection.
- **Explainable:** every `Decision` carries a `reason` enum so the audit log and the user
  prompt can say *why* (drives trust and supportability).

```rust
pub fn decide(act: &Action, ctx: &Context, pol: &PolicyBundle, now: UnixTime) -> Verdict {
    if now > pol.not_after { return Verdict::deny(Reason::PolicyExpired); }
    match act {
        Action::ClipboardTransfer { src, dst, fmt } =>
            Verdict::from(clip_decision(*src, *dst, *fmt, &pol.clipboard), Reason::Clipboard),
        Action::FileOpen { path, proc } => file_decision(path, proc, &pol.files),
        Action::NetConnect { proc, dst } => net_decision(proc, dst, &pol.network),
        // … screen, input, process-join …
    }
}
```

---

## 2. Policy distribution & trust

```
gateway ──signs bundle with tenant key (offline-rooted)──► daemon verifies against PINNED key
   │                                                            │ store in encrypted volume
   │  push (mTLS, WebSocket) or pull (interval + on-unlock)     │ atomic swap; keep last-good
   ▼                                                            ▼
 new bundle vN+1  ────────────────────────────────►  arm subsystems with vN+1; audit the change
```

- **Signature pinning:** the daemon ships with the tenant's (or vendor root's) public key;
  bundles are verified before use. A compromised transport cannot inject policy.
- **Rollback protection:** reject `version` < last-applied (monotonic), so an attacker can't
  replay an old permissive bundle. Persist the high-water mark in the TPM/Keychain-protected
  metadata, not just the volume.
- **Offline grace:** cache last-good; honor `not_after` for a configurable grace window so a
  laptop offline for a weekend still enforces, but a device offline for *months* eventually
  fails closed and requires re-check-in.

---

## 3. IPC topology

```
        ┌──────────── clave-daemon (SYSTEM/root, hosts clave-core) ───────────┐
        │   control bus (authenticated, see §4)                            │
        └───▲────────────▲──────────────▲───────────────▲──────────────────┘
            │            │              │               │
   ┌────────┴───┐ ┌──────┴─────┐ ┌──────┴──────┐ ┌──────┴───────┐
   │ kernel drv │ │ shim (per  │ │ overlay UI  │ │ volume FS    │
   │ / ESF (priv│ │ work app)  │ │ (user)      │ │ (priv)       │
   │  channel)  │ │ (semi-trust│ │             │ │              │
   └────────────┘ └────────────┘ └─────────────┘ └──────────────┘
```

Transports:

| Link | Windows | macOS |
|------|---------|-------|
| daemon ↔ driver/ESF | `DeviceIoControl` IOCTL (inverted-call) | ESF/NE callbacks + XPC to the extension |
| daemon ↔ shim | named pipe `\\.\pipe\clave-{nonce}` | XPC (the shim is limited on mac; mostly the NE/ES do the work) |
| daemon ↔ UI | named pipe / local socket | XPC / Unix domain socket |

Wire format: **`serde` + `postcard`** (compact, no-std-friendly, schema-stable) framed with a
length prefix. Define one `enum Msg` per link; version it.

```rust
// clave-ipc/src/lib.rs
#[derive(Serialize, Deserialize)]
pub enum DaemonMsg {
    PolicySnapshot(Arc<PolicyBundle>),
    Decision { req_id: u64, verdict: Verdict },
    ZoneJoin(ProcId), ZoneLeave(ProcId),
    Wipe { container: Uuid, sig: Signature },
}
#[derive(Serialize, Deserialize)]
pub enum ShimMsg {
    RequestDecision { req_id: u64, action: Action },   // shim asks; daemon decides
    WindowCreated { hwnd: u64 },                        // for overlay/affinity
    Heartbeat,
}
```

---

## 4. IPC authentication (the boundary from doc 01 §3)

The daemon must authenticate every peer; a personal process must not be able to pose as a work
app or the driver. Recap + concretes:

- **Windows named pipe:** `GetNamedPipeClientProcessId` → verify the image with
  `WinVerifyTrust` (Authenticode against the expected publisher) → confirm the PID is in the
  supervised set (driver-backed) → bind the connection to a **per-launch nonce** handed to the
  shim at injection time (so even a signed work binary can't open a *second* control channel it
  shouldn't). Set a restrictive pipe SDDL so only the intended SIDs can connect.
- **macOS XPC:** `xpc_connection_set_peer_code_signing_requirement` (or read `audit_token` and
  `SecCodeCheckValidity` against a pinned requirement: Team ID + signing id) → confirm token in
  the zone set.
- **Never** trust: process *name*, window title, a self-asserted "I'm a work app" flag, or PID
  alone (reuse). The shim *requests*; the daemon *decides* using kernel-authoritative identity.

---

## 5. The daemon runtime

```rust
// clave-daemon/src/main.rs — SKETCH
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let core   = ClaveCore::load(/* cached policy from volume */)?;
    let plat   = platform::init()?;                 // doc 00 Platform trait impl
    let (drv, shim, ui, vol) = bind_all_ipc().await?;

    tokio::join!(
        gateway::sync_loop(&core),                  // policy/key refresh, audit drain
        driver::event_loop(&core, &plat, drv),      // zone join/leave, file/net decisions
        shim::serve(&core, shim),                   // per-app decision requests
        overlay::serve(&core, ui),                  // window geometry → frames
        volume::serve(&core, vol),                  // mount lifecycle, wipe
        health::watchdog(&plat),                    // re-arm hooks, restart extensions
    );
    Ok(())
}
```

- **Async, single privileged process** hosting the portable core; OS subsystems are tasks.
- **Watchdog** re-arms user-mode hooks if stripped (doc 01 §8) and restarts the volume/tunnel
  on failure — always toward **fail-closed**.
- **Hot policy swap:** `arc-swap` the `PolicyBundle` so subsystems pick up vN+1 without a
  restart or a lock on the decision hot path.

---

## 6. Audit & telemetry

The audit log is the company's record and the user's privacy guarantee simultaneously — its
*schema* enforces "work actions only, never personal content."

```rust
#[derive(Serialize)]
pub struct AuditEvent {
    pub ts: UnixTime,
    pub device: DeviceId,
    pub zone: Zone,                  // Work always; Personal events are NEVER emitted
    pub action: AuditAction,         // ClipboardBlocked, FileSaveDenied, ScreenCaptureOverWork…
    pub decision: Verdict,
    pub app_id: Option<AppId>,       // which work app
    pub reason: Reason,
    // NO fields for: personal paths, personal URLs, keystroke content, clipboard *content*
}
```

- **Append-only, signed, spooled** inside the encrypted volume; drained to the gateway over
  mTLS; tamper-evident (hash-chained) so the gateway can detect local suppression by A6 (it
  sees a broken chain / gap).
- **Privacy by schema:** there is literally no field to hold personal data — the type system
  prevents a future contributor from logging a personal URL. Pair with the doc 01 §9 data-flow
  attestation.
- **Rate-limit & coalesce** high-frequency events (a denied clipboard spam loop) so audit
  can't be used to DoS the gateway.

---

## 7. Test plan

- **Property tests** on `decide()`: for all (action, zone-pair, format) the matrix matches the
  spec; expired/oversigned/rollback bundles always fail closed.
- **Golden replays:** record real decision streams, assert deterministic verdicts across
  refactors.
- **IPC fuzzing:** fuzz the `postcard` decoders on every link (untrusted shim input!) — these
  are your most exposed parsers; run them under `cargo fuzz`.
- **Auth bypass attempts:** unsigned process opens the pipe ⇒ rejected; PID-reuse race ⇒
  rejected; wrong nonce ⇒ rejected.
- **Privacy assertion:** static check (a test that greps the audit type) that no personal-path
  field exists; integration test that personal actions emit zero events.

Proceed to [11 — Rust Workspace Layout](11-rust-workspace-layout.md).
