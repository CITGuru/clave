# 18 — Activity Tracking & Monitoring (work-app usage telemetry)

How the enclave measures **time spent in work apps** — active time, idle time, focus time,
sessions and launches — and ships it to the gateway as a **policy-tiered, tamper-evident,
work-zone-only** telemetry stream that a manager dashboard can roll up per person.

The one-sentence version: **the zone boundary is the privacy line.** Only work processes are
supervised, so a tracker built on the supervised set *physically cannot* observe personal
activity — it measures presence *inside* Clave windows and, by subtraction, time spent *away
from* them, without ever recording what "away" is doing.

This subsystem is portable Rust in `clave-core` plus two tiny, **ungated** OS primitives
(foreground PID, OS idle timer). Unlike every enforcement subsystem in docs 05–09, it needs no
driver and no Endpoint Security entitlement, so it runs end-to-end on a plain dev machine.

Rides the audit transport from [doc 10 §6](10-policy-engine-and-ipc.md) and the identity /
enrollment plumbing from [doc 15](15-identity-and-enrollment-auth.md).

---

## 1. The bargain, restated

This is monitoring software running on an employee's **personal** computer. Doc 10 §6 already
committed the audit log to "work actions only, never personal content." Activity tracking makes
the same promise structurally, not by policy:

- **The supervised set is the sensor.** `ZoneRegistry` ([`clave-core/src/zone.rs`]) is the only
  thing that knows which PIDs are in the Work zone. A personal app is never in it, so it never
  appears in a usage sample. There is no code path that attributes time to a non-work process.
- **Absence, not presence, of work focus.** When the foreground is *not* a work app, we accrue a
  single global `away` counter. We do **not** record which app has focus, its title, or its URL.
  The dashboard learns *"3h 40m in work apps, and the rest of an 8h day elsewhere"* — never
  *what* elsewhere was.
- **Aggregates, not a feed.** The default tier ships interval **summaries** (per-app second
  counts), not a keystroke- or click-granularity event stream. Fidelity is a policy choice that
  the company must deliberately raise (§8), and every raise is itself an audited policy change.

> **Honesty marker.** This is **◐ BEST-EFFORT** by construction — user-mode observation with no
> kernel-authoritative backing. A technical user can kill the watch thread. What they *cannot*
> do is hide it: the telemetry rides the same hash-chained spool as the audit log (§7), so a
> suppressed interval shows up at the gateway as a **chain gap**, exactly like a suppressed
> denial. Tracking is not enforcement; it is an *attestable* record with a tamper signal.

---

## 2. The visibility ladder (policy-tiered)

The **company chooses how much is captured**, per policy, and the choice is a signed field of
the `PolicyBundle` (§8). Each tier is a strict superset of the one below; the daemon collects up
to the tier's ceiling and no further.

| Tier | Name | Captures | Never captures | Typical gate |
|---|---|---|---|---|
| **T0** | **Off** *(default)* | nothing | — | — |
| **T1** | **Aggregate** | per-app second buckets (active / idle / foreground), session count, launch count, global `away` total — flushed as interval summaries | window titles, timelines, any personal-zone signal | notice |
| **T2** | **Sessions** | T1 **+** per-session open/close records; **optionally** foreground *window titles of work apps* (`capture_titles`) | personal apps, content, screenshots | consent |
| **T3** | **Full** | T2 **+** fine-grained focus timeline; **optionally** periodic snapshots of **work windows only** | personal-zone anything | consent + legal review |

Two hard invariants hold at **every** tier, T1 through T3:

1. **Work zone only.** The scope of observation is the supervised set. Personal apps, personal
   windows, and the lock screen are never sampled beyond incrementing the opaque `away` counter.
2. **Fail-closed to Off.** An unparseable bundle, an expired `not_after`, or a missing
   `tracking` field ⇒ **T0**. Tracking is the one subsystem where "fail-closed" means *collect
   nothing* — the safe default for a privacy control is silence.

T3 window snapshots are the mirror image of doc 07: instead of *excluding* work surfaces from
capture, the daemon captures *only* surfaces it owns (work windows carrying the Clave Edge),
never the full screen — so a snapshot can never contain a personal window sharing the display.

---

## 3. What we measure

Five signals, all attributed to an `AppId`, plus one derived presence metric. Definitions are
precise because a dashboard that conflates "app was open" with "user was working" is a lie.

| Signal | Definition |
|---|---|
| **Foreground time** | Wall-clock a work app held the OS foreground, regardless of input. "Excel was in front for 50 min." |
| **Active time** | Foreground time **minus** idle intervals — foreground *and* input seen within `idle_threshold`. "Actually typing/clicking in Excel." |
| **Idle time** | Foreground **but** no input for longer than `idle_threshold`. The user is at the app but away from the keyboard. |
| **Sessions** | The lifetime of one work-app instance, bounded by `ProcessJoinedZone` → `ProcessLeftZone`. Carries open/close timestamps at T2+. |
| **Launches** | Count of sessions started, per app, per accounting day. |
| **Away** *(derived)* | Wall-clock where **no** work app is foreground: personal app in front, desktop, or locked. Global, **unattributed** — the only thing we learn about non-work time is its *duration*. |

The identity that ties the day together:

```
foreground_secs[app]  =  active_secs[app] + idle_secs[app]
wall_clock_observed   =  Σ foreground_secs[app]  +  away_secs
```

`away` is what the user asked for: *time spent outside Clave windows*, computed by subtraction
from total presence, with zero observation of what that time contains.

---

## 4. Signal sources (all ungated)

Three inputs per sample tick. The pleasant surprise is that none require an entitlement or a
signed driver — they are the same APIs the clipboard/screen/input *watches* already call.

| Input | macOS | Windows | Gated? |
|---|---|---|---|
| Foreground PID | `NSWorkspace.frontmostApplication` → `frontmost_app_pid()` (`clave-mac/src/clipboard.rs`) | `GetForegroundWindow` + `GetWindowThreadProcessId` → `foreground_pid()` (`clave-win/src/input.rs`) | ✗ no |
| OS idle seconds | `CGEventSourceSecondsSinceLastEventType(.combinedSessionState, …)` **(new, ~5 lines)** | `GetLastInputInfo` **(new, ~5 lines)** | ✗ no |
| Supervised set | `ZoneRegistry::supervised_pids()` (`clave-core/src/zone.rs`) | same | ✗ no |
| Window title *(T2+)* | `CGWindowListCopyWindowInfo` (already used by `edge.rs`) | `GetWindowText` | ◐ needs Screen-Recording TCC on mac |

The only genuinely missing primitive is the OS idle-timer read, and it is trivial and ungated on
both platforms. Everything else is already in-tree.

> **Honesty marker — ◐ BEST-EFFORT.** Foreground/idle sampling is user-mode polling. It can
> undercount (a fast app switch between two ticks) and it trusts the OS idle timer (which an
> attacker could keep warm with synthetic input). It is a *productivity signal*, not a security
> control; do not build access decisions on it.

---

## 5. Attribution and the sampling loop

### 5.1 The PID → AppId gap

Today `ZoneMember` (`clave-core/src/zone.rs`) stores only a `ProcId` and a `JoinReason`; the
`AppId` that `classify_exec` matched at join time (`clave-core/src/app.rs`) is **discarded**. To
attribute a foreground PID to an app without re-classifying its binary every tick, carry the
match forward:

```rust
// clave-core/src/zone.rs — SKETCH (extend the member record)
pub struct ZoneMember {
    pub id: ProcId,
    pub reason: JoinReason,
    pub app_id: Option<AppId>,   // NEW: the matched work app, set at join
}
```

The join sites (`Daemon::on_zone_join`, `on_exec`, `launch`, `launch_web` in
`clave-daemon/src/lib.rs`) already hold the `AppId` — they just stop dropping it. On macOS the
ES-driven join path (`clave_mac_zone_join`) must thread it through the FFI too, or the tracker
falls back to resolving the frontmost PID's binary through `AppPolicy::match_app`.

### 5.2 The tick

A single watch thread, spawned beside the existing guards (`spawn_clipboard_guard` /
`spawn_screen_watch` / `spawn_input_watch` in `mac_main.rs`, mirror in `win_main.rs`), polling on
`sample_interval_secs`:

```rust
// clave-daemon/src/usage.rs — SKETCH
fn tick(dt: Secs, zones: &ZoneRegistry, pol: &TrackingPolicy, acc: &mut UsageAccumulator) {
    let fg   = platform::foreground_pid();
    let idle = platform::idle_seconds();

    match fg.and_then(|pid| zones.member(pid)).and_then(|m| m.app_id) {
        Some(app) if pol.scope.includes(&app) => {
            acc.foreground[&app] += dt;
            if idle < pol.idle_threshold_secs {
                acc.active[&app] += dt;
            } else {
                acc.idle[&app] += dt;
            }
        }
        // foreground is a personal app, the desktop, or the lock screen:
        _ => acc.away += dt,   // duration only — never *what*
    }
}
```

Note the third arm records **only** a duration. There is deliberately no branch that reads a
non-work window's identity.

---

## 6. Accounting model (aggregate on the device)

The tracker does **not** ship raw ticks. It accumulates them into a per-app bucket and flushes a
**summary** on `flush_interval_secs`, mirroring the `LearnSession` → `synthesize` pattern
(`clave-core/src/learn.rs`): observe into a session, fold into a rollup.

```rust
// clave-core/src/usage.rs — SKETCH
pub struct UsageSample { pub app_id: AppId, pub active: Secs, pub idle: Secs, pub foreground: Secs }

pub struct UsageSummary {          // one flush interval, T1 payload
    pub window_start: UnixTime,
    pub window_end:   UnixTime,
    pub per_app:      Vec<UsageSample>,
    pub sessions:     Vec<SessionSpan>,   // (app_id, opened, closed?) — populated at T2+
    pub launches:     Vec<(AppId, u32)>,
    pub away:         Secs,
}
```

Aggregating on the device is a threefold win: it caps the telemetry rate (one summary per
interval, not one event per tick — the same DoS concern doc 10 §6 raises for audit), it lowers
data granularity for privacy, and it survives brief offline windows (buckets accumulate, flush
when the link returns). Sessions derive from the zone-join/leave stream the daemon already emits;
`launches` is their per-day count.

---

## 7. Transport & integrity (a sibling stream, shared machinery)

Usage telemetry is **not** an `AuditAction`. That enum (`clave-core/src/audit.rs`) is a
payload-free `Copy` enum — a `UsageSummary` carries second-counts and cannot ride it, and
widening the *security* audit with productivity data would blur the doc 10 §6 privacy schema.
Instead it is a **distinct event type on its own chain**, reusing the transport wholesale:

```
UsageSummary ──emit──► UsageSpool (hash-chained, signed)      ← same primitives as AuditSpool
     │                    │  drain → DeviceSigningKey::sign_batch
     │                    ▼
     │             GatewayLink::push_usage (mTLS)              ← sibling of push_audit
     ▼                    ▼
  device DB         Gateway::ingest_device_usage → verify_batch → UsageStore::append (Postgres)
```

- **Reuse:** the spool, `entry_hash`/`sig_input` domain-separated hashing, `verify_batch`,
  `DeviceSigningKey`, and the 30 s `GatewaySync` drain loop (`clave-daemon/src/lib.rs`) are all
  generic over the payload. The usage chain is a second `AuditSpool`-shaped spool with its own
  `next_seq`/`head`, checkpointed alongside the audit chain.
- **Distinct persistence:** a `UsageStore` trait beside `AuditStore` (`audit_ingest.rs`), backed
  by a new `usage_summary` / `usage_session` table (Postgres migration), keyed by `DeviceId`.
- **Tamper-evidence for free:** because it is hash-chained and signed, a device that drops or
  rewrites a usage interval produces a **gap/tamper alert** at the gateway — the same
  suppression signal the audit ledger raises. Hours worked cannot be silently falsified.

Whether the usage chain warrants full hash-chaining is a real call: it does if the company
treats hours as an attestable record (payroll-adjacent, contractor billing); a lighter unsigned
channel would suffice if it is purely an internal wellness signal. The design **defaults to
signed** — downgrading is easy, upgrading a deployed fleet is not.

---

## 8. Policy model

A new signed sub-bundle, added the same way `InputPolicy` / `ScreenPolicy` / `WebPolicy` were —
`#[serde(default)]` so old bundles still deserialize, defaulting to **Off**:

```rust
// clave-core/src/policy.rs — SKETCH
#[derive(Serialize, Deserialize)]
pub struct TrackingPolicy {
    pub tier:                 TrackingTier,   // Off | Aggregate | Sessions | Full
    pub sample_interval_secs: u32,            // tick cadence (e.g. 5)
    pub idle_threshold_secs:  u32,            // input gap ⇒ idle (e.g. 60)
    pub flush_interval_secs:  u32,            // summary cadence (e.g. 300)
    pub scope:                TrackingScope,  // AllWorkApps | Only(Vec<AppId>)
    pub capture_titles:       bool,           // honored at T2+ only
    pub consent_ack_required: bool,           // block work launch until acknowledged (§9)
}

impl Default for TrackingPolicy {            // fail-closed = collect nothing
    fn default() -> Self { Self { tier: TrackingTier::Off, /* … */ } }
}
```

- `validate()` (`clave-core/src/policy.rs`) rejects incoherent bundles: `capture_titles` at T0/T1,
  a `flush_interval` below `sample_interval`, an empty `Only([])` scope.
- Propagation is free: a reissued bundle reaches the daemon via `update_policy` and the
  `PolicyObserver` (`clave-daemon/src/lib.rs`); on macOS it is re-published to the ES client by
  `publish_es_policy`. Raising the tier is itself an audited policy version bump.
- Because the default is `Off`, tracking is **opt-in per tenant** and every increase in fidelity
  is a deliberate, signed, version-stamped act — there is no way to "quietly" turn it up.

---

## 9. Gateway, rollup & surfaces

### 9.1 Per-user rollup

Usage arrives keyed by `DeviceId`, but a manager dashboard is per **person**. The edge already
exists: `DeviceRecord.enrolled_by: UserId` (`clave-gateway/src/store.rs`). A
`usage_by_user(ctx, range)` join — `list_devices` (each carries `enrolled_by`) against
`usage_summary` rows — is a pure gateway-layer addition, gated by `AdminAction::ViewAudit` (or a
new `ViewActivity`), no schema change beyond the usage table itself. This mirrors
`Gateway::audit_events` (`clave-gateway/src/gateway.rs`), which today rolls up by device.

### 9.2 Console dashboard

The admin console (doc 15, `apps/clave-console`) gains an **Activity** view: hours per app per
user per day, active-vs-idle split, and the `away` band. Sourced from a
`GET /admin/activity?from=…&to=…` report endpoint beside `/admin/audit/*`.

### 9.3 Launcher transparency (consent is a feature, not fine print)

The employee must *see* what is measured — both to earn trust and because many jurisdictions
require it. The launcher's Status panel (doc's NG-11, `LauncherStatus` in `clave-ipc/src/lib.rs`)
surfaces the active **tier**, and a new `LauncherRequest::UsageReport` returns the device's *own*
current-day rollup so the user sees exactly what their employer sees — no more. When
`consent_ack_required` is set, the first work launch of a session shows the tier and blocks until
acknowledged; the acknowledgement is itself an audit event.

---

## 10. Honest limits

| Limit | Consequence | Mitigation |
|---|---|---|
| User-mode, no kernel backing | A determined user can kill the watch thread | Chain-gap detection flags the suppression at the gateway (§7) |
| OS idle timer is spoofable | Synthetic input can inflate "active" | Treat active-time as a signal, not proof; cross-check against session spans |
| Sub-tick app switches | Brief foregrounds between ticks are missed | Short `sample_interval`; foreground totals are approximate by design |
| Idle ≠ away | "Reading a long doc" reads as idle | Report active **and** idle separately; never collapse to a single "productivity %" |
| Clock skew / sleep | Wall-clock math drifts across suspend | Bound `dt` per tick; anchor windows to monotonic time, stamp with wall time at flush |
| Multiple work windows | Two work apps visible, one foreground | Foreground is authoritative; only the front app accrues active/idle |

The framing to keep: this measures **presence and attention approximately**, over **work apps
only**. It is not a lie detector and the docs should never let a dashboard imply it is.

---

## 11. Test plan

- **Privacy assertion (static).** A test that greps the `UsageSummary` / usage-chain types for
  any field that could carry a personal path, URL, or non-work identity — the doc 10 §7
  "privacy by schema" test, extended. The `away` counter must remain a bare duration.
- **Zone-scoping (integration).** Drive a personal app to the foreground; assert the tracker
  emits only `away` and never names it. Only supervised PIDs produce per-app buckets.
- **Accounting identity (property).** For any tick stream,
  `Σ foreground == Σ(active+idle)` and `Σ foreground + away == observed wall-clock`.
- **Tier ceilings.** T1 never emits titles or session spans; T2 emits titles only when
  `capture_titles`; T0 emits nothing. Fuzz the tier field ⇒ never collects above the ceiling.
- **Fail-closed.** Bundle missing `tracking`, expired, or unparseable ⇒ tier resolves to Off.
- **Tamper-evidence.** Drop / rewrite a usage batch ⇒ gateway raises a gap/tamper alert, matching
  the audit-ledger tests in `audit_ingest.rs`.

---

## 12. Build phasing

Sequenced so the **entire T1 slice ships on a dev machine with no entitlement**, and nothing
early depends on an OS-gated capability.

| Phase | Work | Delivers | Blocked on |
|---|---|---|---|
| **A** | `idle_seconds()` primitive (mac/win); carry `AppId` on `ZoneMember`; `usage.rs` accumulator + `UsageSummary`; `spawn_usage_watch`; `TrackingPolicy` (T0/T1) | **T1 aggregate tracking, end to end**, on a plain dev machine | — |
| **B** | `UsageSpool` + `UsageStore` + `usage_summary` migration; `push_usage` on the gateway link; per-user rollup + `/admin/activity`; console Activity view | Fleet dashboard, tamper-evident | Gateway store (doc 15) |
| **C** | `LauncherRequest::UsageReport`; consent gate; tier surfaced in Status panel | Employee transparency / consent | Launcher Status (NG-11) |
| **D** | T2 session timelines + work-app window titles (Screen-Recording TCC) | Session-level detail | TCC grant on mac |
| **E** | T3 work-window snapshots (capture only Clave-owned surfaces) | Full monitoring tier | Screen-capture machinery (doc 07) |

Phase A is a small extension of machinery that already exists: the foreground/idle APIs sit
beside primitives the clipboard and input watches already call, the spool/sign/verify transport
is generic over its payload, and `PolicyBundle` already distributes tenant-signed from the
gateway. Only the *summary type* and the *policy field* are new.

---

See [10 — Policy Engine, IPC & Audit](10-policy-engine-and-ipc.md) for the transport this rides,
[01 — Threat Model](01-threat-model.md) for the adversaries it must stay honest against, and
[15 — Identity & Enrollment](15-identity-and-enrollment-auth.md) for the per-user rollup edge.
