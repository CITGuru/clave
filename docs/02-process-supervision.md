# 02 — Process Supervision (defining the zone)

Every other subsystem asks one question on its hot path: **"is this process in the work
zone?"** This document specifies how membership is established at process birth, stored, and
made answerable from the kernel-authoritative layer.

Implements the `ProcessSupervisor` trait from [00 §4](00-architecture-overview.md).

---

## 1. Requirements

1. **Decide-at-birth.** Membership must be known *before* the work app executes its first
   instruction, so that registry/FS redirection is armed before the C runtime initializes
   (see [03](03-app-subsystem-virtualization.md)). A late decision = a leak window.
2. **Inheritance.** Work apps spawn helpers (Chrome's renderer/GPU processes, Office's
   click-to-run, installers). Children of supervised processes are supervised by default.
3. **Authoritative identity.** Membership keys on an identity the kernel vouches for
   (Windows PID+create-time; macOS audit token), not a name or a self-report.
4. **O(1) lookup, lock-light.** The set is read on nearly every IRP/flow; use a read-mostly
   concurrent structure.
5. **Fail-closed.** If the supervisor is unsure, treat as **unsupervised** for *privilege*
   (don't grant enclave access) but **supervised** for *containment* if the parent was
   supervised (don't let a child escape). These two defaults point opposite ways on purpose;
   §6 resolves the ambiguity.

---

## 2. Windows implementation

### 2.1 Process-creation callback (kernel)

Register `PsSetCreateProcessNotifyRoutineEx2` from the driver. This fires in the context of
the *creating* thread, **before** the new process runs, and lets you stash data or even
deny creation.

```c
// driver (C / WDK) — the callback. Rust-via-windows-drivers-rs mirrors this 1:1.
VOID OnCreateProcessEx(
    _Inout_ PEPROCESS Process,
    _In_    HANDLE    ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO Info)
{
    if (Info != NULL) {                      // process creation (not exit)
        HANDLE parent = Info->ParentProcessId;
        BOOLEAN parent_supervised = SetContains(g_supervised, parent);
        BOOLEAN launched_by_daemon = (Info->CreatingThreadId.UniqueProcess == g_daemon_pid);

        if (parent_supervised || launched_by_daemon) {
            ProcInfo pi = { .pid = ProcessId,
                            .create_time = QueryCreateTime(Process),
                            .reason = parent_supervised ? CHILD : LAUNCHER };
            SetInsert(g_supervised, &pi);    // O(1), interlocked
            ArmRedirection(ProcessId);       // mark for FS/registry filter (doc 03)
            NotifyUserMode(PROC_ADDED, &pi); // inverted-call to daemon
        }
    } else {                                 // process exit
        SetRemove(g_supervised, ProcessId);
        NotifyUserMode(PROC_REMOVED, ProcessId);
    }
}
```

Key points:

- `g_daemon_pid` is set when the daemon connects and presents its signed token; only the
  daemon's launcher seeds new *root* work processes.
- `QueryCreateTime` (from `PsGetProcessCreateTimeQuadPart` / `KeQuerySystemTime`) defeats
  **PID reuse** — the tuple `(pid, create_time)` is unique for the life of the boot.
- The callback must be **fast and non-blocking** (it runs at `PASSIVE_LEVEL` but in a hot
  path). Do the heavy lifting (telemetry, policy eval) asynchronously in the daemon.

### 2.2 Containment via Job Object / Server Silo

Membership in a set is necessary but not sufficient for *containment*. Assign each root work
process (and thus its descendants) to a **Job Object** so the OS itself enforces grouping,
resource limits, and kill-on-close:

```rust
// daemon (Rust, windows crate) — launch path
use windows::Win32::System::JobObjects::*;
use windows::Win32::System::Threading::*;

let job = unsafe { CreateJobObjectW(None, w!("Clave.Work.Zone\\app-excel"))? };
// Kill all descendants if the job handle closes → no orphaned work procs.
let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
unsafe { SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &info as *const _ as _, size_of_val(&info) as u32)? };

let mut si = STARTUPINFOEXW::default();
let mut pi = PROCESS_INFORMATION::default();
unsafe {
    CreateProcessW(/* app */ None, &mut cmdline, None, None, false,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP,
        None, None, &si.StartupInfo, &mut pi)?;
    AssignProcessToJobObject(job, pi.hProcess)?;   // descendants inherit the job
    // ... inject shim (doc 03), then ResumeThread(pi.hThread)
}
```

> **Server Silos** (the kernel primitive behind Windows Containers) go further: a silo gives
> the work zone its *own* object-manager namespace and registry view, which is the cleanest
> form of the §03 isolation. But silos are heavyweight and constrain which apps run cleanly.
> Recommendation: ship Job-Objects + injected redirection first; evaluate silos as a v2
> hardening once the app-compat matrix is understood.

### 2.3 Sharing the set to user mode (inverted call)

The driver owns the authoritative set; the daemon needs a read view, and the WFP callout /
minifilter need to query it cheaply. Pattern:

- The driver keeps the set in non-paged pool, indexed by a hash of `pid`.
- The daemon posts a pool of **pending IOCTLs** (`METHOD_BUFFERED`) that the driver completes
  on each membership change (the "inverted call model") — push notifications without polling.
- In-kernel consumers (minifilter, callout) call a shared `SetContains` directly; no
  user-mode round trip on the data path.

```rust
// daemon side — drain membership change notifications
let mut ev = ProcEvent::default();
loop {
    device.ioctl(IOCTL_CLAVE_WAIT_PROC_EVENT, &mut ev)?; // blocks until driver completes
    match ev.kind {
        ProcAdded   => core.on_zone_join(ev.proc_id()),
        ProcRemoved => core.on_zone_leave(ev.proc_id()),
    }
}
```

---

## 3. macOS implementation

No kernel code. The **Endpoint Security (ES) framework** is the authoritative source. You
subscribe to exec events; the `audit_token` is the identity.

### 3.1 The ES client (Swift/ObjC host)

ES has no Rust bindings and is entitlement-gated
(`com.apple.developer.endpoint-security.client`). Write a thin Swift host that owns the
client and calls into the Rust core (`libclave_core.a`).

```swift
// ClaveESClient.swift  (System Extension host)
import EndpointSecurity

var client: OpaquePointer?
let res = es_new_client(&client) { (client, msg) in
    switch msg.pointee.event_type {

    case ES_EVENT_TYPE_AUTH_EXEC:
        let target = msg.pointee.event.exec.target.pointee
        let token  = target.audit_token                       // authoritative identity
        let path   = String(cString: target.executable.pointee.path.data)
        let ppid   = msg.pointee.process.pointee.ppid

        // Ask Rust: should this exec be in the zone? Returns join/allow decision.
        let decision = clave_core_on_exec(path, token_bytes(token), ppid)
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false)
        if decision.joins_zone { clave_core_zone_insert(token_bytes(token)) }

    case ES_EVENT_TYPE_NOTIFY_EXIT:
        clave_core_zone_remove(token_bytes(msg.pointee.process.pointee.audit_token))

    default: break
    }
}
es_subscribe(client, [ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT,
                      ES_EVENT_TYPE_NOTIFY_FORK], 3)
```

### 3.2 Membership rules on macOS

- **Launcher-seeded:** the Clave launcher execs work apps with a known parent; the ES client
  recognizes the launcher's audit token as the seed.
- **Inheritance via `NOTIFY_FORK`/`exec` parent token:** children of in-zone processes join
  the zone. ES gives you the parent token on every event, so inheritance is a parent-set
  lookup.
- **Code-identity gating:** because you can't *contain* the way a Job Object does, tighten
  the seed: only allow zone-join for binaries matching a signed allow-list
  (`signing_id`/Team ID from `es_event_exec_t`), so a renamed personal binary can't sneak
  into the zone by parentage alone.

### 3.3 What ES gives you that Windows callbacks don't, and vice-versa

| | Windows driver | macOS ES |
|---|---------------|----------|
| Decide before run | ✅ (pre-create) | ✅ (`AUTH_EXEC` blocks until you respond) |
| Authoritative id | PID+create-time | audit_token |
| Contain children in a kernel group | ✅ Job/Silo | ✗ (no equivalent; tracking only) |
| Deny exec entirely | ✅ | ✅ (`ES_AUTH_RESULT_DENY`) |
| Mute noisy processes for perf | manual | ✅ `es_mute_path` |

> **Performance caution (macOS):** `AUTH_EXEC` is synchronous — the process is *blocked*
> until you respond, and ES enforces a **message deadline** (~seconds); miss it and your
> client is killed. Keep the exec decision O(microseconds): a hash-set lookup + an allow-list
> check, never a network call. Do policy refresh out-of-band.

---

## 4. The membership data structure (shared core)

The core keeps a portable mirror for policy/audit; the OS layer keeps the authoritative copy.

```rust
// clave-core/src/zone.rs
use dashmap::DashMap;          // read-mostly, sharded; or arc-swap of an im::HashSet

pub struct ZoneRegistry {
    members: DashMap<ProcId, ZoneMember>,
}
pub struct ZoneMember {
    pub id:        ProcId,
    pub joined_at: Instant,
    pub reason:    JoinReason,      // Launcher | Child(parent) | AllowList
    pub app_id:    AppId,          // which work app (Excel, Chrome-Work, …)
    pub job:       Option<JobHandle>, // Windows only
}
pub enum JoinReason { Launcher, Child(ProcId), AllowList }

impl ZoneRegistry {
    #[inline] pub fn is_supervised(&self, p: &ProcId) -> bool { self.members.contains_key(p) }
}
```

Design notes:

- **Read-mostly:** writes happen only at exec/exit; reads happen constantly. `DashMap` or an
  `arc-swap`-wrapped immutable set both work; benchmark under your IRP load.
- **PID reuse:** always compare the full `ProcId` (with create-time/audit-token), never the
  bare integer.
- **Crash recovery:** on daemon restart, re-enumerate live processes (Win: `Toolhelp`/`NtQuerySystemInformation`;
  mac: `libproc`) and re-derive membership from running parents + the launcher tree, because
  the in-memory set is lost. The driver/ESF set survives if the driver didn't unload.

---

## 5. TOCTOU and race conditions

- **Exec race (Windows):** between `CreateProcess(SUSPENDED)` and `ResumeThread`, the PID is
  in the set and redirection is armed — so there is *no* window where the app runs
  unsupervised. Never resume before arming. This ordering is a hard invariant.
- **Re-parenting / handoff:** some launchers (Office click-to-run, Chrome) create a broker
  that then spawns the real app and exits. Track the *whole* short-lived tree; rely on
  inheritance, and don't remove a parent's children from the set when the parent exits (the
  Job Object's `KILL_ON_JOB_CLOSE` and per-process exit events handle lifetime).
- **macOS exec deadline race:** if your ES client is slow, the OS may kill it and (depending
  on config) fail-open. Mitigate with a watchdog and a conservative default (deny exec of
  unknown binaries *into* the zone, allow everything else).

---

## 6. Resolving the two fail-closed defaults

§1 said unsure-membership points two ways. Concretely:

```
on uncertain process P:
    grant_enclave_access(P)   = false          // privilege: default DENY  (protect assets)
    allow_escape(P)           = false if parent∈zone else true
                                                // containment: a child of work stays in
```

That is: **never grant a process enclave privileges on a guess**, but **never let a known
work child slip out on a guess**. The only way both hold is to make the join decision at
birth (where parentage is known) and treat post-hoc reclassification as deny-privilege.

---

## 7. Test plan for this subsystem

- Launch a work app; assert its PID and *all* helper PIDs appear in the driver/ESF set
  before any of them open a file.
- Kill the daemon; assert the set is preserved by the driver (Windows) and that ESF restarts
  cleanly (macOS); assert fail-closed (work apps lose enclave access).
- Spawn a deep child tree (Chrome with 30 renderers); assert inheritance and no leaks on
  exit; assert no PID-reuse false positives by rapidly cycling processes.
- Attempt to seed a renamed personal binary via a work parent (macOS); assert the allow-list
  blocks zone-join.

Proceed to [03 — App-Subsystem Virtualization](03-app-subsystem-virtualization.md).
