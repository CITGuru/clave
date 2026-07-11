# 03 — App-Subsystem Virtualization (the "no VM" trick)

This is the conceptual heart of the system: *emulated registry and emulated global objects.* It is
the mechanism that lets unmodified native apps run inside a boundary **without** a guest OS.

> **Core idea.** Don't virtualize the *machine*. Virtualize the *subsystems an application
> touches* — its registry view, its kernel-object namespace, and its filesystem view — so
> the app believes it owns the system while actually living in a redirected, copy-on-write
> layer owned by the enclave.

This document is **heavily Windows-weighted** because Windows both needs it (rich registry +
shared namespaces) and permits it (injection + kernel callbacks). macOS neither needs the
registry part nor permits the injection part; §5 explains what you do instead.

---

## 1. The three subsystems to virtualize (Windows)

| Subsystem | Why an app touches it | Leak/conflict if not virtualized |
|-----------|----------------------|----------------------------------|
| **Registry** | App settings, license, file associations, COM registration | Work app config bleeds into personal hive; two zones collide; uninstall leaves work keys |
| **Object namespace** | Mutexes, events, sections, named pipes, COM monikers (`\BaseNamedObjects`, `\Sessions\…`) | Work and personal instances of the same app share IPC objects → cross-zone signaling and "app already running" clashes |
| **Filesystem** | Files, profiles, caches, temp | Work files land on personal disk in cleartext; can't wipe; can't gate access |

Virtualizing all three yields an app that is *functionally native* (full speed, full API
surface) but *contained* (everything it persists or shares is inside the enclave).

---

## 2. Injection: getting your code into the work app

You need your shim DLL loaded into the work process **before** its first real instruction,
so hooks are in place before the CRT and the app touch anything.

### 2.1 Suspended-create + manual map (recommended)

```rust
// daemon (Rust, windows crate) — abbreviated
unsafe {
    CreateProcessW(.., CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, .., &mut pi)?;

    // 1. allocate a page in the target, write the shim path
    let remote = VirtualAllocEx(pi.hProcess, None, path_bytes.len(),
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, remote, path_bytes.as_ptr() as _,
                       path_bytes.len(), None)?;

    // 2. queue an APC that LoadLibrary's the shim when the main thread first runs
    let load = GetProcAddress(GetModuleHandleW(w!("kernel32"))?, s!("LoadLibraryW"));
    QueueUserAPC(transmute(load), pi.hThread, remote as usize);

    // 3. membership + redirection already armed by the driver (doc 02); now resume
    ResumeThread(pi.hThread);
}
```

Why APC injection over `CreateRemoteThread`: the APC fires on the app's *own* main thread as
it begins, which sequences cleanly before CRT init and avoids a transient extra thread that
some anti-cheat/AV heuristics flag.

> **Alternative loaders.** (a) `IFEO` "Debugger"/`VerifierDlls` keys — durable but global and
> AV-noisy. (b) AppInit_DLLs — deprecated, Secure-Boot-disabled. (c) A Detours-style
> `DetourCreateProcessWithDllEx` — battle-tested, MIT-licensed, and the pragmatic choice if
> you don't want to hand-roll the loader. Prefer Detours' helper for the loader and your own
> Rust for the hooks.

### 2.2 The shim entrypoint

```rust
// clave-shim (Rust cdylib) — DllMain
#[no_mangle]
extern "system" fn DllMain(_h: HINSTANCE, reason: u32, _r: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        // Do the minimum here (loader lock!). Just arm hooks; defer everything else.
        install_hooks();                       // §3
        connect_daemon_async();                // IPC handshake off-thread
    }
    TRUE
}
```

Loader-lock discipline matters: **no** heavy work, **no** synchronous IPC, **no** allocation
that could re-enter the loader inside `DLL_PROCESS_ATTACH`. Arm hooks, return, do the rest
from the first hooked call or a deferred thread.

---

## 3. Hooking: redirecting the three subsystems

Hook at the **Nt\*** layer (the lowest user-mode boundary, `ntdll`), not Win32, so you catch
every caller including statically-linked CRTs and other DLLs. Use the `retour` crate (inline
trampolines) or `minhook-sys`.

### 3.1 Registry virtualization (copy-on-write hive)

```rust
// clave-shim/src/hooks/registry.rs  — SKETCH
static_detour! { static NtCreateKeyHook: unsafe extern "system"
    fn(*mut HANDLE, u32, *const OBJECT_ATTRIBUTES, u32, *const u16, u32, *mut u32) -> NTSTATUS; }

unsafe fn nt_create_key(out: *mut HANDLE, access: u32, attrs: *const OBJECT_ATTRIBUTES,
                        idx: u32, class: *const u16, opts: u32, disp: *mut u32) -> NTSTATUS {
    let path = object_attributes_path(attrs);          // e.g. \REGISTRY\MACHINE\SOFTWARE\Acme
    if policy::is_virtualized_hive(&path) {
        // Redirect into the enclave's private hive, loaded from the Clave Disk and
        // mounted under a per-zone root, e.g. \REGISTRY\A\Clave\{zone}\...
        let redirected = remap_into_zone_hive(&path);
        return NtCreateKeyHook.call(out, access, &redirected, idx, class, opts, disp);
    }
    NtCreateKeyHook.call(out, access, attrs, idx, class, opts, disp)
}
```

Semantics to get right:

- **Copy-on-write:** reads fall through to the real machine hive (so the app sees a working
  Windows), but the *first write* to a key clones the subtree into the zone hive and all
  subsequent reads/writes use the clone. This is exactly App-V's model.
- **Deletion tombstones:** a "deleted" key that exists in the base hive needs a tombstone in
  the zone layer so it appears gone without mutating the base.
- **Enumeration merge:** `NtEnumerateKey`/`NtEnumerateValueKey` must *merge* base + zone +
  tombstones so the app sees a coherent union.
- **The private hive** is a real `.hiv` file living on the Clave Disk, `RegLoadKey`'d under a
  per-zone path at enclave unlock.

### 3.2 Object-namespace virtualization

Prefix every named object so zones (and personal) can't collide or share IPC:

```rust
// hook NtCreateMutant / NtCreateEvent / NtCreateSection / NtCreateNamedPipeFile / NtOpenSection …
unsafe fn rename_object(attrs: *const OBJECT_ATTRIBUTES) -> OwnedObjectAttributes {
    // \BaseNamedObjects\AcmeAppMutex  ->  \BaseNamedObjects\Clave-{zone}\AcmeAppMutex
    prefix_name(attrs, &format!("Clave-{}\\", current_zone_id()))
}
```

This is what makes "work Chrome" and "personal Chrome" two independent instances instead of
one process refusing to start because the singleton mutex already exists. **Server Silos**
(doc 02 §2.2) give you this for free at the kernel level if you adopt them; the hook approach
is the no-silo fallback and has broader app-compat.

### 3.3 Filesystem redirection

Two layers, defense-in-depth:

1. **User-mode hook** (`NtCreateFile`/`NtOpenFile`) redirects work paths into the Clave Disk
   volume and applies COW for system paths the app writes to — fast path, good app-compat.
2. **Kernel minifilter** (the authoritative backstop, doc 04) enforces that *no* process
   outside the zone can open the Clave Disk, and *no* in-zone process can write cleartext work
   data outside it — even if the user-mode hook is removed (A6).

```rust
// hook redirects; minifilter enforces. Both consult the same policy.
unsafe fn nt_create_file(.., attrs: *const OBJECT_ATTRIBUTES, ..) -> NTSTATUS {
    let path = object_attributes_path(attrs);
    match policy::classify_path(&path) {
        PathClass::WorkData   => NtCreateFileHook.call(.., &remap_to_clave_disk(&path), ..),
        PathClass::SystemCow  => NtCreateFileHook.call(.., &cow_remap(&path), ..),
        PathClass::PassThrough=> NtCreateFileHook.call(.., attrs, ..),
    }
}
```

> **Modern alternative to hooking FS:** **Windows Projected File System (ProjFS)** or a
> minifilter with reparse points can present the zone's virtual view without per-call
> hooking. ProjFS is cleaner but adds latency and is designed for on-demand hydration (Git
> VFS) more than for redirection. Recommendation: minifilter for enforcement + Nt-hooks for
> redirection in v1; evaluate ProjFS for the read-through layer later.

---

## 4. Anti-tamper: why the kernel must backstop the hooks

A hostile **work** app (A3) or a privileged user (A6) can walk `ntdll`, detect your
trampolines, and restore the original bytes — defeating *all* user-mode redirection. This is
why the **enforcement** guarantees (can't read the disk from outside, can't write work data
outside) must live in the **minifilter/registry-callback/WFP** layer keyed on the supervised
PID set, exactly as [01 §4](01-threat-model.md) demands.

Division of labor:

| Goal | Lives in | Defeated by hook removal? |
|------|----------|---------------------------|
| *Redirect* app to the right place (app-compat) | user-mode hooks | yes — app breaks, but doesn't leak |
| *Prevent* cross-zone read/write (security) | kernel minifilter / Cm callback | **no** |

The mental model: **hooks make it work; the kernel makes it safe.** If a hook is stripped,
the app should *fail* (fail-closed), not *leak*.

---

## 5. macOS: why this model does not transfer, and what replaces it

Three macOS facts dismantle the Windows approach:

1. **No registry.** The whole registry-virtualization pillar is moot. App config is files
   (`~/Library/Preferences/*.plist`, container dirs) — so it collapses into the *filesystem*
   problem.
2. **Injection is blocked.** **SIP**, **library validation**, **hardened runtime**, and
   **AMFI** prevent `DYLD_INSERT_LIBRARIES` from loading your dylib into signed third-party
   apps. You cannot Detours-style hook Chrome or Excel on a stock Mac. (You could only inject
   into apps you re-sign, which you can't do to others' binaries.)
3. **No kernel hook surface.** kexts are deprecated; you only have user-space System
   Extensions.

So macOS isolation is **filesystem + authorization + sandbox**, not injection + emulation:

- **Filesystem isolation:** work data lives only on the encrypted volume (doc 04). The ES
  client's `ES_EVENT_TYPE_AUTH_OPEN` **denies** any non-supervised process from opening
  paths under the volume, and denies supervised processes from writing work-classified data
  outside it. ES is authoritative and needs no injection.
- **Object/namespace isolation:** macOS uses Mach ports and BSD sockets rather than a global
  named-object namespace; cross-instance collisions are far less common. Where an app uses a
  singleton lock file or a Mach service name, run the work instance under a **distinct
  container** (separate `HOME`/container dir on the encrypted volume) so its per-user paths
  and `NSUserDefaults` domain differ from the personal instance.
- **Optional sandbox profile:** launch work apps via a Seatbelt profile
  (`sandbox_init`/`sandbox-exec`, a *private* API — flag the support risk) to further fence
  reachable resources. This is hardening, not the primary boundary.

### 5.1 The macOS "zone" in practice

```
Personal Chrome:  HOME=/Users/alice          → ~/Library/... on personal APFS
Work Chrome:      HOME=/Volumes/ClaveDisk/work → all profile/cache/prefs on encrypted volume
                  + ES denies it opening anything classified personal
                  + ES denies personal processes opening /Volumes/ClaveDisk/*
```

You get isolation by **giving the work app a different home on an access-gated encrypted
volume**, then using ES to enforce the gate — instead of by emulating subsystems inside the
process. It is coarser than Windows (no per-key COW registry, no namespace prefixing) but it
is *kernel-authoritative* and needs no injection.

### 5.2 Honest gap

Because you can't inject, several Windows niceties are unavailable on macOS: per-app
copy-on-write of system config, transparent path remapping for apps that hardcode
`~/Documents`, and singleton-mutex de-confliction for apps not designed for multi-profile.
Apps that assume a single global instance per user may misbehave when run as both personal
and work. Maintain an **app-compat matrix** and a per-app launch profile (env, container,
ES rules) rather than a universal mechanism.

---

## 6. App-compat: the unglamorous 60% of the work

Whichever OS, the long tail is application compatibility. Build infrastructure for it:

- **Per-app profiles** describing: virtualized hive seeds (Win), container/HOME layout, env
  vars, namespace prefixes, allowed pass-through paths, known singleton locks.
- **A "learn" mode** that runs an app with logging-only hooks/ES-notify to discover which
  paths, keys, and objects it touches, then generates a candidate profile.
- **Regression harness** that launches the top N work apps (Office, Chrome, Edge, Slack,
  Acrobat, Teams, SAP GUI, Citrix Workspace receiver, custom LOB apps) and asserts they boot,
  persist to the right place, and don't leak.

> Plan for this explicitly. Sandboxie's value is less its hooks than its decade of
> app-compat shims; you are signing up to rebuild a slice of that.

---

## 7. Reference blueprint

**Sandboxie-Plus** (`Sandboxie-Plus/Sandboxie`, GPLv3) is the canonical open-source
implementation of exactly this model: `SbieDrv` (the kernel driver: process notify, object
filtering, minifilter-style FS/registry redirection) + `SbieDll` (the injected user-mode
hooks). Read `core/drv/` and `core/dll/` before writing your own. License note: GPLv3 — read
for architecture, don't copy code into a proprietary product.

Proceed to [04 — Encrypted Volume](04-encrypted-volume.md).
