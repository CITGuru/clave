# Appendix A — Windows Primitives Quick Reference

A lookup table mapping each subsystem to the concrete Windows API / driver primitive and the
Rust crate that reaches it. Cross-reference the numbered docs for usage.

---

## A.1 Process supervision (doc 02)

| Need | Primitive | Layer | Rust |
|------|-----------|-------|------|
| Decide membership at process birth | `PsSetCreateProcessNotifyRoutineEx2` | kernel | `windows-drivers-rs` / C |
| Thread-create notifications | `PsSetCreateThreadNotifyRoutine` | kernel | same |
| Contain a process tree | **Job Objects** (`CreateJobObjectW`, `AssignProcessToJobObject`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) | user | `windows` |
| Stronger kernel namespace isolation | **Server Silos** | kernel | (WDK) |
| Enumerate live procs (recovery) | `CreateToolhelp32Snapshot` / `NtQuerySystemInformation` | user | `windows` |
| Authoritative create time (anti-PID-reuse) | `PsGetProcessCreateTimeQuadPart` | kernel | WDK |
| Push set to user mode | inverted-call `DeviceIoControl` (pended IRPs) | both | `windows` |

### Enforced containment model (what `Enforced` requires)

The rows above split into two tiers. **Job Objects are the lab-build stand-in, not the enforced
path**: `AssignProcessToJobObject` runs *after* `CreateProcess`, so it (1) races the process's own
startup and (2) cannot hold a process it did not itself spawn. A launcher that shells out to a
**singleton or broker** — e.g. `explorer.exe`, which forwards the request to the already-running
desktop shell over DCOM and exits; COM/`svchost`-activated or protected processes likewise — leaves
the spawned PID dead and the real window hosted by a process outside the job.

The enforced model does not try to *own* such processes. It decides membership in the kernel at
birth and gates the **resource** by that tag:

- **Tag at birth** — `PsSetCreateProcessNotifyRoutineEx2` fires synchronously just after the first
  thread is created, in the creator's context, carrying `ParentProcessId` +
  `CreatingThreadId->UniqueProcess` + image name, and can set `CreationStatus` to **block** the
  spawn. Every process is classified work/personal before it runs — no assign-after-spawn window —
  and PID reuse is closed with `PsGetProcessCreateTimeQuadPart`.
- **Gate the Clave Disk, not the process** — the encryption minifilter attaches a per-`FileObject`
  context at `IRP_MJ_CREATE` recording the opening process, and decrypts only for tagged work
  processes. An untagged singleton shell reads ciphertext / is denied, so it never needs containing.
- **Gate the network per tag** — the WFP callout (`ALE_CONNECT_REDIRECT` / `ALE_AUTH_CONNECT`)
  classifies and routes each flow by the same kernel PID tag.

All three entry points (`PsSetCreateProcessNotifyRoutineEx2`, `ObRegisterCallbacks`,
`FltRegisterFilter`) return `STATUS_ACCESS_DENIED` for an unsigned driver on a Secure Boot machine
(Win10 1607+). That signing requirement (A.10) is the exact line between today's `DevelopmentOnly`
user-mode controls and `Enforced`. Until it is met, user-mode supervision cannot contain
shell/singleton apps, so the demo allow-list should carry only normally spawnable apps.

### Driver bring-up (the process)

Reaching `Enforced` is a workstream distinct from the user-mode crates. The `PsSetCreateProcessNotifyRoutineEx2`
tag-at-birth callback lives in a new `clave.sys`; standing it up, in order:

1. **Stand up a driver target.** `clave.sys` via `windows-drivers-rs` (WDM/KMDF; mirrors the C in
   [doc 02 §2.1](02-process-supervision.md)) or C/WDK. `DriverEntry` registers the callback and
   removes it on unload; add an IOCTL control device for the user-mode bridge.
2. **Satisfy the load-time gates.** Link `/INTEGRITYCHECK` (sets
   `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`) — without it the callback registration returns
   `STATUS_ACCESS_DENIED`. The image must also be signed: a self-signed **test cert** in dev, the
   Microsoft counter-signature in prod (step 5).
3. **Iterate on a throwaway VM.** Windows 11 VM + WDK/Visual Studio (or the `windows-drivers-rs`
   toolchain) + test cert + kernel debugger; `bcdedit /set testsigning on`, load via
   `sc create clave type= kernel` + `sc start`. Not the primary box — the callback sits in *every*
   process-creation path, so a bug BSODs it, wedges process creation, or breaks boot, and
   test-signing means dropping Secure Boot / HVCI; WinDbg needs a separate target regardless.
4. **Bridge to the daemon (inverted call).** `clave-win` opens the control device, seeds
   `g_daemon_pid`, and drains `PROC_ADDED`/`PROC_REMOVED` over pended IOCTLs into `ZoneRegistry`
   ([doc 02 §2.3](02-process-supervision.md)) — replacing the 500 ms Job-Object poll for
   *membership*; the Job Object stays for kill-on-close *containment*. The same driver (or a
   companion minifilter) later gates the Clave Disk per tag.
5. **Production signing (the long pole).** EV cert → Partner Center → attestation (or WHQL)
   counter-signature; a minifilter also needs a Microsoft-allocated altitude. Weeks of lead,
   re-submitted each revision ([doc 12 §1.2](12-signing-distribution-deployment.md)); only then
   does it load on a stock Secure-Boot machine. (Contrast WinDivert in A.7: a *pre-signed*
   third-party driver that loads on a normal machine and only needs elevation.)

## A.2 App-subsystem virtualization (doc 03)

| Need | Primitive | Layer | Rust |
|------|-----------|-------|------|
| Inject shim before app runs | `CreateProcess(CREATE_SUSPENDED)` + `QueueUserAPC(LoadLibraryW)` | user | `windows` |
| Alt loader | `DetourCreateProcessWithDllEx` (MS Detours) | user | FFI / `retour` ecosystem |
| Inline hooks | trampoline hooks on `ntdll` Nt* stubs | user | `retour`, `minhook-sys` |
| Registry virtualization (COW) | hook `NtCreateKey`/`NtOpenKey`/`NtSetValueKey`/`NtEnumerateKey`; backstop `CmRegisterCallbackEx` | user + kernel | `retour` + WDK |
| Private hive | `RegLoadKey`/`RegUnLoadKey` of an `.hiv` on the Clave Disk | user | `windows` |
| Namespace prefixing | hook `NtCreateMutant`/`NtCreateEvent`/`NtCreateSection`/`NtCreateNamedPipeFile` | user | `retour` |
| Filesystem redirection | hook `NtCreateFile`/`NtOpenFile`; minifilter (`FltRegisterFilter`) backstop; or **ProjFS** | user + kernel | `retour` + WDK |

## A.3 Encrypted volume (doc 04)

| Need | Primitive | Rust |
|------|-----------|------|
| User-mode filesystem | **WinFsp** (or Dokany) | `winfsp` / `dokan` |
| Block cipher | AES-256-XTS | `aes` + `xts-mode` |
| Key wrap / hardware root | **TPM 2.0** (TBS API, `NCrypt*`, sealing to PCRs) | `windows`, `tss-esapi` |
| Lock key in RAM | `VirtualLock` + `Zeroizing` | `windows`, `zeroize` |
| Kernel access gate | minifilter `IRP_MJ_CREATE` deny by PID | WDK |

## A.4 Clipboard & DLP (doc 05)

| Need | Primitive | Rust |
|------|-----------|------|
| Observe clipboard | `AddClipboardFormatListener` / `WM_CLIPBOARDUPDATE` | `windows` |
| Own w/ delayed render | `SetClipboardData(fmt, NULL)` + `WM_RENDERFORMAT`/`WM_RENDERALLFORMATS` | `windows` |
| Private format | `RegisterClipboardFormatW("CF_CLAVE_TOKEN")` | `windows` |
| Paste target id | `GetForegroundWindow` → `GetWindowThreadProcessId` | `windows` |
| Drag-and-drop | OLE `IDataObject` / `DoDragDrop`; gate `CF_HDROP`, file-promise | `windows` |

## A.5 Input isolation (doc 06)

| Need | Primitive | Rust |
|------|-----------|------|
| Detect foreign keyloggers | enumerate `WH_KEYBOARD_LL` hooks | `windows` |
| **Real** input isolation | **kbdclass upper-filter driver** (per-consumer key state) | WDK |
| Block injected input | reject `KEYEVENTF_*`/`SendInput` into work windows (filter) | WDK |

## A.6 Screen capture (doc 07)

| Need | Primitive | Rust |
|------|-----------|------|
| Exclude window from capture | `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` (called from inside via shim) | `windows` |
| Re-apply on new windows | CBT hook / subclass on `WM_CREATE` | `windows` |
| Accurate visual rect | `DwmGetWindowAttribute(DWMWA_EXTENDED_FRAME_BOUNDS)` | `windows` |

## A.7 Network split-tunnel (doc 08)

| Need | Primitive | Rust |
|------|-----------|------|
| Per-PID flow classify/redirect | **WFP** callout at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, `ALE_AUTH_CONNECT` | WDK / `windows` |
| User-mode prototype | **WinDivert** | `windivert` |
| Virtual NIC | **Wintun** | `wintun` |
| WireGuard data plane | boringtun | `boringtun` |
| DNS steering | NRPT + tunnel adapter DNS | `windows` |

## A.8 Overlay (doc 09)

| Need | Primitive | Rust |
|------|-----------|------|
| Click-through layered window | `WS_EX_LAYERED|TRANSPARENT|NOACTIVATE|TOOLWINDOW` + `UpdateLayeredWindow` | `windows` |
| Track geometry/z-order | `SetWinEventHook` (`EVENT_OBJECT_LOCATIONCHANGE`, `EVENT_SYSTEM_FOREGROUND`, `EVENT_OBJECT_REORDER`) | `windows` |
| Z-placement | `SetWindowPos(overlay, just-above-target, SWP_NOACTIVATE)` | `windows` |
| DPI correctness | Per-Monitor-V2 manifest; `WM_DPICHANGED`/`WM_DISPLAYCHANGE` | `windows` |

## A.9 IPC & anti-tamper (docs 01, 10)

| Need | Primitive | Rust |
|------|-----------|------|
| IPC transport | named pipes (restrictive SDDL) | `windows` |
| Authenticate peer | `GetNamedPipeClientProcessId` + `WinVerifyTrust` | `windows` |
| Protect processes | `ObRegisterCallbacks` (strip `PROCESS_VM_WRITE`/`TERMINATE`); PPL | WDK |

## A.10 Minimum OS / signing

- Screen-capture exclusion: **Windows 10 2004+**. Below that, refuse enrollment for that
  control.
- Driver: EV cert + Partner Center attestation/WHQL signing; minifilter altitude allocation.
- See [12](12-signing-distribution-deployment.md).
