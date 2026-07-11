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
