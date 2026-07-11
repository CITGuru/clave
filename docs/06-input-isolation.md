# 06 — Input Isolation (anti-keylogging between zones)

The requirement: unsupervised apps cannot read keyboard input destined for supervised apps.
This is the **single hardest guarantee in the system** to make honestly in user space, and
the docs here are deliberately candid about where it is real and where it is aspirational.

Implements the `InputGuard` trait from [00 §4](00-architecture-overview.md).

---

## 1. The threat, enumerated

A personal-zone process (A2) or curious user (A1) wants to capture what's typed into a work
app (passwords, regulated text). The OS-level capture vectors:

| Vector | Windows | macOS |
|--------|---------|-------|
| Global low-level hook | `SetWindowsHookEx(WH_KEYBOARD_LL / WH_MOUSE_LL)` | — |
| Polling key state | `GetAsyncKeyState` / `GetKeyState` (no install, just poll) | — |
| Raw input | `RegisterRawInputDevices` (`RIDEV_INPUTSINK`) | `IOHIDManager` / HID access |
| Event tap | — | `CGEventTapCreate` (session/annotated) |
| Accessibility | UI Automation read of text | AX API reading focused-element value |
| Injected hook in the work proc | (covered: only work shims injected) | (blocked by SIP — good) |

The nasty one on Windows is **`GetAsyncKeyState`**: it requires **no hook installation**, just
a busy poll. There is no supported way to make it lie to one process and not another from user
mode. The nasty one on macOS is **`CGEventTapCreate`**, which is gated by the **Input
Monitoring** TCC permission but, once granted, sees everything.

---

## 2. Windows

### 2.1 What user mode can do (◐ best-effort)

- **Detect & strip foreign low-level hooks:** enumerate hooks, and when a *non-supervised*
  process has a `WH_KEYBOARD_LL` installed while a work window holds focus, you can (a)
  surface a warning, (b) refuse to dispatch real scancodes (see filter driver below), or (c)
  feed the global hook chain decoys for the work-focus interval. Fragile and racy on its own.
- **Secure input affinity:** while a work window is foreground, route real input only to it
  and present the global hook chain with suppressed/garbage events. Doable only with help
  from the kernel input stack — pure user mode can't reliably exclude one consumer.

These reduce casual keylogging (A1/A2 with off-the-shelf tools) but **do not** stop
`GetAsyncKeyState` polling. **◐ BEST-EFFORT.**

### 2.2 What actually closes it (⚠ requires a keyboard filter driver)

To make this **✅ enforceable**, add an **upper-filter driver on `kbdclass`** (the keyboard
class driver). The filter sees `IRP_MJ_READ` scancode packets *before* they fan out to
`win32k` and the hook chain:

```
keyboard HW → kbdclass → [YOUR FILTER] → win32k → focused window + WH_KEYBOARD_LL chain
                              │
                              ├─ if foreground window ∈ work zone AND policy=protect_input:
                              │     deliver scancodes ONLY down the trusted path; emit
                              │     null/!state to the global hook chain & GetAsyncKeyState
                              │     shadow state for non-work consumers
                              └─ else: pass through unchanged
```

- This is how endpoint products (and anti-cheat) implement "protected input." It requires the
  filter to maintain a **per-consumer view** of key state so that `GetAsyncKeyState` polled by
  a personal app returns *not pressed* during work focus, while the work app gets the real
  stream. The kernel is the only place this view can be authoritative.
- **Cost:** a signed kernel driver in the input path is high-risk (a bug = unkillable keyboard
  or BSOD) and high-scrutiny for WHQL. Many shipping enclave products **accept ◐ best-effort**
  here rather than ship an input filter. Decide deliberately; this is a real
  security-vs-stability-vs-time tradeoff, not a free win.

### 2.3 Bonus: defeat shoulder-surf via remote tools

A common real-world exfil is the user (or malware) running a remote-desktop/streaming tool
that captures the screen *and* input. Screen is handled in [07](07-screen-capture-protection.md);
for input, the same filter can refuse to honor *injected* input (`SendInput` with the
`LLMHF_INJECTED` analog for keyboard, `KEYEVENTF_*`) into work windows, blocking
remote-control of work apps. Policy-gate this (some users legitimately use automation).

---

## 3. macOS

### 3.1 The structural situation

- macOS has **no kernel input filter you can ship** (no kexts). The keyboard path is not
  extensible the way Windows' `kbdclass` is.
- The capture vector (`CGEventTapCreate`, `IOHIDManager`) is gated by the **Input Monitoring**
  TCC permission — the OS *already* forces a user consent prompt before any app can tap keys
  globally. That is the platform's built-in mitigation, and it's a decent one against A2
  (commodity malware can't silently tap).
- You **cannot** make `CGEventTap` lie to a personal app while feeding the work app — there's
  no supported per-consumer input view.

### 3.2 What you can do (◐ / monitoring)

- **Detect** which apps hold Input-Monitoring / Accessibility permission and which have active
  event taps (`CGGetEventTapList`), and **alert/audit** when a non-work app with a tap runs
  while a work app is focused. Visibility, not prevention.
- **Secure-text-field cooperation:** macOS already excludes secure text fields
  (`NSSecureTextField`, password fields) from some event taps and from screen capture; ensure
  work apps that handle secrets use them. You can't force third-party apps to, but you can flag
  apps that don't.
- **Policy via MDM:** lock down Input-Monitoring grants on managed devices so the user can't
  approve a rogue tapper. On BYO-PC (unmanaged) you can't.

### 3.3 Honesty marker

**◐ BEST-EFFORT on macOS, with the OS TCC prompt as the real backstop.** You provide
visibility and audit; the platform provides the consent gate. There is **no** mechanism to
give work apps a private input channel invisible to a permitted tapper. Say so plainly.

---

## 4. Shared core

The core only carries policy + audit; the mechanism is entirely OS-side.

```rust
// clave-core/src/dlp/input.rs
pub struct InputPolicy {
    pub protect_work_input: bool,      // Win: arm kbd filter; mac: monitor+alert only
    pub block_injected_input: bool,    // refuse SendInput/CGEvent post into work windows
    pub alert_on_foreign_tap: bool,    // audit a tapper active during work focus
}
pub fn on_foreign_tap_detected(app: AppId, work_focus: bool, pol: &InputPolicy) -> Vec<AuditEvent> { /* … */ }
```

---

## 5. Recommended posture (and how to talk about it)

| | Without kernel input filter | With kbd filter (Win only) |
|---|---|---|
| Windows | ◐ deter casual hooks; **GetAsyncKeyState hole open** | ✅ work input invisible to personal pollers |
| macOS | ◐ monitor + rely on TCC consent | n/a (no kext) |

**Default recommendation:** ship **◐ best-effort + audit on both OSes** for v1, and treat the
Windows keyboard filter driver as a **v2 hardening** decided per-customer (regulated finance
may require it; most won't justify the stability risk). **Never market input isolation as
absolute.** It is the claim most likely to be falsified by a pen-tester with ten lines of
`GetAsyncKeyState`.

> Cross-reference: the *value* of input isolation is highest exactly when screen capture is
> also blocked (doc 07) and clipboard is gated (doc 05) — together they close the "watch the
> user work" exfil surface. Alone, each is partial.

Proceed to [07 — Screen-Capture Protection](07-screen-capture-protection.md).
