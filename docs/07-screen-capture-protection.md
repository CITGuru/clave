# 07 — Screen-Capture Protection

Goal: a screenshot, screen recording, or screen-share of the desktop must **exclude or
watermark** work windows, while leaving personal windows (and the rest of the desktop)
capturable. The target behavior: the *GPU occludes or watermarks the region associated with the
supervised resource.*

Implements the `ScreenGuard` trait from [00 §4](00-architecture-overview.md).

---

## 1. Two strategies

| Strategy | Result for a capturer | When to use |
|----------|----------------------|-------------|
| **Exclude** | Work window renders **black**/absent in the capture; user sees it normally | Default; strongest |
| **Watermark** | Work window appears in the capture but overlaid with a tamper-evident, user-attributable watermark (employee id, timestamp) | When the business needs *some* screen sharing (support, demos) but wants traceability/deterrence |

Both rely on the **compositor** (DWM on Windows, WindowServer on macOS) doing the right thing
at the moment of capture, because the compositor is the one place that knows "this pixel
belongs to window W, which is protected."

---

## 2. Windows

### 2.1 The primitive: `SetWindowDisplayAffinity`

Since Windows 10 2004, a window can opt out of capture:

```rust
use windows::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity,
    WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR};

// Called for each top-level work window:
unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)?; }
//  WDA_EXCLUDEFROMCAPTURE → window is visible to the user, BLACK to any capturer
//  WDA_MONITOR            → visible only on the monitor, black even to legit capture (older)
```

DWM enforces this in the compositor: `BitBlt`, `PrintWindow`, the Desktop Duplication API,
Graphics Capture API, Snipping Tool, OBS, Teams/Zoom screen-share — all receive black for that
window. This **is** the "GPU occludes the region" behavior. It's the clean, supported,
reliable path.

### 2.2 The catch: it must be called by the window's own process

`SetWindowDisplayAffinity` is intended to be called by the thread that owns the window. You
don't own Excel/Chrome — **but you inject a shim into every work app** (doc 03 §2), so the
shim calls it from *inside* the work process for each top-level window it creates. Wire it to
window lifecycle:

```rust
// clave-shim/src/screen.rs — runs inside the work process
fn protect_all_top_level_windows() {
    // hook CreateWindowEx / track via EnumWindows on our own PID, then:
    for hwnd in own_top_level_windows() {
        unsafe { let _ = SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE); }
    }
}
// Re-apply on WM_CREATE of new top-level windows (dialogs, popups) via a CBT hook
// or by subclassing — new windows default to WDA_NONE and would otherwise be capturable.
```

Edge cases to handle: child popups, tooltips, menus, and **layered/owned windows** spawned
after launch all default to capturable — re-apply on creation. Test against the Graphics
Capture API specifically (modern share tools use it), not just PrintScreen.

### 2.3 Watermark variant

If policy says *watermark, not exclude*, leave the window capturable and have the **overlay
process** (doc 09) draw a `WDA_EXCLUDEFROMCAPTURE`-excluded watermark layer that is composited
*into* the captured frame. Implementation reality: you can't easily force a watermark *into*
someone else's captured surface from outside; the practical approach is to render the
watermark as part of the work window via the shim (a topmost child band drawn by the shim
that is *not* excluded), so it shows to both user and capturer. Document that watermark is
weaker than exclude (a determined capturer can crop).

### 2.4 PrintScreen and clipboard

`PrtScn` copies the screen to the clipboard. With `WDA_EXCLUDEFROMCAPTURE`, work windows are
already black in that bitmap. Additionally, the clipboard broker (doc 05) can detect a
screen-bitmap arriving while a work window was foreground and gate it. Belt and suspenders.

### 2.5 Honesty marker

**✅ Enforceable and reliable** on Windows 10 2004+ via the supported compositor path — *given*
you can inject to call it (which you can, since work apps are launched by you). Residual: a
pre-2004 OS (refuse to enroll), or a hardware capture device / phone camera pointed at the
screen (out of scope for any software solution — A8-adjacent).

---

## 3. macOS

### 3.1 The primitive: `NSWindow.sharingType = .none`

The analog exists:

```swift
window.sharingType = .none   // excluded from screen sharing & ScreenCaptureKit capture
```

ScreenCaptureKit and the legacy `CGWindowListCreateImage`/`screencapture` honor a window's
`sharingType`. Set to `.none`, the window is excluded from captures.

### 3.2 The catch that has no clean fix: you don't own the window, and can't inject

Unlike Windows, you **cannot** set `sharingType` on a third-party app's window:

- It's an instance property you set on *your* `NSWindow`; there's no external "set sharing
  type of window id X" API.
- You **cannot inject** into the work app to call it from inside (SIP/library validation,
  doc 03 §5). The Windows "shim calls it from inside" trick is unavailable.

So for arbitrary work apps (Chrome, Excel) you **cannot proactively exclude** their windows
from capture on macOS. This is a genuine **✗/◐** gap.

### 3.3 What you *can* do on macOS: reactive detection

```
ES client subscribes to ES_EVENT_TYPE_NOTIFY_EXEC / AUTH_EXEC:
   detect launch of capture tooling: /usr/sbin/screencapture, known recorders,
   processes that create an SCStream / use ScreenCaptureKit
   │
   ├─ if a non-work process starts capturing WHILE a work window is visible AND policy=block:
   │     • AUTH_EXEC-deny known screenshot binaries (screencapture) outright, OR
   │     • blank/minimize work windows reactively (move off-screen / reduce), OR
   │     • emit a high-priority audit + user warning
   └─ TCC: Screen Recording already requires user consent — leverage it (MDM can deny it)
```

- **Denying `screencapture` exec** via ES is a real, hard block for the CLI/Screenshot.app
  path. **✅ for that vector.**
- **ScreenCaptureKit by an arbitrary app** is harder — you can detect the process and the
  Screen-Recording TCC grant and react (warn / blank / audit), but you cannot make an
  individual work window invisible to it without owning the window. **◐ reactive.**
- **Screen Recording TCC** is the platform backstop: an app must be granted Screen Recording,
  which prompts the user and is MDM-controllable. On managed devices, deny it for everything
  but approved tools.

### 3.4 Honesty marker

**◐ BEST-EFFORT / reactive on macOS.** Hard block for the `screencapture` CLI and
Screenshot.app via ES exec-deny; detection + react + audit for ScreenCaptureKit recorders;
rely on Screen-Recording TCC consent as the backstop. **No proactive per-window exclusion for
third-party work apps.** This is the macOS subsystem most likely to disappoint relative to
the Windows version; scope it explicitly with customers.

---

## 4. Shared core

```rust
// clave-core/src/dlp/screen.rs
pub enum ScreenMode { Exclude, Watermark, AllowWithAudit }
pub struct ScreenPolicy { pub mode: ScreenMode, pub block_screenshot_tools: bool }

// Windows path calls into shim (SetWindowDisplayAffinity); macOS path arms ES exec-deny +
// reactive handlers. Both emit the same audit schema on a capture attempt over a work window.
```

---

## 5. Test plan

- Windows: Snipping Tool, PrtScn, OBS (Graphics Capture + Display Capture), Teams/Zoom share,
  Desktop Duplication sample ⇒ all render work windows black; personal windows captured fine;
  new dialogs/popups also excluded.
- Windows: kill the shim (A6) ⇒ work windows become capturable (this is the
  fail-*open* exception — note it; the compositor primitive is set by the app, so losing the
  shim loses the protection. If this matters for a customer, the kbd/PPL anti-tamper of doc 01
  §8 must keep the shim alive).
- macOS: `screencapture` CLI ⇒ exec-denied; Screenshot.app ⇒ denied; a ScreenCaptureKit
  recorder ⇒ detected + audited + (per policy) work windows blanked; verify TCC prompt path.
- Both: phone camera at the screen ⇒ out of scope (state it).

> Note the asymmetry vs other subsystems: here the Windows control is *set by the protected
> app itself* (via shim), so it is strong but tied to shim liveness, whereas elsewhere the
> kernel is the backstop. Keep the shim protected (doc 01 §8) or this degrades.

Proceed to [08 — Network Split-Tunnel](08-network-split-tunnel.md).
