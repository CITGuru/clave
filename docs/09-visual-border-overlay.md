# 09 — Visual Border Overlay (the "Clave Edge")

Every work window carries a persistent colored frame so the user always knows which surface is
governed by policy. The behavior is precisely specified: *pixels external to the supervised
resource within n pixels, recomputed every n milliseconds or on OS window events, respecting
z-order.* Pure UI, no security boundary — but it is the product's identity and a real anti-mistake
control (it stops users from typing secrets into the wrong window). **Clave Edge** is Clave's name
for this frame.

Implements the `WindowOverlay` trait from [00 §4](00-architecture-overview.md).

---

## 1. Requirements

1. **Track every work top-level window** — position, size, and **z-order** — and frame it.
2. **Click-through**: the overlay must never steal input or block the user.
3. **Correct occlusion**: when a personal window covers part of a work window, the border is
   covered too; when the work window is on top, its border is on top.
4. **Event-driven, low-CPU**: recompute on window events (move/resize/focus/z-change), not a
   busy poll. The "every n ms" cadence is the fallback, not the primary loop.
5. **Multi-monitor + mixed-DPI correct**; survives display hotplug, resolution changes,
   virtual desktops/Spaces.
6. **Itself excluded from capture** (doc 07) and not interfering with the work window's own
   capture-exclusion.

---

## 2. Windows

### 2.1 Overlay window style

One transparent, click-through, topmost layered window per work window (or one big per-monitor
overlay that draws all frames — fewer HWNDs, simpler z-order; see §2.4):

```rust
use windows::Win32::UI::WindowsAndMessaging::*;
let ex = WS_EX_LAYERED      // alpha / per-pixel transparency
       | WS_EX_TRANSPARENT  // click-through (hit-test passes through)
       | WS_EX_NOACTIVATE   // never takes focus
       | WS_EX_TOOLWINDOW;  // no taskbar entry
// create, then exclude from capture so the border doesn't show in screenshots oddly:
unsafe { SetWindowDisplayAffinity(overlay_hwnd, WDA_EXCLUDEFROMCAPTURE)?; }
```

Paint the frame with **`UpdateLayeredWindow`** (a premultiplied-alpha bitmap: transparent
interior, colored ring of width *n* around the edges).

### 2.2 Tracking geometry & z-order via `SetWinEventHook`

```rust
use windows::Win32::UI::Accessibility::SetWinEventHook;
// out-of-context hooks (WINEVENT_OUTOFCONTEXT) — no DLL injection into other procs
let hooks = [
    EVENT_OBJECT_LOCATIONCHANGE, // move / resize
    EVENT_SYSTEM_FOREGROUND,     // focus change → z-order changed
    EVENT_OBJECT_REORDER,        // sibling z-order change
    EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND,
    EVENT_OBJECT_SHOW, EVENT_OBJECT_HIDE, EVENT_OBJECT_DESTROY,
];
// On each event: if the hwnd belongs to a supervised PID (doc 02), recompute its frame.
```

Why `SetWinEventHook` over polling: it's push-based and fires precisely on the relevant
geometry/z changes. Keep a **debounce** (coalesce a burst of LOCATIONCHANGE during
a drag into one repaint per frame, ~16 ms) plus a slow safety poll (250 ms) for the rare event
you miss.

### 2.3 Z-order correctness

Position each overlay **immediately above its target** in z-order so occlusion is automatic:

```rust
unsafe {
    SetWindowPos(overlay_hwnd, target_hwnd /* place just above target */,
        x, y, w, h, SWP_NOACTIVATE | SWP_NOREDRAW);
}
```

When a personal window comes above the target, the overlay (just above the target, below the
personal window) is correctly occluded by it. This is the cheap, robust way to honor the
"border occludes / is occluded per priority" rule without manual clipping math.

### 2.4 One-overlay-per-monitor alternative

Tracking dozens of child HWNDs is fiddly. An alternative: one full-screen, click-through,
layered overlay per monitor that **paints all work-window frames** by walking the supervised
window list each repaint and clipping each frame to the visible (un-occluded) region computed
from the z-ordered window list (`EnumWindows` + region subtraction). More math, fewer windows,
easier global z-management. Pick per your team's comfort; the per-window approach is simpler to
get pixel-correct first.

### 2.5 DPI & multi-monitor

- Make the process **Per-Monitor-V2 DPI aware** (manifest) so coordinates aren't virtualized.
- Handle `WM_DPICHANGED`, `WM_DISPLAYCHANGE`, and `WM_SETTINGCHANGE`; recompute all frames on
  display topology changes.
- Use physical pixel rects from `DwmGetWindowAttribute(DWMWA_EXTENDED_FRAME_BOUNDS)` rather
  than `GetWindowRect` (the latter includes the invisible resize border and is wrong for the
  visual frame).

---

## 3. macOS

### 3.1 Overlay window

A borderless, transparent, click-through `NSWindow` (or one per `NSScreen`):

```swift
let overlay = NSWindow(contentRect: rect, styleMask: .borderless,
                       backing: .buffered, defer: false)
overlay.isOpaque = false
overlay.backgroundColor = .clear
overlay.ignoresMouseEvents = true                  // click-through
overlay.level = .screenSaver                        // above normal windows
overlay.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle]
overlay.sharingType = .none                          // exclude the border itself from capture
```

Draw the blue frame in the content view (a ring path stroked at width *n*).

### 3.2 Tracking other apps' windows: Accessibility API

You don't own the work app's window, so to learn its geometry you use the **Accessibility (AX)
API**, which requires the **Accessibility TCC permission** (a one-time user grant, MDM-pushable):

```swift
let appElem = AXUIElementCreateApplication(workPid)
var obs: AXObserver?
AXObserverCreate(workPid, axCallback, &obs)
for note in [kAXMovedNotification, kAXResizedNotification,
             kAXWindowMiniaturizedNotification, kAXFocusedWindowChangedNotification,
             kAXUIElementDestroyedNotification] {
    AXObserverAddNotification(obs!, windowElem, note as CFString, nil)
}
// On each notification: read kAXPositionAttribute / kAXSizeAttribute → move the overlay.
```

- **Z-order on macOS** is trickier: AX gives geometry but not a clean global z-index. Use
  `CGWindowListCopyWindowInfo(.optionOnScreenOnly)` to get the on-screen window list **in
  front-to-back order** with `kCGWindowLayer` and bounds; recompute occlusion from that. Poll
  it on a light timer (≈10–15 Hz) *in addition to* AX notifications, because window
  *restacking* by other apps doesn't always emit an AX notification you observe.
- **Spaces / Mission Control:** `.canJoinAllSpaces` + `.stationary` keep the border glued.
  Handle `NSWorkspace.activeSpaceDidChangeNotification`.

### 3.3 Honesty marker

**◐ The border on macOS depends on Accessibility permission** and a hybrid AX-notification +
`CGWindowList`-poll loop; it's slightly less crisp than the Windows `SetWinEventHook` path
during rapid restacking. It's a UI affordance, not a control, so best-effort is acceptable —
but the AX permission grant is a real onboarding step to design for.

---

## 4. Shared core

The geometry/z math is portable; only the event sources and the draw calls are OS-specific.

```rust
// clave-core/src/overlay.rs
pub struct Frame { pub window: WindowId, pub rect: RectPx, pub visible_region: Region, pub color: Rgba }

pub fn recompute_frames(work_windows: &[WindowGeom], z_order: &[WindowId], cfg: &BorderCfg)
    -> Vec<Frame>
{
    // For each work window, subtract the regions of any windows above it in z_order to get
    // visible_region; build a ring of width cfg.n around rect clipped to visible_region.
    // Pure function → unit-testable with synthetic window layouts.
    todo!()
}
```

Keeping `recompute_frames` pure lets you unit-test occlusion (overlapping windows, multi-mon,
partial cover) on a dev machine with no GUI.

---

## 5. Performance

- **Event-driven first, poll as safety net.** Target <1% CPU at idle, no visible lag during a
  window drag (coalesce to one repaint per compositor frame).
- **GPU-cheap paint:** the frame is a hollow rectangle; use a cached premultiplied bitmap
  (Windows `UpdateLayeredWindow`) / a simple layer stroke (macOS) — never re-rasterize the
  whole screen.
- **Throttle `CGWindowList` polling** on macOS; it's the main cost there.

---

## 6. Test plan

- Drag a work window fast across two monitors at different DPI ⇒ border stays glued, no lag,
  correct size on each monitor.
- Cover a work window partially with a personal window ⇒ border is occluded exactly where
  covered; raise the work window ⇒ border returns on top.
- Minimize/restore, full-screen, virtual desktop / Space switch ⇒ border tracks correctly.
- Screenshot the desktop ⇒ border doesn't produce artifacts (it's capture-excluded) and work
  windows are handled per doc 07.
- macOS without Accessibility permission ⇒ graceful degradation + a clear prompt to grant it.

Proceed to [10 — Policy Engine & IPC](10-policy-engine-and-ipc.md).
