# 05 — Clipboard & Data-Transfer DLP

Copy/paste and drag-and-drop are the most-used exfiltration paths for an honest user (A1)
and the easiest for commodity malware (A2). The policy is simple; the enforcement is OS-ugly,
especially on macOS.

Implements the `ClipboardBroker` trait from [00 §4](00-architecture-overview.md).

---

## 1. Policy model

The clipboard/drag policy is a directed matrix over zones:

| From → To | Default | Rationale |
|-----------|---------|-----------|
| work → work | **Allow** | Normal intra-enclave productivity |
| personal → personal | **Allow** (untouched) | Not our business |
| **work → personal** | **Deny** | The exfil case we exist to stop |
| personal → work | **Allow** (often) or **Sanitize** | Usually fine; sanitize to block paste-based injection into work apps if required |

Per-format granularity matters: a policy may allow plain text work→personal (low risk) while
blocking files, images, and `CF_HDROP`/file-promise formats (high risk). Make it
policy-driven, not hardcoded.

---

## 2. Windows: the clipboard broker + per-process gate

The Windows clipboard is a **single global, single-owner** resource; you cannot natively
partition it. You build a **broker** that owns the clipboard on behalf of work apps and a
**per-process read gate** in the shim.

### 2.1 Mechanism: tag on copy, gate on paste

```
WORK app copies
   │  (shim hook on OpenClipboard/SetClipboardData in the work proc)
   ▼
broker keeps the REAL payload inside the enclave, keyed by a token;
places on the GLOBAL clipboard only:
   • a private format  CF_CLAVE_TOKEN = {payload_id, src_zone=work}
   • optional delayed-render stubs for standard formats (CF_UNICODETEXT, CF_HDROP…)
   ▼
PERSONAL app pastes (Ctrl+V) → calls GetClipboardData(CF_UNICODETEXT)
   │  no shim in personal app, so the global clipboard answers:
   ▼
delayed render fires → WM_RENDERFORMAT goes to the broker (the clipboard owner)
   │  broker sees dst is NOT a work proc and src_zone=work → refuses to render real bytes
   ▼
personal app receives empty/again-denied → paste yields nothing + a toast "blocked by policy"
```

### 2.2 Owning the clipboard via delayed rendering

The broker becomes the clipboard owner using **delayed rendering**: it calls
`SetClipboardData(format, NULL)` to advertise formats without materializing them, then
services `WM_RENDERFORMAT` / `WM_RENDERALLFORMATS` on demand — at which point it knows the
*requesting* context and applies policy.

```rust
// clave-clipboard-broker (Rust, windows crate) — SKETCH
fn on_work_app_copied(payload: ClipPayload) {
    let id = enclave_store.put(payload);                 // real bytes stay in enclave
    unsafe {
        OpenClipboard(broker_hwnd)?; EmptyClipboard()?;
        set_private_format(CF_CLAVE_TOKEN, &Token { id, src: Zone::Work });
        // advertise standard formats as delay-rendered (NULL handle)
        SetClipboardData(CF_UNICODETEXT, HANDLE(0))?;
        SetClipboardData(CF_HDROP,       HANDLE(0))?;
        CloseClipboard()?;
    }
}

// WM_RENDERFORMAT handler — fires when *someone* pastes a standard format
fn on_render_format(fmt: u32) -> HANDLE {
    let dst = foreground_paste_target_pid();             // who is pulling? (see 2.3)
    let tok = current_token();
    match policy::clip_decision(tok.src, zone_of(dst), fmt) {
        Decision::Allow => materialize_real_bytes(tok.id, fmt),
        _ => { audit_block(tok, dst, fmt); HANDLE(0) }    // render nothing
    }
}
```

### 2.3 Identifying the paste target

`WM_RENDERFORMAT` doesn't name the requester. Resolve the destination zone via:

- the **foreground window's** PID (`GetForegroundWindow` → `GetWindowThreadProcessId`) at the
  moment of the render — the common case (user hit Ctrl+V in the focused app), or
- a **per-process shim gate**: every *work* app also hooks `GetClipboardData`, so
  work→work is served directly from the enclave (bypassing the global path) and the broker's
  global stubs are only ever consumed by *non-work* apps — which it then denies.

This dual path (enclave-internal for work→work, gated global for the boundary) is what makes
the policy matrix enforceable rather than all-or-nothing.

### 2.4 Drag-and-drop (OLE)

Drag-drop uses `IDataObject`/`DoDragDrop`, not the clipboard, but the model is identical:
the shim wraps the source `IDataObject` so that `GetData` checks the **drop target's** window
zone (resolved at `Drop`), and refuses high-risk formats across the boundary. File-promise
(`CFSTR_FILEDESCRIPTOR`/`CFSTR_FILECONTENTS`) and `CF_HDROP` are the formats that move files —
gate those hardest.

### 2.5 Honesty marker

**◐ BEST-EFFORT against A3/A6.** A malicious *work* app can read the real bytes (it's allowed
to — it's in the zone) and then exfil them by some *other* channel (network, file) — clipboard
DLP doesn't stop a determined in-zone adversary, and isn't meant to. It is a hard control
against **work→personal user action (A1)** and **a personal-zone reader (A2)**, which is the
exfil surface that actually matters for DLP. The network/file controls (docs 04, 08) cover A3.

---

## 3. macOS: monitor, tag, sanitize — but no pre-paste block

This is one of the **✗/◐** rows in the [enforceability matrix](01-threat-model.md#6).

### 3.1 Why you cannot hard-block a paste

- `NSPasteboard` has **no supported interception API** — there is no "before paste" callback
  and no per-app pasteboard ownership broker like the Windows render model.
- You **cannot inject** into the pasting app to gate `readObjects(forClasses:)` (doc 03 §5:
  SIP/library validation). So at the instant a personal app reads the pasteboard, you have no
  hook there.

### 3.2 What you *can* do (and its limits)

```
poll NSPasteboard.general.changeCount  (≈ every 150–300 ms, or on app-activation via NSWorkspace)
   │
   ├─ detect: changeCount bumped AND frontmost app (NSWorkspace.frontmostApplication
   │          cross-checked against the ES-tracked zone set) is a WORK app
   │       → tag: record "last copy came from work", optionally add a private UTI marker
   │
   └─ later: frontmost app becomes a PERSONAL app
           → reactive sanitize: if a work-tagged payload is still on the pasteboard and the
             policy is work→personal Deny, CLEAR or overwrite the pasteboard before the
             user can paste.  ◐ This is a RACE: a fast paste between the activation event
             and your clear wins. You reduce the window; you don't close it.
```

- **Reactive clear** narrows but cannot eliminate the leak window — a scripted paste timed to
  app-switch can beat the poll. Document this as **◐ BEST-EFFORT**, weaker than Windows.
- **Universal Clipboard / Handoff** can move the pasteboard to an iPhone/iPad entirely outside
  your control. Policy should be able to **disable** Handoff/Universal Clipboard via MDM for
  managed users; you cannot intercept it on-device.
- **Per-app container separation** (doc 03 §5) gives a *partial* structural win: the work
  app's NSPasteboard usage of *named, private* pasteboards stays within the work container,
  but the **general** pasteboard is shared system-wide and is the leak vector.

### 3.3 Recommended macOS posture

Treat clipboard DLP on macOS as a **deterrent + audit** feature, not a hard control:
- monitor + tag + reactive-clear for honest-user friction and visibility,
- **audit every work→personal clipboard transition** you observe (even if you couldn't block
  it) so the gateway has a record,
- be explicit in product copy that macOS clipboard control is best-effort. Over-promising
  here is the most common way these products lose customer trust during a pen-test.

---

## 4. Shared core: the decision function

```rust
// clave-core/src/dlp/clipboard.rs — platform-agnostic policy
pub fn clip_decision(src: Zone, dst: Zone, fmt: ClipFormat, pol: &Policy) -> Decision {
    use Zone::*;
    match (src, dst) {
        (Work, Work)         => Decision::Allow,
        (Personal, Personal) => Decision::Allow,        // never reached; we don't instrument
        (Work, Personal)     => pol.work_to_personal(fmt),   // usually Deny; maybe Allow(text)
        (Personal, Work)     => pol.personal_to_work(fmt),   // Allow | Sanitize
    }
}
```

The OS layers differ wildly in *enforcement strength*, but they all funnel through this one
function so policy is consistent and auditable.

---

## 5. Test plan

- Windows: copy in work Excel → paste in personal Notepad ⇒ blocked + audit; copy work →
  paste work Word ⇒ allowed; drag a file from work Explorer view → personal folder ⇒ blocked.
- Windows: strip the shim hooks (simulate A6) ⇒ work→work still works via global path *but*
  work→personal still blocked by the broker render gate (verify the broker, not just the hook,
  enforces the boundary).
- macOS: copy in work app → switch to personal app fast ⇒ measure the leak-window race;
  assert reactive-clear succeeds at human speed and assert the audit event is emitted even
  when the race is lost.
- Both: large payloads (50 MB image), file lists, RTF/HTML with embedded images, promised
  files.

Proceed to [06 — Input Isolation](06-input-isolation.md).
