# Appendix B — macOS Primitives Quick Reference

Lookup table for the macOS implementation. Note the recurring theme: **user-space frameworks,
authorization-based enforcement, no injection, no kexts.** Where a row is ◐/✗ it reflects a
real platform limit, not a missing entry — see the cross-referenced doc.

---

## B.1 Process supervision (doc 02)

| Need | Primitive | Framework | Rust path |
|------|-----------|-----------|-----------|
| Decide membership at exec | `ES_EVENT_TYPE_AUTH_EXEC` (block until respond) | Endpoint Security | Swift host → C ABI → Rust |
| Notify exit/fork | `ES_EVENT_TYPE_NOTIFY_EXIT` / `NOTIFY_FORK` | ES | same |
| Authoritative identity | `audit_token` (from `es_process_t`) | ES | byte array → Rust |
| Allow/deny exec | `es_respond_auth_result(ALLOW/DENY)` | ES | Swift |
| Perf: silence trusted procs | `es_mute_path` / `es_mute_process` | ES | Swift |
| Enumerate live procs (recovery) | `libproc` (`proc_listpids`) | libproc | `libproc` crate |

> ✗ No equivalent to Job Objects/Silos for *containing* a tree — ES tracks, it doesn't contain.

## B.2 "App virtualization" substitute (doc 03 §5)

| Need | Primitive | Notes |
|------|-----------|-------|
| Per-app isolation | distinct `HOME`/container dir on the encrypted volume | the macOS isolation unit |
| Block reads of work data | `ES_EVENT_TYPE_AUTH_OPEN` deny by audit_token | kernel-authoritative |
| Optional fencing | `sandbox_init` / `sandbox-exec` Seatbelt profile | **private API** — support risk |
| ✗ Injection | `DYLD_INSERT_LIBRARIES` | **blocked** by SIP + library validation + hardened runtime + AMFI |
| ✗ Registry COW | — | macOS has no registry; collapses into filesystem |

## B.3 Encrypted volume (doc 04)

| Need | Primitive | Rust path |
|------|-----------|-----------|
| Encrypted container | encrypted **sparsebundle** (`hdiutil create -encryption AES-256`) or encrypted **APFS volume** | shell/DiskImages, daemon-driven |
| Mount | `hdiutil attach -stdinpass -nobrowse` / DiskArbitration | `core-foundation` + DiskArbitration |
| Key in hardware | **Secure Enclave**-protected Keychain item (`kSecAttrTokenIDSecureEnclave`, `SecAccessControlCreateWithFlags`) | `security-framework` + Swift |
| User-presence gate | Touch ID / passcode via access control flags | Swift `LocalAuthentication` |
| Access gate at runtime | ES `AUTH_OPEN` deny non-zone opens of `/Volumes/ClaveDisk` | Swift → Rust |
| Crypto-shred / wipe | delete Keychain wrapped key → unlink bundle | `security-framework` |

## B.4 Clipboard & DLP (doc 05)

| Need | Primitive | Strength |
|------|-----------|----------|
| Observe copies | poll `NSPasteboard.general.changeCount` | ◐ |
| Frontmost app | `NSWorkspace.frontmostApplication` cross-checked vs ES zone set | — |
| ✗ Pre-paste block | — | **no supported interception API**; reactive clear only (racy) |
| Disable Universal Clipboard | MDM (Handoff restriction) | managed only |

## B.5 Input isolation (doc 06)

| Need | Primitive | Strength |
|------|-----------|----------|
| Detect taps | `CGGetEventTapList` | ◐ monitor |
| Platform consent backstop | **Input Monitoring TCC** (OS prompts before any global tap) | the real mitigation |
| ✗ Private input channel | — | none; can't make a tap lie to one app |
| Secret fields | `NSSecureTextField` (excluded from some taps/capture) | app cooperation |

## B.6 Screen capture (doc 07)

| Need | Primitive | Strength |
|------|-----------|----------|
| Exclude **your** window | `NSWindow.sharingType = .none` | ✅ (own windows only) |
| ✗ Exclude 3rd-party work window | — | can't set on others; can't inject |
| Block screenshot CLI | ES `AUTH_EXEC` deny `/usr/sbin/screencapture` | ✅ that vector |
| Detect recorders | observe `SCStream`/ScreenCaptureKit users; Screen-Recording TCC grants | ◐ react |
| Platform backstop | **Screen Recording TCC** (consent + MDM control) | — |

## B.7 Network split-tunnel (doc 08)

| Need | Primitive | Framework | Rust path |
|------|-----------|-----------|-----------|
| Per-app flow routing | `NETransparentProxyProvider` / `NEAppProxyProvider` | Network Extension | Swift provider → Rust |
| Flow identity | `flow.metaData.sourceAppAuditToken` / `sourceAppSigningIdentifier` | NE | byte array → Rust |
| Handle/ignore flow | `handleNewFlow` returns `true`(handle)/`false`(system) | NE | Swift |
| WireGuard data plane | boringtun | — | `boringtun` (shared) |
| DNS steering | NE DNS proxy / on-demand rules; per-app | NE | Swift config |

## B.8 Overlay / Clave Edge (doc 09)

| Need | Primitive | Rust path |
|------|-----------|-----------|
| Click-through window | `NSWindow` `.borderless`, `isOpaque=false`, `ignoresMouseEvents=true`, high `level`, `.canJoinAllSpaces` | `objc2`/`cocoa` |
| Track 3rd-party geometry | **Accessibility API** `AXObserver` (`kAXMoved/Resized/...Notification`) — needs Accessibility TCC | `accessibility-sys`/FFI |
| Z-order | `CGWindowListCopyWindowInfo(.optionOnScreenOnly)` (front-to-back) | `core-graphics` |
| Spaces | `NSWorkspace.activeSpaceDidChangeNotification` | `objc2` |
| Exclude border from capture | `sharingType = .none` | `objc2` |

## B.9 IPC & lifecycle (docs 01, 10)

| Need | Primitive | Rust path |
|------|-----------|-----------|
| IPC | **XPC** / Unix domain socket | `objc2` / `nix` |
| Authenticate peer | `xpc_connection_get_audit_token` + `SecCodeCheckValidity` (pinned Team ID/signing id) | `security-framework` |
| Daemon | **launchd** root daemon | plist |
| Extension lifecycle / lock | **System Extension** + MDM management (user can't unload) | OS-managed |

## B.10 TCC permissions to plan for (doc 12 §2.3)

| Subsystem | TCC |
|-----------|-----|
| Clave Edge (doc 09) | Accessibility |
| Screen detection (doc 07) | Screen Recording |
| Input detection (doc 06) | Input Monitoring |
| ES file gating (doc 04) | Full Disk Access |

Pre-grant via **PPPC profiles** on MDM-managed devices; guided prompts on BYO-PC.

---

## B.11 Entitlements (the wall — doc 12 §2.2)

| Capability | Entitlement | Approval |
|------------|-------------|----------|
| Endpoint Security | `com.apple.developer.endpoint-security.client` | **Apple approval (weeks)** — long pole |
| System Extension | `com.apple.developer.system-extension.install` | Developer ID flow |
| Network Extension | `com.apple.developer.networking.networkextension` | dev portal |

Minimum OS target: **macOS 13 Ventura+** (mature ES + NE). Universal binary (Apple Silicon +
Intel).
