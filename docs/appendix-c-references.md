# Appendix C — References & Reading List

Curated, with *why each matters*. Start with the two open-source blueprints — they will save you
months.

---

## C.1 Open-source blueprints (read the code)

- **Sandboxie-Plus** (`Sandboxie-Plus/Sandboxie`, GPLv3) — *the* reference for Windows
  app-subsystem virtualization. `core/drv/` = the kernel driver (process notify, object/FS/
  registry filtering); `core/dll/` = the injected user-mode hooks. This is doc 03 made real.
  License: GPLv3 — study for architecture, do **not** copy into a proprietary product.
- **Google Santa** (`google/santa`) — the reference for **macOS Endpoint Security**
  architecture: an ES-client daemon doing binary authorization with audit tokens. This is doc
  02/04's macOS side made real. (Obj-C++/Swift.)
- **WireGuard / boringtun** (`cloudflare/boringtun`) — the Rust WireGuard data plane for the
  split tunnel (doc 08).
- **WinFsp** (`winfsp/winfsp`) + the **`winfsp` Rust crate** — the encrypted user-mode FS
  (doc 04).
- **Wintun** (`WireGuard/wintun`) + **`wintun` crate**, **WinDivert** (`basil00/WinDivert`) +
  **`windivert` crate** — Windows network data path / prototype classifier (doc 08).
- **Microsoft Detours** (`microsoft/Detours`, MIT) — the battle-tested injection/loader helper
  if you don't hand-roll it (doc 03 §2).

## C.2 Windows platform docs

- **Process-creation callbacks:** `PsSetCreateProcessNotifyRoutineEx2` (WDK docs).
- **Minifilters:** *File System Minifilter Drivers* (WDK); the **altitude allocation** request
  process.
- **WFP:** *Windows Filtering Platform* — ALE layers, `CONNECT_REDIRECT` callouts.
- **Job Objects / Server Silos:** *Job Objects*, *Windows Containers* internals.
- **Screen capture exclusion:** `SetWindowDisplayAffinity` / `WDA_EXCLUDEFROMCAPTURE` (Win32).
- **WinEvent hooks:** `SetWinEventHook` event constants.
- **TPM:** TBS (TPM Base Services), `NCrypt`/CNG key storage, PCR sealing.
- **Driver signing:** *Windows Hardware Developer Program* (Partner Center), attestation &
  WHQL/HLK.
- **Rust on Windows:** the **`windows`/`windows-sys`** crates; **`windows-drivers-rs`** (KMDF
  in Rust); **`retour`** (hooking).

## C.3 macOS platform docs

- **Endpoint Security:** the `EndpointSecurity` framework reference; `es_new_client`,
  event/auth model, message deadlines, muting; the
  `com.apple.developer.endpoint-security.client` entitlement request.
- **Network Extension:** `NETransparentProxyProvider`, `NEAppProxyProvider`, `NEAppProxyFlow`,
  `NEDNSProxyProvider`; per-app VPN.
- **System Extensions:** `OSSystemExtensionManager`; replacing kexts; MDM management.
- **Disk images / APFS:** `hdiutil`, the DiskImages framework, encrypted APFS volumes;
  DiskArbitration.
- **Secure Enclave / Keychain:** `SecAccessControlCreateWithFlags`,
  `kSecAttrTokenIDSecureEnclave`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`;
  LocalAuthentication.
- **Accessibility API:** `AXUIElement`, `AXObserver`, the notification constants; the
  Accessibility TCC permission.
- **ScreenCaptureKit / sharingType:** `SCStream`, `NSWindow.sharingType`.
- **TCC / PPPC:** Privacy Preferences Policy Control profiles for MDM pre-approval.
- **Rust on macOS:** **`objc2`**, **`core-foundation`**, **`core-graphics`**,
  **`security-framework`**, **`system-configuration`**, **`libproc`**; **`swift-bridge`** for
  the ES/NE Swift↔Rust seam.

## C.4 Crypto & safety

- **AES-XTS** for at-rest (`aes` + `xts-mode` crates); IEEE 1619.
- **AES-KW** (RFC 3394) key wrapping; **crypto-shredding** as a wipe primitive.
- **`zeroize`**, `secrecy` for key handling; pagefile/swap protection considerations.
- **`rustls`** for gateway mTLS; **`ed25519-dalek`** for policy-bundle signing.

## C.5 Background reading on the model

- App-V (Microsoft Application Virtualization) sequencing/COW concepts — the historical
  template for doc 03's registry/FS layering.
- EDR injection & self-protection techniques (for AV coexistence and anti-tamper, docs 01/12).
- Apple's *Endpoint Security* WWDC sessions (architecture & performance guidance).
