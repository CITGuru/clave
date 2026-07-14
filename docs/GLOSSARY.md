# Glossary

Terms and acronyms used across the documentation set.

| Term | Meaning |
|------|---------|
| **AMFI** | Apple Mobile File Integrity — macOS subsystem that enforces code-signing/library validation; one reason injection into signed apps is blocked. |
| **AX API** | macOS **Accessibility** API (`AXUIElement`/`AXObserver`); used to read third-party window geometry for the Clave Edge. Requires the Accessibility TCC grant. |
| **AES-XTS** | Block-cipher mode standard for disk/volume encryption (tweak = sector number). Used for the Clave Disk at rest. |
| **AES-KW** | AES Key Wrap (RFC 3394); wraps the volume DEK under a hardware-rooted KEK. |
| **ALE** | Application Layer Enforcement — WFP layers (`ALE_CONNECT_REDIRECT`, `ALE_AUTH_CONNECT`) where per-process network decisions are made. |
| **APC** | Asynchronous Procedure Call (Windows); used to run `LoadLibraryW` on a work app's first thread for clean shim injection. |
| **Activity telemetry** | The work-app usage stream (active/idle/focus time, sessions, launches); a signed, hash-chained sibling of the audit log, work-zone-only (doc 18). |
| **Away time** | Derived usage metric: wall-clock where no work app is foreground; a bare duration, never attributed to a personal app (doc 18). |
| **Clave Edge** | Clave's persistent colored frame drawn around every work window; a UI affordance, not a security boundary. See doc 09. |
| **BYO-PC / BYOD** | Bring-Your-Own-PC / Device — the unmanaged personal computer the enclave runs on. |
| **COW** | Copy-on-Write — reads fall through to the base (registry/FS); first write clones into the private zone layer. Core of app-subsystem virtualization. |
| **Crypto-shred** | Rendering data unrecoverable by destroying its key (the remote-wipe primitive); O(1), irreversible. |
| **Daemon** | The privileged background service hosting `clave-core` (Windows Service / launchd root daemon). |
| **DEK / KEK** | Data-Encryption Key (encrypts volume sectors) / Key-Encryption Key (wraps the DEK, hardware-bound). |
| **DLP** | Data Loss Prevention — the clipboard/file/screen/network controls that stop work data leaving the zone. |
| **DWM** | Desktop Window Manager — the Windows compositor that enforces `WDA_EXCLUDEFROMCAPTURE`. |
| **Enclave / Secure Enclave** | (1) The product's work zone. (2) Apple's hardware **Secure Enclave** key store. Context disambiguates; doc 04 uses both. |
| **Endpoint Security (ES)** | macOS framework (`EndpointSecurity`) for exec/file authorization by audit token; the macOS source of truth. Entitlement-gated. |
| **Fail-closed** | On failure (daemon killed, policy expired, hook stripped) the system denies/locks rather than allowing — a security requirement here. |
| **HLK / WHQL** | Windows Hardware Lab Kit / Windows Hardware Quality Labs — Microsoft's driver certification/testing path. |
| **Idle threshold** | Input-gap (seconds) past which a foreground work app's time is counted as idle rather than active; a `TrackingPolicy` knob (doc 18). |
| **IRP** | I/O Request Packet — the Windows kernel I/O unit a minifilter intercepts (e.g. `IRP_MJ_CREATE`). |
| **Job Object / Server Silo** | Windows kernel primitives for grouping/containing process trees; Silos additionally virtualize the object/registry namespace. |
| **Kernel-authoritative** | A guarantee that terminates in a kernel-driver (Win) or system-extension (mac) check keyed on a kernel-supplied identity — not a user-mode hook. The core security principle (doc 01 §4). |
| **kbdclass** | Windows keyboard class driver; an upper-filter on it enables real input isolation (doc 06). |
| **MDM** | Mobile Device Management (Intune, Jamf, Kandji) — pre-approves extensions/TCC/network config on managed devices. |
| **Minifilter** | A Windows file-system filter driver; enforces Clave Disk access gating and FS redirection backstop. |
| **NE** | **Network Extension** — macOS framework; `NETransparentProxyProvider` does per-app split-tunnel routing. |
| **NRPT** | Name Resolution Policy Table (Windows) — routes specific domains to specific resolvers (work DNS into the tunnel). |
| **Nt\* hooks** | Inline hooks on `ntdll`'s syscall stubs (`NtCreateFile`, `NtCreateKey`, …) — the lowest user-mode interception point. |
| **PPL** | Protected Process Light — a Windows protection tier that resists tampering; requires meeting MS signing bars. |
| **PPPC** | Privacy Preferences Policy Control — MDM profile type that pre-grants macOS TCC permissions. |
| **ProcId** | Authoritative process identity: `(pid, create_time)` on Windows, `audit_token` on macOS — defeats PID reuse/spoofing. |
| **ProjFS** | Windows Projected File System — an alternative to FS hooking for presenting a virtual file view. |
| **SE** | (Apple) Secure Enclave — hardware key store; wraps the Clave Disk key on macOS. |
| **Shim** | The small code injected into / hosted alongside each work app (Windows DLL with hooks; macOS framework/extension helper). Semi-trusted. |
| **SIP** | System Integrity Protection (macOS) — blocks modification of protected resources and contributes to injection prevention. |
| **Silo** | See Job Object / Server Silo. |
| **Split tunnel** | Routing work flows through the corporate gateway while personal flows go direct (doc 08). |
| **Static egress IP** | The fixed per-tenant IP the gateway NATs work traffic to, enabling SaaS conditional access / IP allowlisting. |
| **Supervised / unsupervised** | In-zone (work) vs out-of-zone (personal) process/window/file/flow. |
| **TCC** | Transparency, Consent, and Control — macOS permission system (Accessibility, Screen Recording, Input Monitoring, Full Disk Access). |
| **TPM** | Trusted Platform Module — Windows hardware key store; seals the Clave Disk KEK to PCRs. |
| **Clave Disk** | The encrypted, access-gated local volume holding all work data/profiles/registry hive (doc 04). |
| **VDI / DaaS** | Virtual Desktop Infrastructure / Desktop-as-a-Service — the remote-desktop model this system explicitly avoids. |
| **WFP** | Windows Filtering Platform — kernel network filtering used for the split tunnel. |
| **WDA_EXCLUDEFROMCAPTURE** | `SetWindowDisplayAffinity` flag making a window black to screen capturers (doc 07). |
| **WinFsp** | "FUSE for Windows" — implements the encrypting user-mode Clave Disk filesystem. |
| **Work zone** | The logical partition containing supervised resources; the system's central abstraction. |
| **Zone membership** | Whether a `ProcId` is in the work zone; queried on nearly every enforcement hot path (doc 02). |
