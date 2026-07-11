# 04 — Encrypted Volume ("Clave Disk")

The Clave Disk is the enclave's data-at-rest store: work files, application profiles, browser
session data, the virtualized registry hive (Windows, doc 03), and work metadata. It is the
cleanest, most portable subsystem — and the one that must survive A5 (device theft) and
support instant remote wipe (A6 mitigation / offboarding).

Implements the `VolumeMount` trait from [00 §4](00-architecture-overview.md).

---

## 1. Requirements

1. **Confidential at rest** against an offline attacker with the raw disk (A5).
2. **Access-gated at runtime:** only supervised processes may read it; personal processes
   may not, *even with the volume mounted* (kernel-authoritative, doc 01 §4).
3. **Hardware-rooted key:** the volume key is wrapped to the device's TPM (Windows) or
   Secure Enclave (macOS) and is **never** persisted in cleartext, so copying the container
   to another machine yields nothing.
4. **Instant remote wipe:** destroying one wrapped key renders the entire container
   unrecoverable in O(1), without touching personal data.
5. **Crash-consistent** and **performant** (native-app file I/O runs through it).
6. **Fail-closed:** if the daemon dies or the key is evicted, the volume unmounts and reads
   fail; plaintext is never exposed.

---

## 2. Key hierarchy

```
            ┌──────────────────────────────────────────────┐
            │ Hardware root                                 │
            │  Windows: TPM 2.0 (sealed to PCRs + PIN/bio)  │
            │  macOS:   Secure Enclave (key never leaves)   │
            └───────────────────────┬──────────────────────┘
                                    │ unwraps (only after user/device auth)
                          ┌─────────▼──────────┐
                          │  KEK (key-encrypt  │   per-device, hardware-bound
                          │  key) — wrapped     │
                          └─────────┬──────────┘
                                    │ AES-KW / RSA-OAEP unwrap in secure element
                          ┌─────────▼──────────┐
                          │  Volume DEK         │   AES-256, lives only in locked memory
                          │  (data-encrypt key) │   while mounted; zeroized on lock
                          └─────────┬──────────┘
                                    │ AES-256-XTS per sector
                          ┌─────────▼──────────┐
                          │  Encrypted container│   on personal disk, opaque blob
                          └────────────────────┘
```

- **Block cipher:** **AES-256-XTS** (the standard for full-disk/whole-volume encryption;
  tweak = sector number). Rust: `aes` + `xts-mode` crates, or `ring`/`OpenSSL` via FFI if you
  want assembly-optimized AES-NI throughput. **Benchmark**: XTS in pure-Rust `aes` is fine
  for laptops with AES-NI; verify you're hitting the hardware path (`target-feature=+aes`).
- **Key wrapping:** **AES-KW (RFC 3394)** or the platform's native seal. Never store the DEK;
  store only `wrap(KEK, DEK)` and let the secure element do the unwrap.
- **Remote-wipe primitive:** wipe = delete the wrapped DEK from the hardware store. Without
  it, the container's XTS plaintext is unrecoverable. This is **crypto-shredding** — O(1),
  irreversible, leaves personal data untouched. The container blob can be lazily deleted
  afterward.

---

## 3. Windows: user-mode encrypting filesystem (WinFsp)

Implement the volume as a **user-mode filesystem** with **WinFsp** (the FUSE-for-Windows
project; Rust bindings: the `winfsp` crate). Each read/write passes through your encrypt /
decrypt + the per-IO access check.

```
work app ──NtCreateFile──► minifilter (gate) ──► WinFsp ──► your Rust FS callbacks
                               │                              │
                               │ deny if caller PID ∉ zone    │ AES-XTS encrypt/decrypt
                               ▼                              ▼
                         (kernel-authoritative)        backing container file on C:
```

### 3.1 The callback skeleton

```rust
// clave-volume-win (Rust, winfsp crate) — SKETCH
use winfsp::filesystem::{FileSystemContext, FileInfo};

struct ClaveVolume {
    dek:       SecretKey,                 // zeroize-on-drop; present only while unlocked
    backing:   BackingStore,             // the encrypted container on personal disk
    zone:      Arc<ZoneRegistry>,        // doc 02 — who's allowed
}

impl FileSystemContext for ClaveVolume {
    fn open(&self, name: &U16CStr, ctx: &OpenContext) -> winfsp::Result<FileCtx> {
        // Belt: enforce caller identity here too (the minifilter is the braces).
        if !self.zone.is_supervised(&ctx.caller_proc_id()) {
            return Err(STATUS_ACCESS_DENIED.into());
        }
        self.backing.open(name)
    }

    fn read(&self, f: &FileCtx, buf: &mut [u8], offset: u64) -> winfsp::Result<usize> {
        let sector = offset / SECTOR;
        let ct = self.backing.read_sectors(f, offset, buf.len())?;
        xts_decrypt(&self.dek, sector, &ct, buf);     // tweak = sector index
        Ok(buf.len())
    }

    fn write(&self, f: &FileCtx, data: &[u8], offset: u64) -> winfsp::Result<usize> {
        let sector = offset / SECTOR;
        let mut ct = vec![0u8; data.len()];
        xts_encrypt(&self.dek, sector, data, &mut ct);
        self.backing.write_sectors(f, offset, &ct)
    }
    // … getinfo, rename, delete, setsize, flush, cleanup …
}
```

### 3.2 Why both a minifilter *and* the WinFsp check

WinFsp's own callback runs in user mode; a privileged attacker could in principle talk to
the WinFsp device directly. The **minifilter** (doc 03 §3.3) is the kernel-authoritative gate
that denies any non-supervised PID from reaching the volume's device at the `IRP_MJ_CREATE`
layer. The WinFsp-level check is defense-in-depth, not the primary control.

### 3.3 Mount lifecycle

- **Unlock:** daemon authenticates user/device → TPM unwraps DEK into a `SecretKey` in
  non-paged, `VirtualLock`'d, `zeroize`-on-drop memory → mount WinFsp volume at a fixed
  mountpoint (e.g. a drive letter or a `\\?\Volume{…}` path) → load the virtualized registry
  hive from it (doc 03) → arm minifilter with the volume device id.
- **Lock / daemon exit / logout:** unmount volume → `RegUnLoadKey` the hive → `zeroize` the
  DEK → drop the `SecretKey`. Reads now fail (fail-closed).

> **`alloc`/paging hazard:** the DEK must never hit the pagefile. `VirtualLock` the buffer and
> use a `Zeroizing<[u8; 32]>`. Confirm the pagefile itself is also protected if you handle
> regulated data (Windows can encrypt the pagefile; document the requirement).

---

## 4. macOS: native encrypted volume

macOS gives you encryption for free; don't reimplement XTS. Two good options:

| Option | Mechanism | Pros | Cons |
|--------|-----------|------|------|
| **Encrypted APFS volume** | Add an APFS volume to the container, encrypted, key in Keychain/SE | Native, fast, snapshot-able, FileVault-class | Volume is visible in Disk Utility; needs careful key policy |
| **Encrypted sparse image** | `hdiutil create -encryption AES-256 -type SPARSEBUNDLE` | Single-file container, trivially wipeable/movable, easy backup semantics | Slightly slower; band files |

Recommended: **encrypted sparsebundle** for v1 (clean container semantics + easy
crypto-shred) — revisit APFS volume for performance later.

```bash
# provisioning (driven by the daemon via DiskImages / hdiutil)
hdiutil create -size 50g -encryption AES-256 -type SPARSEBUNDLE \
   -fs APFS -volname "ClaveDisk" -stdinpass /path/ClaveDisk.sparsebundle
# mount with the SE-wrapped passphrase fed on stdin; never written to disk
hdiutil attach -stdinpass -nobrowse -mountpoint /Volumes/ClaveDisk /path/ClaveDisk.sparsebundle
```

### 4.1 Key storage on macOS

- Store the volume passphrase/DEK in the **Keychain with a Secure-Enclave-protected access
  control** (`SecAccessControlCreateWithFlags` + `kSecAttrTokenIDSecureEnclave` for the
  wrapping key; the SE key never leaves the chip). Require user presence (Touch ID / device
  passcode) to release it. Rust: the `security-framework` crate, or a thin Swift bridge for
  the SE-specific bits.
- **Crypto-shred / wipe:** delete the Keychain item (the wrapped key) → the sparsebundle is
  unrecoverable → then unlink the bundle. O(1), irreversible.

### 4.2 Access-gating the mount

A mounted volume is world-visible on macOS by default. Enforce the access gate with the **ES
client**: subscribe to `ES_EVENT_TYPE_AUTH_OPEN` (and `AUTH_CLONE`, `AUTH_TRUNCATE`) and
**deny** opens of paths under `/Volumes/ClaveDisk` whose caller `audit_token` is not in the
zone. Mount with `-nobrowse` to keep it out of Finder's sidebar.

```swift
case ES_EVENT_TYPE_AUTH_OPEN:
    let file = msg.pointee.event.open.file.pointee
    let path = String(cString: file.path.data)
    let tok  = msg.pointee.process.pointee.audit_token
    if path.hasPrefix("/Volumes/ClaveDisk") && !clave_core_zone_contains(token_bytes(tok)) {
        es_respond_flags_result(client, msg, 0 /* deny all access flags */, false)
    } else {
        es_respond_flags_result(client, msg, UInt32.max /* allow */, false)
    }
```

> **Perf note:** `AUTH_OPEN` on a busy volume is high-frequency. Use `es_mute_path` to mute
> the volume for *supervised* processes you've already decided to trust, so ES only adjudicates
> the boundary crossings, not every work-app read. Re-evaluate mutes on policy change.

---

## 5. Data layout inside the volume

```
ClaveDisk/
├── registry/                 # Windows: the COW hive(s) RegLoadKey'd at unlock (doc 03)
│   └── zone-default.hiv
├── profiles/                 # per-app profiles (Chrome User Data, Office, Slack, …)
│   ├── chrome-work/
│   └── office/
├── documents/                # user work files
├── tmp/                      # work-only temp; redirected from %TEMP%/$TMPDIR
├── .clave-meta/               # policy cache, audit spool, key-version, container uuid
└── .clave-wipe-marker         # set during wipe; checked at mount to refuse a half-wiped vol
```

- **Browser session/cookie data** lives in `profiles/` so a remote wipe instantly revokes
  SaaS sessions (the offboarding story).
- The **audit spool** lives inside so it's encrypted at rest; it is drained to the gateway
  and trimmed.

---

## 6. Remote wipe (the offboarding / lost-device flow) {#remote-wipe}

```
gateway → daemon: signed WIPE{container_uuid, reason}
   │
   ▼
daemon verifies signature + freshness (anti-replay nonce)
   │
   ├─ evict DEK from memory (zeroize)                         ← live data instantly dark
   ├─ delete wrapped DEK from TPM / Keychain (crypto-shred)   ← unrecoverable, O(1)
   ├─ set .clave-wipe-marker, then unlink the container blob   ← reclaim disk, best-effort
   └─ emit audit{wiped, uuid} (may be the last event the gateway sees)
   │
   ▼
personal files: UNTOUCHED (never inside the container)
```

Properties:

- **Irreversible** the instant the wrapped key is gone, even if the container blob lingers
  (e.g. device offline mid-wipe — the marker + missing key prevent any future mount).
- **Bounded blast radius:** only the enclave is destroyed.
- **Offline devices:** the wipe applies on next daemon start because the key is already
  gone; queue a fail-closed mount refusal via the wipe marker.

---

## 7. Performance & correctness checklist

- ✅ AES-NI engaged (`+aes,+sse2` on x86; ARMv8 crypto on Apple Silicon — APFS/SE handle it
  natively on mac).
- ✅ XTS sector size matches the FS cluster size to avoid read-modify-write amplification.
- ✅ Write-back cache flushed on `cleanup`/`flush`; honor `FILE_FLAG_WRITE_THROUGH` for
  databases (Office, SQLite-backed apps).
- ✅ DEK in locked, non-paged, zeroizing memory; never logged, never serialized.
- ✅ Crash consistency: journaled backing writes or copy-on-write band files; test with
  pull-the-plug fault injection.
- ✅ Fail-closed verified: kill daemon mid-write → volume unmounts → no plaintext on the
  backing store.

Proceed to [05 — Clipboard & Data-Transfer DLP](05-clipboard-dlp.md).
