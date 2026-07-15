# 20 — Disk Storage: Cloud Backup & Mountable Cloud Filesystems

Doc [04](04-encrypted-volume.md) defines the Clave Disk crypto (AES-XTS, hardware-rooted key,
remote wipe). This doc adds the storage layer **beneath and beside** that crypto. It covers **two
orthogonal capabilities** — a tenant can adopt either, both, or neither. Do not conflate them:

| | **① Clave Disk Cloud Backup** (§1–§3) | **② Mountable Cloud Filesystem** (§4) |
|---|---|---|
| What | the enclave's *own* container, replicated to the cloud | *external* file stores shown as folders inside Clave Disk |
| Backed by | **object storage — S3 / GCS / Azure** | **file providers — Google Drive, Box, OneDrive** |
| Whose data | the company's, inside the Clave container | third-party, foreign to the container |
| Clave crypto | AES-XTS + company DEK (only ciphertext leaves) | none of Clave's — the provider's; Clave streams plaintext to the app |
| Seam | `BackingStore` (below XTS) | `ProviderMount` (a subtree of the composed FS) |
| Purpose | durability, recovery, roaming to a new device | open external files in work apps |
| Auth | device enrollment | provider OAuth / IAM, gateway-brokered |

**Object storage lives in ①.** S3/GCS/Azure is the backup backend, not a browse-first store. The
*same object-store client* can optionally be reused to surface a bucket as a folder under ② (for a
team that keeps datasets in S3), but that is a secondary reuse — ②'s primary targets are the
file-collaboration providers. That shared client is the only coupling; the two are otherwise
**different subsystems**, specified separately below.

---

## Capability ① — Clave Disk Cloud Backup

A **per-tenant tier** of the disk itself:

| Tier | Custody | Cloud | Recovery / multi-device | Cost |
|---|---|---|---|---|
| **A — Local Vault** | key minted on-device, sealed to SE/TPM | none | ✗ device-bound; device loss = disk loss | free |
| **B — Cloud Backup** | key escrowed at the gateway, delivered SE/TPM-sealed per device | ciphertext replicated to blob storage | ✓ re-wrap DEK to a new device | paid (metered storage) |

The company chooses the tier. Model A is the honest "not even the vendor can decrypt it, and it
never leaves this laptop" story. Model B is the "my disk follows me, survives a lost laptop, and
IT can provision it centrally" story — and the thing they pay for.

> **Backup topology — decision, see §7.** "Backup" can mean **local-primary + async cloud replica**
> (the disk stays a local container exactly as in Model A; a replication engine pushes encrypted
> chunks up and pulls them on recovery — fast, offline-capable) or **cloud-primary streaming** (the
> `BackingStore` *is* the cloud, fronted by a local cache — always-current across devices but
> online-dependent). The mechanism below (chunk + cache + lease) is shared; only *who is
> authoritative* differs. **Recommended default: local-primary + cloud replica** — Model B's disk
> stays identical to Model A's locally and merely gains replication, rather than a second disk
> architecture. This topology is orthogonal to the mount mechanism (§3) and to capability ② (§4).

---

## 1. Why this is a knob, not a fork

The two tiers differ in **exactly two seams**. Everything else — the XTS container, the zone
access-gate, the wipe marker, the mount lifecycle — is identical.

```
        ┌───────────────────────────────────────────────┐
        │  work app  ──►  zone access-gate (doc 02/04)   │   IDENTICAL A & B
        │            ──►  ClaveVolume  (AES-256-XTS)      │   IDENTICAL A & B
        └───────────────────────┬───────────────────────┘
                    seam 1: DEK │ custody          seam 2: BackingStore
          ┌─────────────────────┴───────┐   ┌──────────────┴──────────────┐
   A →    │ Dek minted on-device,        │   │ local file (hdiutil          │
          │ sealed to SE  (Custody)      │   │ sparsebundle / container)    │
          ├──────────────────────────────┤   ├──────────────────────────────┤
   B →    │ Dek escrowed at gateway,     │   │ CloudBacking: chunked blob   │
          │ delivered WrappedVolumeKey   │   │ store + local write cache    │
          │ (ECIES to device SE pubkey)  │   │                              │
          └──────────────────────────────┘   └──────────────────────────────┘
```

- **Seam 1 (key custody)** is `enroll::DeviceVolumeKey` + `clave_volume::KeyStore`.
- **Seam 2 (backing)** is the `clave_volume::BackingStore` trait — which sits *below* XTS, so a
  cloud backend only ever sees ciphertext.

`DiskCustody { LocalOnly, CloudEscrow }` on the tenant policy selects the pair. The daemon already
branches on `clave_mac::Custody { AllowPlainFallback, RequireHardware }` at provisioning; the tier
is one level above that — it decides *provenance and location*, custody decides *how the key seals*.

---

## 2. Model B, layer by layer

### Layer 1 — Key custody & escrow  (~80% already in the tree)

The escrow primitive **exists**. `enroll.rs` already has the gateway hand a device a
`WrappedVolumeKey` (`wrapped_dek` + `ephemeral_pub`) which the device opens with
`DeviceVolumeKey::Sealed(sealing)` → `open_dek(...)` (ECIES to the device's Secure Enclave public
key). The plaintext DEK only ever materializes inside hardware-unwrapped memory.

```
gateway  ──WrappedVolumeKey{ wrapped_dek, ephemeral_pub }──►  device
                                                              │ open_dek(SE key, …)
                                                              ▼
                                                         Dek (locked mem)
```

**What's net-new for B:**
- **Durable escrow store** (Postgres). Today the gateway holds keys in memory. Persist, per
  container: the DEK wrapped under a gateway KEK, plus one `WrappedVolumeKey` per enrolled device.
- **Re-wrap on new device** — the entire recovery / multi-device story is *one endpoint*: a new
  device enrolls, the gateway unwraps the container DEK (server side) and re-wraps it to the new
  device's SE public key. No plaintext DEK crosses the wire; recovery == adding a device.
- **⚠ Trust note.** Under B the gateway can wrap the DEK for an arbitrary device, so the gateway
  *is* in the confidentiality TCB (it could authorize itself a device). This is the deliberate
  cost of recovery. Model A does not have this property — state it plainly in the tier's marketing.

### Layer 2 — The cloud `BackingStore`  (core net-new client work)

Today the only `BackingStore` impl is `MemBacking` (RAM). The trait is the exact seam:

```rust
pub trait BackingStore: Send + Sync {
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), VolumeError>;
    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), VolumeError>;
    fn sector_count(&self) -> u64;
    fn set_wipe_marker(&self) -> Result<(), VolumeError>;   // ← remote-wipe, already modeled
    fn is_wiped(&self) -> bool;
}
```

A `CloudBacking` needs three things a blob store does not give you for free:

- **Chunking.** Object stores are not per-sector random-access. Group N sectors into a chunk
  (~4–8 MB) = one object, keyed by `(container_id, chunk_index)`. `read_sector`/`write_sector`
  resolve to a chunk fetch + in-chunk offset.
- **Local write-back cache.** Reads/writes hit a local cache dir first; dirty chunks upload
  asynchronously. This is what makes native app I/O tolerable over the network.
- **A single-writer lease.** One device holds the container at a time (see §4). Concurrent
  multi-device *block* sync is a distributed-systems problem; a lease sidesteps it and still
  delivers "my disk on my new laptop."

Because XTS runs above this seam, the cache and the blobs are **ciphertext**. The cloud never sees
plaintext or the DEK.

### Layer 3 — Storage service & metering  (the "premium" surface)

A companion service (or gateway routes) that:

- stores per-container encrypted **chunks** in S3/GCS/Azure Blob;
- **authorizes** chunk R/W by the device's enrollment identity (the same signed identity used for
  audit ingest, doc [15](15-identity-and-enrollment-auth.md));
- **meters** bytes per tenant → billing + quota enforcement (reject writes over the plan);
- holds the durable escrow store from Layer 1.

Metering + quota is the mechanism that makes B "pay for storage."

---

## 3. The client mount fork  ◀ decision needed

How the decrypted volume is presented to work apps under B. This choice shapes the entire client
implementation and the cross-platform story.

| | **B1 — Portable `ClaveVolume` + userspace FS** | **B2 — Sparsebundle bands → cloud** |
|---|---|---|
| Mechanism | XTS `ClaveVolume` over `CloudBacking`, exposed via macOS **FSKit**/macFUSE and Windows **WinFsp** | keep `hdiutil` sparsebundle; passphrase = escrow DEK; sync its `bands/` (~8 MB each) to blob store |
| Cross-platform | ✓ one code path both OSes (Windows needs WinFsp anyway, doc 04 §3) | ✗ macOS-only; Windows needs its own backend regardless |
| Reuses today | the `BackingStore` seam, built for exactly this | today's working macOS mount; no FUSE to ship |
| Sync unit | your chunk (you control it at the sector API) | the band file (already ciphertext, maps 1:1 to an object) |
| Main cost | must build/ship a userspace filesystem; macOS is mid-migration kext→**FSKit** | you build a band-scoped sync engine; two disk architectures to maintain long-term |
| Wipe | `set_wipe_marker` on the backing | delete escrow key + band objects (crypto-shred, doc 04 §6) |

**Recommendation: B1.** The `BackingStore` trait was designed for this, it collapses macOS and
Windows onto one storage path, and Windows requires a userspace FS (WinFsp) for the volume no
matter what — so B2's "no FUSE" saving is macOS-only and temporary. B2 ships faster on Mac alone
but leaves two disk architectures to carry. Pick B2 only if a fast Mac-only beta outranks the
uniform architecture.

Either way, **Model A's local-mint sparsebundle path stays unchanged** as the free tier and the
offline / no-gateway fallback.

---

## 4. Capability ② — Mountable Cloud Filesystem (provider federation)

Distinct from backup (§1–§3): here **external file providers** — Google Drive, Box, OneDrive —
appear as browsable folders *inside* Clave Disk, so `documents/` sits next to a `OneDrive/` folder
you click into and open in Excel. This federates foreign namespaces into the enclave view; it does
**not** place that data in the company container. It makes the Clave Disk a **composed filesystem** —
one enclave-gated namespace with the container at the root and foreign stores grafted in as subtrees.

Object storage (S3/GCS/Azure) is primarily ①'s backup backend, *not* a browse-first target; the
same client may optionally mount a bucket here for a team that keeps datasets in S3, but the
file-collaboration providers are ②'s reason to exist.

```
/Volumes/ClaveDisk   (zone-gated: only supervised PIDs — doc 04 §4.2)
├── documents/            ← encrypted container   (local sectors OR CloudBacking, §2)
├── profiles/             ← encrypted container
├── OneDrive/             ← ProviderMount(onedrive)   ┐ file providers —
├── Google Drive/         ← ProviderMount(gdrive)     │ foreign namespaces,
├── Box/                  ← ProviderMount(box)        │ streamed on open,
│                                                     ┘ never in the container
└── s3/acme-datasets/     ← ProviderMount(s3 bucket)  ← optional; object storage is mainly ①
```

The same object-store client written for ①'s backup backend is what makes the optional bucket mount
cheap — that reuse is the "plays into." But it is one integration with a primary consumer (backup)
and a secondary one (the occasional mounted bucket); the file providers are what ② is built for.

### 4.1 The provider adapter seam

Mirroring `BackingStore`, each provider is a pluggable adapter behind one trait, so the FS layer is
provider-agnostic and providers are *data, not special cases* (cf. vendors-as-data, doc 16):

```rust
// SKETCH — one impl per provider (gdrive, onedrive, box, s3, gcs, azure)
pub trait ProviderMount: Send + Sync {
    fn list(&self, dir: &Path) -> Result<Vec<DirEntry>, ProviderError>;
    fn stat(&self, path: &Path) -> Result<Meta, ProviderError>;
    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, ProviderError>;   // stream + cache
    fn open_write(&self, path: &Path) -> Result<Box<dyn WriteAt>, ProviderError>; // gated (§4.3)
    fn caps(&self) -> MountCaps;   // read_only? range reads? OAuth vs key auth
}
```

The composed FS (the B1 userspace filesystem, §3) routes a path to the container store or a
`ProviderMount` by prefix. **This makes B1 mandatory whenever capability ② is enabled** — a
sparsebundle (B2) cannot graft foreign subtrees — *independent of ①'s backup topology*: the
container backing may be local or cloud, but a mounted `OneDrive/` still requires the composed
userspace FS. Provider federation thus settles the §3 fork in favor of B1.

### 4.2 Credential custody — gateway-brokered

Provider auth differs (Google/Box/OneDrive = OAuth; S3/GCS/Azure = IAM keys / SAS), but the custody
rule is uniform and follows the enclave philosophy — the same broker pattern as the AI-gateway
credential path (doc 19):

- The **long-lived** provider secret (OAuth refresh token, IAM key) lives **at the gateway**, never
  on the personal machine.
- The device holds only a **short-lived**, scoped access token, refreshed via the gateway.
  Offboarding and rotation happen centrally; the device keeps nothing durable.
- Streamed bytes hydrate into the **enclave cache** (inside the container, encrypted at rest, wiped
  with it). "Files On-Demand" semantics — placeholders that fetch on open, not a full sync.

### 4.3 A mounted store is a governed egress — ◐ policy-gated

A writable provider mount is a **sanctioned data-exfil channel**: a work app can write container
data into `OneDrive/`, which then leaves the enclave. This is not a gap to paper over; it is a
policy surface that must be explicit:

- **Per-mount policy:** which providers mount, `read-only | read-write`, and which apps may reach
  them — expressed in the policy bundle, same shape as the app allow-list.
- **Container→provider moves** cross the enclave boundary and go through the **ES file gate**
  (`authorize_open` / `authorize_relocation` / `set_allow_save_outside_enclave` — doc 04, clave-mac
  `es_gate`) exactly like any save-outside-the-enclave. A mount does not bypass the gate.
- **Adapter egress is tunneled:** the provider fetch/put runs through the work-zone split-tunnel
  (doc 08), so it uses the company static IP and is visible to IT, not the user's raw ISP path.
- **⚠ Honesty:** a read-only mount still lets a determined user photograph the screen; mounts
  *narrow*, not close, the human-in-the-loop exfil path — the same limit called out for screen and
  clipboard.

---

## 5. v1 scope

- **Single-writer lease** per container (gateway-issued, short TTL, renewed while mounted). Other
  devices are read-only or must acquire. Covers recovery + device migration without concurrent
  block-merge.
- **Chunked encrypted-sector replication** to blob storage + local cache — local-primary per §1's
  recommendation; the same chunk/cache layer becomes the `CloudBacking` backing store if the
  cloud-primary topology is chosen instead.
- **Postgres** for: wrapped DEK, per-device `WrappedVolumeKey`, active lease, per-tenant byte meter.
- **First provider mount** (§4): one file provider (e.g. OneDrive), mounted **read-only**, to prove
  the composed-FS + credential-broker path before enabling writes. (Object storage's v1 work is ①'s
  backup backend above — a bucket mount is not in v1.)
- Model A untouched.

Out of scope for v1: concurrent multi-device writes, delta/dedup sync, offline conflict merge,
writable provider mounts, providers beyond the first two.

---

## 6. What exists vs net-new

| Piece | State |
|---|---|
| AES-XTS container (`ClaveVolume`, `xts.rs`) | ✅ built |
| `BackingStore` trait + `MemBacking` | ✅ trait built; only a RAM impl |
| DEK/KEK, `KeyStore`, AES-KW wrap | ✅ built (`clave-volume`) |
| Gateway→device DEK escrow (`WrappedVolumeKey`, `DeviceVolumeKey::Sealed`, `open_dek`) | ✅ built (`enroll.rs`), in-memory only |
| Remote-wipe marker (`set_wipe_marker`/`is_wiped`) | ✅ modeled |
| macOS local sparsebundle mount (Model A) | ✅ built (`clave-mac::volume`) |
| `DiskCustody { LocalOnly, CloudEscrow }` tenant knob | ✗ net-new |
| Durable escrow store (Postgres) + re-wrap endpoint | ✗ net-new |
| `CloudBacking` (chunking, cache, sync, lease client) | ✗ net-new |
| Storage service: blob R/W authz + per-tenant metering/quota | ✗ net-new |
| Userspace FS mount under B (FSKit / WinFsp) — B1, now required by §4 | ✗ net-new |
| Composed FS: container root + provider subtrees, prefix routing | ✗ net-new |
| `ProviderMount` adapters (gdrive, onedrive, box, s3, gcs, azure) | ✗ net-new |
| Gateway provider-credential broker (OAuth/IAM → short-lived token) | ✗ net-new |
| Per-mount + container→provider DLP policy | ◐ ES file gate built (`es_gate`); mount policy net-new |

---

## 7. Open decisions

1. **Backup topology (capability ①)**: local-primary + async cloud replica vs cloud-primary
   streaming (see the §1 note). Load-bearing — it decides whether Model B is Model A + replication
   or a distinct disk architecture. Recommended: local-primary + replica.
2. **Confirm B1 as the mount mechanism** (§3–§4). Capability ② forces a userspace FS, so B2 is off
   the table for those tenants; the remaining question is FSKit vs macFUSE on macOS given Apple's
   kext→FSKit migration.
3. **Blob backend**: managed (S3/GCS/Azure) vs self-hostable — affects the on-prem story for
   security-conscious tenants, and applies to both container backing (①) and mounted buckets (②).
4. **Lease semantics**: hard single-writer vs read-replica-while-leased.
5. **Provider credential model** (§4.2): gateway-brokered only, or also per-user OAuth consent with
   a refresh token sealed in the enclave keychain for personal-drive-style mounts.
6. **Writable mounts default**: ship provider mounts read-only first, or allow read-write behind
   explicit per-mount policy from day one (§4.3).
7. **Trust disclosure**: how prominently the B-tier documents that the gateway is in the
   confidentiality TCB for both the DEK (①, Layer 1) and provider credentials (②, §4.2).

Related: [04 — Encrypted Volume](04-encrypted-volume.md), [15 — Identity & Enrollment](15-identity-and-enrollment-auth.md), [16 — Third-Party Network Providers](16-third-party-network-providers.md), [19 — AI Gateway](19-ai-gateway.md), [10 — Policy Engine & IPC](10-policy-engine-and-ipc.md).
