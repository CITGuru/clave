# clave-mac

macOS platform adapter. See [`../../docs/08-network-split-tunnel.md`](../../docs/08-network-split-tunnel.md),
[`../../docs/02-process-supervision.md`](../../docs/02-process-supervision.md), and
[`../../docs/04-encrypted-volume.md`](../../docs/04-encrypted-volume.md).

## What builds and tests here (any Mac, no signing)

- `src/lib.rs` — audit-token → zone classification, the exec allow-list decision
  (`clave_mac_authorize_exec`), and the C ABI the Swift hosts call. Built as both `lib` and
  `staticlib` (`libclave_mac.a`).
- `src/volume.rs` — the real Clave Disk mount: an `hdiutil`-created `AES-256` sparsebundle.
- `src/se_seal.rs` — seals the mount passphrase to a Secure-Enclave-resident P-256 key.
- `src/edge.rs` — the Clave Edge overlay (borderless AppKit windows framing supervised windows).

```sh
cargo test -p clave-mac
cargo build -p clave-mac --release   # also produces target/release/libclave_mac.a
```

## `macos/` — the real Xcode project

`macos/project.yml` (regenerate the `.xcodeproj` with `xcodegen generate`) defines three targets:

| Target | What it is | Signing |
|--------|-----------|---------|
| `ClaveES` | Containing app; activates the ES System Extension via `OSSystemExtensionRequest` | Real Apple Development cert + Team ID (needed for `sysextd`'s activation-time trust check) |
| `ClaveESExtension` | The Endpoint Security client — links `libclave_mac.a`, enforces `clave_mac_authorize_exec`/`clave_mac_can_access_volume` | Self-signed (`com.apple.developer.endpoint-security.client` is a restricted entitlement no personal-team account can provision; SIP-disabled AMFI tolerates it on an unentitled binary) |
| `ClaveDaemonHost` | The real, signed launch path for `clave-daemon` — links `libclave_daemon_host.a` | Real Apple Development cert + Team ID + `keychain-access-groups` (needed to reach the Secure Enclave from `se_seal.rs`) |

None of this activates without a SIP-disabled Mac (`ClaveESExtension`) or without the paid Apple
Developer Program (`ClaveES`'s System Extension capability — confirmed blocked on a free personal
team; `ClaveDaemonHost`'s `keychain-access-groups` is *not* blocked and works today). See
`crates/clave-mac/macos/XCODE_NOTES.local.md` (gitignored — not in this repo checkout unless you
generate it) for the full signing/provisioning state and exact blockers.

```sh
cd macos && xcodegen generate
open ClaveES.xcodeproj   # build/run ClaveDaemonHost or ClaveESExtension from here
```

## Linking

Xcode targets link the relevant `lib*.a` and call the `extern "C"` symbols via `@_silgen_name`
(see each target's `main.swift`). Pass the macOS `audit_token_t` (8 × `u32`) straight through as
an `UnsafePointer<UInt32>`.
