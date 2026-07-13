# Agent conventions

## macOS signed hosts — rebuild after Rust changes

`crates/clave-mac/macos/` holds two Xcode targets that **statically link Rust**:

| Target | Links | Why it exists |
|---|---|---|
| `ClaveDaemonHost` | `libclave_daemon_host.a` | The only build that can reach the **Secure Enclave** (`keychain-access-groups`). Runs the real daemon. |
| `ClaveESExtension` | `libclave_mac.a` | The Endpoint Security client. |

**`cargo build` does not update these app bundles.** The `.a` is baked in at Xcode build
time, so after changing any Rust that either target links — `clave-daemon`,
`clave-daemon-host`, `clave-mac`, or anything they depend on (`clave-core`, `clave-volume`,
`clave-platform`, `clave-ipc`, `clave-net`, `clave-proto`) — rebuild before running or
testing them, or you are exercising **stale code**:

```sh
cd crates/clave-mac/macos
xcodegen generate    # only if project.yml changed
xcodebuild -project ClaveES.xcodeproj -scheme ClaveDaemonHost \
  -configuration Release -derivedDataPath build -allowProvisioningUpdates build
```

The Xcode targets run `cargo build --release` themselves, so no separate cargo step is needed.

Run the signed daemon (logs in the terminal):

```sh
crates/clave-mac/macos/build/Build/Products/Release/ClaveDaemonHost.app/Contents/MacOS/ClaveDaemonHost
```

### Two profiles, two disks

The daemon runs under one of two profiles (`clave-daemon/src/mac_main.rs`), which differ only in
whether they can reach the Secure Enclave. **They own separate Clave Disks and never collide:**

| | `Profile::Dev` | `Profile::SignedHost` |
|---|---|---|
| Binary | `cargo run -p clave-daemon` | `ClaveDaemonHost.app` |
| Secure Enclave | unreachable (unsigned) | reachable |
| Key custody | plain Keychain (`AllowPlainFallback`) | SE-sealed (`RequireHardware`) |
| Container | `ClaveDisk-dev.sparsebundle` | `ClaveDisk.sparsebundle` |
| Mount | `/Volumes/ClaveDisk-dev` | `/Volumes/ClaveDisk` |

Each prints its profile on startup. Use `cargo run` for the fast loop; use the signed host to
validate anything touching `se_seal.rs` or hardware-rooted key custody — the dev profile's
fallback is not the real path.

`SignedHost` **refuses to start** rather than provision a software-only disk if the SE is
unreachable: a hardware-rooted deployment must never silently downgrade.

A disk's custody is fixed when the container is **created** and is never re-provisioned on open.
Opening a sealed container without the SE fails closed rather than minting a passphrase that could
not decrypt it. To change custody, delete the container and its Keychain item
(`security delete-generic-password -s com.clave.volume -a sparsebundle-key-<container-id-hex>`)
and let the intended binary re-create it. `CLAVE_DISK_BUNDLE` / `CLAVE_DEV_MOUNT` override the
paths.

## Commit messages

Keep them short and focused on what the change **adds or does now** — not the old
behavior it replaces.

- **Subject:** one line, imperative, Conventional Commits prefix
  (`feat`, `fix`, `chore`, `refactor`, `docs`, `test`), ideally ≤ 70 chars.
  Scope optional, e.g. `feat(launcher): ...`.
- **Body (optional):** only if the subject can't carry it. Terse bullets naming the
  concrete additions (files/crates/features). No paragraphs of prose.
- **Focus on additions.** State what now exists, not what was removed, superseded,
  "previously", or kept as a fallback. Skip restating-the-obvious and marketing tone.
- **Never** add `Co-authored-by:` trailers.

Good:

```
feat: macOS ES host, encrypted Clave Disk, Secure Enclave sealing

- Xcode project for the ES client (ClaveES + ClaveESExtension)
- hdiutil AES-256 sparsebundle mount (clave-mac/src/volume.rs)
- Secure Enclave P-256 sealing for the mount passphrase
```

Avoid: multi-paragraph messages that narrate old behavior, e.g. "Removes the
superseded scaffold it replaces", "instead of generic glyphs", "keeps working
unsigned with a Keychain-only fallback".
