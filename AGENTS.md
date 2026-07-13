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

### Which binary to test against

- `cargo run -p clave-daemon` — unsigned, fast loop. **Cannot reach the Secure Enclave**, so it
  provisions/opens Clave Disks with a plain-Keychain passphrase. Never validate SE-dependent
  behavior here; the fallback path is not the real path.
- `ClaveDaemonHost.app` — signed, the real path. Required to validate anything touching
  `se_seal.rs` or hardware-rooted key custody.

A Clave Disk's key custody (Secure-Enclave-sealed vs plain Keychain) is fixed when the container
is **created**, and opening an existing container never re-provisions it. So a disk created by
`cargo run` stays plain, and a sealed disk is deliberately unopenable by `cargo run` (it fails
closed rather than minting a passphrase that could not decrypt it). To switch, delete the
container and its Keychain item, then let the intended binary create it. To keep a throwaway
plain disk for the fast loop, point it elsewhere:
`CLAVE_DISK_BUNDLE=/tmp/dev.sparsebundle cargo run -p clave-daemon`.

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
