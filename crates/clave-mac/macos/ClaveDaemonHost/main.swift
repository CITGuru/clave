// ClaveDaemonHost — the signed macOS app that actually runs clave-daemon.
//
// This exists because AMFI only lets a properly signed, provisioned binary touch the Secure
// Enclave (crates/clave-mac/src/se_seal.rs seals the Clave Disk passphrase to an SE-resident key;
// an unsigned `cargo run -p clave-daemon` binary falls back to a plain-Keychain passphrase
// instead — see volume.rs's `passphrase_for`). This app links `libclave_daemon_host.a`
// (crates/clave-daemon-host, the tiny FFI shim — kept out of clave-daemon itself, which forbids
// unsafe code) and calls straight into clave-daemon's real startup. It never returns.
import Foundation

@_silgen_name("clave_daemon_run")
func clave_daemon_run()

clave_daemon_run()
