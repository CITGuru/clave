use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use clave_platform::{PResult, PlatformError, VolumeMount};

const KEYCHAIN_SERVICE: &str = "com.clave.volume";

/// Maximum size of the Clave Disk sparsebundle. A sparsebundle is thin-provisioned — its bands are
/// allocated lazily as data is written — so this only *caps* growth; it does not reserve the space
/// up front (the on-disk blob stays as small as the data in it). Real work apps write gigabytes of
/// profile/cache into their contained HOME (Chromium/Electron `--user-data-dir`, Office caches), so
/// the cap has to be roomy: the previous 32 MiB filled instantly and every launched app died with
/// `ENOSPC`. Override with `CLAVE_DISK_SIZE_MB`.
const DEFAULT_SIZE_MB: u64 = 65_536;
const MIN_SIZE_MB: u64 = 512;

fn configured_size_mb() -> u64 {
    std::env::var("CLAVE_DISK_SIZE_MB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SIZE_MB)
        .max(MIN_SIZE_MB)
}

fn passphrase_account(container: u128) -> String {
    format!("sparsebundle-passphrase-{container:032x}")
}

fn keychain_get(account: &str) -> Option<Vec<u8>> {
    security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, account).ok()
}

fn keychain_set(account: &str, secret: &[u8]) -> io::Result<()> {
    security_framework::passwords::set_generic_password(KEYCHAIN_SERVICE, account, secret)
        .map_err(|e| io::Error::other(format!("Keychain set failed: {e}")))
}

fn keychain_delete(account: &str) {
    let _ = security_framework::passwords::delete_generic_password(KEYCHAIN_SERVICE, account);
}

/// Encode raw random bytes as lowercase hex. `-stdinpass` reads its passphrase as a line of text —
/// raw random bytes routinely contain a NUL or newline that truncates or misparses the read (hdiutil
/// then fails with "unable to process -stdinpass argument"); hex is ASCII-safe and still carries
/// the full 256 bits of entropy.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fetch this container's sparsebundle passphrase, preferring the Secure-Enclave-sealed path
/// ([`se_passphrase_for`]) and falling back to a plain Keychain-stored one only when that's
/// unavailable — which is the normal, expected outcome for an unsigned `cargo run` binary (it
/// carries no `keychain-access-groups` entitlement at all, so the SE call fails with an ordinary,
/// catchable OSStatus error, not a kill: AMFI only kills a binary whose entitlements claim a
/// capability it can't prove, not one with no relevant entitlement present). Only a binary built
/// and signed through `crates/clave-mac/macos/ClaveDaemonHost` reaches the SE path.
fn passphrase_for(container: u128) -> io::Result<Vec<u8>> {
    match se_passphrase_for(container) {
        Ok(bytes) => Ok(bytes),
        Err(e) => {
            eprintln!(
                "clave-mac: Secure Enclave sealing unavailable ({e}) — falling back to a plain \
                 Keychain-stored passphrase (DevelopmentOnly, not hardware-rooted). Run the signed \
                 ClaveDaemonHost app for the Secure Enclave path."
            );
            legacy_plain_passphrase_for(container)
        }
    }
}

fn se_sealed_account(container: u128) -> String {
    format!("sparsebundle-se-sealed-{container:032x}")
}

/// Generate (once) a fresh 64-byte hex passphrase, seal it to this device's Secure-Enclave key,
/// and store only the sealed blob in Keychain — the plaintext passphrase never touches disk.
/// Later calls unseal the stored blob, which only succeeds by asking the Secure Enclave itself to
/// perform the ECDH (`se_seal::open`); a copied Keychain database is useless without this device.
fn se_passphrase_for(container: u128) -> io::Result<Vec<u8>> {
    let account = se_sealed_account(container);
    let se_key = crate::se_seal::SeSealingKey::load_or_generate()?;

    if let Some(existing) = keychain_get(&account) {
        let sealed: [u8; crate::se_seal::SEALED_LEN] = existing
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::other("stored SE-sealed passphrase has the wrong length"))?;
        return crate::se_seal::open(&se_key, &sealed).map(|b| b.to_vec());
    }

    let se_pub = se_key.public_key_bytes()?;
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    let passphrase = hex_encode(&bytes).into_bytes();
    let passphrase_arr: [u8; 64] = passphrase
        .as_slice()
        .try_into()
        .expect("hex-encoding 32 bytes always yields 64 ASCII bytes");

    let sealed = crate::se_seal::seal(&se_pub, &passphrase_arr)?;
    keychain_set(&account, &sealed)?;
    Ok(passphrase)
}

/// The pre-SE fallback: a passphrase stored as plain bytes in the ordinary login Keychain — real
/// OS-encrypted-at-rest storage, but not hardware-sealed (extractable by anything with Keychain
/// access, unlike [`se_passphrase_for`]'s blob).
fn legacy_plain_passphrase_for(container: u128) -> io::Result<Vec<u8>> {
    let account = passphrase_account(container);
    if let Some(existing) = keychain_get(&account) {
        return Ok(existing);
    }
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    let passphrase = hex_encode(&bytes).into_bytes();
    keychain_set(&account, &passphrase)?;
    Ok(passphrase)
}

fn run_hdiutil_with_passphrase(args: &[&str], target: &Path, passphrase: &[u8]) -> io::Result<()> {
    let mut child = Command::new("hdiutil")
        .args(args)
        .arg(target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(passphrase)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "hdiutil {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn create_if_missing(bundle_path: &Path, size_mb: u64, passphrase: &[u8]) -> io::Result<()> {
    if bundle_path.exists() {
        return Ok(());
    }
    if let Some(parent) = bundle_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    run_hdiutil_with_passphrase(
        &[
            "create",
            "-size",
            &format!("{size_mb}m"),
            "-fs",
            "APFS",
            "-encryption",
            "AES-256",
            "-type",
            "SPARSEBUNDLE",
            "-volname",
            "ClaveDisk",
            "-nospotlight",
            "-stdinpass",
        ],
        bundle_path,
        passphrase,
    )
}

/// `hdiutil attach -mountpoint` creates the mount directory itself (via `diskarbitrationd`, which
/// has the privilege a plain user doesn't: `/Volumes` is root-owned, `drwxr-xr-x` — `mkdir` under
/// it fails with EACCES even though attaching a disk image there is ordinary, unprivileged user
/// activity). Do **not** pre-create `mount_point`; that would just fail before hdiutil ever runs.
fn attach(bundle_path: &Path, mount_point: &Path, passphrase: &[u8]) -> io::Result<()> {
    run_hdiutil_with_passphrase(
        &[
            "attach",
            "-nobrowse",
            "-mountpoint",
            mount_point.to_str().expect("utf8 mount point"),
            "-stdinpass",
        ],
        bundle_path,
        passphrase,
    )
}

fn detach(mount_point: &Path) -> io::Result<()> {
    let out = Command::new("hdiutil")
        .args(["detach", mount_point.to_str().expect("utf8 mount point")])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "hdiutil detach failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn is_attached(mount_point: &Path) -> bool {
    Command::new("diskutil")
        .args(["info", mount_point.to_str().unwrap_or_default()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub struct MacVolumeMount {
    container: u128,
    bundle_path: PathBuf,
    mount_point: Mutex<Option<PathBuf>>,
}

impl MacVolumeMount {
    pub fn new(container: u128, bundle_path: impl Into<PathBuf>) -> Self {
        Self {
            container,
            bundle_path: bundle_path.into(),
            mount_point: Mutex::new(None),
        }
    }

    /// The container id this mount targets — the daemon matches it against a gateway wipe
    /// command so a wipe meant for another device can't destroy this one (mirrors
    /// `clave_volume::ClaveVolume::container_id`).
    pub fn container_id(&self) -> u128 {
        self.container
    }

    /// Idempotent: if `mount_point` is *already* a live volume — including from a previous process
    /// (e.g. a second `cargo run` while an earlier run's mount is still up, so this instance's own
    /// `mount_point` state starts `None`) — this just adopts it instead of re-running `hdiutil`,
    /// which would otherwise fail with "mount point busy".
    pub fn attach(&self, mount_point: impl Into<PathBuf>) -> PResult<()> {
        let mount_point = mount_point.into();
        if is_attached(&mount_point) {
            *self.mount_point.lock().expect("mount lock poisoned") = Some(mount_point);
            return Ok(());
        }
        let passphrase = passphrase_for(self.container).map_err(io_err)?;
        create_if_missing(&self.bundle_path, configured_size_mb(), &passphrase).map_err(io_err)?;
        attach(&self.bundle_path, &mount_point, &passphrase).map_err(io_err)?;
        *self.mount_point.lock().expect("mount lock poisoned") = Some(mount_point);
        Ok(())
    }

    pub fn detach(&self) -> PResult<()> {
        let mut guard = self.mount_point.lock().expect("mount lock poisoned");
        if let Some(mp) = guard.take() {
            detach(&mp).map_err(io_err)?;
        }
        Ok(())
    }
}

/// A not-yet-configured placeholder (container `0`, an unused path) — `MacPlatform::new` starts
/// here so its tests never touch `hdiutil`/Keychain; `MacPlatform::configure_volume` replaces it
/// with a real target before a lab `main.rs` calls [`MacVolumeMount::attach`].
impl Default for MacVolumeMount {
    fn default() -> Self {
        Self::new(
            0,
            std::env::temp_dir().join("clave-disk-unconfigured.sparsebundle"),
        )
    }
}

fn io_err(e: io::Error) -> PlatformError {
    PlatformError::Io(e.to_string())
}

impl VolumeMount for MacVolumeMount {
    fn is_mounted(&self) -> bool {
        match &*self.mount_point.lock().expect("mount lock poisoned") {
            Some(mp) => is_attached(mp),
            None => false,
        }
    }

    fn mount_point(&self) -> Option<String> {
        self.mount_point
            .lock()
            .expect("mount lock poisoned")
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn request_wipe(&self) -> PResult<()> {
        self.detach()?;
        // Delete both possible passphrase forms — whichever `passphrase_for` actually used (SE
        // sealing when signed, plain Keychain when not) is now unrecoverable; deleting the other
        // (never provisioned) is the same idempotent no-op `KeyStore::destroy` documents.
        keychain_delete(&se_sealed_account(self.container));
        keychain_delete(&passphrase_account(self.container));
        if self.bundle_path.exists() {
            std::fs::remove_dir_all(&self.bundle_path).map_err(io_err)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_container() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        (std::process::id() as u128) << 32 | n as u128
    }

    fn tmp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "clave-volume-test-{}-{}-{name}",
            std::process::id(),
            unique_container()
        ))
    }

    #[test]
    fn not_mounted_before_attach() {
        let vol = MacVolumeMount::new(
            unique_container(),
            tmp_dir("bundle1").with_extension("sparsebundle"),
        );
        assert!(!vol.is_mounted());
        assert_eq!(vol.mount_point(), None);
    }

    #[test]
    fn attach_creates_mounts_and_persists_data_across_detach_reattach() {
        let container = unique_container();
        let bundle = tmp_dir("bundle2").with_extension("sparsebundle");
        let mount_point = tmp_dir("mnt2");
        let vol = MacVolumeMount::new(container, &bundle);

        vol.attach(&mount_point).expect("attach");
        assert!(vol.is_mounted());
        assert_eq!(vol.mount_point().as_deref(), mount_point.to_str());

        let marker = mount_point.join("clave-test-marker.txt");
        std::fs::write(&marker, b"hello from the encrypted volume").expect("write inside mount");

        vol.detach().expect("detach");
        assert!(!vol.is_mounted());

        vol.attach(&mount_point).expect("re-attach");
        let got = std::fs::read(&marker).expect("read back after re-attach");
        assert_eq!(got, b"hello from the encrypted volume");

        vol.detach().expect("final detach");
        let _ = std::fs::remove_dir_all(&bundle);
    }

    #[test]
    fn request_wipe_detaches_deletes_keychain_item_and_removes_bundle() {
        let container = unique_container();
        let bundle = tmp_dir("bundle3").with_extension("sparsebundle");
        let mount_point = tmp_dir("mnt3");
        let vol = MacVolumeMount::new(container, &bundle);
        vol.attach(&mount_point).expect("attach");

        vol.request_wipe().expect("wipe");

        assert!(!vol.is_mounted(), "wipe must unmount");
        assert!(!bundle.exists(), "wipe must remove the container blob");
        assert!(
            keychain_get(&passphrase_account(container)).is_none(),
            "wipe must crypto-shred the Keychain passphrase"
        );
    }

    #[test]
    fn wipe_before_any_attach_is_a_safe_noop() {
        let vol = MacVolumeMount::new(
            unique_container(),
            tmp_dir("bundle4").with_extension("sparsebundle"),
        );
        assert!(vol.request_wipe().is_ok());
    }
}
