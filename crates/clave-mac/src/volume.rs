use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use clave_platform::{PResult, PlatformError, VolumeMount};
use zeroize::Zeroizing;

use crate::se_seal::{Passphrase, SEALED_LEN};

const KEYCHAIN_SERVICE: &str = "com.clave.volume";

const DEFAULT_SIZE_MB: u64 = 65_536;
const MIN_SIZE_MB: u64 = 512;

fn configured_size_mb() -> u64 {
    std::env::var("CLAVE_DISK_SIZE_MB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SIZE_MB)
        .max(MIN_SIZE_MB)
}

fn key_account(container: u128) -> String {
    format!("sparsebundle-key-{container:032x}")
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

enum StoredKey {
    Sealed(Box<[u8; SEALED_LEN]>),
    Plain(Passphrase),
}

const TAG_SEALED: u8 = 1;
const TAG_PLAIN: u8 = 2;

fn load_stored(container: u128) -> io::Result<Option<StoredKey>> {
    let Some(blob) = keychain_get(&key_account(container)) else {
        return Ok(None);
    };
    let (tag, payload) = blob
        .split_first()
        .ok_or_else(|| io::Error::other("stored passphrase blob is empty"))?;
    match *tag {
        TAG_SEALED => {
            let sealed: [u8; SEALED_LEN] = payload
                .try_into()
                .map_err(|_| io::Error::other("stored sealed passphrase has the wrong length"))?;
            Ok(Some(StoredKey::Sealed(Box::new(sealed))))
        }
        TAG_PLAIN => {
            let plain: [u8; 64] = payload
                .try_into()
                .map_err(|_| io::Error::other("stored plain passphrase has the wrong length"))?;
            Ok(Some(StoredKey::Plain(Zeroizing::new(plain))))
        }
        other => Err(io::Error::other(format!(
            "stored passphrase blob has an unknown custody tag ({other})"
        ))),
    }
}

fn store(container: u128, key: &StoredKey) -> io::Result<()> {
    let mut blob = Zeroizing::new(Vec::with_capacity(1 + SEALED_LEN));
    match key {
        StoredKey::Sealed(sealed) => {
            blob.push(TAG_SEALED);
            blob.extend_from_slice(sealed.as_slice());
        }
        StoredKey::Plain(plain) => {
            blob.push(TAG_PLAIN);
            blob.extend_from_slice(plain.as_slice());
        }
    }
    keychain_set(&key_account(container), &blob)
}

fn unwrap_stored(key: StoredKey) -> io::Result<Passphrase> {
    match key {
        StoredKey::Plain(p) => Ok(p),
        StoredKey::Sealed(sealed) => {
            let se_key = crate::se_seal::SeSealingKey::load()?.ok_or_else(|| {
                io::Error::other(
                    "this container's passphrase is sealed to the Secure Enclave, but no SE key is \
                     reachable from this binary. Run the signed ClaveDaemonHost app. Refusing to \
                     mint a replacement passphrase (it could never open the existing container).",
                )
            })?;
            crate::se_seal::open(&se_key, &sealed)
        }
    }
}

fn mint_passphrase() -> io::Result<Passphrase> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut entropy[..])
        .map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    let mut out = Zeroizing::new([0u8; 64]);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in entropy.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    Ok(out)
}

fn passphrase_for_existing(container: u128) -> io::Result<Passphrase> {
    match load_stored(container)? {
        Some(key) => unwrap_stored(key),
        None => Err(io::Error::other(
            "the Clave Disk container exists on disk but its passphrase is not in the Keychain. \
             Refusing to mint a new one (it could never open this container). Delete the container \
             to start fresh, or restore the Keychain item.",
        )),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Custody {
    RequireHardware,
    AllowPlainFallback,
}

fn passphrase_for_new(container: u128, custody: Custody) -> io::Result<Passphrase> {
    if let Some(key) = load_stored(container)? {
        return unwrap_stored(key);
    }

    let passphrase = mint_passphrase()?;
    let stored = match (crate::se_seal::SeSealingKey::load_or_generate(), custody) {
        (Ok(se_key), _) => {
            let se_pub = se_key.public_key_bytes()?;
            StoredKey::Sealed(Box::new(crate::se_seal::seal(&se_pub, &passphrase)?))
        }
        (Err(e), Custody::RequireHardware) => {
            return Err(io::Error::other(format!(
                "this Clave Disk must be sealed to the Secure Enclave, which is unreachable ({e}). \
                 Refusing to provision a software-only disk in its place."
            )))
        }
        (Err(e), Custody::AllowPlainFallback) => {
            eprintln!(
                "clave-mac: Secure Enclave unavailable ({e}) — provisioning this Clave Disk with a \
                 plain Keychain passphrase (DevelopmentOnly, not hardware-rooted)."
            );
            StoredKey::Plain(passphrase.clone())
        }
    };
    store(container, &stored)?;
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

fn create(bundle_path: &Path, size_mb: u64, passphrase: &[u8]) -> io::Result<()> {
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
    custody: Custody,
    mount_point: Mutex<Option<PathBuf>>,
}

impl MacVolumeMount {
    pub fn new(container: u128, bundle_path: impl Into<PathBuf>, custody: Custody) -> Self {
        Self {
            container,
            bundle_path: bundle_path.into(),
            custody,
            mount_point: Mutex::new(None),
        }
    }

    pub fn container_id(&self) -> u128 {
        self.container
    }

    pub fn attach(&self, mount_point: impl Into<PathBuf>) -> PResult<()> {
        let mount_point = mount_point.into();
        if is_attached(&mount_point) {
            *self.mount_point.lock().expect("mount lock poisoned") = Some(mount_point);
            return Ok(());
        }

        let passphrase = if self.bundle_path.exists() {
            passphrase_for_existing(self.container).map_err(io_err)?
        } else {
            let passphrase = passphrase_for_new(self.container, self.custody).map_err(io_err)?;
            create(&self.bundle_path, configured_size_mb(), &passphrase[..]).map_err(io_err)?;
            passphrase
        };

        attach(&self.bundle_path, &mount_point, &passphrase[..]).map_err(io_err)?;
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

impl Default for MacVolumeMount {
    fn default() -> Self {
        Self::new(
            0,
            std::env::temp_dir().join("clave-disk-unconfigured.sparsebundle"),
            Custody::AllowPlainFallback,
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
        keychain_delete(&key_account(self.container));
        if self.bundle_path.exists() {
            std::fs::remove_dir_all(&self.bundle_path).map_err(io_err)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVolume {
        container: u128,
        bundle: PathBuf,
        mount_point: PathBuf,
        vol: MacVolumeMount,
    }

    impl TestVolume {
        fn new(name: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let container = (std::process::id() as u128) << 32 | n as u128;

            let base = std::env::temp_dir().join(format!(
                "clave-volume-test-{}-{n}-{name}",
                std::process::id()
            ));
            let bundle = base.with_extension("sparsebundle");
            let mount_point = base.with_extension("mnt");
            let vol = MacVolumeMount::new(container, &bundle, Custody::AllowPlainFallback);
            Self {
                container,
                bundle,
                mount_point,
                vol,
            }
        }

        fn reopen(&self) -> MacVolumeMount {
            MacVolumeMount::new(self.container, &self.bundle, Custody::AllowPlainFallback)
        }

        fn reopen_requiring_hardware(&self) -> MacVolumeMount {
            MacVolumeMount::new(self.container, &self.bundle, Custody::RequireHardware)
        }
    }

    impl Drop for TestVolume {
        fn drop(&mut self) {
            let _ = self.vol.detach();
            let _ = detach(&self.mount_point);
            keychain_delete(&key_account(self.container));
            let _ = std::fs::remove_dir_all(&self.bundle);
            let _ = std::fs::remove_dir_all(&self.mount_point);
        }
    }

    #[test]
    fn not_mounted_before_attach() {
        let t = TestVolume::new("not-mounted");
        assert!(!t.vol.is_mounted());
        assert_eq!(t.vol.mount_point(), None);
    }

    #[test]
    fn attach_creates_mounts_and_persists_data_across_detach_reattach() {
        let t = TestVolume::new("roundtrip");

        t.vol.attach(&t.mount_point).expect("attach");
        assert!(t.vol.is_mounted());
        assert_eq!(t.vol.mount_point().as_deref(), t.mount_point.to_str());

        let marker = t.mount_point.join("clave-test-marker.txt");
        std::fs::write(&marker, b"hello from the encrypted volume").expect("write inside mount");

        t.vol.detach().expect("detach");
        assert!(!t.vol.is_mounted());

        t.vol.attach(&t.mount_point).expect("re-attach");
        let got = std::fs::read(&marker).expect("read back after re-attach");
        assert_eq!(got, b"hello from the encrypted volume");

        t.vol.detach().expect("final detach");
    }

    #[test]
    fn reopening_an_existing_container_reuses_its_stored_passphrase() {
        let t = TestVolume::new("reopen");

        t.vol.attach(&t.mount_point).expect("first attach creates");
        let marker = t.mount_point.join("provisioned-by-the-first-mount.txt");
        std::fs::write(&marker, b"work data").expect("write inside mount");
        t.vol.detach().expect("detach");

        let second = t.reopen();
        second
            .attach(&t.mount_point)
            .expect("a second mount must open the existing container, not re-provision it");
        assert_eq!(
            std::fs::read(&marker).expect("data survives"),
            b"work data",
            "the second mount must decrypt what the first wrote"
        );
        second.detach().expect("detach");
    }

    #[test]
    fn existing_container_without_a_stored_passphrase_refuses_to_mount() {
        let t = TestVolume::new("orphaned");
        t.vol.attach(&t.mount_point).expect("attach creates");
        t.vol.detach().expect("detach");

        keychain_delete(&key_account(t.container));

        let err = t
            .reopen()
            .attach(&t.mount_point)
            .expect_err("must refuse to mount a container whose passphrase is missing");
        match err {
            PlatformError::Io(msg) => assert!(
                msg.contains("Refusing to mint"),
                "expected a fail-closed refusal, got: {msg}"
            ),
            other => panic!("expected an Io refusal, got {other:?}"),
        }
    }

    #[test]
    fn request_wipe_detaches_deletes_keychain_item_and_removes_bundle() {
        let t = TestVolume::new("wipe");
        t.vol.attach(&t.mount_point).expect("attach");

        t.vol.request_wipe().expect("wipe");

        assert!(!t.vol.is_mounted(), "wipe must unmount");
        assert!(!t.bundle.exists(), "wipe must remove the container blob");
        assert!(
            load_stored(t.container)
                .expect("keychain readable")
                .is_none(),
            "wipe must crypto-shred the Keychain passphrase"
        );
    }

    #[test]
    fn wipe_before_any_attach_is_a_safe_noop() {
        let t = TestVolume::new("wipe-noop");
        assert!(t.vol.request_wipe().is_ok());
    }

    #[test]
    fn require_hardware_refuses_to_provision_without_the_secure_enclave() {
        let t = TestVolume::new("require-hw");
        let err = t
            .reopen_requiring_hardware()
            .attach(&t.mount_point)
            .expect_err("must refuse to provision a plain disk when hardware custody is required");
        match err {
            PlatformError::Io(msg) => assert!(
                msg.contains("Refusing to provision a software-only disk"),
                "expected a hardware-custody refusal, got: {msg}"
            ),
            other => panic!("expected an Io refusal, got {other:?}"),
        }
        assert!(
            !t.bundle.exists(),
            "no container may be created when hardware custody cannot be honored"
        );
        assert!(
            load_stored(t.container)
                .expect("keychain readable")
                .is_none(),
            "no passphrase may be stored when hardware custody cannot be honored"
        );
    }

    #[test]
    fn a_stored_blob_with_an_unknown_custody_tag_is_rejected() {
        let t = TestVolume::new("bad-tag");
        keychain_set(&key_account(t.container), &[0xFF, 1, 2, 3]).expect("seed a bogus blob");
        assert!(
            load_stored(t.container).is_err(),
            "an unrecognized custody tag must fail closed, not be guessed at"
        );
    }
}
