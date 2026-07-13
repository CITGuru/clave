use std::io;
use std::path::Path;
use std::process::Command;

const LOGIN_KEYCHAIN: &str = "login.keychain-db";
const PASS_FILE: &str = ".clave-keychain-pass";

pub fn provision_contained_keychain(home: &Path) -> io::Result<()> {
    let keychains_dir = home.join("Library/Keychains");
    std::fs::create_dir_all(&keychains_dir)?;
    let keychain = keychains_dir.join(LOGIN_KEYCHAIN);
    let pass_path = home.join(PASS_FILE);

    let passphrase = if keychain.exists() {
        read_passphrase(&pass_path)?
    } else {
        let pass = generate_passphrase();
        write_passphrase(&pass_path, &pass)?;
        create_keychain(home, &keychain, &pass)?;
        pass
    };

    unlock_keychain(home, &keychain, &passphrase)?;
    let _ = security_cmd(home)
        .args([
            "set-keychain-settings",
            "-lut",
            "86400",
            path_arg(&keychain)?.as_ref(),
        ])
        .status();
    Ok(())
}

fn security_cmd(home: &Path) -> Command {
    let mut cmd = Command::new("security");
    cmd.env("HOME", home);
    cmd
}

fn path_arg(path: &Path) -> io::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 path"))
}

fn generate_passphrase() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("OS RNG");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_passphrase(path: &Path, pass: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(pass.as_bytes())?;
        return Ok(());
    }
    #[cfg(not(unix))]
    std::fs::write(path, pass.as_bytes())
}

fn read_passphrase(path: &Path) -> io::Result<String> {
    std::fs::read_to_string(path).map(|s| s.trim().to_string())
}

fn create_keychain(home: &Path, path: &Path, pass: &str) -> io::Result<()> {
    let status = security_cmd(home)
        .arg("create-keychain")
        .arg("-p")
        .arg(pass)
        .arg(path_arg(path)?)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "security create-keychain failed for {}",
            path.display()
        )))
    }
}

fn unlock_keychain(home: &Path, path: &Path, pass: &str) -> io::Result<()> {
    let status = security_cmd(home)
        .arg("unlock-keychain")
        .arg("-u")
        .arg("-p")
        .arg(pass)
        .arg(path_arg(path)?)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "security unlock-keychain failed for {}",
            path.display()
        )))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn personal_search_list() -> String {
        let out = Command::new("security")
            .args(["list-keychains", "-d", "user"])
            .output()
            .expect("run security list-keychains");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn provisions_a_clave_owned_login_keychain_under_home() {
        let home = std::env::temp_dir().join(format!("clave-kc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();

        provision_contained_keychain(&home).unwrap();
        let kc = home.join("Library/Keychains").join(LOGIN_KEYCHAIN);
        assert!(kc.is_file());
        assert!(home.join(PASS_FILE).is_file());

        provision_contained_keychain(&home).unwrap();
        assert!(!personal_search_list().contains(kc.to_str().unwrap()));

        let _ = std::fs::remove_dir_all(&home);
    }
}
