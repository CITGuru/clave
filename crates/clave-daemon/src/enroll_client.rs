use clave_core::UnixTime;
use clave_proto::{EnrollmentGrant, SignedCommand, TenantId, TlsCredentials, WrappedVolumeKey};
use serde::Deserialize;

use crate::enroll::{DeviceEnrollment, DeviceVolumeKey, EnrollError};
use crate::EnrollmentRecord;

#[derive(Clone, Debug, Deserialize)]
pub struct DeviceAuth {
    pub user_code: String,
    pub verification_uri: String,
    pub device_code: String,
}

pub enum PollStatus {
    Pending,
    Approved,
}

pub enum CompletionStatus {
    Pending,
    Approved {
        policy: Option<SignedCommand>,
        volume_key: Option<WrappedVolumeKey>,
        tls: Option<Box<TlsCredentials>>,
    },
}

pub struct CompleteRequest {
    pub workspace: u64,
    pub device_code: String,
    pub device_pubkey: String,
    pub device_wrapping_key: Option<String>,
}

pub struct EnrollmentConfig {
    pub workspace: u64,
    pub tenant: TenantId,
    pub pinned_tenant_key: [u8; 32],
    pub device_identity_pubkey: [u8; 32],
    pub device_wrapping_key: [u8; 32],
    pub device_signing_seed: [u8; 32],
    pub max_polls: usize,
}

#[derive(Debug)]
pub enum EnrollClientError {
    Transport(String),
    TimedOut,
    NotApproved,
    NoPolicy,
    Accept(EnrollError),
}

impl std::fmt::Display for EnrollClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollClientError::Transport(e) => write!(f, "enrollment transport error: {e}"),
            EnrollClientError::TimedOut => f.write_str("enrollment timed out waiting for approval"),
            EnrollClientError::NotApproved => f.write_str("enrollment was not approved"),
            EnrollClientError::NoPolicy => f.write_str("enrollment grant carried no policy"),
            EnrollClientError::Accept(e) => write!(f, "enrollment grant rejected: {e:?}"),
        }
    }
}

impl std::error::Error for EnrollClientError {}

pub trait EnrollmentTransport {
    fn start(&self, workspace: u64) -> Result<DeviceAuth, EnrollClientError>;
    fn poll(&self, workspace: u64, device_code: &str) -> Result<PollStatus, EnrollClientError>;
    fn complete(&self, req: CompleteRequest) -> Result<CompletionStatus, EnrollClientError>;
}

pub struct EnrollmentClient<T> {
    transport: T,
}

impl<T: EnrollmentTransport> EnrollmentClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn enroll(
        &self,
        cfg: &EnrollmentConfig,
        on_prompt: impl Fn(&DeviceAuth),
        wait: impl Fn(),
        now: UnixTime,
    ) -> Result<EnrollmentRecord, EnrollClientError> {
        let auth = self.transport.start(cfg.workspace)?;
        on_prompt(&auth);

        let mut polls = 0;
        loop {
            match self.transport.poll(cfg.workspace, &auth.device_code)? {
                PollStatus::Approved => break,
                PollStatus::Pending => {
                    polls += 1;
                    if polls >= cfg.max_polls {
                        return Err(EnrollClientError::TimedOut);
                    }
                    wait();
                }
            }
        }

        let completion = self.transport.complete(CompleteRequest {
            workspace: cfg.workspace,
            device_code: auth.device_code.clone(),
            device_pubkey: hex32(&cfg.device_identity_pubkey),
            device_wrapping_key: Some(hex32(&cfg.device_wrapping_key)),
        })?;

        let (policy, volume_key, tls) = match completion {
            CompletionStatus::Approved {
                policy,
                volume_key,
                tls,
            } => (policy, volume_key, tls),
            CompletionStatus::Pending => return Err(EnrollClientError::NotApproved),
        };

        let grant = EnrollmentGrant::new(policy, volume_key.clone());
        let enrollment = DeviceEnrollment::new(
            cfg.tenant,
            cfg.pinned_tenant_key,
            DeviceVolumeKey::Symmetric(cfg.device_wrapping_key),
        );
        let accepted = enrollment
            .accept(&grant, now)
            .map_err(EnrollClientError::Accept)?;
        let policy = accepted
            .policy()
            .cloned()
            .ok_or(EnrollClientError::NoPolicy)?;

        Ok(EnrollmentRecord {
            tenant: cfg.tenant,
            pinned_tenant_key: cfg.pinned_tenant_key,
            policy,
            volume_key,
            device_signing_seed: cfg.device_signing_seed,
            device_kek: Some(cfg.device_wrapping_key),
            tls: tls.map(|b| *b),
        })
    }
}

pub fn open_url(url: &str) {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    let _ = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0x0f));
    }
    s
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

#[cfg(feature = "enroll-http")]
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(feature = "enroll-http")]
pub fn run_enroll_cli(args: &[String]) -> Result<(), String> {
    use crate::EnrollmentStore;
    use rand::RngCore;

    let mut gateway = None;
    let mut workspace = None;
    let mut tenant = None;
    let mut tenant_key_hex = None;
    let mut state_dir = None;
    let mut tag = "dev".to_string();

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" => gateway = it.next().cloned(),
            "--workspace" => workspace = it.next().and_then(|s| s.parse::<u64>().ok()),
            "--tenant" => tenant = it.next().and_then(|s| s.parse::<u64>().ok()),
            "--tenant-key" => tenant_key_hex = it.next().cloned(),
            "--state-dir" => state_dir = it.next().cloned(),
            "--tag" => {
                if let Some(t) = it.next() {
                    tag = t.clone();
                }
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }

    let gateway = gateway.ok_or("--gateway <url> is required")?;
    let workspace = workspace.ok_or("--workspace <id> is required")?;
    let tenant = tenant.ok_or("--tenant <id> is required")?;
    let pinned_tenant_key = parse_hex32(&tenant_key_hex.ok_or("--tenant-key <64 hex> is required")?)
        .ok_or("--tenant-key must be 64 hex chars")?;
    let state_dir =
        std::path::PathBuf::from(state_dir.ok_or("--state-dir <path> is required")?);

    let mut rng = rand::thread_rng();
    let mut device_wrapping_key = [0u8; 32];
    let mut device_signing_seed = [0u8; 32];
    let mut device_identity_pubkey = [0u8; 32];
    rng.fill_bytes(&mut device_wrapping_key);
    rng.fill_bytes(&mut device_signing_seed);
    rng.fill_bytes(&mut device_identity_pubkey);

    let cfg = EnrollmentConfig {
        workspace,
        tenant: TenantId(tenant),
        pinned_tenant_key,
        device_identity_pubkey,
        device_wrapping_key,
        device_signing_seed,
        max_polls: 150,
    };

    let transport = HttpEnrollmentTransport::new(&gateway)?;
    let client = EnrollmentClient::new(transport);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let record = client
        .enroll(
            &cfg,
            |auth| {
                println!(
                    "clave enroll: open {} and enter code {}",
                    auth.verification_uri, auth.user_code
                );
                open_url(&auth.verification_uri);
            },
            || std::thread::sleep(std::time::Duration::from_secs(3)),
            now,
        )
        .map_err(|e| e.to_string())?;

    let store = crate::FileEnrollmentStore::new(state_dir.join(format!("enrollment-{tag}.bin")));
    store.save(&record);
    println!(
        "clave enroll: enrolled tenant {:?}, policy v{} — saved to {}",
        record.tenant,
        record.policy.version,
        state_dir.display()
    );
    Ok(())
}

#[cfg(not(feature = "enroll-http"))]
pub fn run_enroll_cli(_args: &[String]) -> Result<(), String> {
    Err("enroll needs the HTTP transport: rebuild with `--features enroll-http`".to_string())
}

impl From<EnrollClientError> for String {
    fn from(e: EnrollClientError) -> Self {
        e.to_string()
    }
}

#[cfg(feature = "enroll-http")]
mod http {
    use super::*;
    use serde::Serialize;

    #[derive(Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    enum PollResponse {
        Pending,
        Approved {},
    }

    #[derive(Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    enum CompletionResponse {
        Pending,
        Approved {
            #[serde(default)]
            policy: Option<SignedCommand>,
            #[serde(default)]
            volume_key: Option<WrappedVolumeKey>,
            #[serde(default)]
            tls: Option<Box<TlsCredentials>>,
        },
    }

    #[derive(Serialize)]
    struct StartBody {
        workspace: u64,
    }

    #[derive(Serialize)]
    struct PollBody<'a> {
        workspace: u64,
        device_code: &'a str,
    }

    #[derive(Serialize)]
    struct CompleteBody {
        workspace: u64,
        device_code: String,
        device_pubkey: String,
        device_wrapping_key: Option<String>,
    }

    pub struct HttpEnrollmentTransport {
        base_url: String,
        client: reqwest::blocking::Client,
    }

    impl HttpEnrollmentTransport {
        pub fn new(base_url: impl Into<String>) -> Result<Self, EnrollClientError> {
            let client = reqwest::blocking::Client::builder()
                .build()
                .map_err(|e| EnrollClientError::Transport(e.to_string()))?;
            Ok(Self {
                base_url: base_url.into().trim_end_matches('/').to_string(),
                client,
            })
        }

        fn post<B: Serialize, R: for<'de> Deserialize<'de>>(
            &self,
            path: &str,
            body: &B,
        ) -> Result<R, EnrollClientError> {
            let resp = self
                .client
                .post(format!("{}{path}", self.base_url))
                .json(body)
                .send()
                .map_err(|e| EnrollClientError::Transport(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(EnrollClientError::Transport(format!(
                    "{path} returned HTTP {}",
                    resp.status().as_u16()
                )));
            }
            resp.json::<R>()
                .map_err(|e| EnrollClientError::Transport(e.to_string()))
        }
    }

    impl EnrollmentTransport for HttpEnrollmentTransport {
        fn start(&self, workspace: u64) -> Result<DeviceAuth, EnrollClientError> {
            self.post("/enroll/start", &StartBody { workspace })
        }

        fn poll(&self, workspace: u64, device_code: &str) -> Result<PollStatus, EnrollClientError> {
            let r: PollResponse = self.post(
                "/enroll/poll",
                &PollBody {
                    workspace,
                    device_code,
                },
            )?;
            Ok(match r {
                PollResponse::Pending => PollStatus::Pending,
                PollResponse::Approved {} => PollStatus::Approved,
            })
        }

        fn complete(&self, req: CompleteRequest) -> Result<CompletionStatus, EnrollClientError> {
            let r: CompletionResponse = self.post(
                "/enroll/complete",
                &CompleteBody {
                    workspace: req.workspace,
                    device_code: req.device_code,
                    device_pubkey: req.device_pubkey,
                    device_wrapping_key: req.device_wrapping_key,
                },
            )?;
            Ok(match r {
                CompletionResponse::Pending => CompletionStatus::Pending,
                CompletionResponse::Approved {
                    policy,
                    volume_key,
                    tls,
                } => {
                    CompletionStatus::Approved {
                        policy,
                        volume_key,
                        tls,
                    }
                }
            })
        }
    }
}

#[cfg(feature = "enroll-http")]
pub use http::HttpEnrollmentTransport;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EnrollmentStore;
    use clave_proto::{GatewayCommand, GatewaySigningKey};
    use clave_volume::{Dek, Kek, DEK_LEN};
    use std::cell::Cell;

    const TENANT: TenantId = TenantId(1);

    struct FakeGateway {
        signer: GatewaySigningKey,
        wrapping_key: [u8; 32],
        pending_polls: Cell<usize>,
    }

    impl FakeGateway {
        fn new(wrapping_key: [u8; 32], pending_polls: usize) -> Self {
            Self {
                signer: GatewaySigningKey::from_seed(TENANT, [0x5A; 32]),
                wrapping_key,
                pending_polls: Cell::new(pending_polls),
            }
        }

        fn pinned_key(&self) -> [u8; 32] {
            self.signer.public_key()
        }
    }

    impl EnrollmentTransport for FakeGateway {
        fn start(&self, _workspace: u64) -> Result<DeviceAuth, EnrollClientError> {
            Ok(DeviceAuth {
                user_code: "WXYZ-1234".into(),
                verification_uri: "https://gateway.test/activate".into(),
                device_code: "dev-code".into(),
            })
        }

        fn poll(&self, _workspace: u64, _code: &str) -> Result<PollStatus, EnrollClientError> {
            let left = self.pending_polls.get();
            if left == 0 {
                Ok(PollStatus::Approved)
            } else {
                self.pending_polls.set(left - 1);
                Ok(PollStatus::Pending)
            }
        }

        fn complete(&self, _req: CompleteRequest) -> Result<CompletionStatus, EnrollClientError> {
            let mut bundle = clave_core::PolicyBundle::restrictive_default();
            bundle.version = 5;
            let policy = self
                .signer
                .sign(1, 1_000, GatewayCommand::UpdatePolicy(Box::new(bundle)));
            let wrapped = Kek::from_bytes(self.wrapping_key).wrap(&Dek::from_bytes([0xDE; DEK_LEN]));
            Ok(CompletionStatus::Approved {
                policy: Some(policy),
                volume_key: Some(WrappedVolumeKey {
                    container: 0xC1A5,
                    wrapped_dek: wrapped.as_bytes().to_vec(),
                    ephemeral_pub: None,
                }),
                tls: Some(Box::new(TlsCredentials {
                    ca_pem: b"ca".to_vec(),
                    cert_pem: b"cert".to_vec(),
                    key_pem: b"key".to_vec(),
                    server_name: "gateway.test".to_string(),
                    gateway_addr: "127.0.0.1:9443".to_string(),
                })),
            })
        }
    }

    fn config(gw: &FakeGateway, wrapping_key: [u8; 32]) -> EnrollmentConfig {
        EnrollmentConfig {
            workspace: 7,
            tenant: TENANT,
            pinned_tenant_key: gw.pinned_key(),
            device_identity_pubkey: [0x1D; 32],
            device_wrapping_key: wrapping_key,
            device_signing_seed: [0xD5; 32],
            max_polls: 10,
        }
    }

    #[test]
    fn enroll_polls_until_approved_then_accepts_the_grant() {
        let wrapping_key = [0x4B; 32];
        let gw = FakeGateway::new(wrapping_key, 2);
        let cfg = config(&gw, wrapping_key);
        let client = EnrollmentClient::new(gw);

        let prompted = Cell::new(false);
        let record = client
            .enroll(&cfg, |_| prompted.set(true), || {}, 1_000)
            .expect("enroll succeeds");

        assert!(prompted.get());
        assert_eq!(record.policy.version, 5);
        assert_eq!(record.device_kek, Some(wrapping_key));
        assert_eq!(record.tenant, TENANT);
        assert_eq!(
            record.tls.as_ref().map(|t| t.server_name.as_str()),
            Some("gateway.test"),
            "the delivered TLS credentials are stored on the record"
        );
        let (container, _dek) = record.open_volume(None, 1_000).expect("volume opens");
        assert_eq!(container, clave_volume::ContainerId(0xC1A5));
    }

    #[test]
    fn a_record_from_enroll_survives_the_store() {
        let wrapping_key = [0x4B; 32];
        let gw = FakeGateway::new(wrapping_key, 0);
        let cfg = config(&gw, wrapping_key);
        let client = EnrollmentClient::new(gw);
        let record = client.enroll(&cfg, |_| {}, || {}, 1_000).expect("enroll");

        let dir = std::env::temp_dir().join(format!("clave-enroll-client-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let store = crate::FileEnrollmentStore::new(dir.join("e.bin"));
        store.save(&record);
        assert_eq!(store.load().as_ref(), Some(&record));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_times_out_if_never_approved() {
        let wrapping_key = [0x4B; 32];
        let gw = FakeGateway::new(wrapping_key, 100);
        let mut cfg = config(&gw, wrapping_key);
        cfg.max_polls = 3;
        let client = EnrollmentClient::new(gw);
        let err = client.enroll(&cfg, |_| {}, || {}, 1_000).unwrap_err();
        assert!(matches!(err, EnrollClientError::TimedOut));
    }

    #[test]
    fn a_grant_signed_by_the_wrong_tenant_is_rejected() {
        let wrapping_key = [0x4B; 32];
        let gw = FakeGateway::new(wrapping_key, 0);
        let mut cfg = config(&gw, wrapping_key);
        cfg.pinned_tenant_key = GatewaySigningKey::from_seed(TENANT, [0x01; 32]).public_key();
        let client = EnrollmentClient::new(gw);
        let err = client.enroll(&cfg, |_| {}, || {}, 1_000).unwrap_err();
        assert!(matches!(err, EnrollClientError::Accept(_)));
    }
}
