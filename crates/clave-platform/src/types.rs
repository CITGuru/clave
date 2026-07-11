//! Portable value types shared across the policy brain and every OS adapter.
//!
//! These are deliberately small, `Copy` where possible, and `serde`-serializable so they can
//! also cross the IPC boundary (`clave-ipc`) unchanged.

use serde::{Deserialize, Serialize};

/// Authoritative process identity.
///
/// The bare OS process id is **not** sufficient — it is reused. We always carry a
/// disambiguator so a recycled id cannot impersonate a previous (possibly supervised)
/// process:
///
/// * **Windows** — `pid` + process *create time* (unique for the life of the boot).
/// * **macOS** — the kernel `audit_token` (8 × `u32`), which the Endpoint Security
///   framework supplies on every event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcId {
    Windows { pid: u32, create_time: u64 },
    Macos { audit_token: [u32; 8] },
}

impl ProcId {
    /// Convenience constructor for the Windows form.
    pub fn windows(pid: u32, create_time: u64) -> Self {
        ProcId::Windows { pid, create_time }
    }
    /// Convenience constructor for the macOS form.
    pub fn macos(audit_token: [u32; 8]) -> Self {
        ProcId::Macos { audit_token }
    }
}

/// The two halves of the machine. `Work` == supervised / in-enclave; `Personal` ==
/// unsupervised / out-of-enclave. Personal resources are never instrumented or logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Zone {
    Work,
    Personal,
}

/// Clipboard / data-transfer payload classes, at the granularity policy cares about.
///
/// Splitting by class lets a policy permit low-risk text across the boundary while still
/// blocking files and images.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClipFormat {
    PlainText,
    RichText,
    Html,
    Image,
    /// File references / promises (`CF_HDROP`, file-promise, `NSFilenamesPboardType`).
    Files,
    Other,
}

impl ClipFormat {
    /// Every clipboard class, for exhaustive policy/test iteration.
    pub const ALL: [ClipFormat; 6] = [
        ClipFormat::PlainText,
        ClipFormat::RichText,
        ClipFormat::Html,
        ClipFormat::Image,
        ClipFormat::Files,
        ClipFormat::Other,
    ];
}

/// Opaque per-OS window handle, used by the overlay / screen-guard subsystems.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WindowId(pub u64);

/// Straight 8-bit RGBA, for the Clave Edge frame color.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rgba {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Rgba {
    /// The default Clave Edge color (a calm blue), overridable by policy.
    pub const CLAVE_EDGE: Rgba = Rgba {
        r: 0x1E,
        g: 0x6F,
        b: 0xD6,
        a: 0xFF,
    };
}

/// The raw action an enforcement point can take on a single operation.
///
/// `Verdict` (in `clave-core`) pairs this with a `Reason` for audit/explainability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Permit unchanged.
    Allow,
    /// Block entirely.
    Deny,
    /// Permit, but overlay a tamper-evident watermark (screen capture).
    Watermark,
    /// Defer to the user with an explained prompt.
    Prompt,
    /// Permit, but strip/normalize the payload first (e.g. personal→work paste).
    Sanitize,
}

/// Where a network flow should egress. Returned by the split-tunnel classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Route {
    /// Through the corporate gateway (static egress IP) — work flows.
    Tunnel,
    /// Straight to the user's ISP — personal flows; never seen by the company.
    Direct,
    /// Refused (work egress allowlist).
    Block,
}
