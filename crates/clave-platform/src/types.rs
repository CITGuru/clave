use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcId {
    Windows { pid: u32, create_time: u64 },
    Macos { audit_token: [u32; 8] },
}

impl ProcId {
    pub fn windows(pid: u32, create_time: u64) -> Self {
        ProcId::Windows { pid, create_time }
    }
    pub fn macos(audit_token: [u32; 8]) -> Self {
        ProcId::Macos { audit_token }
    }

    pub fn pid(&self) -> u32 {
        match self {
            ProcId::Windows { pid, .. } => *pid,
            ProcId::Macos { audit_token } => audit_token[5],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Zone {
    Work,
    Personal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClipFormat {
    PlainText,
    RichText,
    Html,
    Image,
    Files,
    Other,
}

impl ClipFormat {
    pub const ALL: [ClipFormat; 6] = [
        ClipFormat::PlainText,
        ClipFormat::RichText,
        ClipFormat::Html,
        ClipFormat::Image,
        ClipFormat::Files,
        ClipFormat::Other,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WindowId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rgba {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Rgba {
    pub const CLAVE_EDGE: Rgba = Rgba {
        r: 0x1E,
        g: 0x6F,
        b: 0xD6,
        a: 0xFF,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
    Watermark,
    Prompt,
    Sanitize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Route {
    Tunnel,
    Direct,
    Block,
}
