//! # clave-volume — encrypted Clave Disk crypto core (Phase 3)
//!
//! The portable, OS-free heart of the encrypted volume — what the design doc calls "the
//! cleanest, most portable subsystem". Both OS adapters (a WinFsp encrypting filesystem on
//! Windows; an encrypted APFS volume / sparsebundle on macOS) sit on top of this one
//! implementation and one test surface:
//!
//! * [`XtsCipher`] — the **AES-256-XTS** block layer (tweak = sector index): the data plane.
//! * [`Dek`] / [`Kek`] / [`WrappedDek`] — the **KEK→DEK key hierarchy** and AES-KW (RFC 3394)
//!   wrapping. The DEK lives only in `zeroize`-on-drop memory while unlocked.
//! * [`KeyStore`] — the hardware-root seam (TPM / Secure Enclave) with an in-memory
//!   [`MemKeyStore`] double; **crypto-shred** is [`KeyStore::destroy`].
//! * [`BackingStore`] — the opaque-ciphertext container seam with a [`MemBacking`] double.
//! * [`ClaveVolume`] — the mount lifecycle: unlock / lock / sector read+write through XTS / the
//!   runtime access gate / crypto-shred **remote wipe**, all fail-closed.
//!
//! ## What needs more than this Mac
//!
//! Only the *mount* and the *hardware* are OS-specific: the WinFsp / APFS mount that exposes a
//! drive letter or `/Volumes/ClaveDisk`, and the TPM / Secure Enclave that backs [`KeyStore`].
//! Everything in this crate — confidentiality at rest, the key hierarchy, the
//! runtime access gate, and crypto-shred — is exercised by `cargo test` with no driver,
//! entitlement, or signing.
#![forbid(unsafe_code)]

mod container;
mod keys;
mod seal;
mod store;
mod volume;
mod xts;

pub use container::{BackingStore, ContainerId, ContainerMeta, MemBacking};
pub use keys::{Dek, Kek, WrappedDek, DEK_LEN, KEK_LEN, WRAPPED_DEK_LEN};
pub use seal::{open_dek, seal_dek, DeviceSealingKey, SealedDek};
pub use store::{KeyStore, MemKeyStore};
pub use volume::ClaveVolume;
pub use xts::{XtsCipher, SECTOR_SIZE};

/// Errors from the encrypted-volume core. Every variant is a **fail-closed** outcome — the
/// caller gets no plaintext. The OS adapter maps these onto `clave_platform::PlatformError` at
/// its boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeError {
    /// Caller is not in the work zone — denied even though the volume is mounted.
    AccessDenied,
    /// The volume is locked: no DEK in memory, so all I/O fails closed.
    Locked,
    /// The wrapped DEK was crypto-shredded or never provisioned — unrecoverable.
    KeyDestroyed,
    /// AES-KW integrity check failed: the wrong KEK or a corrupted wrapped key.
    KeyUnwrap,
    /// An X25519 sealing/opening operation failed: an invalid public key or low-order point
    /// (the enrollment sealed-box).
    Seal,
    /// The OS CSPRNG was unavailable during key generation — fail closed (no weak keys).
    Rng,
    /// The container's `.clave-wipe-marker` is set — refuse to mount a half-wiped volume.
    WipeMarkerSet,
    /// Sector index past the end of the backing container.
    OutOfRange,
    /// Buffer length is not a whole number of [`SECTOR_SIZE`] sectors.
    Misaligned,
    /// Backing-store I/O failure.
    Io(String),
}

impl std::fmt::Display for VolumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolumeError::AccessDenied => write!(f, "access denied: caller is not in the work zone"),
            VolumeError::Locked => write!(f, "volume is locked"),
            VolumeError::KeyDestroyed => write!(f, "wrapped key destroyed or never provisioned"),
            VolumeError::KeyUnwrap => write!(f, "key unwrap failed (wrong KEK or corrupted key)"),
            VolumeError::Seal => write!(f, "sealed-box seal/open failed (invalid public key)"),
            VolumeError::Rng => write!(f, "OS RNG unavailable for key generation"),
            VolumeError::WipeMarkerSet => write!(f, "wipe marker set: refusing to mount"),
            VolumeError::OutOfRange => write!(f, "sector out of range"),
            VolumeError::Misaligned => write!(f, "buffer is not sector-aligned"),
            VolumeError::Io(e) => write!(f, "backing I/O error: {e}"),
        }
    }
}

impl std::error::Error for VolumeError {}
