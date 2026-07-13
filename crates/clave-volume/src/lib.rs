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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeError {
    AccessDenied,
    Locked,
    KeyDestroyed,
    KeyUnwrap,
    Seal,
    Rng,
    WipeMarkerSet,
    OutOfRange,
    Misaligned,
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
