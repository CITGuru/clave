//! # clave-platform
//!
//! The seam between Clave's portable policy brain ([`clave-core`]) and the OS-specific
//! mechanism crates (`clave-win`, `clave-mac`). It contains only:
//!
//! * **portable value types** ([`types`]) — identities, zones, decisions, formats; and
//! * **capability traits** ([`traits`]) — the behaviours each OS must provide.
//!
//! `clave-core` depends on these traits, never on a concrete OS implementation, so ~70% of
//! the security-critical logic compiles and tests on any machine.
#![forbid(unsafe_code)]

pub mod enforcement;
pub mod traits;
pub mod types;

pub use enforcement::*;
pub use traits::*;
pub use types::*;
