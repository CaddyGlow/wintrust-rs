//! Portable catalog trust with idiomatic Rust functions and Windows-name aliases.
//!
//! With the `std` feature, `WinVerifyTrust` re-exports `win_verify_trust` with the same safe
//! Rust signature. These names do not expose the Windows C ABI or inherit the
//! machine catalog database. Policy and member format remain explicit.
//!
//! The default build uses `no_std` with `alloc`. Supply pinned artifact bytes
//! through [`portable::Verifier::from_artifact_reader`] and an explicit clock.
//! Filesystem APIs and automatic clock capture require `std`.
//!
//! ```
//! # #[cfg(feature = "std")]
//! # fn example() -> wintrust::error::Result<()> {
//! use wintrust::{CryptCATAdminAcquireContext2, crypt_cat_admin_acquire_context2};
//! use wintrust::portable::sip::{DigestAlgorithm, MemberHashPolicy, SipKind};
//!
//! let context = CryptCATAdminAcquireContext2(
//!     DigestAlgorithm::Sha256, SipKind::FlatXml, MemberHashPolicy::default(),
//! )?;
//! let other = crypt_cat_admin_acquire_context2(
//!     DigestAlgorithm::Sha256, SipKind::FlatXml, MemberHashPolicy::default(),
//! )?;
//! # let _ = (context, other);
//! # Ok::<(), wintrust::error::Error>(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(feature = "std")]
mod api;
pub mod catalog;
pub mod catalog_trust;
pub mod ctl;
mod der;
pub mod error;
pub use error::{Error, Result};
mod certificates;
pub use ::der::asn1::ObjectIdentifier;
pub use certificates::CertificateStore;
mod oid_serde;
mod stringprep;

#[cfg(feature = "std")]
pub use api::{
    CatalogAdminContext, crypt_cat_admin_acquire_context2,
    crypt_cat_admin_calc_hash_from_file_handle2, crypt_cat_admin_release_context, win_verify_trust,
};
pub use catalog_trust::portable;

// Aliases are the same function items, not duplicate Windows-style wrappers.
#[cfg(feature = "std")]
pub use crypt_cat_admin_acquire_context2 as CryptCATAdminAcquireContext2;
#[cfg(feature = "std")]
pub use crypt_cat_admin_calc_hash_from_file_handle2 as CryptCATAdminCalcHashFromFileHandle2;
#[cfg(feature = "std")]
pub use crypt_cat_admin_release_context as CryptCATAdminReleaseContext;
#[cfg(feature = "std")]
pub use win_verify_trust as WinVerifyTrust;
