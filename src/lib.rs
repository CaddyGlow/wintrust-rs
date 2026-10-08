//! Portable catalog trust with idiomatic Rust functions and Windows-name aliases.
//!
//! [`WinVerifyTrust`] is a re-export of [`win_verify_trust`], with the same safe
//! Rust signature. These names do not expose the Windows C ABI or inherit the
//! machine catalog database. Policy and member format remain explicit.
//!
//! ```
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
//! # Ok::<(), anyhow::Error>(())
//! ```

mod api;
pub mod catalog;
pub mod catalog_trust;
pub mod ctl;

pub use api::{
    CatalogAdminContext, crypt_cat_admin_acquire_context2,
    crypt_cat_admin_calc_hash_from_file_handle2, crypt_cat_admin_release_context, win_verify_trust,
};
pub use catalog_trust::portable;

// Aliases are the same function items, not duplicate Windows-style wrappers.
pub use crypt_cat_admin_acquire_context2 as CryptCATAdminAcquireContext2;
pub use crypt_cat_admin_calc_hash_from_file_handle2 as CryptCATAdminCalcHashFromFileHandle2;
pub use crypt_cat_admin_release_context as CryptCATAdminReleaseContext;
pub use win_verify_trust as WinVerifyTrust;
