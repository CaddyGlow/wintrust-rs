//! Windows catalog-member trust reference. Hash matching alone is not trust.
//!
//! The native backend uses the host's Authenticode policy and trust stores. It
//! does not restrict the signer to Microsoft or establish CBS applicability.
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path};

pub mod portable;

#[cfg(all(windows, feature = "native-reference"))]
mod native;

/// Hash algorithm used by the Windows subject-interface package (SIP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogHashAlgorithm {
    Sha256,
    /// Explicit compatibility mode; SHA-1 is never silently selected.
    Sha1,
}

/// Network and revocation behavior of the Windows chain policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationPolicy {
    /// Require chain revocation checks using locally cached information only.
    CacheOnly,
    /// Require chain revocation checks and permit Windows network retrieval.
    Online,
    /// Disable revocation checking. Success does not establish non-revocation.
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustOptions {
    pub hash_algorithm: CatalogHashAlgorithm,
    pub revocation: RevocationPolicy,
}
impl Default for TrustOptions {
    fn default() -> Self {
        Self {
            hash_algorithm: CatalogHashAlgorithm::Sha256,
            revocation: RevocationPolicy::CacheOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    /// Catalog membership and signature passed the host Authenticode policy.
    WindowsAuthenticodeTrusted,
    Rejected,
}

/// A native reference result, never a portable or Microsoft-specific claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustReport {
    pub backend: String,
    pub status: TrustStatus,
    /// Exact WinVerifyTrust LONG status represented as an unsigned bit pattern.
    pub winverifytrust_status: u32,
    pub member_hash: String,
    pub catalog_path: std::path::PathBuf,
    pub member_path: std::path::PathBuf,
    /// Raw file fingerprints for reproducible evidence, distinct from SIP hash.
    pub catalog_sha256: String,
    pub member_sha256: String,
    pub options: TrustOptions,
    /// Always false: this backend does not implement Microsoft signer policy.
    pub microsoft_signer_verified: bool,
}

#[derive(Debug)]
pub enum TrustError {
    BackendUnavailable,
    InvalidInput(String),
    Io(std::io::Error),
    WindowsApi { operation: &'static str, code: u32 },
}
impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable => {
                f.write_str("Windows catalog trust backend unavailable on this platform")
            }
            Self::InvalidInput(message) => f.write_str(message),
            Self::Io(error) => error.fmt(f),
            Self::WindowsApi { operation, code } => write!(f, "{operation} failed: 0x{code:08x}"),
        }
    }
}
impl std::error::Error for TrustError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<std::io::Error> for TrustError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Verify one member against an explicitly supplied catalog without registering
/// that catalog in the Windows catalog database. Rejections are report values;
/// setup and I/O failures are errors. No verification UI is displayed.
pub fn verify_catalog_member(
    catalog: &Path,
    member: &Path,
    options: TrustOptions,
) -> Result<TrustReport, TrustError> {
    #[cfg(all(windows, feature = "native-reference"))]
    {
        native::verify(catalog, member, options)
    }
    #[cfg(not(all(windows, feature = "native-reference")))]
    {
        let _ = (catalog, member, options);
        Err(TrustError::BackendUnavailable)
    }
}
