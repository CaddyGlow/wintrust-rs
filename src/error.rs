//! Errors exposed by cryptographic verification and trust-policy APIs.
use alloc::{format, string::String};
use core::fmt;

/// A failed verification operation. Categories are independent of message text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    MalformedInput(String),
    UnsupportedAlgorithm(String),
    PolicyRejected(String),
    ResourceLimit(String),
    InvalidConfiguration(String),
    InvalidSignature(String),
    Io(String),
}

/// The result of a verification operation.
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    pub fn malformed(message: impl fmt::Display) -> Self {
        Self::MalformedInput(format!("{message}"))
    }
    pub fn unsupported(message: impl fmt::Display) -> Self {
        Self::UnsupportedAlgorithm(format!("{message}"))
    }
    pub fn policy(message: impl fmt::Display) -> Self {
        Self::PolicyRejected(format!("{message}"))
    }
    pub fn resource_limit(message: impl fmt::Display) -> Self {
        Self::ResourceLimit(format!("{message}"))
    }
    pub fn configuration(message: impl fmt::Display) -> Self {
        Self::InvalidConfiguration(format!("{message}"))
    }
    pub fn signature(message: impl fmt::Display) -> Self {
        Self::InvalidSignature(format!("{message}"))
    }

    /// Add diagnostic context without changing the error category.
    pub fn context(self, context: impl fmt::Display) -> Self {
        let message = format!("{context}: {self}");
        match self {
            Self::MalformedInput(_) => Self::MalformedInput(message),
            Self::UnsupportedAlgorithm(_) => Self::UnsupportedAlgorithm(message),
            Self::PolicyRejected(_) => Self::PolicyRejected(message),
            Self::ResourceLimit(_) => Self::ResourceLimit(message),
            Self::InvalidConfiguration(_) => Self::InvalidConfiguration(message),
            Self::InvalidSignature(_) => Self::InvalidSignature(message),
            Self::Io(_) => Self::Io(message),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedInput(message)
            | Self::UnsupportedAlgorithm(message)
            | Self::PolicyRejected(message)
            | Self::ResourceLimit(message)
            | Self::InvalidConfiguration(message)
            | Self::InvalidSignature(message)
            | Self::Io(message) => f.write_str(message),
        }
    }
}
impl core::error::Error for Error {}
impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self::policy(message)
    }
}
impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::PolicyRejected(message)
    }
}
#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(format!("{error}"))
    }
}
impl From<der::Error> for Error {
    fn from(error: der::Error) -> Self {
        Self::malformed(error)
    }
}
impl From<der::oid::Error> for Error {
    fn from(error: der::oid::Error) -> Self {
        Self::malformed(error)
    }
}
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::malformed(error)
    }
}
impl From<crate::catalog::CatalogError> for Error {
    fn from(error: crate::catalog::CatalogError) -> Self {
        match error {
            crate::catalog::CatalogError::Limit(message) => Self::resource_limit(message),
            crate::catalog::CatalogError::Unsupported(message) => Self::unsupported(message),
            error => Self::malformed(error),
        }
    }
}
impl From<core::num::TryFromIntError> for Error {
    fn from(error: core::num::TryFromIntError) -> Self {
        Self::malformed(error)
    }
}
impl From<core::num::ParseIntError> for Error {
    fn from(error: core::num::ParseIntError) -> Self {
        Self::malformed(error)
    }
}
impl From<core::str::Utf8Error> for Error {
    fn from(error: core::str::Utf8Error) -> Self {
        Self::malformed(error)
    }
}
impl From<alloc::string::FromUtf8Error> for Error {
    fn from(error: alloc::string::FromUtf8Error) -> Self {
        Self::malformed(error)
    }
}
impl From<hexspell::errors::FileParseError> for Error {
    fn from(error: hexspell::errors::FileParseError) -> Self {
        Self::malformed(error)
    }
}
impl From<hex::FromHexError> for Error {
    fn from(error: hex::FromHexError) -> Self {
        Self::malformed(error)
    }
}
#[cfg(feature = "std")]
impl From<std::time::SystemTimeError> for Error {
    fn from(error: std::time::SystemTimeError) -> Self {
        Self::configuration(error)
    }
}

/// Attach context to errors while preserving typed verification categories.
pub(crate) trait Context<T> {
    fn context(self, message: impl fmt::Display) -> Result<T>;
}
impl<T, E: Into<Error>> Context<T> for core::result::Result<T, E> {
    fn context(self, message: impl fmt::Display) -> Result<T> {
        self.map_err(|error| error.into().context(message))
    }
}
impl<T> Context<T> for Option<T> {
    fn context(self, message: impl fmt::Display) -> Result<T> {
        self.ok_or_else(|| Error::malformed(message))
    }
}
macro_rules! bail {
    ($error:expr $(,)?) => { return Err(($error).into()) };
    ($format:expr, $($arg:tt)*) => { return Err($crate::error::Error::policy(alloc::format!($format, $($arg)*))) };
}
macro_rules! ensure {
    ($condition:expr $(,)?) => { if !$condition { return Err($crate::error::Error::policy(concat!("condition failed: ", stringify!($condition)))); } };
    ($condition:expr, $($arg:tt)*) => { if !$condition { $crate::error::bail!($($arg)*); } };
}
pub(crate) use {bail, ensure};
