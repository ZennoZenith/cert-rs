use chrono::{DateTime, Utc};

use crate::{Problem, account::AccountStatus};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The server returned a well-formed ACME problem document.
    ///
    /// See [RFC 8555 §6.7](https://datatracker.ietf.org/doc/html/rfc8555#section-6.7).
    #[error(transparent)]
    Problem(#[from] Problem),

    /// Failed to parse a URL.
    #[error(transparent)]
    Url(#[from] url::ParseError),

    /// Failed to (de)serialize a JSON object
    #[error("failed to (de)serialize JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// The HTTP request failed due to a network error, timeout, or other transport-level issue.
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    /// The order does not contain a certificate URL, likely because it has not been finalized yet.
    #[error("Certificate url not present order")]
    CertificateUrlNotPresent,

    /// Failed from cryptographic operations
    #[error("Cryptographic operation failed: {0}")]
    Crypto(&'static str),

    /// The account status is not valid for the attempted operation.
    #[error("Account status no valid. Status: {0}")]
    AccountStatusNoValid(AccountStatus),

    /// Key rollover was aborted because an account derived from the provided
    /// private key already exists. The existing account will be used instead.
    #[error(
        "Key rollover aborted: an account derived from the provided private key already exists; using existing account instead."
    )]
    ExistingAccountDuringKeyRollover,

    #[error("Timed out: ")]
    Timeout(DateTime<Utc>),

    #[error("ACME server does not support: {0}")]
    Unsupported(&'static str),

    /// Miscellaneous errors
    #[error("Unhandled data: {0}")]
    Str(&'static str),

    /// Other kind of error
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Key generation error
    #[cfg(feature = "generate")]
    #[error(transparent)]
    KeyGeneration(Box<dyn std::error::Error + Send + Sync + 'static>),
}
