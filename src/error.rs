use chrono::{DateTime, Utc};

use crate::{ApiError, account::AccountStatus};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Wraps an [`ApiError`] returned during HTTP communication with the ACME server.
    #[error(transparent)]
    Api(#[from] ApiError),

    /// The provided string could not be parsed as a valid URL.
    #[error(transparent)]
    Url(#[from] url::ParseError),

    /// The ACME directory response could not be parsed into the expected structure.
    #[error("{0}")]
    DirectoryParse(String),

    /// The order does not contain a certificate URL, likely because it has not been finalized yet.
    #[error("Certificate url not present order")]
    CertificateUrlNotPresent,

    /// CSR generation or encoding failed.
    #[error("{0}")]
    Csr(String),

    /// A code path that is not yet implemented was reached.
    #[error("{0}")]
    Unimplemented(Box<str>),

    /// The account status is not valid for the attempted operation.
    #[error("{0}")]
    AccountStatusNoValid(AccountStatus),

    /// Key rollover was aborted because an account derived from the provided
    /// private key already exists. The existing account will be used instead.
    #[error(
        "Key rollover aborted: an account derived from the provided private key already exists; using existing account instead."
    )]
    ExistingAccountDuringKeyRollover,

    #[error("timed out waiting for an order update")]
    Timeout(DateTime<Utc>),

    /// Miscellaneous errors
    #[error("Unhandled data: {0}")]
    Str(&'static str),
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Self::Api(ApiError::from(value))
    }
}
