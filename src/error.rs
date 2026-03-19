pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Api(#[from] crate::api::Error),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    DirectoryParse(String),

    #[error("{0}")]
    ResponseToText(String),

    #[error("Certificate url not present order")]
    CertificateUrlNotPresent,

    #[error("{0}")]
    Csr(String),

    #[error("{0}")]
    Unimplemented(String),

    #[error("{0}")]
    AccountStatusNoValid(String),
}
