pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Api(#[from] crate::api::Error),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    // #[error("{0}")]
    // Url(String),
    #[error("{0}")]
    DirectoryParse(String),

    #[error("{0}")]
    ResponseToText(String),

    #[error("{0}")]
    Unimplemented(String),

    #[error("{0}")]
    AccountStatusNoValid(String),
    // GetReqwest(String),
    // // -- Modules
    // #[error(transparent)]
    // Scheme(#[from] scheme::Error),
}
