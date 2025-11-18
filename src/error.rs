pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug, strum_macros::Display)]
pub enum Error {
    GetReqwest(String),
    AcmeDirectoryParse(String),
    // // -- Modules
    // #[error(transparent)]
    // Scheme(#[from] scheme::Error),
}
