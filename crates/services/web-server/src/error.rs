use lib_core::model;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    // -- Modules
    #[error(transparent)]
    Model(#[from] model::Error),
}
