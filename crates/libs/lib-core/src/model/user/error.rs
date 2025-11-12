use crate::model::store::dbx::{self, UniqueViolation};
use lib_auth::pwd;
use serde::Serialize;
use serde_with::serde_as;

pub type Result<T> = std::result::Result<T, Error>;

#[serde_as]
#[derive(thiserror::Error, Debug, Serialize, strum_macros::Display)]
pub enum Error {
    UserNotFound {
        user_id: String,
    },
    UserEmailNotFound,

    // // -- DB
    // UniqueViolation { table: String, constraint: String },
    UserNotUnique,

    // -- Modules
    #[error(transparent)]
    Pwd(#[from] pwd::Error),

    #[error(transparent)]
    Dbx(dbx::Error),
}

impl From<dbx::Error> for Error {
    fn from(value: dbx::Error) -> Self {
        match value.resolve_unique_violation() {
            Some(UniqueViolation { .. }) => Self::UserNotUnique,
            None => Self::Dbx(value),
        }
    }
}

// region:    --- Error Boilerplate
