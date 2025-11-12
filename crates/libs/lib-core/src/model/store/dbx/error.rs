use std::borrow::Cow;

use serde::Serialize;
use serde_with::{DisplayFromStr, serde_as};

pub type Result<T> = std::result::Result<T, Error>;

#[serde_as]
#[derive(thiserror::Error, Debug, Serialize, strum_macros::Display)]
pub enum Error {
    TxnCantCommitNoOpenTxn,
    CannotBeginTxnWithTxnFalse,
    CannotCommitTxnWithTxnFalse,
    NoTxn,
    // -- Externals
    #[error(transparent)]
    Sqlx(
        #[from]
        #[serde_as(as = "DisplayFromStr")]
        sqlx::Error,
    ),
}

pub struct UniqueViolation {
    pub table: String,
    pub constraint: String,
}

impl Error {
    /// This function will transform the error into a more precise variant if it is an SQLX or PGError Unique Violation.
    /// The resolver can contain a function (table_name: &str, constraint: &str) that may return a specific Error if desired.
    /// If the resolver is None, or if the resolver function returns None, it will default to Error::UniqueViolation {table, constraint}.
    pub fn resolve_unique_violation(&self) -> Option<UniqueViolation> {
        match self {
            Self::Sqlx(sqlx_error) => {
                match sqlx_error.as_database_error().map(|db_error| {
                    (db_error.code(), db_error.table(), db_error.constraint())
                }) {
                    // "23505" => postgresql "unique violation"
                    Some((
                        Some(Cow::Borrowed("23505")),
                        Some(table),
                        Some(constraint),
                    )) => Some(UniqueViolation {
                        table: table.to_string(),
                        constraint: constraint.to_string(),
                    }),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}
