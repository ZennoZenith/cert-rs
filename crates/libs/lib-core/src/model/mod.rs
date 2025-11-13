//! Model Layer
//!
//! Design:
//!
//! - The Model layer normalizes the application's data type
//!   structures and access.
//! - All application code data access must go through the Model layer.
//! - The `ModelManager` holds the internal states/resources
//!   needed by ModelControllers to access data.
//!   (e.g., db_pool, S3 client, redis client).
//!   (`Bmc` is short for Backend Model Controller).
//! - In frameworks like Axum, Tauri, `ModelManager` are typically used as App State.
//! - ModelManager are designed to be passed as an argument
//!   to all Model Controllers functions.
//!

// region:    --- Modules

mod acs;
mod error;
mod store;

pub mod user;

pub use self::error::{Error, Result};

use crate::model::store::dbx::Dbx;
use crate::model::store::new_db_pool;

#[cfg(test)]
use sqlx::{Pool, Sqlite};

// endregion: --- Modules

// region:    --- ModelManager

#[derive(Clone)]
pub struct ModelManager {
    dbx: Dbx,
}

impl ModelManager {
    pub async fn new() -> Result<Self> {
        let db_pool = new_db_pool().await.map_err(|ex| {
            Error::CantCreateModelManagerProvider(ex.to_string())
        })?;
        let dbx = Dbx::new(db_pool, false);
        Ok(ModelManager { dbx })
    }

    #[cfg(test)]
    pub async fn new_with_pool(db_pool: Pool<Sqlite>) -> Result<Self> {
        let dbx = Dbx::new(db_pool, false);
        Ok(ModelManager { dbx })
    }

    pub fn new_with_txn(&self) -> ModelManager {
        let dbx = Dbx::new(self.dbx.db().clone(), true);
        ModelManager { dbx }
    }

    pub fn dbx(&self) -> &Dbx {
        &self.dbx
    }
}

// endregion: --- ModelManager
