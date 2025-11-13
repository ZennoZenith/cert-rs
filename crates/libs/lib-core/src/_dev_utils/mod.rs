// region:    --- Modules

mod dev_db;

use crate::ctx::Ctx;
use crate::model::user::UserForCreate;
use crate::model::{self, ModelManager};
use sqlx::{Pool, Sqlite};
// use tokio::sync::OnceCell;
use tracing::info;

pub use dev_db::{init_test_db, pexec};

// endregion: --- Modules

/// Initialize test environment.
pub async fn init_test(pool: Pool<Sqlite>) -> ModelManager {
    println!("Initializing db");
    info!("{:<12} - init_dev_all()", "FOR-DEV-ONLY");
    dev_db::init_test_db(pool).await.unwrap()
}

// region:    --- User seed/clean

pub async fn seed_users(
    ctx: &Ctx,
    mm: &ModelManager,
    users_for_seed: Vec<UserForCreate>,
) -> model::user::Result<Vec<String>> {
    let mut ids = Vec::new();

    for user in users_for_seed {
        let id = seed_user(ctx, mm, user).await?;
        ids.push(id);
    }

    Ok(ids)
}

pub async fn seed_user(
    ctx: &Ctx,
    mm: &ModelManager,
    user_for_seed: UserForCreate,
) -> model::user::Result<String> {
    // let pwd_clear = "seed-user-pwd";

    let id = model::user::UserBmc::create(ctx, mm, user_for_seed).await?;

    Ok(id)
}

// endregion: --- User seed/clean
