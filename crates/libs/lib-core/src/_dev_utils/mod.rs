// region:    --- Modules

mod dev_db;

use crate::ctx::Ctx;
use crate::model::user::UserForCreate;
use crate::model::{self, ModelManager};
use sqlx::{Pool, Postgres};
// use tokio::sync::OnceCell;
use tracing::info;

pub use dev_db::{init_test_db, pexec};

// endregion: --- Modules

/// Initialize test environment.
pub async fn init_test(pool: Pool<Postgres>) -> ModelManager {
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

pub async fn clean_users(
    ctx: &Ctx,
    mm: &ModelManager,
    // _contains_user_id: &str,
) -> model::user::Result<usize> {
    let users = model::user::UserBmc::list(ctx, mm).await?;
    let count = users.len();

    for user in users {
        model::user::UserBmc::delete(ctx, mm, &user.user_id).await?;
    }

    Ok(count)
}

// endregion: --- User seed/clean
