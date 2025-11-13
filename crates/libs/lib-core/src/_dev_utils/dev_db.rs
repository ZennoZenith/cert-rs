use crate::model::ModelManager;
use sqlx::migrate::Migrator;
use sqlx::{Pool, Sqlite};
use std::path::{Path, PathBuf};
use tracing::info;

const MIGRATION_DIR: &str = "db/migrations";
const DEV_INITIAL_SEED_USER: &str = "db/fixtures/dev-seed-user.sql";

pub async fn init_test_db(
    pool: Pool<Sqlite>,
) -> Result<ModelManager, Box<dyn std::error::Error>> {
    info!("{:<12} - init_dev_db()", "FOR-DEV-ONLY");

    // -- Get the sql_dir
    // Note: This is because cargo test and cargo run won't give the same
    //       current_dir given the worspace layout.
    let current_dir = std::env::current_dir().unwrap();
    let v: Vec<_> = current_dir.components().collect();
    let path_comp = v.get(v.len().wrapping_sub(3));
    let base_dir = if Some(true) == path_comp.map(|c| c.as_os_str() == "crates")
    {
        v[..v.len() - 3].iter().collect::<PathBuf>()
    } else {
        current_dir.clone()
    };
    let migration_dir = base_dir.join(MIGRATION_DIR);
    let dev_inital_seed_user = base_dir.join(DEV_INITIAL_SEED_USER);

    Migrator::new(migration_dir).await?.run(&pool).await?;
    pexec(&pool, &dev_inital_seed_user).await?;

    // -- Init model layer.
    Ok(ModelManager::new_with_pool(pool).await?)
}

pub async fn pexec(db: &Pool<Sqlite>, file: &Path) -> Result<(), sqlx::Error> {
    use std::fs;
    info!("{:<12} - pexec: {file:?}", "FOR-DEV-ONLY");

    // -- Read the file.
    let content = fs::read_to_string(file)?;

    // FIXME: Make the split more sql proof.
    let sqls: Vec<&str> = content.split(';').collect();

    for sql in sqls {
        sqlx::query(sql).execute(db).await.map_err(|e| {
            println!("pexec error while running:\n{sql}");
            println!("cause:\n{e}");
            e
        })?;
    }

    Ok(())
}
