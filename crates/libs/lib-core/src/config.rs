use lib_utils::envs::{DefaultIfMissing, get_env, get_env_parse};
use std::{sync::OnceLock, time::Duration};

pub fn core_config() -> &'static CoreConfig {
    static INSTANCE: OnceLock<CoreConfig> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        CoreConfig::load_from_env().unwrap_or_else(|ex| {
            panic!("FATAL - WHILE LOADING CONF - Cause: {ex:?}")
        })
    })
}

#[allow(non_snake_case)]
pub struct CoreConfig {
    // -- Db
    pub DB_URL: String,
    pub DB_MAX_CONNECTIONS: u32,
    pub DB_CONNECTION_TIMEOUT: Duration,
}

impl CoreConfig {
    fn load_from_env() -> lib_utils::envs::Result<CoreConfig> {
        let db_max_connections =
            get_env_parse::<u32>("SERVICE_DB_MAX_CONNECTIONS").if_missing(5)?;
        let db_connections_timeout =
            get_env_parse::<u64>("SERVICE_DB_CONNECTION_TIMEOUT_MS")
                .if_missing(500)
                .map(Duration::from_millis)?;

        Ok(CoreConfig {
            DB_URL: get_env("SERVICE_DB_URL")?,
            DB_MAX_CONNECTIONS: db_max_connections,
            DB_CONNECTION_TIMEOUT: db_connections_timeout,
        })
    }
}
