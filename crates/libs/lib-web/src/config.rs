use lib_utils::envs::{get_env, get_env_parse};
use std::{net::SocketAddr, sync::OnceLock};

pub fn web_config() -> &'static WebConfig {
    static INSTANCE: OnceLock<WebConfig> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        WebConfig::load_from_env().unwrap_or_else(|ex| {
            panic!("FATAL - WHILE LOADING CONF - Cause: {ex:?}")
        })
    })
}

#[allow(non_snake_case)]
pub struct WebConfig {
    pub TEMPLATE_FOLDER: String,
    pub STATIC_FOLDER: String,
    pub HOST_PORT: SocketAddr,
}

impl WebConfig {
    fn load_from_env() -> lib_utils::envs::Result<WebConfig> {
        Ok(WebConfig {
            TEMPLATE_FOLDER: get_env("SERVICE_TEMPLATE_FOLDER")?,
            STATIC_FOLDER: get_env("SERVICE_STATIC_FOLDER")?,
            HOST_PORT: get_env_parse("SERVICE_HOST_PORT")?,
        })
    }
}
