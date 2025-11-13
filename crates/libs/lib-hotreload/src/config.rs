use lib_utils::envs::{DefaultIfMissing, IfMissing, get_env_parse};
use std::{path::PathBuf, sync::OnceLock};

pub fn reload_config() -> &'static ReloadConfig {
    static INSTANCE: OnceLock<ReloadConfig> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        ReloadConfig::load_from_env().unwrap_or_else(|ex| {
            panic!("FATAL - WHILE LOADING CONF - Cause: {ex:?}")
        })
    })
}

#[allow(non_snake_case)]
pub struct ReloadConfig {
    /// Always hard reload the page instead of hot-reload
    pub HARD_RELOAD: bool,

    /// Ignore hidden and ignored files
    pub AUTO_IGNORE: bool,

    /// Create listener using `PollWatcher`
    ///
    /// `PollWatcher` is a fallback that manually checks file paths for changes at a regular interval.
    /// It is useful for cases where real-time OS notifications fail, such as when a symbolic link is
    /// atomically replaced, or when the monitored directory itself is moved or renamed.
    pub POLL: bool,

    /// Dir to watch for hot reloading
    pub HOT_RELOAD_DIR: PathBuf,
}

impl ReloadConfig {
    fn load_from_env() -> lib_utils::envs::Result<ReloadConfig> {
        let hard_reload =
            get_env_parse::<bool>("SERVICE_HOT_RELOAD_HARD_RELOAD")
                .default_if_missing()?;

        let auto_ignore =
            get_env_parse::<bool>("SERVICE_HOT_RELOAD_AUTO_IGNORE")
                .if_missing(false)?;

        let poll = get_env_parse::<bool>("SERVICE_HOT_RELOAD_POLL")
            .default_if_missing()?;

        let hot_reload_dir: PathBuf =
            get_env_parse::<String>("SERVICE_HOT_RELOAD_DIR")
                .if_missing(String::from("frontend/"))?
                .into();

        Ok(ReloadConfig {
            HARD_RELOAD: hard_reload,
            AUTO_IGNORE: auto_ignore,
            POLL: poll,
            HOT_RELOAD_DIR: hot_reload_dir,
        })
    }
}
