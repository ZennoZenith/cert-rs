//! Launch a local network server with live reload feature for static pages.
//!
//! ## Create live server
//! ```
//! use live_server::{listen, Options};
//!
//! async fn serve() -> Result<(), Box<dyn std::error::Error>> {
//!     listen("127.0.0.1:8080", "./").await?.start(Options::default()).await
//! }
//! ```
//!
//! ## Enable logs (Optional)
//! ```rust
//! env_logger::init();
//! ```

mod config;
mod file_layer;
mod http_layer;
mod utils;

pub use config::reload_config;
pub use http_layer::format_script;

use file_layer::watcher::{create_poll_watcher, watch};
use notify::{PollWatcher, RecommendedWatcher, Watcher};
use notify_debouncer_full::{DebouncedEvent, Debouncer, RecommendedCache};
use path_absolutize::Absolutize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{broadcast::Sender, mpsc::Receiver};

use crate::file_layer::watcher::create_recommended_watcher;

pub struct Listener<W: Watcher> {
    root_path: PathBuf,
    debouncer: Debouncer<W, RecommendedCache>,
    rx: Receiver<Result<Vec<DebouncedEvent>, Vec<notify::Error>>>,
}

impl<W: Watcher + Send + 'static> Listener<W> {
    pub fn start(self, arc_tx: Arc<Sender<()>>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(watch(
            self.root_path,
            self.debouncer,
            self.rx,
            arc_tx,
            reload_config().AUTO_IGNORE,
        ))
    }
}

/// Create live-server listener using [RecommendedWatcher].
pub async fn listen(
    root: impl AsRef<Path>,
) -> Result<Listener<RecommendedWatcher>, String> {
    let (debouncer, rx) = create_recommended_watcher().await?;

    let abs_root = get_absolute_path(root.as_ref())?;
    print_listening_on_path(&abs_root)?;

    Ok(Listener {
        debouncer,
        root_path: abs_root,
        rx,
    })
}

/// Create live-server listener using [PollWatcher].
///
/// [PollWatcher] is a fallback that manually checks file paths for changes at a regular interval.
/// It is useful for cases where real-time OS notifications fail, such as when a symbolic link is
/// atomically replaced, or when the monitored directory itself is moved or renamed.
pub async fn listen_poll(
    root: impl AsRef<Path>,
) -> Result<Listener<PollWatcher>, String> {
    let (debouncer, rx) = create_poll_watcher().await?;

    let abs_root = get_absolute_path(root.as_ref())?;
    print_listening_on_path(&abs_root)?;

    Ok(Listener {
        debouncer,
        root_path: abs_root,
        rx,
    })
}

fn get_absolute_path(path: &Path) -> Result<PathBuf, String> {
    match path.absolutize() {
        Ok(path) => Ok(path.to_path_buf()),
        Err(err) => {
            let err_msg =
                format!("Failed to get absolute path of {path:?}: {err}");
            tracing::error!("{err_msg}");
            Err(err_msg)
        }
    }
}

fn print_listening_on_path(path: &PathBuf) -> Result<(), String> {
    match path.as_os_str().to_str() {
        Some(path_str) => {
            tracing::info!("Listening on {path_str}");
            Ok(())
        }
        None => {
            let err_msg =
                format!("Failed to parse path to string for `{path:?}`");
            tracing::error!("{err_msg}");
            Err(err_msg)
        }
    }
}

pub async fn run_watcher(
    arc_tx: Arc<Sender<()>>,
) -> tokio::task::JoinHandle<()> {
    let root = reload_config().HOT_RELOAD_DIR.clone();

    if reload_config().POLL {
        let listener = listen_poll(root).await.unwrap();
        listener.start(arc_tx)
    } else {
        let listener = listen(root).await.unwrap();
        listener.start(arc_tx)
    }
}
