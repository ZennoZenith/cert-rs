mod config;
mod error;

pub mod extractors;
pub mod handlers;
pub mod log;
pub mod middleware;
pub mod tera;
pub mod utils;

pub use config::web_config;
pub use error::Error;
