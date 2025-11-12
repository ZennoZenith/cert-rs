use crate::error::{Error, Result};
use axum::http::Uri;

pub mod handlers_login;

pub async fn fallback(uri: Uri) -> Result<()> {
    Err(Error::RouteNotExist(uri.to_string()))
}
