use axum::Router;
use axum::handler::HandlerWithoutStateExt;
use axum::http::StatusCode;
use axum::routing::{MethodRouter, any_service};
use tower_http::services::{ServeDir, ServeFile};

use crate::web_config;

// Note: Here we can just return a MethodRouter rather than a full Router
//       since ServeDir is a service.
pub fn serve_dir(web_folder: &str) -> MethodRouter {
    async fn handle_404() -> (StatusCode, &'static str) {
        (StatusCode::NOT_FOUND, "Resource not found.")
    }

    any_service(
        ServeDir::new(web_folder).not_found_service(handle_404.into_service()),
    )
}

pub fn favicon() -> ServeFile {
    ServeFile::new(
        format!("{}/images/favicon.ico", web_config().STATIC_FOLDER,),
    )
}

pub fn server_assets() -> Router {
    let serve_css_dir =
        ServeDir::new(format!("{}/css", web_config().STATIC_FOLDER));
    let serve_html_dir =
        ServeDir::new(format!("{}/html", web_config().STATIC_FOLDER));
    let serve_image_dir =
        ServeDir::new(format!("{}/images", web_config().STATIC_FOLDER));

    // Can use ServeDir directly or use serve_dir()
    Router::new()
        .nest_service(
            "/js",
            serve_dir(&format!("{}/js", web_config().STATIC_FOLDER)),
        )
        .nest_service("/css", serve_css_dir)
        .nest_service("/html", serve_html_dir)
        .nest_service("/images", serve_image_dir)
}
