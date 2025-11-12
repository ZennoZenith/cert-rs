use axum::{Router, routing::get};
use lib_core::model::ModelManager;
use lib_web::handlers::web;

// region:    --- Modules
mod routes_fragmant;
pub mod routes_static;

// endregion: --- Modules

pub fn routes(mm: ModelManager) -> Router {
    Router::new()
        .route("/", get(web::render_index))
        .route(
            "/toast/variant/{variant_id}",
            get(web::render_toast_variant_id),
        )
        .route(
            "/login/variant/{variant_id}",
            get(web::render_login_variant_id),
        )
        .route(
            "/register/variant/{variant_id}",
            get(web::render_register_variant_id),
        )
        .route("/echo", get(web::render_echo))
        .nest_service("/fragmant", routes_fragmant::routes(mm.clone()))
        .with_state(mm)
}
