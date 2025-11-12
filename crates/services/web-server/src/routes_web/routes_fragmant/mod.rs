use axum::{Router, routing::get};
use lib_core::model::ModelManager;
use lib_web::handlers::web::fragmant::echo;

pub fn routes(mm: ModelManager) -> Router {
    Router::new().route("/echo", get(echo::echo)).with_state(mm)
}
