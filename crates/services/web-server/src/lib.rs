mod error;
mod routes_api;
mod routes_web;

use crate::routes_web::routes_static;

use lib_core::model::ModelManager;
use lib_web::{
    handlers::web,
    middleware::{
        mw_auth::mw_ctx_resolver, mw_req_stamp::mw_req_stamp_resolver,
        mw_res_map::mw_reponse_map,
    },
    web_config,
};

use axum::{Router, middleware};
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;

pub use self::error::{Error, Result};

pub async fn routes() -> Result<Router> {
    let model_manager = ModelManager::new().await?;

    let router = Router::new()
        .nest("/api", routes_api::routes(model_manager.clone()))
        .merge(routes_web::routes(model_manager.clone()))
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(mw_req_stamp_resolver))
                .layer(CookieManagerLayer::new())
                .layer(middleware::from_fn_with_state(
                    model_manager.clone(),
                    mw_ctx_resolver,
                ))
                .layer(middleware::map_response(mw_reponse_map)), //
                                                                  // .layer(middleware::from_fn(
                                                                  //     lib_web::middleware::mw_auth::mw_ctx_require,
                                                                  // )),
        )
        .nest("/static", routes_static::server_assets())
        .route_service("/favicon.ico", routes_static::favicon())
        .fallback(web::fallback);

    Ok(router)
}
