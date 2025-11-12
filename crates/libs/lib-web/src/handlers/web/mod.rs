use crate::{error::Result, middleware::mw_auth::CtxW, tera::render};
use axum::extract::Path;
use axum::extract::rejection::PathRejection;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use tera::Context;
use tracing::debug;

pub mod fragmant;

pub async fn fallback(uri: Uri) -> (StatusCode, Response) {
    let body = format!("404 - Not found {uri}");

    let mut context = Context::new();
    context.insert("title", "Not Found");
    context.insert("message", &body);

    (
        StatusCode::NOT_FOUND,
        render("error404.html", &context).into_response(),
    )
}

pub async fn render_index(_ctxw: Result<CtxW>) -> Result<impl IntoResponse> {
    debug!("{:<12} - web_index_handler", "HANDLER");

    let context = Context::new();
    render("index.html", &context).map(IntoResponse::into_response)
}

pub async fn render_echo(_ctxw: Result<CtxW>) -> Result<impl IntoResponse> {
    debug!("{:<12} - web_echo_handler", "HANDLER");

    let context = Context::new();
    render("echo.html", &context).map(IntoResponse::into_response)
}

pub async fn render_toast_variant_id(
    _ctxw: Result<CtxW>,
    variant_id: std::result::Result<Path<u8>, PathRejection>,
) -> Result<impl IntoResponse> {
    debug!("{:<12} - web_toast_handler", "HANDLER");

    let context = Context::new();

    match variant_id.map(|v| v.0).unwrap_or(1) {
        1 => render("toast/variant-1.html", &context)
            .map(IntoResponse::into_response),
        _ => render("toast/variant-1.html", &context)
            .map(IntoResponse::into_response),
    }
}

pub async fn render_login_variant_id(
    _ctxw: Result<CtxW>,
    variant_id: std::result::Result<Path<u8>, PathRejection>,
) -> Result<impl IntoResponse> {
    debug!("{:<12} - web_login_handler", "HANDLER");

    // if ctxw.is_ok() {
    //     return Ok(Redirect::temporary("/dashboard").into_response());
    // }

    let context = Context::new();

    match variant_id.map(|v| v.0).unwrap_or(1) {
        x if (1..=3).contains(&x) => {
            render(&format!("login/variant-{x}.html"), &context)
                .map(IntoResponse::into_response)
        }
        _ => render("login/variant-1.html", &context)
            .map(IntoResponse::into_response),
    }
}

pub async fn render_register_variant_id(
    _ctxw: Result<CtxW>,
    variant_id: std::result::Result<Path<u8>, PathRejection>,
) -> Result<impl IntoResponse> {
    debug!("{:<12} - web_login_handler", "HANDLER");

    // if ctxw.is_ok() {
    //     return Ok(Redirect::temporary("/dashboard").into_response());
    // }

    let context = Context::new();
    match variant_id.map(|v| v.0).unwrap_or(1) {
        x if (1..=3).contains(&x) => {
            render(&format!("register/variant-{x}.html"), &context)
                .map(IntoResponse::into_response)
        }
        _ => render("register/variant-1.html", &context)
            .map(IntoResponse::into_response),
    }
}
