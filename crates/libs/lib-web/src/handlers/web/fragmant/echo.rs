use crate::{
    error::Result,
    extractors::{DatastarQuery, DatastarQueryError},
    tera::render_fragmant,
};
use axum::{extract::State, response::IntoResponse};
use lib_core::model::ModelManager;
use serde::Deserialize;
use tera::Context;

#[derive(Debug, Deserialize)]
pub struct Echo {
    echo: String,
    id: String,
}

pub async fn echo(
    State(_mm): State<ModelManager>,
    query: std::result::Result<DatastarQuery<Echo>, DatastarQueryError>,
) -> Result<impl IntoResponse> {
    let Echo { echo, id } = query?.0;

    let mut context = Context::new();
    context.insert("id", &id);
    context.insert("echo", &echo);

    render_fragmant("fragmants/echo.html", &context)
        .map(IntoResponse::into_response)
}
