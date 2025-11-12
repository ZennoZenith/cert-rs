use axum::{
    Form, Json, RequestExt,
    extract::{
        FromRequest, Request,
        rejection::{FormRejection, JsonRejection},
    },
    http::{StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
};
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct JsonOrForm<T>(pub T);

#[derive(Debug)]
pub enum JsonOrFormError {
    JsonRejection(JsonRejection),
    FormRejection(FormRejection),
    UnsupportedMedia,
}

impl IntoResponse for JsonOrFormError {
    fn into_response(self) -> axum::response::Response {
        match self {
            JsonOrFormError::JsonRejection(v) => v.into_response(),
            JsonOrFormError::FormRejection(v) => v.into_response(),
            JsonOrFormError::UnsupportedMedia => {
                StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()
            }
        }
    }
}

impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    Form<T>: FromRequest<S, Rejection = FormRejection>,
    T: for<'de> Deserialize<'de> + 'static,
{
    type Rejection = JsonOrFormError;

    async fn from_request(
        req: Request,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let content_type_header = req.headers().get(CONTENT_TYPE);
        let content_type =
            content_type_header.and_then(|value| value.to_str().ok());

        if let Some(content_type) = content_type {
            if content_type.starts_with("application/json") {
                let Json(payload) = req
                    .extract()
                    .await
                    .map_err(JsonOrFormError::JsonRejection)?;
                return Ok(Self(payload));
            }

            if content_type.starts_with("application/x-www-form-urlencoded") {
                let Form(payload) = req
                    .extract()
                    .await
                    .map_err(JsonOrFormError::FormRejection)?;
                return Ok(Self(payload));
            }
        }

        Err(JsonOrFormError::UnsupportedMedia)
    }
}
