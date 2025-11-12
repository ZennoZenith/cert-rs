use axum::{
    RequestExt,
    extract::{FromRequest, Query, Request},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct DatastarQuery<T: for<'a> Deserialize<'a>>(pub T);

#[derive(Debug)]
pub enum DatastarQueryError {
    NotDatastarRequest,
    InvalidDatastarJson,
}

impl IntoResponse for DatastarQueryError {
    fn into_response(self) -> axum::response::Response {
        match self {
            DatastarQueryError::NotDatastarRequest => {
                StatusCode::BAD_REQUEST.into_response()
            }
            DatastarQueryError::InvalidDatastarJson => {
                StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()
            }
        }
    }
}

impl<S, T> FromRequest<S> for DatastarQuery<T>
where
    S: Send + Sync,
    T: for<'de> Deserialize<'de> + 'static,
{
    type Rejection = DatastarQueryError;

    async fn from_request(
        req: Request,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        #[derive(Deserialize)]
        struct InternalDatastarQuery {
            datastar: String,
        }

        let Query::<InternalDatastarQuery>(InternalDatastarQuery { datastar }) =
            req.extract()
                .await
                .map_err(|_| DatastarQueryError::NotDatastarRequest)?;

        let signals: T = serde_json::from_str(&datastar)
            .map_err(|_| DatastarQueryError::InvalidDatastarJson)?;

        Ok(DatastarQuery(signals))
    }
}
