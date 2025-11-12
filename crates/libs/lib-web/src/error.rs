use crate::extractors::{DatastarQueryError, JsonOrFormError};
use crate::middleware;
use axum::extract::rejection::{FormRejection, JsonRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use lib_auth::{pwd, token};
use lib_core::model;
use serde::Serialize;
use serde_with::{DisplayFromStr, serde_as};
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

pub type Result<T> = std::result::Result<T, Error>;

#[serde_as]
#[derive(Error, Debug, Serialize, strum_macros::AsRefStr)]
#[serde(tag = "type", content = "data")]
pub enum Error {
    #[error("RouteNotExist: {0}")]
    RouteNotExist(String),

    // -- Json Deserialization
    #[error("JsonDeserialization: {0}")]
    JsonDeserialization(String),

    // -- Form Deserialization
    #[error("FormDeserialization: {0}")]
    FormDeserialization(String),

    // -- Query Deserialization
    #[error("QueryDeserialization: {0}")]
    QueryDeserialization(String),

    // -- DatastarQuery Deserialization
    #[error("DatastarQueryDeserialization: {0}")]
    DatastarQueryDeserialization(&'static str),

    // -- Login
    #[error("LoginFailPwdNotMatching: user_id: {user_id}")]
    LoginFailPwdNotMatching { user_id: String },

    // -- CtxExtError
    #[error(transparent)]
    CtxExt(#[from] middleware::mw_auth::CtxExtError),

    // -- Extractors
    #[error("ReqStampNotInReqExt")]
    ReqStampNotInReqExt,

    // -- Modules
    #[error(transparent)]
    Model(#[from] model::Error),

    #[error(transparent)]
    Pwd(#[from] pwd::Error),

    #[error(transparent)]
    Token(#[from] token::Error),

    // -- External Modules
    #[error(transparent)]
    SerdeJson(
        #[from]
        #[serde_as(as = "DisplayFromStr")]
        serde_json::Error,
    ),

    #[error(transparent)]
    TeraRender(
        #[from]
        #[serde_as(as = "DisplayFromStr")]
        tera::Error,
    ),

    #[error("UnsupportedMedia")]
    UnsupportedMedia,
}

impl From<JsonRejection> for Error {
    fn from(value: JsonRejection) -> Self {
        Self::JsonDeserialization(value.to_string())
    }
}

impl From<FormRejection> for Error {
    fn from(value: FormRejection) -> Self {
        Self::FormDeserialization(value.to_string())
    }
}

impl From<JsonOrFormError> for Error {
    fn from(value: JsonOrFormError) -> Self {
        match value {
            JsonOrFormError::JsonRejection(json_rejection) => {
                Self::JsonDeserialization(json_rejection.to_string())
            }
            JsonOrFormError::FormRejection(form_rejection) => {
                Self::FormDeserialization(form_rejection.to_string())
            }
            JsonOrFormError::UnsupportedMedia => Self::UnsupportedMedia,
        }
    }
}

impl From<DatastarQueryError> for Error {
    fn from(value: DatastarQueryError) -> Self {
        match value {
            DatastarQueryError::NotDatastarRequest => {
                Self::DatastarQueryDeserialization(
                    "Query does not contain datastar parameter",
                )
            }
            DatastarQueryError::InvalidDatastarJson => {
                Self::DatastarQueryDeserialization(
                    "Query parameter datastar in not valid json",
                )
            }
        }
    }
}

// region:    --- Axum IntoResponse
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        debug!("{:<12} - {self:?}", "INTO_RES");

        // Create a placeholder Axum reponse.
        let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();

        // Insert the Error into the reponse.
        response.extensions_mut().insert(Arc::new(self));

        response
    }
}
// endregion: --- Axum IntoResponse

// region:    --- Client Error

/// From the root error to the http status code and ClientError
impl Error {
    pub fn client_status_and_error(&self) -> (StatusCode, ClientError) {
        use Error::*; // TODO: should change to `use web::Error as E`

        match self {
            UnsupportedMedia => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ClientError::UNSUPPORTED_MEDIA,
            ),

            RouteNotExist(uri) => (
                StatusCode::NOT_FOUND,
                ClientError::ROUTE_NOT_EXIST {
                    uri: uri.to_string(),
                },
            ),

            // -- Json Deserialization
            JsonDeserialization(..) => (
                StatusCode::BAD_REQUEST,
                ClientError::JSON_DESERIALIZE {
                    message: "Some fields are missing or incorrect",
                },
            ),

            FormDeserialization(..) => (
                StatusCode::BAD_REQUEST,
                ClientError::FORM_DESERIALIZE {
                    message: "Some fields are missing or incorrect",
                },
            ),

            QueryDeserialization(..) => (
                StatusCode::BAD_REQUEST,
                ClientError::QUERY_DESERIALIZE {
                    message: "Some fields are missing or incorrect",
                },
            ),

            DatastarQueryDeserialization(v) => (
                StatusCode::BAD_REQUEST,
                ClientError::DATASTAR_QUERY_DESERIALIZATION { message: v },
            ),

            // // -- Login
            // LoginFailEmailNotFound
            // | LoginFailUserHasNoPwd { .. } |
            LoginFailPwdNotMatching { .. } => {
                (StatusCode::FORBIDDEN, ClientError::LOGIN_FAIL)
            }

            // -- Auth
            CtxExt(_) => (StatusCode::FORBIDDEN, ClientError::NO_AUTH),

            // -- Model
            Model(model::Error::User(model::user::Error::UserNotUnique)) => {
                (StatusCode::CONFLICT, ClientError::USER_ALREADY_EXISTS)
            }
            Model(model::Error::User(
                model::user::Error::UserEmailNotFound,
            ))
            | Model(model::Error::User(model::user::Error::UserNotFound {
                ..
            })) => (StatusCode::FORBIDDEN, ClientError::LOGIN_FAIL),

            // -- Tera.
            TeraRender(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ClientError::SERVICE_ERROR,
            ),

            // -- Fallback.
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ClientError::SERVICE_ERROR,
            ),
        }
    }
}

#[derive(Debug, Serialize, strum_macros::AsRefStr)]
#[serde(tag = "message", content = "detail")]
#[allow(non_camel_case_types)]
pub enum ClientError {
    ROUTE_NOT_EXIST { uri: String },
    JSON_DESERIALIZE { message: &'static str },
    FORM_DESERIALIZE { message: &'static str },
    QUERY_DESERIALIZE { message: &'static str },
    DATASTAR_QUERY_DESERIALIZATION { message: &'static str },
    LOGIN_FAIL,
    NO_AUTH,
    ENTITY_NOT_FOUND { entity: &'static str, id: String },
    USER_ALREADY_EXISTS,
    SERVICE_ERROR,
    UNSUPPORTED_MEDIA,
}
// endregion: --- Client Error
