use http::{
    HeaderMap, HeaderValue,
    header::{CONTENT_TYPE, USER_AGENT},
};
use mime::Mime;
use reqwest::{Client, IntoUrl, Response};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::VecDeque, fmt};
use tokio::sync::Mutex;
use url::Url;

const ACME_PREFIX: &str = "urn:ietf:params:acme:error:";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    HeaderToStr(#[from] http::header::ToStrError),

    #[error(transparent)]
    MimeFromStr(#[from] mime::FromStrError),

    #[error("{0}")]
    JsonParse(String),

    #[error("Cannot extract content-type from response")]
    ContentType,

    #[error("{0}")]
    AcmeErrorParse(String),

    #[error("{0}")]
    AcmeError(AcmeError),

    #[error("Invalid Mime: {0}")]
    InvalidContentType(Mime),

    #[error("replay-nonce header not found in request")]
    ReplayNonce,
}

/// ```json
/// {
///    "type": "urn:ietf:params:acme:error:malformed",
///    "detail": "All requests MUST include a User-Agent header",
///    "status": 400
/// }
/// ```
#[derive(Debug, Clone, Deserialize, thiserror::Error)]
pub struct AcmeError {
    #[serde(rename = "type")]
    type_: AcmeErrorType,
    detail: Box<str>,
    status: u16,
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} (HTTP {})", self.type_, self.detail, self.status)
    }
}

#[derive(Debug, Clone, strum_macros::Display)]
// TODO: is this better?
// #[strum(prefix = "urn:ietf:params:acme:error:")]
pub enum AcmeErrorType {
    AccountDoesNotExist,
    AlreadyRevoked,
    BadCSR,
    BadNonce,
    BadSignatureAlgorithm,
    Caa,
    Connection,
    Dns,
    ExternalAccountRequired,
    IncorrectResponse,
    InvalidContact,
    Malformed,
    RateLimited,
    RejectedIdentifier,
    ServerInternal,
    Tls,
    Unauthorized,
    UnsupportedIdentifier,
    UserActionRequired,

    #[strum(serialize = "Unknown({0})")]
    Unknown(Box<str>),
}

impl<'de> Deserialize<'de> for AcmeErrorType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let name = s.strip_prefix(ACME_PREFIX).unwrap_or(&s);

        // TODO: add rfc section for all error types
        let err = match name {
            // "accountDoesNotExist" => Self::AccountDoesNotExist,
            // "alreadyRevoked" => Self::AlreadyRevoked,
            // "badCSR" => Self::BadCSR,
            // "badNonce" => Self::BadNonce,
            // "badSignatureAlgorithm" => Self::BadSignatureAlgorithm,
            // "caa" => Self::Caa,
            // "connection" => Self::Connection,
            // "dns" => Self::Dns,
            // "externalAccountRequired" => Self::ExternalAccountRequired,
            // "incorrectResponse" => Self::IncorrectResponse,
            // "invalidContact" => Self::InvalidContact,
            "malformed" => Self::Malformed,
            // "rateLimited" => Self::RateLimited,
            // "rejectedIdentifier" => Self::RejectedIdentifier,
            // "serverInternal" => Self::ServerInternal,
            // "tls" => Self::Tls,
            // "unauthorized" => Self::Unauthorized,
            // "unsupportedIdentifier" => Self::UnsupportedIdentifier,
            // "userActionRequired" => Self::UserActionRequired,
            _ => Self::Unknown(name.into()),
        };

        Ok(err)
    }
}

pub fn reqwest_client_builder() -> Result<Client> {
    let client_builder = Client::builder();

    let danger_accept_invalid_certs: bool = std::env::var("DANGER_ACCEPT_INVALID_CERTS")
        .is_ok_and(|v| v.to_lowercase() == "true" || v.parse::<u8>().unwrap_or(0) == 1);

    let client_builder = if danger_accept_invalid_certs {
        client_builder.danger_accept_invalid_certs(true)
    } else {
        client_builder
    };

    Ok(client_builder.build()?)
}

async fn parse_acme_error(response: Response) -> Result<AcmeError> {
    response
        .json::<AcmeError>()
        .await
        .map_err(|e| Error::AcmeErrorParse(e.to_string()))
}

async fn handle_response_error(response: Response) -> Result<Response> {
    let headers = response.headers();
    // dbg!(headers);

    let Some(ct) = headers.get(CONTENT_TYPE) else {
        return Err(Error::ContentType);
    };

    let mime: Mime = ct.to_str()?.parse()?;

    // dbg!(&mime);
    // dbg!(&mime.type_());
    // dbg!(&mime.subtype());

    if mime.type_() == mime::APPLICATION
        && mime.subtype() == "problem"
        && mime.suffix().is_some_and(|v| v == "json")
    {
        let acme_error = parse_acme_error(response).await?;
        return Err(Error::AcmeError(acme_error));
    }

    match (mime.type_(), mime.subtype()) {
        (mime::APPLICATION, mime::JSON) => (),
        // (mime::TEXT, mime::HTML) => println!("HTML"),
        // (mime::TEXT, mime::PLAIN) => println!("HTML"),
        _ => return Err(Error::InvalidContentType(mime)),
    }

    // TODO: ???
    // let status = response.status();
    // dbg!(status);
    // match status.as_u16() {
    //     100..=399 => (),
    //     400 => (),
    //     _ => (),
    // };

    Ok(response)
}

#[derive(Debug, Clone)]
pub(crate) struct GetRequest {
    pub(crate) url: Url,
    pub(crate) header: Option<HeaderMap>,
}

#[derive(Debug, Clone)]
pub(crate) struct PostRequest {
    pub(crate) url: Url,
    pub(crate) header: Option<HeaderMap>,
    pub(crate) body: String,
}

pub struct AcmeClient {
    reqwest_client: reqwest::Client,
    nonce_store: Mutex<VecDeque<Box<str>>>,
}

impl AcmeClient {
    pub fn new(reqwest_client: reqwest::Client) -> Self {
        Self {
            reqwest_client,
            nonce_store: Default::default(),
        }
    }

    pub(crate) async fn get(&self, request: GetRequest) -> Result<Response> {
        let mut headers = HeaderMap::new();

        // TODO: add rfc section here
        headers.insert(USER_AGENT, HeaderValue::from_static("cert-rs 0.1"));

        let response = self.reqwest_client.get(request.url).headers(headers).send().await?;

        let success_response = handle_response_error(response).await?;

        Ok(success_response)
    }

    pub(crate) async fn post(&self, request: PostRequest) -> Result<Response> {
        let mut headers = HeaderMap::new();

        // TODO: add rfc section here
        headers.insert(USER_AGENT, HeaderValue::from_static("cert-rs 0.1"));

        let response = self.reqwest_client.get(request.url).headers(headers).send().await?;

        let success_response = handle_response_error(response).await?;

        Ok(success_response)
    }

    fn extract_nonce(headers: &HeaderMap) -> Option<Box<str>> {
        headers
            .get("replay-nonce")
            .map(|v| v.to_str())
            .and_then(|v| v.ok())
            .map(Box::from)
    }

    pub async fn enqueue_nonce(&self, headers: &HeaderMap) {
        let Some(nonce) = Self::extract_nonce(headers) else {
            #[cfg(feature = "tracing")]
            tracing::warn!("replay-nonce header not found in request");

            return;
        };

        self.nonce_store.lock().await.push_back(nonce);
    }

    pub async fn nonce<U: IntoUrl>(&self, url: U) -> Result<Box<str>> {
        // // try get nonce from store
        let value = self.nonce_store.lock().await.pop_front();

        if let Some(nonce) = value {
            return Ok(nonce);
        };

        let response = self.reqwest_client.head(url).send().await?;
        let headers = response.headers();

        Self::extract_nonce(headers).ok_or(Error::ReplayNonce)
    }
}

#[derive(Debug, Clone)]
pub enum AcmeApiBody<T: Serialize + Clone = ()> {
    EmptyString,
    EmptyObject,
    Other(T),
}

// region:    --- Tests
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn parse(json: &str) -> AcmeError {
        serde_json::from_str(json).expect("failed to parse acme error")
    }

    #[test]
    fn malformed_error() {
        let json = r#"
        {
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "Request body was invalid",
            "status": 400
        }
        "#;

        let err = parse(json);

        match err.type_ {
            AcmeErrorType::Malformed => (),
            _ => panic!("expected malformed error"),
        }

        assert_eq!(err.detail, "Request body was invalid".into());
        assert_eq!(err.status, 400);
    }

    #[test]
    fn unknown_error_type() {
        let json = r#"
        {
            "type": "urn:ietf:params:acme:error:someNewError",
            "detail": "Something unexpected happened",
            "status": 500
        }
        "#;

        let err = parse(json);

        match err.type_ {
            AcmeErrorType::Unknown(code) => {
                assert_eq!(code, "someNewError".into());
            }
            _ => panic!("expected unknown error"),
        }

        assert_eq!(err.status, 500);
    }

    #[test]
    fn missing_prefix_fallback() {
        let json = r#"
        {
            "type": "malformed",
            "detail": "Bad request",
            "status": 400
        }
        "#;

        let err = parse(json);

        match err.type_ {
            AcmeErrorType::Malformed => (),
            _ => panic!("expected malformed"),
        }
    }

    #[test]
    fn display_format() {
        let json = r#"
        {
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "Invalid payload",
            "status": 400
        }
        "#;

        let err = parse(json);

        let msg = format!("{err}");
        dbg!(&msg);

        assert!(msg.contains("Malformed"));
        assert!(msg.contains("Invalid payload"));
        assert!(msg.contains("400"));
    }
}
// endregion: --- Tests
