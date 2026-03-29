use http::{
    HeaderMap, HeaderValue,
    header::{CONTENT_TYPE, LOCATION, USER_AGENT},
};
use mime::Mime;
use reqwest::{RequestBuilder, Response};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeMap as _};
use std::fmt;
use url::Url;

use crate::Client;

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

    #[error("Max Nonce Retry reached. max = {0}")]
    MaxNonceRetry(usize),

    #[error("{0}")]
    AcmeErrorParse(String),

    #[error("{0}")]
    AcmeError(AcmeError),

    #[error("Invalid Mime: {0}")]
    InvalidContentType(Mime),

    /// Header name does not exist
    #[error("{0}")]
    MissingHeaderName(&'static str),

    /// Header value does not exist
    #[error("{0}")]
    MissingHeaderValue(&'static str),
}

/// ```json
/// {
///    "type": "urn:ietf:params:acme:error:malformed",
///    "detail": "All requests MUST include a User-Agent header",
///    "status": 400
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub struct AcmeError {
    #[serde(rename = "type")]
    pub type_: AcmeErrorType,
    pub detail: Box<str>,
    pub status: u16,
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} (HTTP {})", self.type_, self.detail, self.status)
    }
}

#[derive(Debug, Clone, Serialize, strum_macros::Display)]
// TODO: add rfc section for all error types
pub enum AcmeErrorType {
    /// The request specified an account that does not exist
    AccountDoesNotExist,

    /// The request specified a certificate to be revoked that has already been revoked
    AlreadyRevoked,

    /// The CSR is unacceptable (e.g., due to a short key)
    BadCSR,

    /// The client sent an unacceptable anti- replay nonce
    BadNonce,

    /// The JWS was signed by a public key the server does not support
    BadPublicKey,

    /// The revocation reason provided is not allowed by the server
    BadRevocationReason,

    /// The JWS was signed with an algorithm the server does not support
    BadSignatureAlgorithm,

    /// Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate
    Caa,

    /// Specific error conditions are indicated in the "subproblems" array
    Compound,

    /// The server could not connect to validation target
    Connection,

    /// There was a problem with a DNS query during identifier validation
    Dns,

    /// The request must include a value for the "externalAccountBinding" field
    ExternalAccountRequired,

    /// Response received didn't match the challenge's requirements
    IncorrectResponse,

    /// A contact URL for an account was invalid
    InvalidContact,

    /// The request message was malformed
    Malformed,

    /// The request attempted to finalize an order that is not ready to be finalized
    OrderNotReady,

    /// The request exceeds a rate limit
    RateLimited,

    /// The server will not issue certificates for the identifier
    RejectedIdentifier,

    /// The server experienced an internal error
    ServerInternal,

    /// The server received a TLS error during validation
    Tls,

    /// The client lacks sufficient authorization
    Unauthorized,

    /// A contact URL for an account used an unsupported protocol scheme
    UnsupportedContact,

    /// An identifier is of an unsupported type
    UnsupportedIdentifier,

    /// Visit the "instance" URL and take actions specified there
    UserActionRequired,

    /// Variant not defined in [RFC 8555]
    ///
    /// [RFC 8555]: https://www.rfc-editor.org/rfc/rfc8555
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
            "accountDoesNotExist" => Self::AccountDoesNotExist,
            "alreadyRevoked" => Self::AlreadyRevoked,
            "badCSR" => Self::BadCSR,
            "badNonce" => Self::BadNonce,
            "badPublicKey" => Self::BadPublicKey,
            "badRevocationReason" => Self::BadRevocationReason,
            "badSignatureAlgorithm" => Self::BadSignatureAlgorithm,
            "caa" => Self::Caa,
            "compound" => Self::Compound,
            "connection" => Self::Connection,
            "dns" => Self::Dns,
            "externalAccountRequired" => Self::ExternalAccountRequired,
            "incorrectResponse" => Self::IncorrectResponse,
            "invalidContact" => Self::InvalidContact,
            "malformed" => Self::Malformed,
            "orderNotReady" => Self::OrderNotReady,
            "rateLimited" => Self::RateLimited,
            "rejectedIdentifier" => Self::RejectedIdentifier,
            "serverInternal" => Self::ServerInternal,
            "tls" => Self::Tls,
            "unauthorized" => Self::Unauthorized,
            "unsupportedContact" => Self::UnsupportedContact,
            "unsupportedIdentifier" => Self::UnsupportedIdentifier,
            "userActionRequired" => Self::UserActionRequired,
            _ => Self::Unknown(name.into()),
        };

        Ok(err)
    }
}

pub fn extract_location_header(headers: &HeaderMap) -> Result<Url> {
    headers
        .get(LOCATION)
        // TODO: handle error
        .and_then(|v| v.to_str().unwrap_or_default().parse::<Url>().ok())
        .ok_or(Error::MissingHeaderName(LOCATION.as_str()))
}

async fn parse_acme_error(response: Response) -> Result<AcmeError> {
    response
        .json::<AcmeError>()
        .await
        .map_err(|e| Error::AcmeErrorParse(e.to_string()))
}

pub trait RequestBuilderExt {
    fn add_rfc_headers(self) -> Self;
}

impl RequestBuilderExt for RequestBuilder {
    fn add_rfc_headers(self) -> Self {
        // TODO: add rfc section here
        self.header(USER_AGENT, HeaderValue::from_static("cert-rs 0.1"))
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/jose+json"),
            )
    }
}

pub trait ResponseExt {
    async fn extract_nonce(self, client: &Client) -> Self;

    async fn handle_response_error(self) -> Result<Self>
    where
        Self: std::marker::Sized;
}

impl ResponseExt for Response {
    async fn extract_nonce(self, client: &Client) -> Self {
        client.enqueue_nonce(self.headers()).await;

        self
    }

    async fn handle_response_error(self) -> Result<Self> {
        let headers = self.headers();
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
            let acme_error = parse_acme_error(self).await?;
            return Err(Error::AcmeError(acme_error));
        }

        match (mime.type_(), mime.subtype()) {
            (mime::APPLICATION, mime::JSON) => (),
            (mime::APPLICATION, name) if name.as_str() == "pem-certificate-chain" => (),
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

        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub enum AcmeApiBody<T = ()>
where
    T: Serialize + fmt::Debug,
{
    EmptyString,
    EmptyObject,
    Other(T),
}

impl AcmeApiBody<()> {
    pub const EMPTY_STRING: Self = Self::EmptyString;
    pub const EMPTY_OBJECT: Self = Self::EmptyObject;
}

impl<T> Serialize for AcmeApiBody<T>
where
    T: Serialize + fmt::Debug + Clone,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // EmptyString   ->  ""
        // EmptyObject   ->  {}
        // Other(T)      ->  serialization of T
        match self {
            Self::EmptyString => serializer.serialize_str(""),
            Self::EmptyObject => {
                let map = serializer.serialize_map(Some(0))?;
                map.end()
            }
            Self::Other(v) => v.serialize(serializer),
        }
    }
}

// region:    --- Tests
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde::Serialize;

    fn parse(json: &str) -> AcmeError {
        serde_json::from_str(json).expect("failed to parse acme error")
    }

    #[test]
    fn serialize_empty_string() {
        let body: AcmeApiBody = AcmeApiBody::EmptyString;

        let json =
            serde_json::to_string(&body).expect("failed to convert acme api body to json string");

        assert_eq!(json, r#""""#);
    }

    #[test]
    fn serialize_empty_object() {
        let body: AcmeApiBody = AcmeApiBody::EmptyObject;

        let json =
            serde_json::to_string(&body).expect("failed to convert acme api body to json string");

        assert_eq!(json, "{}");
    }

    #[test]
    fn serialize_other_struct() {
        #[derive(Serialize, Debug, Clone)]
        struct Payload {
            a: u32,
            b: &'static str,
        }

        let body = AcmeApiBody::Other(Payload { a: 1, b: "test" });

        let json =
            serde_json::to_string(&body).expect("failed to convert acme api body to json string");

        assert_eq!(json, r#"{"a":1,"b":"test"}"#);
    }

    #[test]
    fn serialize_other_primitive() {
        let body = AcmeApiBody::Other(42u32);

        let json =
            serde_json::to_string(&body).expect("failed to convert acme api body to json string");

        assert_eq!(json, "42");
    }

    #[test]
    fn serialize_other_array() {
        let body = AcmeApiBody::Other(vec![1, 2, 3]);

        let json =
            serde_json::to_string(&body).expect("failed to convert acme api body to json string");

        assert_eq!(json, "[1,2,3]");
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
