use std::fmt;

use chrono::{DateTime, Duration, Utc};
use http::{
    HeaderMap, HeaderValue,
    header::{ACCEPT_LANGUAGE, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, RETRY_AFTER, USER_AGENT},
};
use mime::Mime;
use reqwest::{RequestBuilder, Response};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeMap as _};
use url::Url;

use crate::{CRATE_USER_AGENT, Client, Error, JOSE_JSON, LANGUAGE, Result, order::Identifier};

const ACME_PREFIX: &str = "urn:ietf:params:acme:error:";

/// # ACME problem document
///
/// See: [RFC 8555 §6.7](https://datatracker.ietf.org/doc/html/rfc8555#section-6.7),
/// [RFC 7807](https://datatracker.ietf.org/doc/html/rfc7807),
///
/// # Example
///
/// ```json
/// {
///    "type": "urn:ietf:params:acme:error:malformed",
///    "detail": "All requests MUST include a User-Agent header",
///    "status": 400
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub struct Problem {
    /// One of an enumerated list of problem types
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc8555#section-6.7>
    pub r#type: ProblemType,

    /// A human-readable explanation of the problem
    pub detail: Option<Box<str>>,

    /// The HTTP status code returned for this response
    pub status: Option<u16>,

    /// One or more subproblems associated with specific identifiers
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1>
    #[serde(default)]
    pub subproblems: Vec<Subproblem>,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("API error")?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }

        write!(f, " ({})", self.r#type)?;

        if !self.subproblems.is_empty() {
            let count = self.subproblems.len();
            write!(f, ": {count} subproblems: ")?;
            for (i, subproblem) in self.subproblems.iter().enumerate() {
                write!(f, "{subproblem}")?;
                if i != count - 1 {
                    f.write_str(", ")?;
                }
            }
        }

        Ok(())
    }

    // fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    //     write!(f, "{}: {} (HTTP {})", self.type_, self.detail, self.status)
    // }
}

/// An RFC 8555 subproblem document contained within a problem returned by the ACME server
///
/// See <https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1>
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subproblem {
    /// The identifier associated with this problem
    pub identifier: Option<Identifier>,
    /// One of an enumerated list of problem types
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc8555#section-6.7>
    pub r#type: Option<String>,
    /// A human-readable explanation of the problem
    pub detail: Option<String>,
}

impl fmt::Display for Subproblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(identifier) = &self.identifier {
            write!(f, r#"for "{identifier}""#)?;
        }

        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }

        if let Some(r#type) = &self.r#type {
            write!(f, " ({type})")?;
        }

        Ok(())
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, strum_macros::Display)]
/// # ACME Error Type.
///
/// Defined in [RFC 8555 §6.7].
/// This list is not exhaustive
///
/// [RFC 8555 §6.7]: https://datatracker.ietf.org/doc/html/rfc8555#section-6.7
pub enum ProblemType {
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

    /// Variant not defined in [RFC 8555 §6.7]
    ///
    /// [RFC 8555 §6.7]: https://datatracker.ietf.org/doc/html/rfc8555#section-6.7
    #[strum(serialize = "Unknown({0})")]
    Unknown(Box<str>),
}

impl<'de> Deserialize<'de> for ProblemType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let name = s.strip_prefix(ACME_PREFIX).unwrap_or(&s);

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

/// # Error
///
/// TODO:
/// - [``Error::MissingLocationHeader``]
/// - [``Error::LocationHeaderNotUrl``]
pub fn extract_location_header(headers: &HeaderMap) -> Result<Url> {
    let location_header = headers.get(LOCATION).ok_or(Error::Str("Missing Location header"))?;

    location_header
        .to_str()
        .map_err(|_| Error::Str("Cannot convert location header to string"))?
        .parse::<Url>()
        .map_err(|_| Error::Str("Cannot convert location header to Url"))
}

/// # Error
/// TODO:
pub fn extract_retry_after(headers: &HeaderMap) -> Result<DateTime<Utc>> {
    let value = headers
        .get(RETRY_AFTER)
        .ok_or(Error::Str("Retry After header not found"))?
        .to_str()
        .map_err(|_| Error::Str("Retry After header cannot be parsed as string"))?
        .trim();

    let now = Utc::now();

    // Case 1: seconds
    if let Ok(secs) = value.parse::<i64>() {
        return Ok(now + Duration::seconds(secs));
    }

    // Case 2: `HTTP-date` looks like `Fri, 31 Dec 1999 23:59:59 GMT`
    httpdate::parse_http_date(value)
        .map(Into::into)
        .map_err(|_| Error::Str("Retry After header cannot be parsed.")) // Case 3: invalid header
}

async fn parse_acme_error(response: Response) -> Result<Problem> {
    response.json::<Problem>().await.map_err(Into::into)
}

pub trait RequestBuilderExt {
    fn add_rfc_headers(self) -> Self;
}

impl RequestBuilderExt for RequestBuilder {
    /// See [RFC 8555 §6.2](https://datatracker.ietf.org/doc/html/rfc8555#section-6.1),
    /// [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231)
    fn add_rfc_headers(self) -> Self {
        self.header(USER_AGENT, HeaderValue::from_static(CRATE_USER_AGENT))
            .header(CONTENT_TYPE, HeaderValue::from_static(JOSE_JSON))
            .header(ACCEPT_LANGUAGE, HeaderValue::from_static(LANGUAGE))
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

        if let Some(content_length) = headers.get(CONTENT_LENGTH)
            && content_length == HeaderValue::from_static("0")
        {
            return Ok(self);
        }

        let Some(content_type) = headers.get(CONTENT_TYPE) else {
            return Err(Error::Str("Cannot extract content-type from response"));
        };

        let mime: Mime = content_type
            .to_str()
            .map_err(|_| Error::Str("Cannot convert content-type header to string"))?
            .parse()
            .map_err(|_| Error::Str("Cannot convert content-type header to mime type"))?;

        if mime.type_() == mime::APPLICATION
            && mime.subtype() == "problem"
            && mime.suffix().is_some_and(|v| v == "json")
        {
            let problem = parse_acme_error(self).await?;
            return Err(Error::Problem(problem));
        }

        match (mime.type_(), mime.subtype()) {
            (mime::APPLICATION, mime::JSON) => (),
            (mime::APPLICATION, name) if name.as_str() == "pem-certificate-chain" => (),
            // (mime::TEXT, mime::HTML) => println!("HTML"),
            // (mime::TEXT, mime::PLAIN) => println!("HTML"),
            _ => {
                return Err(Error::Str(
                    "The response MIME type is not an accepted ACME media type",
                ));
            }
        }

        // TODO: ???
        // let status = response.status();
        // match status.as_u16() {
        //     100..=399 => (),
        //     400 => (),
        //     _ => (),
        // };

        Ok(self)
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct EmptyString;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct EmptyObject;

impl Serialize for EmptyString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("")
    }
}

impl Serialize for EmptyObject {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_map(Some(0))?.end()
    }
}

// region:    --- Tests
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde::Serialize;

    fn parse(json: &str) -> Problem {
        serde_json::from_str(json).expect("failed to parse acme error")
    }

    #[test]
    fn serialize_empty_string() {
        let body = EmptyString;

        let json =
            serde_json::to_string(&body).expect("failed to convert acme api body to json string");

        assert_eq!(json, r#""""#);
    }

    #[test]
    fn serialize_empty_object() {
        let body = EmptyObject;

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

        let body = Payload { a: 1, b: "test" };

        let json =
            serde_json::to_string(&body).expect("failed to convert acme api body to json string");

        assert_eq!(json, r#"{"a":1,"b":"test"}"#);
    }

    #[test]
    fn serialize_other_primitive() {
        let body = 42u32;

        let json =
            serde_json::to_string(&body).expect("failed to convert acme api body to json string");

        assert_eq!(json, "42");
    }

    #[test]
    fn serialize_other_array() {
        let body = vec![1, 2, 3];

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

        match err.r#type {
            ProblemType::Malformed => (),
            _ => panic!("expected malformed error"),
        }

        assert_eq!(err.detail, Some("Request body was invalid".into()));
        assert_eq!(err.status, Some(400));
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

        match err.r#type {
            ProblemType::Unknown(code) => {
                assert_eq!(code, "someNewError".into());
            }
            _ => panic!("expected unknown error"),
        }

        assert_eq!(err.status, Some(500));
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

        match err.r#type {
            ProblemType::Malformed => (),
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
        println!("{msg}");

        assert!(msg.contains("Malformed"));
        assert!(msg.contains("Invalid payload"));
        assert!(msg.contains("400"));
    }
}
// endregion: --- Tests
