//! Challenge responding/retrying
//!
//! To prove control of the identifier and receive authorization, the client
//! needs to provision the required challenge response based on the challenge
//! type and indicate to the server that it is ready for the challenge validation
//! to be attempted.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    Result,
    account::Account,
    api::{EmptyObject, EmptyString},
    time::TimeRfc3339,
};

/// Challenge Status
///
/// Defined in [RFC 8555 §7.1.6].
///
/// Challenge objects are created in the "pending" state. They transition to the
/// "processing" state when the client responds to the challenge and the server
/// begins attempting to validate that the client has completed the challenge.
/// Note that within the "processing" state, the server may attempt to validate the
/// challenge multiple times. Likewise, client requests for retries do not cause a
/// state change. If validation is successful, the challenge moves to the "valid"
/// state; if there is an error, the challenge moves to the "invalid" state.
///
/// ```text
///             pending
///               |
///               | Receive
///               | response
///               V
///           processing <-+
///               |   |    | Server retry or
///               |   |    | client retry request
///               |   +----+
///               |
///               |
///   Successful  |   Failed
///   validation  |   validation
///     +---------+---------+
///     |                   |
///     V                   V
///   valid              invalid
///
///                  State Transitions for Challenge Objects
///
/// ```
///
/// [RFC 8555 §7.1.6]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6
#[derive(
    Debug,
    Clone,
    Copy,
    Deserialize,
    Serialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    #[default]
    Pending,
    Processing,
    Valid,
    Invaid,
}

/// Challenge objects all contain the following basic fields.
///
/// All additional fields are specified by the challenge type.
///
/// `type`: The type of challenge encoded in the object is defined by [``KnownChallenge``].
///
/// All additional fields are specified by the challenge type
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeBase {
    pub url: Url,
    pub status: ChallengeStatus,
    pub validated: Option<TimeRfc3339>,
    // TODO: Error object
    pub error: Option<serde_json::Value>,
}

/// HTTP Challenge. Defined in [RFC 8555 §8.3](https://datatracker.ietf.org/doc/html/rfc8555#section-8.3)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http01Challenge {
    #[serde(flatten)]
    pub base: ChallengeBase,

    pub token: Box<str>,
}

/// DNS Challenge. Defined in [RFC 8555 §8.4](https://datatracker.ietf.org/doc/html/rfc8555#section-8.4)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Dns01Challenge {
    #[serde(flatten)]
    pub base: ChallengeBase,

    pub token: Box<str>,
}

/// TODO: Not defined in rfc 8555
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAlpn01Challenge {
    #[serde(flatten)]
    pub base: ChallengeBase,
    // TODO:
    // pub token: Box<str>,
}

/// ACME clients must ignore unknown challenge types per the spec.
///
/// From RFC 8555 Section 7.1.4:
///
/// Clients should ignore challenge types they do not recognize.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum KnownChallenge {
    /// HTTP Challenge. Defined in [RFC 8555 §8.3](https://datatracker.ietf.org/doc/html/rfc8555#section-8.3)
    #[serde(rename = "http-01")]
    Http01(Http01Challenge),

    /// DNS Challenge. Defined in [RFC 8555 §8.4](https://datatracker.ietf.org/doc/html/rfc8555#section-8.4)
    #[serde(rename = "dns-01")]
    Dns01(Dns01Challenge),

    // TODO: tls-alpn-01 is not defined in RFC 8555
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01(TlsAlpn01Challenge),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnknownChallenge {
    #[serde(rename = "type")]
    pub type_: Box<str>,

    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// An ACME challenge object represents a server's offer to validate a
/// client's possession of an identifier in a specific way.
///
/// Unlike the other objects, there is not a single standard structure
/// for a challenge object. The contents of a challenge object depend on
/// the validation method being used. The general structure of challenge
/// objects and an initial set of validation methods are described in
/// [RFC 8555 §8](https://datatracker.ietf.org/doc/html/rfc8555#section-8)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Challenge {
    Known(KnownChallenge),
    Unknown(UnknownChallenge),
}

impl Challenge {
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        matches!(self, Self::Known { .. })
    }
}

impl KnownChallenge {
    #[must_use]
    pub const fn base(&self) -> &ChallengeBase {
        match self {
            Self::Http01(Http01Challenge { base, .. })
            | Self::Dns01(Dns01Challenge { base, .. })
            | Self::TlsAlpn01(TlsAlpn01Challenge { base, .. }) => base,
        }
    }

    /// Retruns Option because later new challenge type might not have token field
    #[must_use]
    pub const fn token(&self) -> Option<&str> {
        match self {
            Self::Http01(Http01Challenge { token, .. })
            | Self::Dns01(Dns01Challenge { token, .. }) => Some(token),
            Self::TlsAlpn01(_) => None,
        }
    }

    /// Responds to an ACME challenge by notifying the server that the client
    /// is ready for validation.
    ///
    /// This sends an empty JSON object (`{}`) in a signed POST request to the
    /// **challenge URL** (not the authorization URL).
    ///
    /// # ACME Context
    /// As defined in RFC [8555 §7.5.1], once the client has fulfilled the
    /// requirements of a challenge (e.g., provisioning an HTTP resource or DNS
    /// record), it must explicitly notify the ACME server to begin validation.
    ///
    /// This is done by sending a POST request with an empty payload to the
    /// challenge URL. The server will then attempt to validate the challenge
    /// asynchronously.
    ///
    /// The returned challenge object reflects the updated state, which may still
    /// be `pending` or transition to `processing`.
    ///
    /// # Parameters
    /// - `account`: The ACME account used to authenticate the request.
    /// - `url`: The challenge URL to which the response should be sent.
    ///
    /// # Returns
    /// The updated challenge object as returned by the ACME server.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The POST request to the challenge URL fails (e.g., network, TLS,
    ///   or request signing issues).
    /// - The server responds with a non-success status code.
    /// - The response body cannot be deserialized into a challenge object.
    /// - The ACME server returns a malformed or unexpected response.
    ///
    /// Any error from HTTP communication or JSON deserialization is propagated
    /// as [``crate::Error``].
    ///
    /// [RFC 8555 §7.5.1]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1
    pub async fn respond(account: &Account, url: &Url) -> Result<Self> {
        let response = account
            .client
            .post(
                url,
                &account.credentials.key,
                account.auth_kid(),
                &EmptyObject,
            )
            .await?;

        let challenge = response.json::<Self>().await?;
        Ok(challenge)
    }

    /// Retries an ACME challenge by re-sending a response to the challenge URL.
    ///
    /// This is equivalent to calling [`Self::respond`] again, allowing the client
    /// to explicitly request the ACME server to re-attempt validation.
    ///
    /// # ACME Context
    /// As described in RFC [8555 §8.2], if a challenge validation fails (e.g.,
    /// due to transient issues like DNS propagation delays or temporary
    /// misconfiguration), the client may retry by submitting another response
    /// to the same challenge URL.
    ///
    /// The server will then perform a new validation attempt.
    ///
    /// # Parameters
    /// - `account`: The ACME account used to authenticate the request.
    /// - `url`: The challenge URL to retry.
    ///
    /// # Returns
    /// The updated challenge object as returned by the ACME server.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The POST request to the challenge URL fails (e.g., network, TLS,
    ///   or request signing issues).
    /// - The server responds with a non-success status code.
    /// - The response body cannot be deserialized into a challenge object.
    /// - The ACME server rejects the retry request (e.g., challenge is no longer retryable).
    /// - The ACME server returns a malformed or unexpected response.
    ///
    /// Any error from [`Self::respond`] is propagated as [``crate::Error``].
    ///
    /// [RFC 8555 §8.2]: https://datatracker.ietf.org/doc/html/rfc8555#section-8.2
    pub async fn retry(account: &Account, url: &Url) -> Result<Self> {
        Self::respond(account, url).await
    }

    /// Retrieves the current state of an ACME challenge.
    ///
    /// This performs a POST-as-GET request to the challenge URL and returns
    /// the latest representation of the challenge object.
    ///
    /// # ACME Context
    /// In [RFC 8555], challenge resources are queried using POST-as-GET requests
    /// (i.e., POST with an empty payload) authenticated with the account's `kid`.
    ///
    /// Clients typically use this to:
    /// - Poll the status of a challenge after responding
    /// - Inspect validation results (e.g., `pending`, `processing`, `valid`, `invalid`)
    ///
    /// # Parameters
    /// - `account`: The ACME account used to authenticate the request.
    /// - `url`: The challenge URL to fetch.
    ///
    /// # Returns
    /// The current challenge object as returned by the ACME server.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The POST-as-GET request to the challenge URL fails (e.g., network,
    ///   TLS, or request signing issues).
    /// - The server responds with a non-success status code.
    /// - The response body cannot be deserialized into a challenge object.
    /// - The ACME server returns a malformed or unexpected response.
    ///
    /// Any error from HTTP communication or JSON deserialization is propagated
    /// as [``crate::Error``].
    ///
    /// [RFC 8555]: https://datatracker.ietf.org/doc/html/rfc8555
    pub async fn get(account: &Account, url: &Url) -> Result<Self> {
        let response = account
            .client
            .post(
                url,
                &account.credentials.key,
                account.auth_kid(),
                &EmptyString,
            )
            .await?;

        let challenge = response.json::<Self>().await?;
        Ok(challenge)
    }
}
