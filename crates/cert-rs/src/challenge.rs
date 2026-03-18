use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    AcmeClient, Result,
    account::Account,
    api::{AcmeApiBody, RequestBuilderExt as _, ResponseExt as _},
    authentication::{JwkOrKid, Jws},
    time::TimeRfc3339,
};

// /// ACME clients must ignore unknown challenge types per the spec.
// ///
// /// From RFC 8555 Section 7.1.4:
// ///
// /// Clients should ignore challenge types they do not recognize.
// #[derive(
//     Debug,
//     Clone,
//     Copy,
//     strum_macros::Display,
//     strum_macros::EnumString,
//     strum_macros::IntoStaticStr,
//     PartialEq,
//     Eq,
// )]
// #[non_exhaustive]
// pub enum ChallengeType {
//     Http01,
//     Dns01,
//     // // TODO: tls-alpn-01 is not defined in RFC 8555
//     // TlsAlpn01,
// }

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
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ChallengeStatus {
    #[default]
    Pending,
    Processing,
    Valid,
    Invaid,
}

/// basic field
///
/// All additional fields are specified by the challenge type.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeBase {
    pub url: Url,
    pub status: ChallengeStatus,
    pub validated: Option<TimeRfc3339>,
    // TODO: Error object
    pub error: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http01Challenge {
    #[serde(flatten)]
    pub base: ChallengeBase,

    pub token: Box<str>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Dns01Challenge {
    #[serde(flatten)]
    pub base: ChallengeBase,

    pub token: Box<str>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsAlpn01Challenge {
    #[serde(flatten)]
    pub base: ChallengeBase,
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
    #[serde(rename = "http-01")]
    Http01(Http01Challenge),

    #[serde(rename = "dns-01")]
    Dns01(Dns01Challenge),
    // // TODO: tls-alpn-01 is not defined in RFC 8555
    // #[serde(rename = "tls-alpn-01")]
    // TlsAlpn01(TlsAlpn01Challenge),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnknownChallenge {
    #[serde(rename = "type")]
    pub type_: Box<str>,

    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// [RFC 8555 section 8]: https://www.rfc-editor.org/rfc/rfc8555#section-8
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
            | Self::Dns01(Dns01Challenge { base, .. }) => base,
        }
    }

    /// Retruns Option because later new challenge type might not have token field
    #[must_use]
    pub const fn token(&self) -> Option<&str> {
        match self {
            Self::Http01(Http01Challenge { token, .. })
            | Self::Dns01(Dns01Challenge { token, .. }) => Some(token),
        }
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn respond(acme_client: &AcmeClient, account: &Account, url: &Url) -> Result<Self> {
        let url = &url;

        let nonce = &acme_client.nonce().await?;

        let auth = JwkOrKid::Kid(account.account_id().clone());
        let body = AcmeApiBody::EMPTY_OBJECT;
        let jws = Jws::new_from_parts(account.private_key().clone(), url, auth, nonce, body);

        let response = acme_client
            .client()
            .post(url.as_str())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?
            .handle_response_error()
            .await?;

        let challenge = response.json::<Self>().await?;
        Ok(challenge)
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn get(acme_client: &AcmeClient, account: &Account, url: &Url) -> Result<Self> {
        let url = &url;

        let nonce = &acme_client.nonce().await?;

        let auth = JwkOrKid::Kid(account.account_id().clone());
        let body = AcmeApiBody::EMPTY_STRING;
        let jws = Jws::new_from_parts(account.private_key().clone(), url, auth, nonce, body);

        let response = acme_client
            .client()
            .post(url.as_str())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?
            .handle_response_error()
            .await?;

        let challenge = response.json::<Self>().await?;
        Ok(challenge)
    }
}
