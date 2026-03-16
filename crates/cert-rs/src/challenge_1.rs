use serde::{Deserialize, Serialize};
use url::Url;

use crate::time::TimeRfc3339;

/// ACME clients must ignore unknown challenge types per the spec.
///
/// From RFC 8555 Section 7.1.4:
///
/// Clients should ignore challenge types they do not recognize.
#[derive(
    Debug,
    Clone,
    Deserialize,
    Serialize,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01 { token: Box<str> },

    #[serde(rename = "dns-01")]
    Dns01 { token: Box<str> },

    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01 { token: Box<str> },

    /// Example
    /// dns-account-01 -> Pebble-specific account-based DNS validation
    /// dns-persist-01 -> Pebble persistence testing
    Unknown,
}

// #[derive(
//     Debug,
//     Clone,
//     Deserialize,
//     Serialize,
//     Default,
//     strum_macros::Display,
//     strum_macros::EnumString,
//     strum_macros::IntoStaticStr,
//     PartialEq,
//     Eq,
// )]
// #[strum(ascii_case_insensitive)]
// #[strum(serialize_all = "kebab-case")]
// #[serde(rename_all = "kebab-case")]
// #[non_exhaustive]
// pub enum ChallengeType {
//     #[default]
//     Http01,

//     Dns01,

//     TlsAlpn01,

//     /// Example
//     /// dns-account-01 -> Pebble-specific account-based DNS validation
//     /// dns-persist-01 -> Pebble persistence testing
//     Unknown(Box<str>),
// }

impl ChallengeType {
    pub const fn is_supported(&self) -> bool {
        matches!(
            self,
            Self::Http01 { .. } | Self::Dns01 { .. } | Self::TlsAlpn01 { .. }
        )
    }
}

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

/// [RFC 8555 section 8]: https://www.rfc-editor.org/rfc/rfc8555#section-8
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    // basic field
    // #[serde(rename = "type")]
    #[serde(flatten)]
    pub type_: ChallengeType,
    pub url: Url,
    pub status: ChallengeStatus,
    pub validated: Option<TimeRfc3339>,
    // TODO: Error object
    pub error: Option<serde_json::Value>,
    // // All additional fields are specified by the challenge type.
    // pub token: String,
}

#[derive(Debug, Clone)]
pub struct ChallengeResponder {
    pub domain: String,
    pub r#type: ChallengeType,
    pub token: String,
    /// {token}.{jwk_thumbprint}, used of http-01 challange
    pub keyauth: String,
    /// keyauth -> sha256 -> bash64url, used of dns-01 challange
    pub sha_256_keyauth: String,
    pub challange_response_url: Url,
    pub authorization_url: Url,
}
