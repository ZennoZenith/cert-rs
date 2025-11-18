use serde::{Deserialize, Serialize};
use url::Url;

use crate::utils::time::TimeRfc3339;

#[derive(
    Debug,
    Clone,
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
#[strum(serialize_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ChallengeType {
    #[default]
    #[serde(rename = "http-01")]
    #[strum(serialize = "http-01")]
    Http01,

    #[serde(rename = "dns-01")]
    #[strum(serialize = "dns-01")]
    Dns01,

    #[serde(rename = "tls-alpn-01")]
    #[strum(serialize = "tls-alpn-01")]
    TlsAlpn01,

    #[serde(rename = "dns-account-01")]
    #[strum(serialize = "dns-account-01")]
    DnsAccount01,

    #[serde(untagged)]
    Unknown(String),
}

#[derive(
    Debug,
    Clone,
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

#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    pub r#type: ChallengeType,
    pub url: Url,
    pub status: ChallengeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated: Option<TimeRfc3339>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,

    /// Specific to challenge type
    pub token: String,
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
