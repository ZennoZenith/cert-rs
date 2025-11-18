use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    challenge::Challenge, order::Identifier, utils::time::TimeRfc3339,
};

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
pub enum AuthorizationStatus {
    #[default]
    Pending,
    Valid,
    Invaid,
    Deactivated,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
    pub status: AuthorizationStatus,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<TimeRfc3339>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationWithUrl {
    pub url: Url,
    pub authorization: Authorization,
}
