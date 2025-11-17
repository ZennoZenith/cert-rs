use lib_utils::time::TimeRfc3339;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{challenge::Challenge, order::Identifier};

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
pub(crate) enum AuthorizationStatus {
    #[default]
    Pending,
    Valid,
    Invaid,
    Deactivated,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Authorization {
    pub(crate) status: AuthorizationStatus,
    pub(crate) identifier: Identifier,
    pub(crate) challenges: Vec<Challenge>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires: Option<TimeRfc3339>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) wildcard: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AuthorizationWithUrl {
    pub(crate) url: Url,
    pub(crate) authorization: Authorization,
}
