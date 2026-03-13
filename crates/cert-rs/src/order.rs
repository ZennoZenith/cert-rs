use crate::time::TimeRfc3339;

use serde::{Deserialize, Serialize};
use url::Url;

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
pub enum IdentifierType {
    #[default]
    #[serde(rename = "dns")]
    #[strum(serialize = "dns")]
    Dns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identifier {
    pub r#type: IdentifierType,
    pub value: String,
}

impl<T: ToString> From<T> for Identifier {
    fn from(value: T) -> Self {
        Self {
            r#type: IdentifierType::Dns,
            value: value.to_string(),
        }
    }
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
pub enum OrderStatus {
    #[default]
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub status: OrderStatus,
    pub identifiers: Vec<Identifier>,
    pub authorizations: Vec<Url>,
    pub finalize: Url,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<TimeRfc3339>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<TimeRfc3339>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<TimeRfc3339>,
    // TODO: error object type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Url>,
}
