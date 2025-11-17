use lib_utils::time::TimeRfc3339;
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
pub(crate) struct Identifier {
    pub(crate) r#type: IdentifierType,
    pub(crate) value: String,
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
pub(crate) enum OrderStatus {
    #[default]
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Order {
    pub(crate) status: OrderStatus,
    pub(crate) identifiers: Vec<Identifier>,
    pub(crate) authorizations: Vec<Url>,
    pub(crate) finalize: Url,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires: Option<TimeRfc3339>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) not_before: Option<TimeRfc3339>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) not_after: Option<TimeRfc3339>,
    // TODO: error object type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) certificate: Option<Url>,
}
