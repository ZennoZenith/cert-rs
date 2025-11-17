use serde::{Deserialize, Serialize};
use url::Url;

use crate::challenge::AuthZ;

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

#[derive(Debug, Serialize, Deserialize)]
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

/// headers:
///
/// ```json
///{
///    "location": "https://example.com/my-order/FGCGiiJ2yHuTSkNtg7kYJBETqIYlKbtXeqg9KXmIJEg",
///}
/// ````
/// Body
///
/// ```jsonc
///{
///   "status": "pending",
///   "expires": "2025-11-16T18:33:30Z",
///   "identifiers": [
///      {
///         "type": "dns",
///         "value": "example.com"
///      },
///      {
///         "type": "dns",
///         "value": "*.example.com"
///      }
///   ],
///   "profile": "default", // "shortlived" ...,
///   "finalize": "https://example.com/finalize-order/Mkwup-NKFRSiVdl3Mjc7c0y0shW6Em0--gZLe9KQkio",
///   "authorizations": [
///      "https://example.com/authZ/hXIxKCZwI8BhmGQhn16d98YMqHw5ldMOnnaGm5O_a34",
///      "https://example.com/authZ/q1HUYPqI2BFX-DuZhy2UNvNRMGnXxFz65xmXmY_Xy4o"
///   ]
///}
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct OrderStatus {
    pub(crate) status: String,
    pub(crate) expires: String,
    pub(crate) identifiers: Vec<Identifier>,
    pub(crate) profile: String,
    pub(crate) finalize: Url,
    pub(crate) authorizations: Vec<Url>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Order {
    pub(crate) authorization: Url,
    pub(crate) auth_z: AuthZ,
}

impl From<(Url, AuthZ)> for Order {
    fn from((url, auth_z): (Url, AuthZ)) -> Self {
        Self {
            authorization: url,
            auth_z,
        }
    }
}
