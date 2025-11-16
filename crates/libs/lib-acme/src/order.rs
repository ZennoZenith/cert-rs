use std::iter::zip;

use serde::Deserialize;
use url::Url;

use crate::challange::AuthZ;

#[derive(Debug, Deserialize)]
pub(crate) struct Identifier {
    pub(crate) r#type: String,
    pub(crate) value: String,
}

/// headers:
///
/// ```json
///{
///    "location": "https://<host>/my-order/FGCGiiJ2yHuTSkNtg7kYJBETqIYlKbtXeqg9KXmIJEg",
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
///   "finalize": "https://<host>/finalize-order/Mkwup-NKFRSiVdl3Mjc7c0y0shW6Em0--gZLe9KQkio",
///   "authorizations": [
///      "https://<host>/authZ/hXIxKCZwI8BhmGQhn16d98YMqHw5ldMOnnaGm5O_a34",
///      "https://<host>/authZ/q1HUYPqI2BFX-DuZhy2UNvNRMGnXxFz65xmXmY_Xy4o"
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
