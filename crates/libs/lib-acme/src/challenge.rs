use serde::Deserialize;
use url::Url;

use crate::order::Identifier;

///```json
///{
///   "status": "pending",
///   "identifier": {
///      "type": "dns",
///      "value": "test.com"
///   },
///   "challenges": [
///      {
///         "type": "http-01",
///         "url": "https://<host>/chalZ/CBFrgdBV4mLzJh7mkieu7kSZq_Fd02s_YyUrrbB25Ko",
///         "token": "xJ9Wg4G20OlC5ovxjv3qqTfIJHFdAdlRo8pazT4yHko",
///         "status": "pending"
///      },
///      {
///         "type": "dns-01",
///         "url": "https://<host>/chalZ/UTvYhc4NAEtGOS3yclO4t7eZG3yzQW_Mc0NWjUXhflw",
///         "token": "K3LldHaVl2Ovrr3M1Y5L09jATVv-enf7R42k4iS-vMU",
///         "status": "pending"
///      },
///      {
///         "type": "tls-alpn-01",
///         "url": "https://<host>/chalZ/qyvqAvbpv3oQLSYX0_73IDHv3Fvuzr-CyszmQb3vQUk",
///         "token": "KLBhCfj33nyz44aWPfniOPgxskN6psRAlFxSpNdUHG8",
///         "status": "pending"
///      },
///      {
///         "type": "dns-account-01",
///         "url": "https://<host>/chalZ/JgqFvvAs_T8gu1FaIjto0HyKDunr_4JCbnh1vK-Q1xE",
///         "token": "j0_JMI937tgbIqZ6l0tHyFD7DI6b4lYVxhIf26Opg5E",
///         "status": "pending"
///      }
///   ],
///   "expires": "2025-11-16T06:06:10Z"
///}
///```
#[derive(Debug, Deserialize)]
pub(crate) struct AuthZ {
    pub(crate) status: String,
    pub(crate) identifier: Identifier,
    pub(crate) challenges: Vec<Challenge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) wildcard: Option<bool>,
    pub(crate) expires: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    #[serde(rename = "dns-account-01")]
    DnsAccount01,
}

///```json
///{
///   "type": "http-01",
///   "url": "https://<host>/chalZ/CBFrgdBV4mLzJh7mkieu7kSZq_Fd02s_YyUrrbB25Ko",
///   "token": "xJ9Wg4G20OlC5ovxjv3qqTfIJHFdAdlRo8pazT4yHko",
///   "status": "pending"
///}
///```
#[derive(Debug, Deserialize)]
pub(crate) struct Challenge {
    pub(crate) r#type: ChallengeType,
    pub(crate) url: Url,
    pub(crate) token: String,
    pub(crate) status: String,
}
