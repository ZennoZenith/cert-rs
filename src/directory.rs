use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    Error, Result,
    api::{RequestBuilderExt, ResponseExt as _},
};

/// ACME directory object.
///
/// Defined in [RFC 8555 §7.1.1].
///
/// [RFC 8555 §7.1.1]: https://www.rfc-editor.org/rfc/rfc8555#section-7.1.1
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: Url,
    pub new_account: Url,
    pub new_order: Url,
    pub revoke_cert: Url,
    pub key_change: Url,

    pub new_authz: Option<Url>,
    pub meta: Option<DirectoryMeta>,
}

/// ACME Directory Metadata Fields.
///
/// Defined in [RFC 8555 §9.7.6].
///
/// [RFC 8555 §9.7.6]: https://www.rfc-editor.org/rfc/rfc8555#section-9.7.6
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
}

impl Directory {
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn new_from_url_with_client(client: &reqwest::Client, url: &Url) -> Result<Self> {
        let response = client
            .get(url.as_str())
            .add_rfc_headers()
            .send()
            .await?
            .handle_response_error()
            .await?;

        response
            .json()
            .await
            .map_err(|e| Error::ResponseToText(e.to_string()))
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn new_from_url(url: &Url) -> Result<Self> {
        let response = reqwest::Client::new()
            .get(url.as_str())
            .add_rfc_headers()
            .send()
            .await?
            .handle_response_error()
            .await?;

        response
            .json()
            .await
            .map_err(|e| Error::ResponseToText(e.to_string()))
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn new_from_json(directory_json: &str) -> Result<Self> {
        serde_json::from_str(directory_json).map_err(|e| Error::DirectoryParse(e.to_string()))
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn lets_encrypt() -> Result<Self> {
        Self::new_from_url(&Url::try_from(LetsEncrypt::Production)?).await
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn lets_encrypt_staging() -> Result<Self> {
        Self::new_from_url(&Url::try_from(LetsEncrypt::Staging)?).await
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn zero_ssl() -> Result<Self> {
        Self::new_from_url(&Url::try_from(ZeroSsl::Production)?).await
    }
}

impl Directory {
    #[must_use]
    pub fn terms_of_service(&self) -> Option<&str> {
        self.meta.as_ref().map(|v| v.terms_of_service.as_deref())?
    }

    #[must_use]
    pub fn website(&self) -> Option<&str> {
        self.meta.as_ref().map(|v| v.website.as_deref())?
    }

    #[must_use]
    pub fn external_account_required(&self) -> Option<bool> {
        self.meta.as_ref().map(|v| v.external_account_required)?
    }
}

/// Helper type to reference Let's Encrypt server URLs
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LetsEncrypt {
    Production,
    Staging,
}

impl TryFrom<LetsEncrypt> for Url {
    type Error = url::ParseError;

    fn try_from(value: LetsEncrypt) -> std::result::Result<Self, Self::Error> {
        match value {
            LetsEncrypt::Production => "https://acme-v02.api.letsencrypt.org/directory".parse(),
            LetsEncrypt::Staging => {
                "https://acme-staging-v02.api.letsencrypt.org/directory".parse()
            }
        }
    }
}

/// ``ZeroSSL`` ACME only supports production at the moment
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum ZeroSsl {
    Production,
}

impl TryFrom<ZeroSsl> for Url {
    type Error = url::ParseError;

    fn try_from(value: ZeroSsl) -> std::result::Result<Self, Self::Error> {
        match value {
            ZeroSsl::Production => "https://acme.zerossl.com/v2/DV90".parse(),
        }
    }
}

// region:    --- Tests
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    #[test]
    fn directory_from_json_str() {
        const DIRECTORY_JSON: &str = r#"{
   "keyChange": "https://localhost:14000/rollover-account-key",
   "meta": {
      "caaIdentities": [
         "pebble.letsencrypt.org"
      ],
      "externalAccountRequired": false,
      "profiles": {
         "default": "The profile you know and love",
         "shortlived": "A short-lived cert profile, without actual enforcement"
      },
      "termsOfService": "data:text/plain,Do%20what%20thou%20wilt"
   },
   "newAccount": "https://localhost:14000/sign-me-up",
   "newNonce": "https://localhost:14000/nonce-plz",
   "newOrder": "https://localhost:14000/order-plz",
   "renewalInfo": "https://localhost:14000/draft-ietf-acme-ari-03/renewalInfo",
   "revokeCert": "https://localhost:14000/revoke-cert"
}"#;

        assert!(Directory::new_from_json(DIRECTORY_JSON).is_ok());
    }
}
// endregion: --- Tests
