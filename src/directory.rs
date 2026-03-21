use reqwest::IntoUrl;
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
    const LETS_ENCRYPT_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
    const LETS_ENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn new_from_url_with_client<T: IntoUrl>(
        client: &reqwest::Client,
        url: T,
    ) -> Result<Self> {
        let response = client
            .get(url)
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
    pub async fn new_from_url<T: IntoUrl>(url: T) -> Result<Self> {
        let response = reqwest::Client::new()
            .get(url)
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
        Self::new_from_url(Self::LETS_ENCRYPT_URL).await
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn lets_encrypt_staging() -> Result<Self> {
        Self::new_from_url(Self::LETS_ENCRYPT_STAGING_URL).await
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
