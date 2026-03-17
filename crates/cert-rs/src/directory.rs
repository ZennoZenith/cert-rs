use reqwest::IntoUrl;
use serde::Deserialize;
use url::Url;

use crate::{
    Error, Result,
    api::{RequestBuilderExt, handle_response_error},
};

/// ACME directory object.
///
/// Defined in [RFC 8555 §7.1.1].
///
/// [RFC 8555 §7.1.1]: https://www.rfc-editor.org/rfc/rfc8555#section-7.1.1
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub(crate) new_nonce: Url,
    pub(crate) new_account: Url,
    pub(crate) new_order: Url,
    pub(crate) revoke_cert: Url,
    pub(crate) key_change: Url,

    pub(crate) new_authz: Option<Url>,
    pub(crate) meta: Option<DirectoryMeta>,
}

/// ACME Directory Metadata Fields.
///
/// Defined in [RFC 8555 §7.1.1].
///
/// [RFC 8555 §7.1.1]: https://www.rfc-editor.org/rfc/rfc8555#section-9.7.6

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub(crate) terms_of_service: Option<String>,
    pub(crate) website: Option<String>,
    pub(crate) caa_identities: Option<Vec<String>>,
    pub(crate) external_account_required: Option<bool>,
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
        let response = client.get(url).add_rfc_headers().send().await?;

        let response = handle_response_error(response).await?;

        response
            .json()
            .await
            .map_err(|e| Error::ResponseToText(e.to_string()))
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn new_from_url<T: IntoUrl>(url: T) -> Result<Self> {
        let response = reqwest::Client::new().get(url).add_rfc_headers().send().await?;

        let response = handle_response_error(response).await?;

        response
            .json()
            .await
            .map_err(|e| Error::ResponseToText(e.to_string()))
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
