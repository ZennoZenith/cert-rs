use reqwest::IntoUrl;
use serde::Deserialize;
use url::Url;

use crate::{Error, Result, api::reqwest_client};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectory {
    pub(crate) new_nonce: Url,
    pub(crate) new_account: Url,
    pub(crate) new_order: Url,
    pub(crate) revoke_cert: Url,
    pub(crate) key_change: Url,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) new_authz: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) meta: Option<AcmeDirectoryMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectoryMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) terms_of_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) caa_identities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) external_account_required: Option<bool>,
}

impl AcmeDirectory {
    pub async fn new_from_url<T: IntoUrl>(url: T) -> Result<Self> {
        let client = reqwest_client();

        let acme_directory = client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::GetReqwest(e.to_string()))?
            .json::<AcmeDirectory>()
            .await
            .map_err(|e| Error::AcmeDirectoryParse(e.to_string()))?;
        Ok(acme_directory)
    }

    pub const LETS_ENCRYPT_URL: &str =
        "https://acme-v02.api.letsencrypt.org/directory";
    pub const LETS_ENCRYPT_STAGING_URL: &str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";

    pub async fn lets_encrypt() -> Result<AcmeDirectory> {
        Self::new_from_url(Self::LETS_ENCRYPT_URL).await
    }

    pub async fn lets_encrypt_staging() -> Result<AcmeDirectory> {
        Self::new_from_url(Self::LETS_ENCRYPT_STAGING_URL).await
    }
}

impl AcmeDirectory {
    pub fn terms_of_service(&self) -> Option<&str> {
        self.meta.as_ref().map(|v| v.terms_of_service.as_deref())?
    }

    pub fn website(&self) -> Option<&str> {
        self.meta.as_ref().map(|v| v.website.as_deref())?
    }

    pub fn external_account_required(&self) -> Option<bool> {
        self.meta.as_ref().map(|v| v.external_account_required)?
    }
}
