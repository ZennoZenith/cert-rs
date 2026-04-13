//! Directory Resource
//!
//! In order to help clients configure themselves with the right URLs for each
//! ACME operation, ACME servers provide a directory object. This should be the
//! only URL needed to configure clients.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    Result,
    api::{RequestBuilderExt, ResponseExt as _},
};

/// Directory object.
///
/// Defined in [RFC 8555 §7.1.1], [RFC 8555 §9.7.5].
///
/// [RFC 8555 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1
/// [RFC 8555 §9.7.5]: https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.5
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: Url,
    pub new_account: Url,
    pub new_order: Url,
    pub revoke_cert: Url,
    pub key_change: Url,

    pub new_authz: Option<Url>,

    #[serde(default)]
    pub meta: DirectoryMeta,
}

/// Directory Metadata Fields.
///
/// Defined in [RFC 8555 §9.7.6].
///
/// [RFC 8555 §9.7.6]: https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.6
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,

    #[serde(default)]
    pub(crate) profiles: HashMap<String, String>,
}

/// Profile meta information from the server directory
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProfileMeta<'a> {
    pub name: &'a str,
    pub description: &'a str,
}

impl Directory {
    /// Fetches and constructs a [`Directory`] from the given ACME directory URL using the provided HTTP client.
    ///
    /// This is useful when you need to reuse an existing [`reqwest::Client`] (e.g. to share
    /// connection pools or custom TLS configuration) rather than using the default client.
    ///
    /// # Arguments
    ///
    /// * `client` - The HTTP client to use for the request
    /// * `url` - The ACME directory URL (e.g. `https://acme-v02.api.letsencrypt.org/directory`)
    ///
    /// # Errors
    ///
    pub async fn new_from_url_with_client(client: &reqwest::Client, url: &Url) -> Result<Self> {
        let response = client
            .get(url.as_str())
            .add_rfc_headers()
            .send()
            .await?
            .handle_response_error()
            .await?;

        response.json().await.map_err(Into::into)
    }

    /// Fetches and constructs a [Self] from the given ACME directory URL using a default HTTP client.
    ///
    /// For cases where you need custom client configuration such as connection pooling or TLS settings,
    /// use [``Self::new_from_url_with_client``] instead.
    ///
    /// # Arguments
    ///
    /// * `url` - The ACME directory URL (e.g. `https://acme-v02.api.letsencrypt.org/directory`)
    ///
    /// # Errors
    ///
    pub async fn new_from_url(url: &Url) -> Result<Self> {
        let response = reqwest::Client::new()
            .get(url.as_str())
            .add_rfc_headers()
            .send()
            .await?
            .handle_response_error()
            .await?;

        response.json().await.map_err(Into::into)
    }

    /// Constructs a [Self] by deserializing a JSON string.
    ///
    /// Useful when you have already fetched the directory response and want to avoid an additional
    /// HTTP request, or for testing with a cached directory payload.
    ///
    /// # Arguments
    ///
    /// * `directory_json` - A JSON string representing the ACME directory object
    ///
    /// # Errors
    ///
    pub fn new_from_json(directory_json: &str) -> Result<Self> {
        serde_json::from_str(directory_json).map_err(Into::into)
    }

    /// Yield the profiles supported according to the account's server directory
    pub fn profiles(&self) -> impl Iterator<Item = ProfileMeta<'_>> {
        self.meta
            .profiles
            .iter()
            .map(|(name, description)| ProfileMeta { name, description })
    }

    /// Fetches and constructs a [Self] from the Let's Encrypt production endpoint.
    ///
    /// For staging/testing, use [``Self::lets_encrypt_staging``] to avoid hitting production rate limits.
    ///
    /// # Errors
    ///
    /// - [``crate::Error::Url``] — Let's Encrypt production URL could not be parsed
    pub async fn lets_encrypt() -> Result<Self> {
        Self::new_from_url(&Url::try_from(LetsEncrypt::Production)?).await
    }

    /// Fetches and constructs a [Self] from the Let's Encrypt staging endpoint.
    ///
    /// For production, use [``Self::lets_encrypt``].
    ///
    /// # Errors
    ///
    /// - [``crate::Error::Url``] — Let's Encrypt production URL could not be parsed
    pub async fn lets_encrypt_staging() -> Result<Self> {
        Self::new_from_url(&Url::try_from(LetsEncrypt::Staging)?).await
    }

    /// Fetches and constructs a [Directory] from the `ZeroSSL` production endpoint.
    ///
    /// # Errors
    ///
    /// - [``crate::Error::Url``] — `ZeroSSL` production URL could not be parsed
    pub async fn zero_ssl() -> Result<Self> {
        Self::new_from_url(&Url::try_from(ZeroSsl::Production)?).await
    }
}

impl Directory {
    #[must_use]
    pub fn terms_of_service(&self) -> Option<&str> {
        self.meta.terms_of_service.as_deref()
    }

    #[must_use]
    pub fn website(&self) -> Option<&str> {
        self.meta.website.as_deref()
    }

    #[must_use]
    pub const fn external_account_required(&self) -> Option<bool> {
        self.meta.external_account_required
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

/// Helper type to reference ``ZeroSSL`` server URL
///
/// ``ZeroSSL`` ACME only supports production at the moment
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
