use crate::{
    AcmeClient, Result,
    account::Account,
    api::{AcmeApiBody, RequestBuilderExt as _, ResponseExt as _},
    authentication::{JwkOrKid, Jws},
    b64,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{challenge::Challenge, order::Identifier, time::TimeRfc3339};

#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum AuthorizationStatus {
    #[default]
    Pending,
    Valid,
    Invaid,
    Deactivated,
    Expired,
    Revoked,
}

/// Authorization Objects
///
/// Defined in [RFC 8555 §7.1.4].
///
/// [RFC 8555 §7.1.4]: https://www.rfc-editor.org/rfc/rfc8555#section-7.1.4
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub status: AuthorizationStatus,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
    pub expires: Option<TimeRfc3339>,
    pub wildcard: Option<bool>,
}

impl Authorization {
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn get(acme_client: &AcmeClient, account: &Account, url: &Url) -> Result<Self> {
        let nonce = &acme_client.nonce().await?;

        let auth = JwkOrKid::Kid(account.account_id().clone());
        let body = AcmeApiBody::EMPTY_STRING;
        let jws = Jws::new_from_parts(account.private_key().clone(), url, auth, nonce, body);

        let response = acme_client
            .client()
            .post(url.as_str())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?
            .handle_response_error()
            .await?;

        let authorization = response.json::<Self>().await?;
        Ok(authorization)
    }

    #[must_use]
    pub fn gen_keyauth(&self, challenge_token: &str, jwk_thumbprint: &str) -> String {
        format!("{challenge_token}.{jwk_thumbprint}")
    }

    #[must_use]
    pub fn gen_sha_256_keyauth(&self, challenge_token: &str, jwk_thumbprint: &str) -> String {
        let keyauth = self.gen_keyauth(challenge_token, jwk_thumbprint);
        let hash = Sha256::digest(&keyauth).to_vec();

        b64::b64u_encode(hash)
    }
}
