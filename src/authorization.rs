use crate::{Result, account::Account, api::AcmeApiBody, authentication::JwkOrKid, b64};
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
    pub async fn get(account: &Account, url: &Url) -> Result<Self> {
        let auth = JwkOrKid::Kid(&account.credentials.kid);
        let body = AcmeApiBody::EMPTY_STRING;

        let response = account
            .client
            .post(url, &account.credentials.private_key, auth, body)
            .await?;

        let authorization = response.json::<Self>().await?;
        Ok(authorization)
    }

    #[must_use]
    pub fn gen_keyauth(challenge_token: &str, jwk_thumbprint: &str) -> String {
        format!("{challenge_token}.{jwk_thumbprint}")
    }

    #[must_use]
    pub fn gen_sha_256_keyauth(challenge_token: &str, jwk_thumbprint: &str) -> String {
        let keyauth = Self::gen_keyauth(challenge_token, jwk_thumbprint);
        let hash = Sha256::digest(&keyauth).to_vec();

        b64::b64u_encode(hash)
    }
}
