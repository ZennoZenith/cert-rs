use crate::{Result, account::Account, api::AcmeApiBody, authentication::JwkOrKid, b64};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{challenge::Challenge, order::Identifier, time::TimeRfc3339};

/// Authorization Status
///
/// Defined in [RFC 8555 §7.1.6].
///
/// Authorization objects are created in the "pending" state. If one of
/// the challenges listed in the authorization transitions to the "valid"
/// state, then the authorization also changes to the "valid" state. If
/// the client attempts to fulfill a challenge and fails, or if there is
/// an error while the authorization is still pending, then the
/// authorization transitions to the "invalid" state. Once the
/// authorization is in the "valid" state, it can expire ("expired"), be
/// deactivated by the client, or revoked by the server ("revoked").
///
/// ```text
///                      pending --------------------+
///                         |                        |
///       Challenge failure |                        |
///              or         |                        |
///             Error       |  Challenge valid       |
///               +---------+---------+              |
///               |                   |              |
///               V                   V              |
///            invalid              valid            |
///                                   |              |
///                                   |              |
///                                   |              |
///                    +--------------+--------------+
///                    |              |              |
///                    |              |              |
///             Server |       Client |   Time after |
///             revoke |   deactivate |    "expires" |
///                    V              V              V
///                 revoked      deactivated      expired
///
///                State Transitions for Authorization Objects
///
/// ```
///
/// [RFC 8555 §7.1.6]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invaid,
    Deactivated,
    Expired,
    Revoked,
}

/// Authorization Object
///
/// Defined in [RFC 8555 §7.1.4].
///
/// Authorization object represents a server's authorization for an account to represent an identifier.
///
/// [RFC 8555 §7.1.4]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub identifier: Identifier,

    /// The status of this authorization
    pub status: AuthorizationStatus,

    /// The timestamp after which the server will consider this authorization invalid.
    /// This field is REQUIRED for objects with "valid" in the "status" field
    pub expires: Option<TimeRfc3339>,

    /// For pending authorizations, the challenges that the client can fulfill in
    /// order to prove possession of the identifier. For valid authorizations, the
    /// challenge that was validated. For invalid authorizations, the challenge
    /// that was attempted and failed. Each array entry is an object with
    /// parameters required to validate the challenge. A client should attempt to
    /// fulfill one of these challenges, and a server should consider any one of the
    /// challenges sufficient to make the authorization valid.
    pub challenges: Vec<Challenge>,

    /// This field MUST be present and true for authorizations created as a result
    /// of a newOrder request containing a DNS identifier with a value that was a
    /// wildcard domain name. For other authorizations, it MUST be absent
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
