use std::sync::Arc;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    Client, Error, Result,
    api::{AcmeApiBody, extract_location_header},
    authentication::{Jwk, JwkOrKid, JwkThumbprint, Kid, PrivateKey, rsa_private_to_rsa_public},
};

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<serde_json::Value>,
}

#[derive(
    Debug,
    Clone,
    Copy,
    Deserialize,
    Serialize,
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
pub enum AccountStatus {
    #[default]
    Valid,
    Deactivated,
    Revoked,
}

/// TODO: add docs, [RFC 8555 §9.7.1]
///
/// [RFC 8555 §9.7.1]: https://www.rfc-editor.org/rfc/rfc8555#section-9.7.1
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountObject {
    pub status: AccountStatus,

    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,

    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    // TODO: external_account_binding object type
    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<serde_json::Value>,

    /// A Url from which a list of orders submitted by this acocount can be fetched
    /// The ACME spec optionally defines an orders field in the account object, but:
    /// Let’s Encrypt does NOT implement order listing
    pub orders: Option<Url>,
}

/// ACME account credentials
///
/// This opaque type contains the account ID, the private key data and the
/// server URLs from the relevant ACME server. This can be used to serialize
/// the account credentials to a file or secret manager and restore the
/// account from persistent storage.
#[must_use]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountCredentials {
    pub(crate) kid: Kid,

    /// The account's private key
    pub(crate) private_key: PrivateKey,
    pub(crate) directory_url: Url,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub(crate) client: Arc<Client>,
    pub(crate) credentials: AccountCredentials,

    /// jwk -> to json -> sha256 hash -> base64url
    jwk_thumbprint: JwkThumbprint,
    // pub(crate) status: AccountStatus,
    // pub(crate) orders: Option<Url>,
}

impl Account {
    // #[must_use]
    // pub const fn status(&self) -> AccountStatus {
    //     self.status
    // }

    // TODO: Fetch order url if acme account uri
    // #[must_use]
    // pub const fn orders(&self) -> Option<&Url> {
    //     self.orders.as_ref()
    // }

    #[must_use]
    pub fn jwk_thumbprint(&self) -> &str {
        &self.jwk_thumbprint
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn create(client: Client, new_account: NewAccount) -> Result<Self> {
        let private_key = PrivateKey::new()?;

        Self::fetch_of_create(client, &private_key, new_account).await
    }

    async fn fetch_of_create(
        client: Client,
        private_key: &PrivateKey,
        new_account: NewAccount,
    ) -> Result<Self> {
        #[derive(Deserialize)]
        struct IntermidiateAccount {
            status: AccountStatus,
            #[serde(rename = "orders")]
            _orders: Option<Url>,
        }

        let url = &client.directory.new_account;

        let public_key = rsa_private_to_rsa_public(private_key.rsa_key())
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let auth = JwkOrKid::Jwk(Jwk::from(public_key.clone()));
        let body = AcmeApiBody::Other(new_account);

        let response = client.post(url, private_key, auth, body).await?;

        // TODO: handle if status is 200 or 201(created) https://www.rfc-editor.org/rfc/rfc8555#section-7.3
        let kid: Kid = extract_location_header(response.headers()).map(Into::into)?;

        let intermediate_account = response
            .json::<IntermidiateAccount>()
            .await
            .map_err(|_| Error::Unimplemented("Cannot extact account status".into()))?;

        if intermediate_account.status != AccountStatus::Valid {
            return Err(Error::AccountStatusNoValid(
                intermediate_account.status.to_string(),
            ));
        }

        let jwk_thumbprint = public_key.into();
        let directory_url = client.directory_url.clone();

        Ok(Self {
            client: Arc::new(client),
            // status: intermediate_account.status,
            // orders: intermediate_account.orders,
            credentials: AccountCredentials {
                kid,
                private_key: private_key.clone(),
                directory_url,
            },
            jwk_thumbprint,
        })
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn get_account_object(
        _client: &Client,
        _kid: &Kid,
        _private_key: &PrivateKey,
    ) -> Result<AccountObject> {
        // TODO:
        unimplemented!(
            "Not yet know how to get account object, or is there even a need to get account object"
        );

        // let url: &Url = kid;

        // let auth = JwkOrKid::Kid(kid);
        // let body = AcmeApiBody::EMPTY_STRING;

        // let response = client.post(url, private_key, auth, body).await?;

        // Ok(response.json().await?)
    }

    // TODO: Account Update
    //
    // TODO: External Account Binding
    //
    // TODO: Account Key Rollover
    //
    // TODO: Account Deactivation
}
