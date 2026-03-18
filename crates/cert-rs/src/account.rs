use std::fmt;

use openssl::{pkey::Private, rsa::Rsa};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    AcmeClient, Error, Result,
    api::{AcmeApiBody, RequestBuilderExt, ResponseExt as _, extract_location_header},
    authentication::{Jwk, JwkOrKid, JwkThumbprint, Jws, rsa_private_to_rsa_public},
};

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountCreate {
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
struct AccountObject {
    status: AccountStatus,

    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    contact: Option<Vec<String>>,

    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    terms_of_service_agreed: Option<bool>,

    // TODO: external_account_binding object type
    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    external_account_binding: Option<serde_json::Value>,

    /// A Url from which a list of orders submitted by this acocount can be fetched
    orders: Url,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[must_use]
pub struct AccountId(Url);

impl AccountId {
    #[must_use = "Account url is must use"]
    pub const fn new(url: Url) -> Self {
        Self(url)
    }

    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> Url {
        self.0
    }
}

impl std::ops::Deref for AccountId {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Url> for AccountId {
    fn as_ref(&self) -> &Url {
        &self.0
    }
}

impl std::borrow::Borrow<Url> for AccountId {
    fn borrow(&self) -> &Url {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Url> for AccountId {
    fn from(url: Url) -> Self {
        Self(url)
    }
}

impl From<AccountId> for Url {
    fn from(id: AccountId) -> Self {
        id.0
    }
}

impl std::str::FromStr for AccountId {
    type Err = url::ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(Url::parse(s)?))
    }
}

impl TryFrom<&str> for AccountId {
    type Error = url::ParseError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Ok(Self(Url::parse(value)?))
    }
}

#[derive(Debug, Clone)]
pub struct Account {
    status: AccountStatus,
    id: AccountId,
    private_key: Rsa<Private>,

    /// A Url from which a list of orders submitted by this acocount can be fetched
    orders: Url,

    /// jwk -> to json -> sha256 hash -> base64url
    jwk_thumbprint: JwkThumbprint,
}

impl Account {
    #[must_use]
    pub const fn status(&self) -> AccountStatus {
        self.status
    }

    #[must_use]
    pub const fn orders(&self) -> &Url {
        &self.orders
    }

    #[must_use = "Must use account id"]
    pub const fn account_id(&self) -> &AccountId {
        &self.id
    }

    #[must_use]
    pub const fn private_key(&self) -> &Rsa<Private> {
        &self.private_key
    }

    #[must_use]
    pub fn jwk_thumbprint(&self) -> &str {
        &self.jwk_thumbprint
    }

    async fn fetch_of_create_account_id(
        acme_client: &AcmeClient,
        private_key: Rsa<Private>,
        account_create: AccountCreate,
    ) -> Result<AccountId> {
        #[derive(Deserialize)]
        struct IntermidiateAccount {
            status: AccountStatus,
        }

        let url = &acme_client.directory().new_account;

        let public_key = rsa_private_to_rsa_public(&private_key)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let nonce = &acme_client.nonce().await?;

        let auth = JwkOrKid::Jwk(Jwk::from(public_key));
        let body = AcmeApiBody::Other(account_create);
        let jws = Jws::new_from_parts(private_key, url, auth, nonce, body);

        let response = acme_client
            .client()
            .post(url.clone())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?
            .handle_response_error()
            .await?;

        // TODO: handle if status is 200 or 201(created) https://www.rfc-editor.org/rfc/rfc8555#section-7.3
        let account_id = extract_location_header(response.headers()).map(Into::into)?;

        let intermediate_account = response
            .json::<IntermidiateAccount>()
            .await
            .map_err(|_| Error::Unimplemented("Cannot extact account status".into()))?;

        if intermediate_account.status != AccountStatus::Valid {
            return Err(Error::AccountStatusNoValid(
                intermediate_account.status.to_string(),
            ));
        }

        Ok(account_id)
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn create(acme_client: &AcmeClient, account_create: AccountCreate) -> Result<Self> {
        let private_key = Rsa::generate(4096).map_err(|e| Error::Unimplemented(e.to_string()))?;

        let account_id =
            Self::fetch_of_create_account_id(acme_client, private_key.clone(), account_create)
                .await?;

        Self::fetch_account(acme_client, &account_id, private_key).await
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn fetch_account(
        acme_client: &AcmeClient,
        account_id: &AccountId,
        private_key: Rsa<Private>,
    ) -> Result<Self> {
        let url: &Url = account_id;
        let public_key = rsa_private_to_rsa_public(&private_key)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let nonce = &acme_client.nonce().await?;

        let auth = JwkOrKid::Kid(account_id.clone());
        let body = AcmeApiBody::EMPTY_STRING;
        let jws = Jws::new_from_parts(private_key.clone(), url, auth, nonce, body);

        let response = acme_client
            .client()
            .post(account_id.as_url().clone())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?
            .handle_response_error()
            .await?;

        let AccountObject { status, orders, .. } = response.json::<AccountObject>().await?;

        if status != AccountStatus::Valid {
            return Err(Error::AccountStatusNoValid(status.to_string()));
        }

        let jwk_thumbprint = public_key.into();

        Ok(Self {
            status,
            id: account_id.clone(),
            private_key,
            orders,
            jwk_thumbprint,
        })
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn fetch_account_with_private_key(
        acme_client: &AcmeClient,
        private_key: Rsa<Private>,
    ) -> Result<Self> {
        let account_create = AccountCreate {
            only_return_existing: Some(true),
            ..Default::default()
        };

        let account_id =
            Self::fetch_of_create_account_id(acme_client, private_key.clone(), account_create)
                .await?;

        Self::fetch_account(acme_client, &account_id, private_key).await
    }

    // TODO: Account Update
    //
    // TODO: External Account Binding
    //
    // TODO: Account Key Rollover
    //
    // TODO: Account Deactivation
}
