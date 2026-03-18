use openssl::{pkey::Private, rsa::Rsa};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    AcmeClient, Error, Result,
    api::{AcmeApiBody, extract_location_header},
    authentication::{Jwk, JwkOrKid, JwkThumbprint, Kid, rsa_private_to_rsa_public},
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
    pub orders: Url,
}

#[derive(Debug, Clone)]
pub struct Account {
    status: AccountStatus,
    kid: Kid,
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
    pub const fn kid(&self) -> &Kid {
        &self.kid
    }

    #[must_use]
    pub const fn private_key(&self) -> &Rsa<Private> {
        &self.private_key
    }

    #[must_use]
    pub fn jwk_thumbprint(&self) -> &str {
        &self.jwk_thumbprint
    }

    async fn fetch_of_create(
        acme_client: &AcmeClient,
        private_key: &Rsa<Private>,
        account_create: AccountCreate,
    ) -> Result<Kid> {
        #[derive(Deserialize)]
        struct IntermidiateAccount {
            status: AccountStatus,
        }

        let url = &acme_client.directory().new_account;

        let public_key = rsa_private_to_rsa_public(private_key)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let auth = JwkOrKid::Jwk(Jwk::from(public_key));
        let body = AcmeApiBody::Other(account_create);

        let response = acme_client.post(url, private_key, auth, body).await?;

        // TODO: handle if status is 200 or 201(created) https://www.rfc-editor.org/rfc/rfc8555#section-7.3
        let kid = extract_location_header(response.headers()).map(Into::into)?;

        let intermediate_account = response
            .json::<IntermidiateAccount>()
            .await
            .map_err(|_| Error::Unimplemented("Cannot extact account status".into()))?;

        if intermediate_account.status != AccountStatus::Valid {
            return Err(Error::AccountStatusNoValid(
                intermediate_account.status.to_string(),
            ));
        }

        Ok(kid)
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn create(acme_client: &AcmeClient, account_create: AccountCreate) -> Result<Self> {
        let private_key = Rsa::generate(4096).map_err(|e| Error::Unimplemented(e.to_string()))?;
        let kid = Self::fetch_of_create(acme_client, &private_key, account_create).await?;

        Self::get_account(acme_client, kid, private_key).await
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn get_account_object(
        acme_client: &AcmeClient,
        kid: &Kid,
        private_key: &Rsa<Private>,
    ) -> Result<AccountObject> {
        let url: &Url = kid;

        let auth = JwkOrKid::Kid(kid);
        let body = AcmeApiBody::EMPTY_STRING;

        let response = acme_client.post(url, private_key, auth, body).await?;

        Ok(response.json().await?)
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn get_account(
        acme_client: &AcmeClient,
        kid: Kid,
        private_key: Rsa<Private>,
    ) -> Result<Self> {
        let public_key = rsa_private_to_rsa_public(&private_key)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let AccountObject { status, orders, .. } =
            Self::get_account_object(acme_client, &kid, &private_key).await?;

        if status != AccountStatus::Valid {
            return Err(Error::AccountStatusNoValid(status.to_string()));
        }

        let jwk_thumbprint = public_key.into();

        Ok(Self {
            status,
            kid,
            private_key,
            orders,
            jwk_thumbprint,
        })
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn get_account_with_private_key(
        acme_client: &AcmeClient,
        private_key: Rsa<Private>,
    ) -> Result<Self> {
        let account_create = AccountCreate {
            only_return_existing: Some(true),
            ..Default::default()
        };
        let kid = Self::fetch_of_create(acme_client, &private_key, account_create).await?;

        Self::get_account(acme_client, kid, private_key).await
    }

    // TODO: Account Update
    //
    // TODO: External Account Binding
    //
    // TODO: Account Key Rollover
    //
    // TODO: Account Deactivation
}
