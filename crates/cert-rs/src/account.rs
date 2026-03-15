use openssl::{pkey::Private, rsa::Rsa};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    Error, Result,
    api::{
        AcmeApiBody, AcmeClient, RequestBuilderExt, extract_location_header, handle_response_error,
    },
    authentication::{
        Jwk, JwkOrKid, JwkThumbprint, Jws, JwsAlgorithm, JwsProtectedHeaders,
        rsa_private_to_rsa_public,
    },
    directory::Directory,
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
#[strum(serialize_all = "lowercase")]
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
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountObject {
    pub(crate) status: AccountStatus,
    pub(crate) contact: Option<Vec<String>>,
    pub(crate) terms_of_service_agreed: Option<bool>,
    // TODO: external_account_binding object type
    pub(crate) external_account_binding: Option<serde_json::Value>,
    /// A Url from which a list of orders submitted by this acocount can be fetched
    pub(crate) orders: Url,
}

// TODO: AccountId(Url)

#[derive(Debug, Clone)]
pub struct Account {
    status: AccountStatus,
    id: Url,
    private_key: Rsa<Private>,

    /// A Url from which a list of orders submitted by this acocount can be fetched
    orders: Url,

    /// jwk -> to json -> sha256 hash -> base64url
    jwk_thumbprint: JwkThumbprint,
}

// impl Account {
//     pub fn new(account_id: Url, private_key: Rsa<Private>) -> Result<Self> {
//         let public_key_pem = private_key.public_key_to_pem().map_err(|_| {
//             Error::Unimplemented(
//                 "Unable to convert rsa private key to public_key_pem format".into(),
//             )
//         })?;
//         let public_key = Rsa::public_key_from_pem(&public_key_pem).map_err(|_| {
//             Error::Unimplemented("Unable to convert public_key_pem to public_key".into())
//         })?;

//         let jwk_thumbprint = public_key.into();

//         Ok(Self {
//             account_id,
//             private_key,
//             jwk_thumbprint,
//         })
//     }

// }

impl Account {
    #[must_use]
    pub const fn status(&self) -> AccountStatus {
        self.status
    }

    #[must_use]
    pub const fn orders(&self) -> &Url {
        &self.orders
    }

    #[must_use]
    pub const fn account_id(&self) -> &Url {
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
        directory: &Directory,
        private_key: Rsa<Private>,
        account_create: AccountCreate,
    ) -> Result<Url> {
        #[derive(Deserialize)]
        struct IntermidiateAccount {
            status: AccountStatus,
        }

        let url = &directory.new_account;

        let public_key = rsa_private_to_rsa_public(&private_key)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let jwk: Jwk = public_key.into();

        let nonce = &acme_client.nonce(directory.new_nonce.clone()).await?;

        let jws_protected_headers = JwsProtectedHeaders {
            algorithm: JwsAlgorithm::RS256,
            url,
            auth: JwkOrKid::Jwk(jwk.clone()),
            nonce,
        };

        let body = AcmeApiBody::Other(account_create);

        let jws = Jws::new(private_key.clone(), jws_protected_headers, body);

        let response = acme_client
            .client()
            .post(url.clone())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?;

        let response = handle_response_error(response).await?;

        // TODO: handle if status is 200 or 201(created) https://www.rfc-editor.org/rfc/rfc8555#section-7.3
        let account_id = extract_location_header(response.headers())?;

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
    pub async fn create(
        acme_client: &AcmeClient,
        directory: &Directory,
        account_create: AccountCreate,
    ) -> Result<Self> {
        let private_key = Rsa::generate(4096).map_err(|e| Error::Unimplemented(e.to_string()))?;

        let account_id = Self::fetch_of_create_account_id(
            acme_client,
            directory,
            private_key.clone(),
            account_create,
        )
        .await?;

        Self::fetch_account(acme_client, directory, &account_id, private_key).await
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn fetch_account(
        acme_client: &AcmeClient,
        directory: &Directory,
        account_id: &Url,
        private_key: Rsa<Private>,
    ) -> Result<Self> {
        let url = account_id;
        let public_key = rsa_private_to_rsa_public(&private_key)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let nonce = &acme_client.nonce(directory.new_nonce.clone()).await?;
        let jws_protected_headers = JwsProtectedHeaders {
            algorithm: JwsAlgorithm::RS256,
            url,
            auth: JwkOrKid::Kid(url.clone()),
            nonce,
        };
        let body = AcmeApiBody::EMPTY_STRING;
        let jws = Jws::new(private_key.clone(), jws_protected_headers, body);

        let response = acme_client
            .client()
            .post(account_id.clone())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?;

        let response = handle_response_error(response).await?;

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
        directory: &Directory,
        private_key: Rsa<Private>,
    ) -> Result<Self> {
        let account_create = AccountCreate {
            only_return_existing: Some(true),
            ..Default::default()
        };

        let account_id = Self::fetch_of_create_account_id(
            acme_client,
            directory,
            private_key.clone(),
            account_create,
        )
        .await?;

        Self::fetch_account(acme_client, directory, &account_id, private_key).await
    }

    // TODO: Account Update
    //
    // TODO: External Account Binding
    //
    // TODO: Account Key Rollover
    //
    // TODO: Account Deactivation
}
