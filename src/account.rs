//! Account Management
//!
//! Create an account on an ACME server and perform some modifications to
//! the account after it has been created.

use std::sync::Arc;

use serde::{Deserialize, Serialize, Serializer, de, ser::SerializeStruct as _};
use url::Url;

use crate::{
    Client, Error, Result,
    api::{AcmeApiBody, extract_location_header},
    authentication::{Jwk, JwkOrKid, JwkThumbprint, Kid, PrivateKey, rsa_private_to_rsa_public},
};

/// New Account
///
/// Defined in [RFC 8555 §7.3].
///
/// Stub account object for creating new account.
///
/// [RFC 8555 §7.3]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccount {
    /// [RFC 8555 §7.1.2](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,

    /// [RFC 8555 §7.1.2](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,

    /// [RFC 8555 §7.1.2](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<serde_json::Value>,
}

/// Update Account
///
/// Defined in [RFC 8555 §7.3.2].
///
/// Stub account object for updating account.
///
/// [RFC 8555 §7.3.2]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.2
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAccount {
    /// [RFC 8555 §7.1.2](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,

    /// [RFC 8555 §7.1.2](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<serde_json::Value>,
}

/// Account Status
///
/// Defined in [RFC 8555 §7.1.6].
///
/// Account objects are created in the "valid" state, since no further
/// action is required to create an account after a successful newAccount
/// request. If the account is deactivated by the client or revoked by
/// the server, it moves to the corresponding state.
///
/// ```text
///
///                     valid
///                       |
///                       |
///           +-----------+-----------+
///    Client |                Server |
///   deactiv.|                revoke |
///           V                       V
///      deactivated               revoked
///
///                   State Transitions for Account Objects
///
/// ```
///
/// [RFC 8555 §7.1.6]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6
#[derive(
    Debug,
    Clone,
    Copy,
    Deserialize,
    Serialize,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Valid,

    /// client-initiated deactivation
    Deactivated,
    /// server-initiated deactivation
    Revoked,
}

/// Account Object
///
/// Defined in [RFC 8555 §7.1.2], [RFC 8555 §9.7.1].
///
/// An ACME account resource represents a set of metadata associated with an account.
///
/// [RFC 8555 §7.1.2]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2
/// [RFC 8555 §9.7.1]: https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.1
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountObject {
    /// The status of this account
    pub status: AccountStatus,

    #[allow(dead_code)]
    pub contact: Option<Vec<String>>,

    #[allow(dead_code)]
    pub terms_of_service_agreed: Option<bool>,

    // TODO: external_account_binding object type
    #[allow(dead_code)]
    pub external_account_binding: Option<serde_json::Value>,

    /// A Url from which a list of orders submitted by this acocount can be fetched
    /// The ACME spec required an orders field in the account object, but:
    /// Let’s Encrypt does NOT implement order listing
    /// [RFC 8555 §7.1.2.1](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2.1)
    pub orders: Option<Url>,
}

/// Account credentials
///
/// This opaque type contains the account ID, the private key data and the
/// server URLs from the relevant ACME server. This can be used to serialize
/// the account credentials to a file or secret manager and restore the
/// account from persistent storage.
#[must_use]
#[derive(Debug, Clone)]
pub struct AccountCredentials {
    pub(crate) kid: Kid,

    /// The account's private key
    pub(crate) private_key: PrivateKey,
    pub(crate) directory_url: Url,

    /// jwk -> to json -> sha256 hash -> base64url
    pub(crate) jwk_thumbprint: JwkThumbprint,
}

impl Serialize for AccountCredentials {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AccountCredentials", 4)?;

        state.serialize_field("kid", &self.kid)?;
        state.serialize_field("private_key", &self.private_key)?;
        state.serialize_field("directory_url", &self.directory_url)?;
        state.serialize_field("jwk_thumbprint", &self.jwk_thumbprint)?;

        state.end()
    }
}

impl<'de> serde::de::Deserialize<'de> for AccountCredentials {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            kid: Kid,
            private_key: PrivateKey, // base64-encoded DER
            directory_url: Url,
        }

        let Helper {
            kid,
            private_key,
            directory_url,
        } = Helper::deserialize(deserializer)?;

        let public_key =
            rsa_private_to_rsa_public(private_key.rsa_key()).map_err(de::Error::custom)?;

        let jwk_thumbprint = public_key.into();

        Ok(Self {
            kid,
            private_key,
            directory_url,
            jwk_thumbprint,
        })
    }
}

impl AccountCredentials {
    #[must_use]
    pub fn jwk_thumbprint(&self) -> &str {
        &self.jwk_thumbprint
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn load_from_parts(directory_url: Url, kid: Kid, private_key: PrivateKey) -> Result<Self> {
        let public_key = rsa_private_to_rsa_public(private_key.rsa_key())
            .map_err(|e| Error::Unimplemented(e.to_string()))?;
        let jwk_thumbprint = public_key.into();

        Ok(Self {
            kid,
            private_key,
            directory_url,
            jwk_thumbprint,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Account {
    pub(crate) client: Arc<Client>,
    pub(crate) credentials: AccountCredentials,
}

impl Account {
    pub fn load(client: Client, credentials: AccountCredentials) -> Self {
        if client.directory_url != credentials.directory_url {
            // TODO: add directory url in warn
            #[cfg(feature = "tracing")]
            tracing::warn!("Client and Credentials Directory Url do not match");
        }

        Self {
            client: Arc::from(client),
            credentials,
        }
    }

    #[must_use]
    pub fn check(&self) -> bool {
        // TODO: check if current account object status is valid
        unimplemented!("check if current account object status is valid")
    }

    pub const fn credentials(&self) -> &AccountCredentials {
        &self.credentials
    }

    #[must_use]
    pub fn jwk_thumbprint(&self) -> &str {
        &self.credentials.jwk_thumbprint
    }

    /// Create new account by sending a POST request to the server's newAccount URL
    /// Will overwrite `new_account.only_return_existing` to false.
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn create(client: Client, new_account: NewAccount) -> Result<Self> {
        let private_key = PrivateKey::new()?;

        let new_account = NewAccount {
            only_return_existing: Some(false),
            ..new_account
        };

        Self::fetch_or_create(client, &private_key, new_account).await
    }

    /// Fetch account by sending a POST request to the server's newAccount URL.
    /// Will overwrite `new_account.only_return_existing` to true.
    /// Will not create a new account if one does not already exist.
    ///
    /// Refer [RFC 8555 §7.3.1](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.1)
    ///
    /// # Errors
    ///
    /// Will fail if account does not exist `AcmeErrorType::AccountDoesNotExist`.
    ///
    /// TODO: Write error docs
    pub async fn fetch(
        client: Client,
        private_key: &PrivateKey,
        new_account: NewAccount,
    ) -> Result<Self> {
        let new_account = NewAccount {
            only_return_existing: Some(true),
            ..new_account
        };

        Self::fetch_or_create(client, private_key, new_account).await
    }

    /// Create new account by sending a POST request to the server's newAccount URL
    /// If account already exists for a given private key, then fetch details else create new account
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn fetch_or_create(
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
            credentials: AccountCredentials {
                kid,
                private_key: private_key.clone(),
                directory_url,
                jwk_thumbprint,
            },
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
        // TODO: [RFC 8555 §7.3](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3)
        unimplemented!(
            "Not yet know how to get account object, or is there even a need to get account object"
        );

        // let url: &Url = kid;

        // let auth = JwkOrKid::Kid(kid);
        // let body = AcmeApiBody::EMPTY_STRING;

        // let response = client.post(url, private_key, auth, body).await?;

        // Ok(response.json().await?)
    }

    /// Update account by sending a POST request to the server's account URL (Kid)
    ///
    /// Will ignore any updates to the "orders" field, "termsOfServiceAgreed" field,
    /// the "status" field.
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn update(&self, update_account: UpdateAccount) -> Result<Self> {
        #[derive(Deserialize)]
        struct IntermidiateAccount {
            status: AccountStatus,
            #[serde(rename = "orders")]
            _orders: Option<Url>,
        }

        let url = &self.credentials.kid;

        let public_key = rsa_private_to_rsa_public(self.credentials.private_key.rsa_key())
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let auth = JwkOrKid::Kid(&self.credentials.kid);
        let body = AcmeApiBody::Other(update_account);

        let response = self
            .client
            .post(url, &self.credentials.private_key, auth, body)
            .await?;

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

        Ok(Self {
            client: Arc::clone(&self.client),
            credentials: AccountCredentials {
                kid: self.credentials.kid.clone(),
                private_key: self.credentials.private_key.clone(),
                directory_url: self.credentials.directory_url.clone(),
                jwk_thumbprint,
            },
        })
    }

    // TODO: External Account Binding.
    // Defined in [RFC 8555 §7.3.4](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4).
    //
    // TODO: Account Key Rollover
    // Defined in [RFC 8555 §7.3.5](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5).
    //
    // TODO: Account Deactivation
    // Defined in [RFC 8555 §7.3.6](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.6).
}
