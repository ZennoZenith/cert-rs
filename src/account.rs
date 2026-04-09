//! Account Management
//!
//! Create an account on an ACME server and perform some modifications to
//! the account after it has been created.

use std::sync::Arc;

use http::StatusCode;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct as _};
use url::Url;

use crate::{
    Client, Error, Result,
    api::extract_location_header,
    authentication::{Jwk, JwkOrKid, Jws, JwsProtectedHeaders, Key, Kid},
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
    pub(crate) directory_url: Url,

    pub(crate) kid: Kid,

    /// The account's private key
    pub(crate) key: Key,

    /// Account jwk. Not Serialized
    pub(crate) jwk: Jwk,
}

impl Serialize for AccountCredentials {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AccountCredentials", 4)?;

        state.serialize_field("directory_url", &self.directory_url)?;
        state.serialize_field("kid", &self.kid)?;
        state.serialize_field("key", &self.key)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for AccountCredentials {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            kid: Kid,
            key: Key,
            directory_url: Url,
        }

        let Helper {
            kid,
            key,
            directory_url,
        } = Helper::deserialize(deserializer)?;

        // todo: document
        let jwk = Jwk::try_from(&key).map_err(serde::de::Error::custom)?;

        Ok(Self {
            directory_url,
            kid,
            key,
            jwk,
        })
    }
}

impl AccountCredentials {
    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn load_from_parts(directory_url: Url, kid: Kid, key: Key) -> Result<Self> {
        let jwk =
            Jwk::try_from(&key).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        Ok(Self {
            directory_url,
            kid,
            key,
            jwk,
        })
    }
}

/// Used for ACME account management, Not to be confused with [``AccountObject``].
///
/// This opaque type contains the [``Client``] and the [``AccountCredentials``]
#[derive(Debug, Clone)]
pub struct Account {
    pub(crate) client: Arc<Client>,
    pub(crate) credentials: AccountCredentials,
}

impl Account {
    pub fn load(client: Arc<Client>, credentials: AccountCredentials) -> Self {
        if client.directory_url != credentials.directory_url {
            // TODO: add directory url in warn
            #[cfg(feature = "tracing")]
            tracing::warn!("Client and Credentials Directory Url do not match");
        }

        Self {
            client,
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

    /// Create new account or fetch existing by sending a POST request to the server's newAccount URL
    /// Will overwrite `new_account.only_return_existing` to false.
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn create(client: Arc<Client>, key: Key, new_account: NewAccount) -> Result<Self> {
        let new_account = NewAccount {
            only_return_existing: Some(false),
            ..new_account
        };

        Self::fetch_or_create(client, &key, new_account).await
    }

    /// Fetch account by sending a POST request to the server's newAccount URL.
    /// Will not create a new account if one does not already exist.
    ///
    /// See [RFC 8555 §7.3.1](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.1)
    ///
    /// # Errors
    ///
    /// Will fail if account does not exist `AcmeErrorType::AccountDoesNotExist`.
    ///
    /// TODO: Write error docs
    pub async fn fetch(client: Arc<Client>, key: &Key) -> Result<Self> {
        let new_account = NewAccount {
            only_return_existing: Some(true),
            ..Default::default()
        };

        Self::fetch_or_create(client, key, new_account).await
    }

    /// Create new account by sending a POST request to the server's newAccount URL
    /// If account already exists for a given private key, then fetch details else create new account
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn fetch_or_create(
        client: Arc<Client>,
        key: &Key,
        new_account: NewAccount,
    ) -> Result<Self> {
        let url = &client.directory.new_account;

        let jwk = Jwk::try_from(key).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        let auth = JwkOrKid::Jwk(jwk.clone());
        let body = new_account;

        let response = client.post(url, key, auth, body).await?;

        // TODO: handle if status is 200 or 201(created) https://www.rfc-editor.org/rfc/rfc8555#section-7.3
        let kid: Kid = extract_location_header(response.headers()).map(Into::into)?;

        let account_object = response
            .json::<AccountObject>()
            .await
            .map_err(|_| Error::Unimplemented("Cannot extact account status".into()))?;

        if account_object.status != AccountStatus::Valid {
            return Err(Error::AccountStatusNoValid(account_object.status));
        }

        let directory_url = client.directory_url.clone();

        Ok(Self {
            client,
            credentials: AccountCredentials {
                kid,
                key: key.clone(),
                directory_url,
                jwk,
            },
        })
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn get_account_object(client: &Client, key: &Key) -> Result<AccountObject> {
        let new_account = NewAccount {
            only_return_existing: Some(true),
            ..Default::default()
        };

        let url = &client.directory.new_account;

        let jwk = Jwk::try_from(key).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
        let auth = JwkOrKid::Jwk(jwk);
        let body = new_account;

        let response = client.post(url, key, auth, body).await?;

        let account_object = response
            .json::<AccountObject>()
            .await
            .map_err(|_| Error::Unimplemented("Cannot extact account status".into()))?;

        Ok(account_object)
    }

    /// Update account by sending a POST request to the server's account URL (Kid)
    ///
    /// Will ignore any updates to the "orders" field, "termsOfServiceAgreed" field,
    /// the "status" field.
    ///
    /// See: [RFC 8555 §7.3.2](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.2)
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

        let jwk = Jwk::try_from(&self.credentials.key)
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        let auth = JwkOrKid::Kid(&self.credentials.kid);
        let body = update_account;

        let response = self.client.post(url, &self.credentials.key, auth, body).await?;

        let intermediate_account = response
            .json::<IntermidiateAccount>()
            .await
            .map_err(|_| Error::Unimplemented("Cannot extact account status".into()))?;

        if intermediate_account.status != AccountStatus::Valid {
            return Err(Error::AccountStatusNoValid(intermediate_account.status));
        }

        Ok(Self {
            client: Arc::clone(&self.client),
            credentials: AccountCredentials {
                kid: self.credentials.kid.clone(),
                key: self.credentials.key.clone(),
                directory_url: self.credentials.directory_url.clone(),
                jwk,
            },
        })
    }

    /// Account Key Rollover
    ///
    /// Update account public key associated with an account by sending a POST
    /// request to the server's keyChange URL
    ///
    /// If key rollover is success, You should abandon current [Account] and start
    /// using returned [Account]
    ///
    /// See: [RFC 8555 §7.3.5]
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    ///
    /// # Panics
    ///
    /// [RFC 8555 §7.3.5]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5
    pub async fn key_rollover(self, new_key: Key) -> Result<Self> {
        let mut account = self;
        account.key_rollover_mut(new_key).await?;
        Ok(account)
    }

    /// Account Key Rollover
    ///
    /// Update account public key associated with an account by sending a POST
    /// request to the server's keyChange URL
    ///
    /// If key rollover is success, current [Account] is updated.
    ///
    /// See: [RFC 8555 §7.3.5]
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    ///
    /// # Panics
    ///
    /// [RFC 8555 §7.3.5]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5
    pub async fn key_rollover_mut(&mut self, new_key: Key) -> Result<()> {
        #![allow(clippy::similar_names)]

        #[derive(Debug, Clone, Serialize)]
        #[serde(rename_all = "camelCase")]
        struct InnerPayload<'a> {
            account: &'a Kid,
            #[serde(rename = "oldKey")]
            old_jwk: Jwk,
        }

        let url = &self.client.directory.key_change;

        // {
        //  "protected": base64url({
        //    "alg": "ES256",
        //    "kid": "https://example.com/acme/acct/evOfKhNU60wg",
        //    "nonce": "S9XaOcxP5McpnTcWPIhYuB",
        //    "url": "https://example.com/acme/key-change"
        //  }),
        //  "payload": base64url({
        //    "protected": base64url({
        //      "alg": "ES256",
        //      "jwk": /* new key */,
        //      "url": "https://example.com/acme/key-change"
        //    }),
        //    "payload": base64url({
        //      "account": "https://example.com/acme/acct/evOfKhNU60wg",
        //      "oldKey": /* old key */
        //    }),
        //    "signature": "Xe8B94RD30Azj2ea...8BmZIRtcSKPSd8gU"
        //  }),
        //  "signature": "5TWiqIYQfIDfALQv...x9C2mg8JGPxl5bI4"
        // }

        let old_key = &self.credentials.key;
        let old_jwk =
            Jwk::try_from(old_key).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        let inner_payload = InnerPayload {
            account: &self.credentials.kid,
            old_jwk,
        };

        let inner_jwk =
            Jwk::try_from(&new_key).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
        let inner_auth = JwkOrKid::Jwk(inner_jwk);

        let inner_jws_header = JwsProtectedHeaders::new(&new_key, url, inner_auth, None);
        let inner_jws = Jws::new(&new_key, inner_jws_header, inner_payload);

        let outer_auth = JwkOrKid::Kid(&self.credentials.kid);

        let new_account_maybe = match self.client.post(url, old_key, outer_auth, inner_jws).await {
            Ok(v) => match v.status() {
                StatusCode::OK => Self::fetch(self.client.clone(), &new_key).await,
                StatusCode::CONFLICT => Err(Error::ExistingAccountDuringKeyRollover),
                status_code => Err(Error::Unimplemented(Box::from(format!(
                    "Invalid status code recieved when key rollover: {status_code}",
                )))),
            },
            Err(e) => {
                if let crate::api::Error::AcmeError(acme_error_type) = &e
                    && let crate::api::AcmeErrorType::Unknown(v) = &acme_error_type.type_
                    && v.as_ref() == "conflict"
                {
                    return Err(Error::ExistingAccountDuringKeyRollover);
                }

                Err(Error::Api(e))
            }
        };

        let new_account = new_account_maybe?;

        self.client = new_account.client;
        self.credentials = new_account.credentials;

        Ok(())
    }

    /// Account Deactivation
    ///
    /// See: [RFC 8555 §7.3.6](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.6)
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn deactivate(self) -> Result<()> {
        let url = &self.credentials.kid.as_url();

        let auth = JwkOrKid::Kid(&self.credentials.kid);
        let body = serde_json::json!({
           "status": "deactivated"
        });

        self.client.post(url, &self.credentials.key, auth, body).await?;

        Ok(())
    }

    // TODO: External Account Binding.
    // Defined in [RFC 8555 §7.3.4](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4).
}
