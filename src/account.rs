//! Account Management
//!
//! Create an account on an ACME server and perform some modifications to
//! the account after it has been created.

use std::sync::Arc;

use http::StatusCode;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct as _};
use url::Url;

use crate::{
    Client, Error, Key, Kid, Result,
    api::extract_location_header,
    crypto::{
        jwk::{Jwk, JwkOrKid},
        jws::{Jws, JwsProtectedHeaders},
        key_dto::VersionedKeyDto,
    },
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

    /// Account jwk
    pub(crate) jwk: Jwk,
}

impl Serialize for AccountCredentials {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AccountCredentials", 4)?;

        state.serialize_field("directoryUrl", &self.directory_url)?;
        state.serialize_field("kid", &self.kid)?;
        state.serialize_field("keyDto", &VersionedKeyDto::from(&self.key))?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for AccountCredentials {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Helper {
            kid: Kid,
            key_dto: VersionedKeyDto,
            directory_url: Url,
        }

        let Helper {
            kid,
            key_dto,
            directory_url,
        } = Helper::deserialize(deserializer)?;

        let key = Key::from(key_dto);

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
    /// Constructs an account from previously persisted credentials.
    ///
    /// This is typically used when resuming an existing ACME account session
    /// without re-registering with the ACME server.
    ///
    /// # ACME Context
    /// In RFC 8555, accounts are identified by a Key ID (`kid`) issued by the
    /// server during account creation. The corresponding private key must be
    /// retained by the client to authenticate subsequent requests.
    ///
    /// This constructor rebuilds the internal JWK representation from the
    /// stored private key to enable request signing.
    ///
    /// # Parameters
    /// - `directory_url`: The ACME directory URL associated with this account.
    /// - `kid`: The account Key ID assigned by the ACME server.
    /// - `key`: The persisted private key used to authenticate requests.
    ///
    /// # Returns
    /// Returns an initialized [`Account`] ready to perform authenticated ACME
    /// operations (orders, authorizations, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided private key cannot be converted into a JWK representation.
    /// - The key format is unsupported or malformed.
    /// - Internal cryptographic conversion fails.
    ///
    /// Any error during JWK conversion is propagated as [`Error`].
    pub fn load_from_parts(directory_url: Url, kid: Kid, key: Key) -> Result<Self> {
        let jwk = Jwk::try_from(&key)?;

        Ok(Self {
            directory_url,
            kid,
            key,
            jwk,
        })
    }

    #[must_use]
    pub const fn auth_jwk(&self) -> JwkOrKid<'_> {
        JwkOrKid::Jwk(&self.jwk)
    }

    #[must_use]
    pub const fn auth_kid(&self) -> JwkOrKid<'_> {
        JwkOrKid::Kid(&self.kid)
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

    pub const fn credentials(&self) -> &AccountCredentials {
        &self.credentials
    }

    #[must_use]
    pub const fn auth_jwk(&self) -> JwkOrKid<'_> {
        self.credentials.auth_jwk()
    }

    #[must_use]
    pub const fn auth_kid(&self) -> JwkOrKid<'_> {
        self.credentials.auth_kid()
    }

    /// Creates a new ACME account or retrieves an existing one by sending a
    /// POST request to the server's `newAccount` endpoint.
    ///
    /// This function ensures that account creation is allowed by explicitly
    /// setting `only_return_existing` to `false`, overriding any value provided
    /// in `new_account`.
    ///
    /// # ACME Context
    /// In RFC 8555, the `newAccount` endpoint is used to register a new account
    /// with the ACME server. If an account with the given key already exists,
    /// the server may return the existing account instead of creating a new one.
    ///
    /// Unlike account lookup (`onlyReturnExisting = true`), this request permits
    /// account creation and is authenticated using the account key as a JWK.
    ///
    /// # Parameters
    /// - `client`: The ACME client used to communicate with the server.
    /// - `key`: The private key used to identify and authenticate the account.
    /// - `new_account`: The account creation payload (contact info, terms of service, etc.).
    ///
    /// # Returns
    /// An initialized [Account] representing either the newly created or
    /// pre-existing account associated with the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The request to the `newAccount` endpoint fails (e.g., network, TLS, or signing issues).
    /// - The ACME server rejects the account creation request (e.g., terms of service not agreed).
    /// - The server responds with a non-success status code.
    /// - The provided key cannot be converted into a valid JWK representation.
    /// - The response cannot be parsed into a valid account structure.
    ///
    /// Any error from HTTP communication, cryptographic conversion, or response
    /// deserialization is propagated as [`Error`].
    pub async fn create(
        client: impl Into<Arc<Client>>,
        key: Key,
        new_account: NewAccount,
    ) -> Result<Self> {
        let new_account = NewAccount {
            only_return_existing: Some(false),
            ..new_account
        };

        Self::get_or_create(client, key, new_account).await
        // #[cfg(feature = "tracing")]
        // {
        //     // TODO: handle if status is 200 or 201(created) https://www.rfc-editor.org/rfc/rfc8555#section-7.3
        //     if response.status() == StatusCode::OK {
        //         tracing::warn!("Account already exist for give credentials");
        //     } else if response.status() == StatusCode::CREATED {
        //         tracing::info!("Account Created.");
        //     }
        // }
    }

    /// Fetches an existing ACME account by sending a POST request to the
    /// server's `newAccount` endpoint with `onlyReturnExisting = true`.
    ///
    /// This operation will **not** create a new account. If no account exists
    /// for the provided key, the server will return an error.
    ///
    /// # ACME Context
    /// As defined in [RFC 8555 §7.3.1], clients may query the `newAccount`
    /// endpoint with the `onlyReturnExisting` flag set to `true` to look up
    /// an existing account without risking accidental creation.
    ///
    /// The request is authenticated using the account key as a JWK, since
    /// the account's `kid` may not yet be known.
    ///
    /// # Parameters
    /// - `client`: The ACME client used to communicate with the server.
    /// - `key`: The private key associated with the ACME account.
    ///
    /// # Returns
    /// An [`Account`] corresponding to the existing account associated with
    /// the provided key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No account exists for the given key (`AcmeErrorType::AccountDoesNotExist`).
    /// - The request to the `newAccount` endpoint fails (network, TLS, or signing issues).
    /// - The server responds with a non-success status code.
    /// - The provided key cannot be converted into a valid JWK representation.
    /// - The response cannot be parsed into a valid account structure.
    ///
    /// Any error from HTTP communication, cryptographic conversion, or response
    /// deserialization is propagated as [`Error`].
    ///
    /// [RFC 8555 §7.3.1]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.1
    pub async fn fetch(client: impl Into<Arc<Client>>, key: Key) -> Result<Self> {
        let new_account = NewAccount {
            only_return_existing: Some(true),
            ..Default::default()
        };

        Self::get_or_create(client, key, new_account).await
    }

    /// Creates a new ACME account or retrieves an existing one using the
    /// server's `newAccount` endpoint.
    ///
    /// If an account already exists for the provided key, the server will return
    /// the existing account. Otherwise, a new account is created.
    ///
    /// # ACME Context
    /// According to RFC [8555 §7.3], the `newAccount` endpoint serves both account
    /// creation and retrieval. The client authenticates using a JWK (derived from
    /// the provided key), since a `kid` is not yet known.
    ///
    /// The server response semantics:
    /// - `201 Created`: A new account was created.
    /// - `200 OK`: An account already exists for the given key.
    ///
    /// The account URL (Key ID / `kid`) is returned via the `Location` header and
    /// is used for all subsequent authenticated requests.
    ///
    /// # Parameters
    /// - `client`: The ACME client used to communicate with the server.
    /// - `key`: The private key used to identify and authenticate the account.
    /// - `new_account`: The account creation payload (e.g., contact info,
    ///   terms of service agreement).
    ///
    /// # Returns
    /// An initialized [Account] with valid credentials (including `kid`)
    /// ready for authenticated ACME operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The request to the `newAccount` endpoint fails (e.g., network, TLS,
    ///   or request signing issues).
    /// - The provided key cannot be converted into a valid JWK representation.
    /// - The `Location` header is missing or cannot be parsed into a valid `kid`.
    /// - The response body cannot be deserialized into an [`AccountObject`].
    /// - The ACME server returns an account with a non-`valid` status
    ///   (e.g., `deactivated`, `revoked`), resulting in `Error::AccountStatusNoValid`.
    /// - The server responds with a malformed or unexpected response.
    ///
    /// Any error from HTTP communication, header extraction, cryptographic
    /// conversion, or JSON deserialization is propagated as [`Error`].
    ///
    /// [RFC 8555 §7.3]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3
    pub async fn get_or_create(
        client: impl Into<Arc<Client>>,
        key: Key,
        new_account: NewAccount,
    ) -> Result<Self> {
        let client = client.into();
        let url = &client.directory.new_account;

        let jwk = Jwk::try_from(&key)?;
        let auth = JwkOrKid::Jwk(&jwk);

        let response = client.post(url, &key, auth, &new_account).await?;

        let kid: Kid = extract_location_header(response.headers()).map(Into::into)?;

        let account_object = response.json::<AccountObject>().await?;

        if account_object.status != AccountStatus::Valid {
            return Err(Error::AccountStatusNoValid(account_object.status));
        }

        let directory_url = client.directory_url.clone();

        Ok(Self {
            client,
            credentials: AccountCredentials {
                directory_url,
                kid,
                key,
                jwk,
            },
        })
    }

    /// Retrieves an existing ACME account object from the server without creating a new account.
    ///
    /// This function uses the `onlyReturnExisting` flag as defined in RFC 8555 to query
    /// whether an account already exists for the given key. If the account exists, the
    /// server returns the corresponding [`AccountObject`]; otherwise, the request fails.
    ///
    /// # ACME Context
    /// In RFC 8555, account creation is performed via the `newAccount` endpoint. Clients
    /// can include the `onlyReturnExisting` field to avoid accidentally creating a new
    /// account, which is useful during account resumption flows.
    ///
    /// This request must be authenticated using the account's public key (JWK), not a `kid`,
    /// since the account may not yet exist.
    ///
    /// # Returns
    /// The ACME [`AccountObject`] associated with the provided key if it already exists.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ACME server does not recognize an existing account for the provided key.
    /// - The request to the `newAccount` endpoint fails (network, TLS, or signing issues).
    /// - The server responds with a non-success status code.
    /// - The response body cannot be deserialized into an [`AccountObject`].
    /// - The key cannot be converted into a valid JWK representation.
    ///
    /// Any cryptographic conversion, HTTP request failure, or JSON parsing error is
    /// propagated as [`Error`].
    pub async fn get_account_object(client: &Client, key: &Key) -> Result<AccountObject> {
        let new_account = NewAccount {
            only_return_existing: Some(true),
            ..Default::default()
        };

        let url = &client.directory.new_account;

        let jwk = Jwk::try_from(key)?;
        let auth = JwkOrKid::Jwk(&jwk);

        let response = client.post(url, key, auth, &new_account).await?;

        let account_object = response.json::<AccountObject>().await?;

        Ok(account_object)
    }

    /// Updates an existing ACME account by sending a signed POST request to the
    /// account URL (`kid`).
    ///
    /// Only mutable account fields (such as contact information) should be included
    /// in `update_account`. Fields like `orders`, `termsOfServiceAgreed`, and
    /// `status` are ignored or controlled by the server and will not be updated
    /// even if provided.
    ///
    /// # ACME Context
    /// As defined in RFC [8555 §7.3.2], account updates are performed by sending a
    /// POST request to the account URL using `kid`-based authentication.
    ///
    /// The server processes only permitted fields and returns the updated account
    /// object. The account must remain in a `valid` state for further use.
    ///
    /// # Parameters
    /// - `update_account`: The set of account fields to update (e.g., contact info).
    ///
    /// # Returns
    /// A refreshed [`Account`] instance reflecting the updated account state.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The request to the account URL fails (e.g., network, TLS, or signing issues).
    /// - The account key cannot be converted into a valid JWK representation.
    /// - The server responds with a non-success status code.
    /// - The response body cannot be deserialized into the expected account structure.
    /// - The returned account status is not `valid` (e.g., `deactivated`, `revoked`),
    ///   resulting in `Error::AccountStatusNoValid`.
    /// - The ACME server returns a malformed or unexpected response.
    ///
    /// Any error from HTTP communication, cryptographic conversion, or JSON
    /// deserialization is propagated as [`Error`].
    ///
    /// [RFC 8555 §7.3.2]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.2
    pub async fn update(&self, update_account: UpdateAccount) -> Result<Self> {
        #[derive(Deserialize)]
        struct IntermidiateAccount {
            status: AccountStatus,
            #[serde(rename = "orders")]
            _orders: Option<Url>,
        }

        let url = &self.credentials.kid;
        let jwk = Jwk::try_from(&self.credentials.key)?;

        let response = self
            .client
            .post(url, &self.credentials.key, self.auth_kid(), &update_account)
            .await?;

        let intermediate_account = response.json::<IntermidiateAccount>().await?;

        if intermediate_account.status != AccountStatus::Valid {
            return Err(Error::AccountStatusNoValid(intermediate_account.status));
        }

        Ok(Self {
            client: Arc::clone(&self.client),
            credentials: AccountCredentials {
                jwk,
                ..AccountCredentials::clone(&self.credentials)
            },
        })
    }

    /// Performs an ACME account key rollover, returning a new [`Account`] with
    /// updated credentials.
    ///
    /// This is a consuming variant of [``Self::key_rollover_mut``]. On success,
    /// the returned [Account] contains the new key material, and the caller
    /// should discard the previous instance.
    ///
    /// # ACME Context
    /// As defined in [RFC 8555 §7.3.5], key rollover allows an account to securely
    /// transition to a new key pair using a nested JWS request to the `keyChange`
    /// endpoint.
    ///
    /// After a successful rollover:
    /// - The new key becomes the authoritative key for the account.
    /// - The old key must no longer be used.
    /// - The client should continue all subsequent operations with the returned
    ///   [`Account`] instance.
    ///
    /// # Parameters
    /// - `new_key`: The new private key to associate with the account.
    ///
    /// # Returns
    /// A new [Account] instance updated with the rolled-over key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying key rollover operation fails (see [`Self::key_rollover_mut`]).
    /// - The old or new key cannot be converted into a valid JWK representation.
    /// - The request to the `keyChange` endpoint fails (network, TLS, or signing issues).
    /// - The server reports a conflict (e.g., the new key is already in use),
    ///   resulting in `Error::ExistingAccountDuringKeyRollover`.
    /// - Fetching or reconstructing the updated account fails.
    /// - The ACME server returns a malformed or unexpected response.
    ///
    /// Any error from HTTP communication, cryptographic operations, or account
    /// retrieval is propagated as [`Error`].
    ///
    /// [RFC 8555 §7.3.5]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5
    pub async fn key_rollover(self, new_key: Key) -> Result<Self> {
        let mut account = self;
        account.key_rollover_mut(new_key).await?;
        Ok(account)
    }

    /// Performs an ACME account key rollover, replacing the current account key
    /// with a new one.
    ///
    /// This sends a signed request to the server's `keyChange` endpoint to update
    /// the account’s public key. On success, the current [Account] instance is
    /// updated in-place with the new credentials.
    ///
    /// # ACME Context
    /// Defined in [RFC 8555 §7.3.5], key rollover is a secure mechanism that allows
    /// an account to transition to a new key pair without losing account identity.
    ///
    /// The request uses a **nested JWS** structure:
    /// - The **inner JWS** is signed with the *new key* and contains the account
    ///   URL (`kid`) and the *old key* (as JWK).
    /// - The **outer JWS** is signed with the *old key* and authenticates the request.
    ///
    /// If successful:
    /// - The server associates the new key with the existing account.
    /// - Subsequent requests must use the new key.
    /// - The client typically re-fetches the account using the new key.
    ///
    /// # Parameters
    /// - `new_key`: The new private key to associate with the account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The old or new key cannot be converted into a valid JWK representation.
    /// - The request to the `keyChange` endpoint fails (e.g., network, TLS,
    ///   or signing issues).
    /// - The server responds with an unexpected status code.
    /// - The server indicates a conflict (e.g., the new key is already associated
    ///   with another account), resulting in
    ///   `Error::ExistingAccountDuringKeyRollover`.
    /// - Fetching the account with the new key after rollover fails.
    /// - The ACME server returns a malformed or unexpected response.
    ///
    /// Any error from HTTP communication, nested JWS construction, cryptographic
    /// conversion, or follow-up account retrieval is propagated as [`Error`].
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

        let old_key = &self.credentials.key;
        let old_jwk = Jwk::try_from(old_key)?;

        let inner_payload = &InnerPayload {
            account: &self.credentials.kid,
            old_jwk,
        };

        let inner_jwk = &Jwk::try_from(&new_key)?;
        let inner_auth = JwkOrKid::Jwk(inner_jwk);

        let inner_jws_header = JwsProtectedHeaders::new(&new_key, url, &inner_auth, None);
        let inner_jws = &Jws::new(&new_key, inner_jws_header, inner_payload);

        let outer_auth = JwkOrKid::Kid(&self.credentials.kid);

        let new_account_maybe = match self.client.post(url, old_key, outer_auth, inner_jws).await {
            Ok(v) => match v.status() {
                StatusCode::OK => Self::fetch(self.client.clone(), new_key).await,
                StatusCode::CONFLICT => Err(Error::ExistingAccountDuringKeyRollover),
                _ => Err(Error::Str(
                    "Status code other than OK/CONFLICT recieved when key rollover.",
                )),
            },
            Err(e) => {
                if let Error::Problem(problem) = &e
                    && let crate::api::ProblemType::Unknown(v) = &problem.r#type
                    && v.as_ref() == "conflict"
                {
                    return Err(Error::ExistingAccountDuringKeyRollover);
                }

                Err(e)
            }
        };

        let new_account = new_account_maybe?;

        self.client = new_account.client;
        self.credentials = new_account.credentials;

        Ok(())
    }

    /// Deactivates the ACME account by sending a POST request to the account URL
    /// with status set to `"deactivated"`.
    ///
    /// After successful deactivation, the account is permanently disabled and
    /// can no longer be used to perform ACME operations (e.g., creating orders
    /// or responding to challenges).
    ///
    /// # ACME Context
    /// As defined in RFC [8555 §7.3.6], account deactivation is performed by
    /// sending a signed POST request to the account URL (`kid`) with the
    /// `"status": "deactivated"` field.
    ///
    /// This operation is irreversible:
    /// - The account transitions to the `deactivated` state.
    /// - The server will reject further requests authenticated with this account.
    ///
    /// # Returns
    /// Returns `Ok(())` if the deactivation request is successfully processed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The POST request to the account URL fails (e.g., network, TLS,
    ///   or signing issues).
    /// - The server responds with a non-success status code.
    /// - The ACME server rejects the deactivation request.
    /// - The server returns a malformed or unexpected response.
    ///
    /// Any error from HTTP communication or request signing is propagated as [`Error`].
    ///
    /// # Notes
    /// - Since this method consumes `self`, the current [Account] instance
    ///   cannot be used after calling this function.
    ///
    /// [RFC 8555 §7.3.6]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.6
    pub async fn deactivate(self) -> Result<()> {
        #[derive(Serialize)]
        pub(crate) struct DeactivateRequest {
            status: &'static str,
        }

        let url = &self.credentials.kid.as_url();

        let body = DeactivateRequest {
            status: "deactivated",
        };

        self.client
            .post(url, &self.credentials.key, self.auth_kid(), &body)
            .await?;

        Ok(())
    }

    // TODO: External Account Binding.
    // Defined in [RFC 8555 §7.3.4](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4).
}
