use std::{collections::VecDeque, sync::Mutex};

use color_eyre::{
    Result,
    eyre::{Context, OptionExt},
};
use lib_core::model::ModelManager;
use openssl::{pkey::Private, rsa::Rsa};
use reqwest::{
    Client, IntoUrl, Response,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use url::Url;

use crate::{
    account::{
        Account, AccountCert, JwkOrKid, Jws, JwsAlgorithm, JwsProtectedHeaders,
    },
    directory::AcmeDirectory,
};

struct AcmeClient {
    client: Client,
    nonce_url: Url,
    nonce_store: Mutex<VecDeque<Box<str>>>,
}

#[cfg(debug_assertions)]
fn headermap_to_hashmap(
    headers: &HeaderMap,
) -> std::collections::HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(key, value)| {
            // Convert HeaderValue to &str (may fail if not valid UTF-8)
            value
                .to_str()
                .ok()
                .map(|v| (key.to_string(), v.to_string()))
        })
        .collect()
}

#[cfg(debug_assertions)]
#[allow(dead_code)]
fn hashmap_to_headermap(
    map: std::collections::HashMap<String, String>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    for (key, value) in map {
        let name = match reqwest::header::HeaderName::from_bytes(key.as_bytes())
        {
            Ok(n) => n,
            Err(_) => continue, // skip invalid header names
        };

        let val = match HeaderValue::from_str(&value) {
            Ok(v) => v,
            Err(_) => continue, // skip invalid values
        };

        headers.insert(name, val);
    }

    headers
}

pub(crate) enum AcmeApiBody<T: Serialize = ()> {
    EmptyString,
    #[allow(dead_code)]
    EmptyObject,
    Other(T),
}

impl AcmeApiBody<()> {
    pub const EMPTY_STRING: Self = AcmeApiBody::EmptyString;
    #[allow(dead_code)]
    pub const EMPTY_OBJECT: Self = AcmeApiBody::EmptyObject;
}

impl AcmeClient {
    fn extract_nonce(headers: &HeaderMap) -> Option<Box<str>> {
        headers
            .get("replay-nonce")
            .map(|v| v.to_str())
            .and_then(|v| v.ok())
            .map(Box::from)
    }

    fn enqueue_nonce(&self, headers: &HeaderMap) {
        if let Some(nonce) = Self::extract_nonce(headers) {
            self.nonce_store
                .lock()
                .expect("Unable to lock Nonce Store mutex")
                .push_back(nonce);

            return;
        };

        tracing::warn!("replay-nonce header not found in request");
    }

    async fn get_nonce(&self) -> Result<Box<str>> {
        if let Some(nonce) = self
            .nonce_store
            .lock()
            .expect("Unable to lock Nonce Store mutex")
            .pop_front()
        {
            return Ok(nonce);
        };

        let req = self.nonce(self.nonce_url.as_str()).await?;

        let nonce = Self::extract_nonce(req.headers())
            .ok_or_eyre("replay-nonce header not found in request")?;

        Ok(nonce)
    }

    async fn nonce<T: IntoUrl>(
        &self,
        url: T,
    ) -> std::result::Result<Response, reqwest::Error> {
        self.client.head(url).send().await
    }

    pub async fn post<B, R>(
        &self,
        url: &Url,
        private_key: Rsa<Private>,
        auth: JwkOrKid,
        body: AcmeApiBody<B>,
    ) -> Result<(HeaderMap, R)>
    where
        B: Serialize,
        R: DeserializeOwned + std::fmt::Debug,
    {
        // OPTIMIZE: new directly from array without mut
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/jose+json"),
        );

        let nonce = &self.get_nonce().await?;

        let jws_protected_headers = JwsProtectedHeaders {
            algorithm: JwsAlgorithm::RS256,
            url,
            auth,
            nonce,
        };

        let jws = Jws::new(private_key, &jws_protected_headers, body)?;

        let res = self
            .client
            .post(url.as_str())
            .headers(headers)
            .json(&jws)
            .send()
            .await?;

        let headers = res.headers().clone();
        self.enqueue_nonce(&headers);

        let body_text = res.text().await?;

        #[cfg(debug_assertions)]
        tracing::debug!(
            "\nheaders: {}\nbody: {}",
            serde_json::to_string_pretty(&headermap_to_hashmap(&headers))?,
            body_text,
        );

        let body: R = serde_json::from_str(&body_text)?;

        Ok((headers, body))
    }
}

pub struct AcmeApi<Account = ()> {
    client: AcmeClient,
    acme_directory: AcmeDirectory,
    model_manager: ModelManager,
    account: Account,
}

impl AcmeApi<()> {
    pub async fn _new(
        acme_uri: Url,
        model_manager: ModelManager,
    ) -> Result<AcmeApi<()>> {
        let client = Client::builder()
            // .danger_accept_invalid_certs(true)
            .build()
            .wrap_err("Unable to build reqwest client")?;

        Self::new_from_client(acme_uri, model_manager, client).await
    }

    pub async fn new_from_client(
        acme_uri: Url,
        model_manager: ModelManager,
        client: Client,
    ) -> Result<AcmeApi<()>> {
        let acme_directory = client
            .get(acme_uri)
            .send()
            .await?
            .json::<AcmeDirectory>()
            .await?;

        Ok(AcmeApi {
            client: AcmeClient {
                client,
                nonce_store: Default::default(),
                nonce_url: acme_directory.new_nonce.clone(),
            },
            model_manager,
            acme_directory,
            account: (),
        })
    }
}

impl AcmeApi<()> {
    fn into_registerd(self, account: Account) -> AcmeApi<Account> {
        AcmeApi {
            account,
            client: self.client,
            model_manager: self.model_manager,
            acme_directory: self.acme_directory,
        }
    }

    pub async fn register_account(self) -> Result<AcmeApi<Account>> {
        let new_account_cert = AccountCert::new()?;

        let url = &self.acme_directory.new_account;
        let jwk: JwkOrKid = new_account_cert.public_key.clone().into();
        let body = json!({ "termsOfServiceAgreed": true });

        /// ```json
        /// {
        ///    "status": "valid",
        ///    "orders": "{order_url}",
        ///    "key": {
        ///       "kty": "{key_type: RSA}",
        ///       "n": "{modulus}",
        ///       "e": "{exponent}"
        ///    }
        /// }
        /// ```
        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct Res {
            status: String,
            orders: Url,
        }

        let (headers, _): (_, Res) = self
            .client
            .post(
                url,
                new_account_cert.private_key.clone(),
                jwk,
                AcmeApiBody::Other(&body),
            )
            .await?;

        let account_id: Url = headers
            .get("location")
            .map(|v| {
                String::from(
                    v.to_str().wrap_err("location header not utf-8 string")?,
                )
                .parse()
                .wrap_err("location header account_id not a url")
            })
            .ok_or_eyre("cannot extract location header")??;

        let account = Account::new(account_id, new_account_cert.clone());

        Ok(self.into_registerd(account))
    }
}

impl AcmeApi<Account> {
    async fn orders_url(&self) -> Result<Url> {
        let url = &self.account.account_id();
        let auth: JwkOrKid = self.account.account_id().into();

        /// ```json
        /// {
        ///    "status": "valid",
        ///    "orders": "{order_url}",
        ///    "key": {
        ///       "kty": "{key_type: RSA}",
        ///       "n": "{modulus}",
        ///       "e": "{exponent}"
        ///    }
        /// }
        /// ```
        #[derive(Debug, Deserialize)]
        struct Res {
            status: String,
            orders: Url,
        }

        let (_, res): (_, Res) = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth,
                AcmeApiBody::EMPTY_STRING,
            )
            .await?;

        if res.status != "valid" {
            return Err(color_eyre::eyre::eyre!(
                "account info status not valid"
            ));
        }
        Ok(res.orders)
    }

    pub(crate) async fn orders(&self) -> Result<()> {
        let url = &self.orders_url().await?;

        let auth: JwkOrKid = self.account.account_id().into();

        /// ```json
        /// {
        ///    "orders": ["{order_url}"]
        /// }
        /// ```
        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct Res {
            orders: Vec<serde_json::Value>,
        }

        let _: (_, Res) = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth,
                AcmeApiBody::EMPTY_STRING,
            )
            .await?;

        Ok(())
    }

    // pub async fn create_order(&self) {}
}
