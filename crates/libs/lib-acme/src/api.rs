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
use serde::{Deserialize, Serialize};
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

    pub async fn post<B: Serialize>(
        &self,
        url: &Url,
        private_key: Rsa<Private>,
        auth: JwkOrKid,
        body: Option<B>,
    ) -> Result<Response> {
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

        self.enqueue_nonce(res.headers());

        Ok(res)
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

        let res = self
            .client
            .post(url, new_account_cert.private_key.clone(), jwk, Some(&body))
            .await?;

        let account_id: Url = res
            .headers()
            .get("location")
            .map(|v| {
                String::from(
                    v.to_str().wrap_err("location header not utf-8 string")?,
                )
                .parse()
                .wrap_err("location header account_id not a url")
            })
            .ok_or_eyre("cannot extract location header")??;

        #[cfg(debug_assertions)]
        {
            use tracing::debug;

            let text = res.text().await.unwrap();
            debug!("{text}");
        }

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

        let res: Res = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth,
                Option::<u8>::None,
            )
            .await?
            .json()
            .await?; // u8 is just a placeholder

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

        let res = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth,
                Option::<u8>::None,
            )
            .await?
            .text()
            .await?; // u8 is just a placeholder

        println!("{res}");

        Ok(())
    }

    // pub async fn orders(&self, order_url: &Url) -> Result<()> {
    //     let res = self.client.order_status(url).await?.text().await?;
    //     println!("{res}");
    //     Ok(())
    // }

    // pub async fn create_order(&self) {}
}
