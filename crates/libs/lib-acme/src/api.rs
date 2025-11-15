use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use color_eyre::{
    Result,
    eyre::{Context, OptionExt},
};
use lib_core::model::ModelManager;
use reqwest::{
    Client, IntoUrl, Response,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use crate::{
    account::{
        Account, AccountCert, Jwk, JwkOrKid, Jws, JwsAlgorithm,
        JwsProtectedHeaders,
    },
    acme_bmc::AcmeAccountBmc,
    directory::AcmeDirectory,
};

#[derive(Clone)]
struct AcmeClient {
    client: Client,
    acme_directory: AcmeDirectory,
    nonce_store: Arc<Mutex<VecDeque<Box<str>>>>,
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

        let req = self.nonce(self.acme_directory.new_nonce.as_str()).await?;

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

    async fn post<B: Serialize>(
        &self,
        url: &Url,
        account: &Account,
        body: Option<B>,
    ) -> Result<Response> {
        // OPTIMIZE: new directly from array without mut
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/jose+json"),
        );

        let nonce = self.get_nonce().await?;

        let jws_protected_headers = JwsProtectedHeaders {
            algorithm: JwsAlgorithm::RS256,
            url,
            auth: JwkOrKid::Kid {
                kid: account.account_id(),
            },
            nonce: &nonce,
        };

        let jws = Jws::new(
            account.cert().private_key.clone(),
            &jws_protected_headers,
            body,
        )?;

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

    pub async fn new_account(
        &self,
        account_cert: &AccountCert,
    ) -> Result<Response> {
        let url = &self.acme_directory.new_account;
        let body = json!({ "termsOfServiceAgreed": true });

        let jwk = Jwk::from(account_cert);

        let nonce = self.get_nonce().await?;

        let jws_protected_headers = JwsProtectedHeaders {
            algorithm: JwsAlgorithm::RS256,
            url,
            auth: JwkOrKid::Jwk { jwk },
            nonce: &nonce,
        };

        let jws = Jws::new(
            account_cert.private_key.clone(),
            &jws_protected_headers,
            Some(body),
        )?;

        // OPTIMIZE: new directly from array without mut
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/jose+json"),
        );

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

    /// Returns orders url
    pub async fn account_info(&self, account: &Account) -> Result<Url> {
        #[derive(Debug, Deserialize)]
        struct Res {
            orders: Url,
        }

        let url = account.account_id();
        let res: Res = self
            .post(url, account, Option::<u8>::None)
            .await?
            .json()
            .await?; // u8 is just a placeholder

        Ok(res.orders)
    }

    pub async fn order_status(&self, account: &Account) -> Result<Response> {
        let url = self.account_info(account).await?;
        let res = self.post(&url, account, Option::<u8>::None).await?; // u8 is just a placeholder
        Ok(res)
    }
}

#[derive(Clone)]
pub struct AcmeApi {
    client: Arc<AcmeClient>,
    model_manager: ModelManager,
}

impl AcmeApi {
    pub async fn _new(
        acme_uri: Url,
        model_manager: ModelManager,
    ) -> Result<Self> {
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
    ) -> Result<Self> {
        let acme_directory = client
            .get(acme_uri)
            .send()
            .await?
            .json::<AcmeDirectory>()
            .await?;

        Ok(Self {
            client: (AcmeClient {
                client,
                acme_directory,
                nonce_store: Default::default(),
            })
            .into(),
            model_manager,
        })
    }
}

impl AcmeApi {
    pub async fn create_new_account(&self) -> Result<Account> {
        if let Ok(account) =
            AcmeAccountBmc::get_first(&self.model_manager).await
        {
            return account.try_into();
        }

        let new_account_cert = AccountCert::new()?;

        let res = self.client.new_account(&new_account_cert).await?;

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

        // Save acount to database
        AcmeAccountBmc::create(&self.model_manager, &account).await?;

        Ok(account)
    }

    // pub async fn account_info(&self) -> Result<()> {
    //     let account: Account = AcmeAccountBmc::get_first(&self.model_manager)
    //         .await?
    //         .try_into()?;
    //     let res = self.client.account_info(&account).await?.text().await?;
    //     println!("{res}");
    //     Ok(())
    // }

    pub async fn orders(&self) -> Result<()> {
        let account: Account = AcmeAccountBmc::get_first(&self.model_manager)
            .await?
            .try_into()?;
        let res = self.client.order_status(&account).await?.text().await?;
        println!("{res}");
        Ok(())
    }
}
