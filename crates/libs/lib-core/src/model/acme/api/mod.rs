mod account;
mod acme_dir;

pub use account::{AccountCert, Jwk};
pub use acme_dir::{AcmeDirectory, AcmeDirectoryMeta};

use lib_utils::b64;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::Serialize;
use serde_json::json;

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use color_eyre::{
    Result,
    eyre::{Context, OptionExt},
};
use reqwest::{
    Client,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};

use url::Url;

use crate::model::acme::account::AccountId;

#[derive(Debug, Clone)]
pub struct AcmeApi {
    client: Arc<Client>,
    acme_directory: Arc<AcmeDirectory>,
    nonce_store: Arc<Mutex<VecDeque<Box<str>>>>,
}

impl AcmeApi {
    pub async fn new(acme_uri: Url) -> Result<Self> {
        let client = Client::builder()
            // .danger_accept_invalid_certs(true)
            .build()
            .wrap_err("Unable to build reqwest client")?;

        Self::new_from_client(acme_uri, client).await
    }

    pub async fn new_from_client(
        acme_uri: Url,
        client: Client,
    ) -> Result<Self> {
        let acme_directory = client
            .get(acme_uri)
            .send()
            .await?
            .json::<AcmeDirectory>()
            .await?;

        Ok(Self {
            client: client.into(),
            acme_directory: acme_directory.into(),
            nonce_store: Default::default(),
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

impl AcmeApi {
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

        let req = self
            .client
            .head(self.acme_directory.new_nonce.as_ref())
            .send()
            .await?;

        let nonce = Self::extract_nonce(req.headers())
            .ok_or_eyre("replay-nonce header not found in request")?;

        Ok(nonce)
    }

    pub async fn create_new_account(&self) -> Result<(AccountId, AccountCert)> {
        let url = &self.acme_directory.new_account;
        let new_account = AccountCert::new().unwrap();

        let jwk = Jwk::from(&new_account);

        let body = json!({ "termsOfServiceAgreed": true });
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/jose+json"),
        );

        let nonce = self.get_nonce().await?;

        #[derive(Debug, Serialize)]
        enum JwsAlgorithm {
            RS256,
        }

        #[derive(Debug, Serialize)]
        struct JwsProtectedHeaders<'a> {
            #[serde(rename = "alg")]
            algorithm: JwsAlgorithm,
            url: &'a Url,
            #[serde(skip_serializing_if = "Option::is_none")]
            jwk: Option<Jwk>,
            #[serde(skip_serializing_if = "Option::is_none")]
            kid: Option<Url>,
            nonce: Box<str>,
        }

        let jws_protected_headers = JwsProtectedHeaders {
            algorithm: JwsAlgorithm::RS256,
            url,
            jwk: Some(jwk),
            kid: None,
            nonce,
        };

        let jws_protected = b64::b64u_encode(
            serde_json::to_string(&jws_protected_headers)
                .expect("Unable to serialize jws_protected_headers"),
        );

        let jws_payload = b64::b64u_encode(
            serde_json::to_string(&body).expect("Unable to serialize body"),
        );

        let jws_signature = format!("{jws_protected}.{jws_payload}");

        let keypair = PKey::from_rsa(new_account.private_key.clone())?;

        let mut signer = Signer::new(MessageDigest::sha256(), &keypair)?;
        signer.update(jws_signature.as_bytes())?;
        let signature = signer.sign_to_vec()?;

        let jws_signature = b64::b64u_encode(signature);

        #[derive(Debug, Serialize)]
        struct Jws {
            protected: String,
            payload: String,
            signature: String,
        }

        let jws = Jws {
            protected: jws_protected,
            payload: jws_payload,
            signature: jws_signature,
        };
        let t = self
            .client
            .post(self.acme_directory.new_account.as_ref())
            .headers(headers)
            .json(&jws)
            .send()
            .await
            .unwrap();

        self.enqueue_nonce(t.headers());

        let account_id = t
            .headers()
            .get("location")
            .map(|v| String::from(v.to_str().unwrap()))
            .ok_or_eyre("cannot extract location header")?;

        let text = t.text().await.unwrap();
        println!("account_id: {account_id:?}");
        println!("{text}");

        Ok((account_id.into(), new_account))
    }
}
