use http::HeaderMap;
use openssl::{pkey::Private, rsa::Rsa};
use reqwest::Response;
use serde::Serialize;
use std::collections::VecDeque;
use tokio::sync::Mutex;
use url::Url;

use crate::{
    AcmeError,
    authentication::{JwkOrKid, Jws},
    directory::Directory,
};

use api::{AcmeApiBody, Error, RequestBuilderExt as _, ResponseExt as _, Result};

pub mod api;

const MAX_NONCE_STORE_CAPACITY: usize = 100;

pub struct AcmeClient {
    reqwest_client: reqwest::Client,
    directory: Directory,
    nonce_store: Mutex<VecDeque<Box<str>>>,
}

impl AcmeClient {
    #[must_use]
    pub fn new(reqwest_client: reqwest::Client, directory: Directory) -> Self {
        Self {
            reqwest_client,
            directory,
            nonce_store: Mutex::new(VecDeque::with_capacity(MAX_NONCE_STORE_CAPACITY)),
        }
    }

    // #[must_use]
    // pub const fn client(&self) -> &Client {
    //     &self.reqwest_client
    // }

    #[must_use]
    pub const fn directory(&self) -> &Directory {
        &self.directory
    }

    fn extract_nonce(headers: &HeaderMap) -> Option<Box<str>> {
        headers
            .get("replay-nonce")
            .map(|v| v.to_str())
            .and_then(std::result::Result::ok)
            .map(Box::from)
    }

    pub(self) async fn enqueue_nonce(&self, headers: &HeaderMap) {
        let Some(nonce) = Self::extract_nonce(headers) else {
            #[cfg(feature = "tracing")]
            tracing::warn!("replay-nonce header not found in request");

            return;
        };

        let nonce_store_len = { self.nonce_store.lock().await.len() };
        if nonce_store_len >= MAX_NONCE_STORE_CAPACITY {
            // Remove oldest nonce
            self.nonce_store.lock().await.pop_front();
        }

        self.nonce_store.lock().await.push_back(nonce);
    }

    async fn nonce(&self) -> Result<Box<str>> {
        let value = self.nonce_store.lock().await.pop_front();

        if let Some(nonce) = value {
            return Ok(nonce);
        }

        let response = self
            .reqwest_client
            .head(self.directory.new_nonce.as_str())
            .add_rfc_headers()
            .send()
            .await?;

        let headers = response.headers();

        Self::extract_nonce(headers).ok_or(Error::MissingHeaderName("replay-nonce"))
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn post<T: Clone + Serialize>(
        &self,
        url: &Url,
        private_key: &Rsa<Private>,
        auth: JwkOrKid,
        body: AcmeApiBody<T>,
    ) -> Result<Response> {
        let mut nonce_retry: usize = 0;
        loop {
            let nonce = self.nonce().await?;
            let jws = Jws::new_from_parts(
                private_key.clone(),
                url,
                auth.clone(),
                nonce.as_ref(),
                body.clone(),
            );

            let maybe_response = self
                .reqwest_client
                .post(url.as_str())
                .add_rfc_headers()
                .json(&jws)
                .send()
                .await?
                .extract_nonce(self)
                .await
                .handle_response_error()
                .await;

            match maybe_response {
                Err(Error::AcmeError(AcmeError {
                    type_: acme_error_type @ api::AcmeErrorType::BadNonce,
                    ..
                })) => {
                    nonce_retry += 1;
                    println!("AcmeErrorType: {acme_error_type}. Retried: {nonce_retry}");
                }
                response => break response,
            }
        }
    }
}
