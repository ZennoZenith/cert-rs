use http::HeaderMap;
use reqwest::Response;
use serde::Serialize;
use std::{collections::VecDeque, fmt};
use tokio::sync::Mutex;
use url::Url;

use crate::{
    AcmeError, AcmeErrorType,
    authentication::{JwkOrKid, Jws, PrivateKey},
    directory::Directory,
};

use crate::api::{AcmeApiBody, Error, RequestBuilderExt as _, ResponseExt as _, Result};

const MAX_NONCE_STORE_CAPACITY: usize = 100;
const MAX_NONCE_RETRIES: usize = 10;
const NONCE_RETRIES_DURATION_MS: u64 = 500;

#[derive(Debug)]
pub struct Client {
    pub(crate) directory: Directory,
    pub(crate) directory_url: Url,

    #[allow(clippy::struct_field_names)]
    client: reqwest::Client,
    nonce_store: Mutex<VecDeque<Box<str>>>,
}

impl Client {
    #[must_use]
    pub fn new(client: reqwest::Client, directory: Directory, directory_url: Url) -> Self {
        Self {
            client,
            directory,
            directory_url,
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

    pub(crate) async fn enqueue_nonce(&self, headers: &HeaderMap) {
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
            .client
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
    pub async fn post<T: Clone + fmt::Debug + Serialize>(
        &self,
        url: &Url,
        private_key: &PrivateKey,
        auth: JwkOrKid<'_>,
        body: AcmeApiBody<T>,
    ) -> Result<Response> {
        for i in 0..MAX_NONCE_RETRIES {
            let nonce = self.nonce().await?;

            // TODO: try to optimize auth and body clones
            let jws =
                Jws::new_from_parts(private_key, url, auth.clone(), nonce.as_ref(), body.clone());

            let maybe_response = self
                .client
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
                    type_: AcmeErrorType::BadNonce,
                    ..
                })) => {
                    println!("Bad nonce. retrying... {}", i + 1);
                    // TODO: Set throttle time for env or config or something
                    tokio::time::sleep(std::time::Duration::from_millis(NONCE_RETRIES_DURATION_MS))
                        .await;
                }
                response => return response,
            }
        }

        println!("Could not get nonce after max({MAX_NONCE_RETRIES}) retries");
        Err(Error::MaxNonceRetry(MAX_NONCE_RETRIES))
    }
}
