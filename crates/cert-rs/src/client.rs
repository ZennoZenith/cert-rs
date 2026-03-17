use http::HeaderMap;
use reqwest::Client;
use std::collections::VecDeque;
use tokio::sync::Mutex;

use crate::{
    api::{Error, RequestBuilderExt as _, Result},
    directory::Directory,
};

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
            nonce_store: Mutex::default(),
        }
    }

    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.reqwest_client
    }

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

    pub async fn enqueue_nonce(&self, headers: &HeaderMap) {
        let Some(nonce) = Self::extract_nonce(headers) else {
            #[cfg(feature = "tracing")]
            tracing::warn!("replay-nonce header not found in request");

            return;
        };

        // TODO: Limit store length
        self.nonce_store.lock().await.push_back(nonce);
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn nonce(&self) -> Result<Box<str>> {
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
}
