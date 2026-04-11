use chrono::Duration;
use http::HeaderMap;
use reqwest::Response;
use serde::Serialize;
use std::{collections::VecDeque, fmt, ops::ControlFlow};
use tokio::sync::Mutex;
use url::Url;

use crate::{
    Error, Key, Problem, ProblemType, REPLAY_NONCE, Result, RetryPolicy,
    api::{RequestBuilderExt as _, ResponseExt as _},
    crypto::{
        jwk::JwkOrKid,
        jws::{Jws, JwsProtectedHeaders},
    },
    directory::Directory,
};

const MAX_NONCE_STORE_CAPACITY: usize = 100;

#[derive(Debug)]
pub struct Client {
    pub(crate) directory: Directory,
    pub(crate) directory_url: Url,

    #[allow(clippy::struct_field_names)]
    client: reqwest::Client,
    nonce_store: Mutex<VecDeque<Box<str>>>,
    nonce_retry_policy: RetryPolicy,
}

impl Client {
    /// Creates a new instance by fetching the ACME directory and initializing
    /// internal state.
    ///
    /// This function performs an asynchronous request to the provided `directory_url`
    /// using the given `client` to retrieve the ACME directory metadata.
    ///
    /// If `nonce_retry_policy` is not provided, a default policy is used with:
    /// - no initial delay,
    /// - a 3-second timeout,
    /// - and no exponential backoff.
    ///
    /// # Parameters
    /// - `client`: The HTTP client used to make requests.
    /// - `directory_url`: The URL of the ACME directory endpoint.
    /// - `nonce_retry_policy`: Optional retry policy for nonce acquisition.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The directory cannot be fetched from `directory_url`.
    /// - The HTTP request fails (e.g., network issues, DNS resolution failure).
    /// - The server returns an invalid or unexpected response.
    /// - The directory response cannot be parsed into a valid `Directory`.
    ///
    /// Any error returned by ``Directory::new_from_url_with_client`` is propagated.
    pub async fn new(
        client: reqwest::Client,
        directory_url: Url,
        nonce_retry_policy: Option<RetryPolicy>,
    ) -> Result<Self> {
        let directory = Directory::new_from_url_with_client(&client, &directory_url).await?;

        Ok(Self {
            client,
            directory,
            directory_url,
            nonce_store: Mutex::new(VecDeque::with_capacity(MAX_NONCE_STORE_CAPACITY)),
            nonce_retry_policy: nonce_retry_policy.unwrap_or_else(|| {
                RetryPolicy::default()
                    .initial_delay(Duration::zero())
                    .timeout(Duration::seconds(3))
                    .backoff(1.0)
            }),
        })
    }

    #[must_use]
    pub const fn directory(&self) -> &Directory {
        &self.directory
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

    /// # Error
    ///
    /// - [``Error::MissingReplayNonceHeader``]
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

        Self::extract_nonce(headers).ok_or(Error::Str("Missing Replay-Nonce header"))
    }

    fn extract_nonce(headers: &HeaderMap) -> Option<Box<str>> {
        headers
            .get(REPLAY_NONCE)
            .map(|v| v.to_str())
            .and_then(std::result::Result::ok)
            .map(Box::from)
    }

    pub(crate) async fn post<T: Clone + fmt::Debug + Serialize>(
        &self,
        url: &Url,
        key: &Key,
        auth: JwkOrKid<'_>,
        body: T,
    ) -> Result<Response> {
        let mut retrying = self.nonce_retry_policy.state();

        loop {
            let nonce = self.nonce().await?;

            // TODO: try to optimize auth and body clones
            let jws_header = JwsProtectedHeaders::new(key, url, auth.clone(), Some(nonce.as_ref()));
            let jws = Jws::new(key, jws_header, body.clone());

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
                Err(Error::Problem(Problem {
                    r#type: ProblemType::BadNonce,
                    ..
                })) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Bad nonce. retrying...");

                    if let ControlFlow::Break(e) = retrying.wait(None).await {
                        return Err(e);
                    }
                }
                response => break response,
            }
        }
    }
}
