use std::{collections::VecDeque, sync::Mutex};

use color_eyre::{
    Result,
    eyre::{Context, OptionExt, eyre},
};
use lib_utils::b64;
use openssl::{pkey::Private, rsa::Rsa};
use reqwest::{
    Client, IntoUrl, Response,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    account::{
        Account, AccountCert, AccountInternal, AccountOrdersList,
        AccountStatus, JwkOrKid, Jws, JwsAlgorithm, JwsProtectedHeaders,
    },
    challenge::ChallengeType,
    directory::AcmeDirectory,
    order::{Identifier, Order, OrderStatus},
};

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

fn extract_location_header(headers: &HeaderMap) -> Result<Url> {
    headers
        .get("location")
        .map(|v| {
            String::from(
                v.to_str().wrap_err("location header not utf-8 string")?,
            )
            .parse()
            .wrap_err("location header account_id not a url")
        })
        .ok_or_eyre("cannot extract location header")?
}

#[derive(Debug, Clone)]
pub(crate) enum AcmeApiBody<T: Serialize + Clone = ()> {
    EmptyString,
    EmptyObject,
    Other(T),
}

impl AcmeApiBody<()> {
    pub const EMPTY_STRING: Self = AcmeApiBody::EmptyString;
    pub const EMPTY_OBJECT: Self = AcmeApiBody::EmptyObject;
}

struct ApiResponse<T>
where
    T: DeserializeOwned + std::fmt::Debug,
{
    headers: HeaderMap,
    body: T,
}

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

    pub async fn post<B, R>(
        &self,
        url: &Url,
        private_key: Rsa<Private>,
        auth: JwkOrKid,
        body: AcmeApiBody<B>,
    ) -> Result<ApiResponse<R>>
    where
        B: Serialize + Clone,
        R: DeserializeOwned + std::fmt::Debug,
    {
        loop {
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
                auth: auth.clone(),
                nonce,
            };

            let jws = Jws::new(
                private_key.clone(),
                &jws_protected_headers,
                body.clone(),
            )?;

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
                "\nurl: {}\nheaders: {}\nbody: {}",
                url,
                serde_json::to_string_pretty(&headermap_to_hashmap(&headers))?,
                body_text,
            );

            // error body
            //
            // {
            //    "type": "urn:ietf:params:acme:error:badNonce",
            //    "detail": "JWS has an invalid anti-replay nonce: ...",
            //    "status": 400
            // }

            // let body: R = serde_json::from_str(&body_text)?;
            //
            match serde_json::from_str::<R>(&body_text) {
                Ok(body) => return Ok(ApiResponse { headers, body }),
                Err(_) => {
                    if body_text.contains("urn:ietf:params:acme:error:badNonce")
                    {
                        tracing::warn!("Bad nonce. Retrying...");
                        continue;
                    } else {
                        return Err(eyre!(body_text));
                    }
                }
            };
        }
    }
}

pub struct AcmeApi<Account = ()> {
    client: AcmeClient,
    acme_directory: AcmeDirectory,
    account: Account,
}

impl AcmeApi<()> {
    pub async fn _new(acme_uri: Url) -> Result<AcmeApi<()>> {
        let client = Client::builder()
            // .danger_accept_invalid_certs(true)
            .build()
            .wrap_err("Unable to build reqwest client")?;

        Self::new_from_client(acme_uri, client).await
    }

    pub async fn new_from_client(
        acme_uri: Url,
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
            acme_directory,
            account: (),
        })
    }
}

impl AcmeApi<()> {
    fn into_registerd(
        self,
        account: AccountInternal,
    ) -> AcmeApi<AccountInternal> {
        AcmeApi {
            account,
            client: self.client,
            acme_directory: self.acme_directory,
        }
    }

    pub async fn register_account(self) -> Result<AcmeApi<AccountInternal>> {
        let new_account_cert = AccountCert::new()?;

        let url = &self.acme_directory.new_account;
        let auth: JwkOrKid = new_account_cert.public_key.clone().into(); // JwkOrKid::Jwk
        // TODO: Convert to struct
        let body = json!({ "termsOfServiceAgreed": true });

        let ApiResponse { headers, .. }: ApiResponse<Account> = self
            .client
            .post(
                url,
                new_account_cert.private_key.clone(),
                auth,
                AcmeApiBody::Other(&body),
            )
            .await?;

        let account_id: Url = extract_location_header(&headers)?;

        let account =
            AccountInternal::new(account_id, new_account_cert.clone());

        Ok(self.into_registerd(account))
    }
}

impl AcmeApi<AccountInternal> {
    async fn orders_url(&self) -> Result<Url> {
        let url = &self.account.account_id();
        let auth: JwkOrKid = self.account.account_id().into();

        let ApiResponse {
            body: Account { status, orders, .. },
            ..
        } = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth,
                AcmeApiBody::EMPTY_STRING,
            )
            .await?;

        if status != AccountStatus::Valid {
            return Err(color_eyre::eyre::eyre!(
                "account info status not valid"
            ));
        }
        Ok(orders)
    }

    pub(crate) async fn orders(&self) -> Result<Vec<Url>> {
        let url = &self.orders_url().await?;

        let auth: JwkOrKid = self.account.account_id().into();

        let ApiResponse {
            body: AccountOrdersList { orders },
            ..
        } = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth,
                AcmeApiBody::EMPTY_STRING,
            )
            .await?;

        Ok(orders)
    }

    pub(crate) async fn create_order(
        &self,
        domains: Vec<String>,
    ) -> Result<(Url, OrderStatus)> {
        let url = &self.acme_directory.new_order;

        let auth: JwkOrKid = self.account.account_id().into();

        let identifiers: Vec<Identifier> =
            domains.iter().map(|v| v.into()).collect();

        let body = json!({"identifiers":identifiers});

        let ApiResponse {
            body: order_status,
            headers,
        } = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth,
                AcmeApiBody::Other(body),
            )
            .await?;

        let order_url: Url = extract_location_header(&headers)?;

        Ok((order_url, order_status))
    }

    pub(crate) async fn order_status(
        &self,
        order_url: &Url,
    ) -> Result<OrderStatus> {
        let url = order_url;

        let auth: JwkOrKid = self.account.account_id().into();

        let ApiResponse {
            body: ordre_status, ..
        } = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth,
                AcmeApiBody::EMPTY_STRING,
            )
            .await?;

        Ok(ordre_status)
    }

    pub(crate) async fn challenges(
        &self,
        order_status: OrderStatus,
    ) -> Result<Vec<Order>> {
        let authorizations: Vec<Url> = order_status.authorizations;
        let auth: JwkOrKid = self.account.account_id().into();
        let mut orders: Vec<Order> = Vec::new();

        for authorization in authorizations {
            let url = authorization;
            let ApiResponse { body: auth_z, .. } = self
                .client
                .post(
                    &url,
                    self.account.private_key().clone(),
                    auth.clone(),
                    AcmeApiBody::EMPTY_STRING,
                )
                .await?;

            orders.push(Order::from((url, auth_z)));
        }

        Ok(orders)
    }

    pub(crate) async fn clean_challenges(
        &self,
        orders: Vec<Order>,
    ) -> Result<Vec<ChallengeToken>> {
        let (dns_01_challenges, http_01_challenges): (Vec<_>, Vec<_>) = orders
            .into_iter()
            .partition(|v| v.auth_z.wildcard.unwrap_or_default());

        let jwk_thumbprint = self.account.jwk_thumbprint();

        let _http_01_challenges_tokens: Vec<ChallengeToken> =
            http_01_challenges
                .into_iter()
                .filter_map(|v| {
                    v.auth_z
                        .challenges
                        .into_iter()
                        .find(|v| v.r#type == ChallengeType::Http01)
                        .map(|t| {
                            (v.auth_z.identifier.value, v.authorization, t)
                        })
                })
                .map(|(domain, authz_url, challenge)| {
                    let keyauth =
                        format!("{}.{}", challenge.token, jwk_thumbprint);
                    let hash = Sha256::digest(&keyauth).to_vec();
                    let sha_256_keyauth = b64::b64u_encode(hash);
                    ChallengeToken {
                        domain,
                        token: challenge.token,
                        keyauth,
                        sha_256_keyauth,
                        challange_response_url: challenge.url,
                        authz_url,
                    }
                })
                .collect();

        let dns_01_challenges_tokens: Vec<ChallengeToken> = dns_01_challenges
            .into_iter()
            .filter_map(|v| {
                v.auth_z
                    .challenges
                    .into_iter()
                    .find(|v| v.r#type == ChallengeType::Dns01)
                    .map(|t| (v.auth_z.identifier.value, v.authorization, t))
            })
            .map(|(domain, authz_url, challenge)| {
                let keyauth = format!("{}.{}", challenge.token, jwk_thumbprint);
                let hash = Sha256::digest(&keyauth).to_vec();
                let sha_256_keyauth = b64::b64u_encode(hash);
                ChallengeToken {
                    domain,
                    token: challenge.token,
                    keyauth,
                    sha_256_keyauth,
                    challange_response_url: challenge.url,
                    authz_url,
                }
            })
            .collect();

        Ok(dns_01_challenges_tokens)
    }

    pub(crate) async fn prove_challenge(
        &self,
        challenge: &ChallengeToken,
    ) -> Result<()> {
        let url = &challenge.challange_response_url;
        let auth: JwkOrKid = self.account.account_id().into();

        let _: ApiResponse<serde_json::Value> = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth.clone(),
                AcmeApiBody::EMPTY_OBJECT,
            )
            .await?;

        Ok(())
    }

    pub(crate) async fn poll_challange(
        &self,
        challenge: &ChallengeToken,
    ) -> Result<()> {
        let url = &challenge.authz_url;
        let auth: JwkOrKid = self.account.account_id().into();

        let _: ApiResponse<serde_json::Value> = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth.clone(),
                AcmeApiBody::EMPTY_STRING,
            )
            .await?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ChallengeToken {
    pub domain: String,
    pub token: String,
    pub keyauth: String,
    pub sha_256_keyauth: String,
    pub challange_response_url: Url,
    pub authz_url: Url,
}
