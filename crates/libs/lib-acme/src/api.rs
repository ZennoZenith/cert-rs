use std::{collections::VecDeque, sync::Mutex};

use color_eyre::{
    Result,
    eyre::{Context, OptionExt, eyre},
};
use lib_utils::b64;
use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::X509Req,
};
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
        Account, AccountOrdersList, AccountStatus, JwkOrKid, Jws, JwsAlgorithm,
        JwsProtectedHeaders, RegisteredAccount,
    },
    authorization::AuthorizationWithUrl,
    challenge::{Challenge, ChallengeResponder, ChallengeType},
    csr::generate_csr,
    directory::AcmeDirectory,
    order::{Identifier, Order},
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
                Err(e) => {
                    if body_text.contains("urn:ietf:params:acme:error:badNonce")
                    {
                        tracing::warn!("Bad nonce. Retrying...");
                        continue;
                    } else {
                        tracing::error!("{}", e);
                        return Err(eyre!("response body: {}", body_text));
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
        account: RegisteredAccount,
    ) -> AcmeApi<RegisteredAccount> {
        AcmeApi {
            account,
            client: self.client,
            acme_directory: self.acme_directory,
        }
    }

    pub async fn register_account(self) -> Result<AcmeApi<RegisteredAccount>> {
        let private_key = Rsa::generate(4096)?;
        let public_key_pem = private_key.public_key_to_pem()?;
        let public_key = Rsa::public_key_from_pem(&public_key_pem)?;

        let url = &self.acme_directory.new_account;
        let auth: JwkOrKid = public_key.into(); // JwkOrKid::Jwk

        // TODO: Convert to struct
        let body = json!({ "termsOfServiceAgreed": true });

        let ApiResponse { headers, .. }: ApiResponse<Account> = self
            .client
            .post(url, private_key.clone(), auth, AcmeApiBody::Other(&body))
            .await?;

        let account_id: Url = extract_location_header(&headers)?;

        let account = RegisteredAccount::new(account_id, private_key);

        Ok(self.into_registerd(account))
    }
}

impl AcmeApi<RegisteredAccount> {
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

        // TODO: The server may return incomplete list
        // check of Link header with rel="next" for more orders
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

    /// Return Url: ordre url
    pub(crate) async fn create_order(
        &self,
        domains: Vec<String>,
    ) -> Result<(Url, Order)> {
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

    pub(crate) async fn order_status(&self, order_url: &Url) -> Result<Order> {
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
        order: &Order,
    ) -> Result<Vec<AuthorizationWithUrl>> {
        let authorization_url: &[Url] = &order.authorizations;
        let auth: JwkOrKid = self.account.account_id().into();
        let mut authorization_with_urls = Vec::new();

        for authorization in authorization_url {
            let url = authorization.clone();
            let ApiResponse {
                body: authorization,
                ..
            } = self
                .client
                .post(
                    &url,
                    self.account.private_key().clone(),
                    auth.clone(),
                    AcmeApiBody::EMPTY_STRING,
                )
                .await?;

            authorization_with_urls
                .push(AuthorizationWithUrl { url, authorization });
        }

        Ok(authorization_with_urls)
    }

    pub(crate) async fn clean_challenges(
        &self,
        authorization_with_url: &[AuthorizationWithUrl],
    ) -> Result<Vec<ChallengeResponder>> {
        let jwk_thumbprint = self.account.jwk_thumbprint();

        let challenge_responders: Vec<ChallengeResponder> =
            authorization_with_url
                .iter()
                .filter_map(|v| {
                    v.authorization
                        .challenges
                        .clone()
                        .into_iter()
                        .find(|v| {
                            v.r#type == ChallengeType::Http01
                                || v.r#type == ChallengeType::Dns01
                        })
                        .map(|t| {
                            (
                                v.authorization.identifier.value.clone(),
                                v.url.clone(),
                                t,
                            )
                        })
                })
                .map(|(domain, authorization_url, challenge)| {
                    let keyauth =
                        format!("{}.{}", challenge.token, jwk_thumbprint);
                    let hash = Sha256::digest(&keyauth).to_vec();
                    let sha_256_keyauth = b64::b64u_encode(hash);
                    ChallengeResponder {
                        r#type: challenge.r#type,
                        domain,
                        token: challenge.token,
                        keyauth,
                        sha_256_keyauth,
                        challange_response_url: challenge.url,
                        authorization_url,
                    }
                })
                .collect();

        Ok(challenge_responders)
    }

    pub(crate) async fn respond_to_challanges(
        &self,
        authorization_with_url: &[AuthorizationWithUrl],
    ) -> Result<Vec<Challenge>> {
        let challenge_responders =
            self.clean_challenges(authorization_with_url).await?;

        let mut challanges = Vec::new();

        for challenge_responder in challenge_responders {
            let url = &challenge_responder.challange_response_url;
            let auth: JwkOrKid = self.account.account_id().into();

            let ApiResponse {
                body: challange, ..
            } = self
                .client
                .post(
                    url,
                    self.account.private_key().clone(),
                    auth.clone(),
                    AcmeApiBody::EMPTY_OBJECT,
                )
                .await?;

            challanges.push(challange);
        }

        Ok(challanges)
    }

    // /// Poll specific challange
    // pub(crate) async fn poll_challange(
    //     &self,
    //     challenge: &ChallengeResponder,
    // ) -> Result<()> {
    //     let url = &challenge.authorization_url;
    //     let auth: JwkOrKid = self.account.account_id().into();

    //     let _: ApiResponse<serde_json::Value> = self
    //         .client
    //         .post(
    //             url,
    //             self.account.private_key().clone(),
    //             auth.clone(),
    //             AcmeApiBody::EMPTY_STRING,
    //         )
    //         .await?;

    //     Ok(())
    // }

    pub(crate) async fn finalize_order(
        &self,
        order: &Order,
    ) -> Result<X509Req> {
        let domain_key = Rsa::generate(4096)?;
        let domain_pkey = PKey::from_rsa(domain_key)?;

        let domains: Vec<String> =
            order.identifiers.iter().map(|v| v.value.clone()).collect();

        let csr = generate_csr(domain_pkey, &domains)?;

        let csr_der_bytes = csr.to_der()?;
        let csr_der_encoded = b64::b64u_encode(csr_der_bytes);

        let url = &order.finalize;
        let auth: JwkOrKid = self.account.account_id().into();
        let body = serde_json::json!({"csr":csr_der_encoded });

        let _: ApiResponse<Order> = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth.clone(),
                AcmeApiBody::Other(body),
            )
            .await?;

        Ok(csr)
    }

    pub(crate) async fn download_cert(&self, order: &Order) -> Result<String> {
        let Some(url) = &order.certificate else {
            return Err(eyre!("Certificate url not present"));
        };

        let auth: JwkOrKid = self.account.account_id().into();

        // "content-type": "application/pem-certificate-chain; charset=utf-8",
        let ApiResponse { body, .. }: ApiResponse<String> = self
            .client
            .post(
                url,
                self.account.private_key().clone(),
                auth.clone(),
                AcmeApiBody::EMPTY_STRING,
            )
            .await?;

        tracing::info!("Certificate: {}", body);

        Ok(body)
    }
}
