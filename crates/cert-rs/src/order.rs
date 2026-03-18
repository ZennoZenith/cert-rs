use crate::{
    AcmeClient, AcmeError, Error, Result,
    account::Account,
    api::{AcmeApiBody, RequestBuilderExt as _, ResponseExt as _, extract_location_header},
    authentication::{JwkOrKid, Jws},
    b64, csr,
    time::TimeRfc3339,
};

use openssl::{pkey::PKey, rsa::Rsa, x509::X509Req};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(
    Debug,
    Clone,
    Copy,
    Deserialize,
    Serialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
pub enum IdentifierType {
    #[default]
    #[serde(rename = "dns")]
    Dns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub type_: IdentifierType,
    pub value: String,
}

impl<T: ToString> From<T> for Identifier {
    fn from(value: T) -> Self {
        Self {
            type_: IdentifierType::Dns,
            value: value.to_string(),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Deserialize,
    Serialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    #[default]
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// TODO: add docs, [RFC 8555 §9.7.2]
///
/// [RFC 8555 §9.7.1]: https://www.rfc-editor.org/rfc/rfc8555#section-9.7.2
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub status: OrderStatus,
    pub identifiers: Vec<Identifier>,
    pub authorizations: Vec<Url>,
    pub finalize: Url,

    pub expires: Option<TimeRfc3339>,
    pub profile: Option<String>,
    pub not_before: Option<TimeRfc3339>,
    pub not_after: Option<TimeRfc3339>,
    // TODO: error object type
    pub error: Option<AcmeError>,
    pub certificate: Option<Url>,
}

impl Order {
    /// Return (Url: ordre url, Order)
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn create(
        acme_client: &AcmeClient,
        account: &Account,
        domains: Vec<String>,
    ) -> Result<(Url, Self)> {
        let url = &acme_client.directory().new_order;

        let identifiers: Vec<Identifier> = domains.iter().map(Into::into).collect();

        let nonce = &acme_client.nonce().await?;

        let auth = JwkOrKid::Kid(account.account_id().clone());
        let body = AcmeApiBody::Other(serde_json::json!({"identifiers":identifiers}));
        let jws = Jws::new_from_parts(account.private_key().clone(), url, auth, nonce, body);

        let response = acme_client
            .client()
            .post(url.clone())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?
            .extract_nonce(acme_client)
            .await
            .handle_response_error()
            .await?;

        let order_url: Url = extract_location_header(response.headers())?;
        let order = response.json::<Self>().await?;

        Ok((order_url, order))
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn status(
        acme_client: &AcmeClient,
        account: &Account,
        order_url: &Url,
    ) -> Result<Self> {
        let url = order_url;
        let nonce = &acme_client.nonce().await?;

        let auth = JwkOrKid::Kid(account.account_id().clone());
        let body = AcmeApiBody::EMPTY_STRING;
        let jws = Jws::new_from_parts(account.private_key().clone(), url, auth, nonce, body);

        let response = acme_client
            .client()
            .post(url.clone())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?
            .extract_nonce(acme_client)
            .await
            .handle_response_error()
            .await?;

        let order = response.json::<Self>().await?;

        Ok(order)
    }

    /// Returns csr
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn finalize(&self, acme_client: &AcmeClient, account: &Account) -> Result<X509Req> {
        let domain_key = Rsa::generate(4096).map_err(|e| Error::Unimplemented(e.to_string()))?;
        let domain_private_key =
            PKey::from_rsa(domain_key).map_err(|e| Error::Unimplemented(e.to_string()))?;

        let domains: Vec<String> = self.identifiers.iter().map(|v| v.value.clone()).collect();
        let csr = csr::generate_csr(&domain_private_key, &domains)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;
        let csr_der_bytes = csr.to_der().map_err(|e| Error::Unimplemented(e.to_string()))?;
        let csr_der_encoded = b64::b64u_encode(csr_der_bytes);

        let url = &self.finalize;
        let nonce = &acme_client.nonce().await?;

        let auth = JwkOrKid::Kid(account.account_id().clone());
        let body = AcmeApiBody::Other(serde_json::json!({"csr":csr_der_encoded }));
        let jws = Jws::new_from_parts(account.private_key().clone(), url, auth, nonce, body);

        let response = acme_client
            .client()
            .post(url.clone())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?
            .extract_nonce(acme_client)
            .await
            .handle_response_error()
            .await?;

        let finiazlize = response.json::<Self>().await?;
        dbg!(finiazlize);

        Ok(csr)
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn download_cert(
        &self,
        acme_client: &AcmeClient,
        account: &Account,
    ) -> Result<String> {
        let Some(url) = &self.certificate else {
            return Err(Error::CertificateUrlNotPresent);
        };

        let nonce = &acme_client.nonce().await?;

        let auth = JwkOrKid::Kid(account.account_id().clone());
        let body = AcmeApiBody::EMPTY_STRING;
        let jws = Jws::new_from_parts(account.private_key().clone(), url, auth, nonce, body);

        // TODO: Check in RFC if there is a accept header. If present add to mime type in api::handle_response_error
        let response = acme_client
            .client()
            .post(url.clone())
            .add_rfc_headers()
            .json(&jws)
            .send()
            .await?
            .extract_nonce(acme_client)
            .await
            .handle_response_error()
            .await?;
        // response "content-type": "application/pem-certificate-chain; charset=utf-8",

        let cert = response.text().await?;

        Ok(cert)
    }
}
