use crate::{
    AcmeError, Error, Result,
    account::Account,
    api::{AcmeApiBody, extract_location_header},
    authentication::JwkOrKid,
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
    /// [RFC 8555 §9.7.7](https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7)
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

/// Order Status
///
/// Defined in [RFC 8555 §7.1.6].
///
/// Order objects are created in the "pending" state. Once all of the
/// authorizations listed in the order object are in the "valid" state,
/// the order transitions to the "ready" state. The order moves to the
/// "processing" state after the client submits a request to the order's
/// "finalize" URL and the CA begins the issuance process for the
/// certificate. Once the certificate is issued, the order enters the
/// "valid" state. If an error occurs at any of these stages, the order
/// moves to the "invalid" state. The order also moves to the "invalid"
/// state if it expires or one of its authorizations enters a final state
/// other than "valid" ("expired", "revoked", or "deactivated").
///
/// ```text
///    pending --------------+
///       |                  |
///       | All authz        |
///       | "valid"          |
///       V                  |
///     ready ---------------+
///       |                  |
///       | Receive          |
///       | finalize         |
///       | request          |
///       V                  |
///   processing ------------+
///       |                  |
///       | Certificate      | Error or
///       | issued           | Authorization failure
///       V                  V
///     valid             invalid
///
///                    State Transitions for Order Objects
/// ```
///
/// [RFC 8555 §7.1.6]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6
#[derive(
    Debug,
    Clone,
    Copy,
    Deserialize,
    Serialize,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// Order Object
///
/// Defined in [RFC 8555 §7.1.3]
///
/// An ACME order object represents a client's request for a certificate
/// and is used to track the progress of that order through to issuance.
/// Thus, the object contains information about the requested
/// certificate, the authorizations that the server requires the client
/// to complete, and any certificates that have resulted from this order.
///
/// [RFC 8555 §7.1.3]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// The status of this order
    pub status: OrderStatus,

    /// The timestamp after which the server will consider this order invalid
    pub expires: Option<TimeRfc3339>,

    pub identifiers: Vec<Identifier>,

    // TODO
    pub profile: Option<String>,

    /// The requested value of the notBefore field in the certificate
    pub not_before: Option<TimeRfc3339>,
    /// The requested value of the notAfter field in the certificate
    pub not_after: Option<TimeRfc3339>,
    // TODO: error object type
    pub error: Option<AcmeError>,

    pub authorizations: Vec<Url>,

    /// A URL that a CSR must be ``POSTed`` to once
    /// all of the order's authorizations are satisfied to finalize the
    /// order.The result of a successful finalization will be the
    /// population of the certificate URL for the order.
    pub finalize: Url,

    /// A URL for the certificate that has been issued in response to this order.
    pub certificate: Option<Url>,
}

impl Order {
    /// Return (Url: ordre url, Order)
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn create(account: &Account, domains: Vec<String>) -> Result<(Url, Self)> {
        let url = &account.client.directory().new_order;

        let identifiers: Vec<Identifier> = domains.iter().map(Into::into).collect();

        let auth = JwkOrKid::Kid(&account.credentials.kid);
        let body = AcmeApiBody::Other(serde_json::json!({"identifiers":identifiers}));

        let response = account
            .client
            .post(url, &account.credentials.private_key, auth, body)
            .await?;

        let order_url: Url = extract_location_header(response.headers())?;
        let order = response.json::<Self>().await?;

        Ok((order_url, order))
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn status(account: &Account, order_url: &Url) -> Result<Self> {
        let url = order_url;

        let auth = JwkOrKid::Kid(&account.credentials.kid);
        let body = AcmeApiBody::EMPTY_STRING;

        let response = account
            .client
            .post(url, &account.credentials.private_key, auth, body)
            .await?;

        let order = response.json::<Self>().await?;

        Ok(order)
    }

    /// Returns csr
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn finalize(&self, account: &Account) -> Result<X509Req> {
        let domain_key = Rsa::generate(4096).map_err(|e| Error::Unimplemented(e.to_string()))?;
        let domain_private_key =
            PKey::from_rsa(domain_key).map_err(|e| Error::Unimplemented(e.to_string()))?;

        let domains: Vec<&str> = self.identifiers.iter().map(|v| v.value.as_str()).collect();
        let csr = csr::generate_csr(&domain_private_key, &domains)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;
        let csr_der_bytes = csr.to_der().map_err(|e| Error::Unimplemented(e.to_string()))?;
        let csr_der_encoded = b64::b64u_encode(csr_der_bytes);

        let url = &self.finalize;

        let auth = JwkOrKid::Kid(&account.credentials.kid);
        let body = AcmeApiBody::Other(serde_json::json!({"csr":csr_der_encoded }));

        account
            .client
            .post(url, &account.credentials.private_key, auth, body)
            .await?;

        Ok(csr)
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn download_cert(&self, account: &Account) -> Result<String> {
        let Some(url) = &self.certificate else {
            return Err(Error::CertificateUrlNotPresent);
        };

        let auth = JwkOrKid::Kid(&account.credentials.kid);
        let body = AcmeApiBody::EMPTY_STRING;

        // TODO: Check in RFC if there is a accept header. If present add to mime type in api::handle_response_error
        let response = account
            .client
            .post(url, &account.credentials.private_key, auth, body)
            .await?;
        // response "content-type": "application/pem-certificate-chain; charset=utf-8",

        let cert = response.text().await?;

        Ok(cert)
    }
}
