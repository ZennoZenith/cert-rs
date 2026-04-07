//! Order Management

use crate::{
    AcmeError, Error, Result,
    account::Account,
    api::{EmptyString, extract_location_header},
    authentication::JwkOrKid,
    b64, csr,
    time::TimeRfc3339,
};

use openssl::{pkey::PKey, rsa::Rsa, x509::X509Req};
use serde::{Deserialize, Serialize};
use url::Url;

/// [RFC 8555 §9.7.7](https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7)
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

/// TODO: docs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identifier {
    /// [RFC 8555 §9.7.7](https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7)
    #[serde(rename = "type")]
    pub type_: IdentifierType,
    /// The identifier itself
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

/// New Order
///
/// Defined in [RFC 8555 §7.1.3].
///
/// Subset of the order object defined in [Order], containing the fields
/// that describe the certificate to be issued
///
/// [RFC 8555 §7.1.3]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrder {
    pub identifiers: Vec<Identifier>,

    /// The requested value of the notBefore field in the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<TimeRfc3339>,
    /// The requested value of the notAfter field in the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<TimeRfc3339>,
}

impl NewOrder {
    pub fn from_domains(domains: Vec<String>) -> Self {
        let identifiers: Vec<Identifier> = domains.into_iter().map(Into::into).collect();
        Self {
            identifiers,
            not_before: None,
            not_after: None,
        }
    }
}

/// Order Object
///
/// Defined in [RFC 8555 §7.1.3], [RFC 8555 §9.7.2].
///
/// An ACME order object represents a client's request for a certificate
/// and is used to track the progress of that order through to issuance.
/// Thus, the object contains information about the requested
/// certificate, the authorizations that the server requires the client
/// to complete, and any certificates that have resulted from this order.
///
/// [RFC 8555 §7.1.3]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2
/// [RFC 8555 §9.7.2]: https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.2
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// The status of this order
    pub status: OrderStatus,

    /// The timestamp after which the server will consider this order invalid
    pub expires: Option<TimeRfc3339>,

    /// An array of identifier objects that the order pertains to.
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
    /// Create new order by sending a POST request to the server's newOrder resource
    ///
    /// Returns: (Url: ordre url, Order)
    ///
    /// Refer [RFC 8555 §7.4](https://datatracker.ietf.org/doc/html/rfc8555#section-7.4)
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn create(account: &Account, new_order: NewOrder) -> Result<(Url, Self)> {
        let url = &account.client.directory().new_order;

        let auth = JwkOrKid::Kid(&account.credentials.kid);
        let body = new_order;

        let response = account
            .client
            .post(url, &account.credentials.key, auth, body)
            .await?;

        // TODO: If the server is willing to issue the requested certificate,
        // it responds with a 201 (Created) response.

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
        let body = EmptyString;

        let response = account
            .client
            .post(url, &account.credentials.key, auth, body)
            .await?;

        let order = response.json::<Self>().await?;

        Ok(order)
    }

    /// Returns csr
    ///
    /// A CSR encoding the parameters for the certificate being requested
    /// [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986)
    ///
    /// If a request to finalize an order is successful, the server will
    /// return a 200 (OK) with an updated order object.
    ///
    /// The status of the order will indicate what action the client should take:
    ///
    /// - "invalid": The certificate will not be issued. Consider this
    ///   order process abandoned.
    ///
    /// - "pending": The server does not believe that the client has
    ///   fulfilled the requirements. Check the "authorizations" array for
    ///   entries that are still pending.
    ///
    /// - "ready": The server agrees that the requirements have been
    ///   fulfilled, and is awaiting finalization. Submit a finalization
    ///   request.
    ///
    /// - "processing": The certificate is being issued. Send a POST-as-GET
    ///   request after the time given in the Retry-After header field of
    ///   the response, if any.
    ///
    /// - "valid": The server has issued the certificate and provisioned its
    ///   URL to the "certificate" field of the order. Download the
    ///   certificate.
    ///
    /// See [RFC 8555 §7.4](https://datatracker.ietf.org/doc/html/rfc8555#section-7.4)
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn finalize(&self, account: &Account) -> Result<X509Req> {
        let domain_key =
            Rsa::generate(4096).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
        let domain_private_key = PKey::from_rsa(domain_key)
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        let domains: Vec<&str> = self.identifiers.iter().map(|v| v.value.as_str()).collect();
        let csr = csr::generate_csr(&domain_private_key, &domains)
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
        let csr_der_bytes = csr
            .to_der()
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
        let csr_der_encoded = b64::b64u_encode(csr_der_bytes);

        let url = &self.finalize;

        let auth = JwkOrKid::Kid(&account.credentials.kid);
        let body = serde_json::json!({
            "csr": csr_der_encoded
        });

        account
            .client
            .post(url, &account.credentials.key, auth, body)
            .await?;

        Ok(csr)
    }

    /// Download the issued certificate, sends a POST- as-GET request to the certificate URL.
    ///
    /// See [RFC 8555 §7.4.2](https://datatracker.ietf.org/doc/html/rfc8555#section-7.4.2)
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn download_cert(&self, account: &Account) -> Result<String> {
        let Some(url) = &self.certificate else {
            return Err(Error::CertificateUrlNotPresent);
        };

        let auth = JwkOrKid::Kid(&account.credentials.kid);
        let body = EmptyString;

        // TODO: Check in RFC if there is a accept header. If present add to mime type in api::handle_response_error
        let response = account
            .client
            .post(url, &account.credentials.key, auth, body)
            .await?;
        // response "content-type": "application/pem-certificate-chain; charset=utf-8",

        // TODO: The default format of the certificate is application/pem-certificate-
        // chain [RFC 8555 §7.4.2].
        //
        // TODO: The server MAY provide one or more link relation header fields
        // [RFC8288] with relation "alternate". [RFC 8555 §7.4.2]

        let cert = response.text().await?;

        Ok(cert)
    }
}
