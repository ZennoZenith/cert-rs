//! Order Management

use std::{fmt, net::IpAddr, ops::ControlFlow};

use crate::{
    Error, Key, Problem, Result, RetryPolicy,
    account::Account,
    api::{EmptyString, extract_location_header, extract_retry_after},
    b64, csr,
    time::TimeRfc3339,
};

use openssl::x509::X509Req;
use serde::{Deserialize, Serialize};
use url::Url;

// /// [RFC 8555 §9.7.7](https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7)
// #[derive(
//     Debug,
//     Clone,
//     Copy,
//     Deserialize,
//     Serialize,
//     Default,
//     strum_macros::Display,
//     strum_macros::EnumString,
//     strum_macros::IntoStaticStr,
//     PartialEq,
//     Eq,
// )]
// #[strum(ascii_case_insensitive)]
// pub enum IdentifierType {
//     #[default]
//     #[serde(rename = "dns")]
//     Dns,
// }

/// An ACME identifier object describing the entity for which a certificate
/// is requested.
///
/// In the ACME protocol [RFC 8555], identifiers are used in `newOrder`
/// requests to indicate the subject(s) that should be included in the
/// issued certificate. Most commonly, this represents a domain name
/// (DNS identifier).
///
/// # ACME Context
/// Each identifier consists of a `type` and a `value`. The CA uses this
/// information to determine what kind of validation challenges must be
/// completed (e.g., DNS-01, HTTP-01).
///
/// For example, a DNS identifier might look like:
/// ```json
/// { "type": "dns", "value": "example.com" }
/// ```
///
/// # References
/// - [RFC 8555 §7.1.3] (Order Objects)
/// - [RFC 8555 §9.7.7] (Identifier Types)
///
/// [RFC 8555]: https://datatracker.ietf.org/doc/html/rfc8555
/// [RFC 8555 §7.1.3]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3
/// [RFC 8555 §9.7.7]: https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7
/// [RFC 8738 §3]: https://datatracker.ietf.org/doc/html/rfc8738#section-3
#[allow(missing_docs)]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum Identifier {
    Dns(String),

    /// Note that not all ACME servers will accept an order with an IP address identifier.
    ///
    /// Defined in [RFC 8738 §3](https://datatracker.ietf.org/doc/html/rfc8738#section-3)
    Ip(IpAddr),
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(v) => write!(f, r#"type: "dns", value: "{v}""#)?,
            Self::Ip(v) => write!(f, r#"type: "ip", value: "{v}""#)?,
        }
        Ok(())
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
        let identifiers: Vec<Identifier> = domains.into_iter().map(Identifier::Dns).collect();
        Self {
            identifiers,
            not_before: None,
            not_after: None,
        }
    }

    pub fn from_ips(ips: Vec<IpAddr>) -> Self {
        let identifiers: Vec<Identifier> = ips.into_iter().map(Identifier::Ip).collect();
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
    pub error: Option<Problem>,

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
    /// Creates a new ACME order by sending a signed POST request to the server's
    /// `newOrder` endpoint.
    ///
    /// On success, the ACME server returns an order object along with a `Location`
    /// header containing the canonical URL for the created order.
    ///
    /// # Returns
    /// A tuple containing:
    /// - `Url`: The order URL (from the `Location` header), used for subsequent
    ///   interactions (e.g., polling status, finalization).
    /// - `Order`: The parsed order object returned by the ACME server.
    ///
    /// # ACME Context
    /// This corresponds to the "newOrder" request defined in [RFC 8555 §7.4].
    /// The request must be authenticated using the account's key (JWS with `kid`),
    /// and includes one or more identifiers describing the certificate subjects.
    ///
    /// The returned order will typically include:
    /// - authorization URLs to complete challenges
    /// - a finalize URL to submit a CSR
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The POST request to the `newOrder` endpoint fails (e.g., network issues,
    ///   TLS errors, or request signing failures).
    /// - The server responds with a non-success status code.
    /// - The `Location` header is missing or cannot be parsed into a valid `Url`.
    /// - The response body cannot be deserialized into an `Order`.
    /// - The ACME server returns a malformed or unexpected response.
    ///
    /// Any error from the underlying HTTP client, header extraction, or JSON
    /// deserialization is propagated.
    ///
    /// [RFC 8555 §7.4]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
    pub async fn create(account: &Account, new_order: NewOrder) -> Result<(Url, Self)> {
        let url = &account.client.directory().new_order;

        let response = account
            .client
            .post(
                url,
                &account.credentials.key,
                account.auth_kid(),
                &new_order,
            )
            .await?;

        let order_url: Url = extract_location_header(response.headers())?;
        let order = response.json::<Self>().await?;

        Ok((order_url, order))
    }

    /// Fetches the current status of an existing ACME order.
    ///
    /// This sends a POST-as-GET request (as required by the ACME protocol)
    /// to the order URL and returns the latest representation of the order.
    ///
    /// # ACME Context
    /// Order resources are polled by the client to track progress through
    /// the issuance workflow (e.g., `pending`, `ready`, `processing`, `valid`,
    /// or `invalid`). This operation uses a POST request with an empty payload
    /// authenticated via the account's key (`kid`), as specified in RFC 8555.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The POST-as-GET request to the `order_url` fails (e.g., network issues,
    ///   TLS errors, or request signing failures).
    /// - The server responds with a non-success status code.
    /// - The response body cannot be deserialized into an `Order`.
    /// - The ACME server returns a malformed or unexpected response.
    ///
    /// Any error from the underlying HTTP client or JSON deserialization
    /// is propagated.
    pub async fn status(account: &Account, order_url: &Url) -> Result<Self> {
        let response = account
            .client
            .post(
                order_url,
                &account.credentials.key,
                account.auth_kid(),
                &EmptyString,
            )
            .await?;

        let order = response.json::<Self>().await?;

        Ok(order)
    }

    /// Polls an ACME order until it reaches a terminal state or the retry policy
    /// is exhausted.
    ///
    /// This function repeatedly performs a POST-as-GET request to the order URL,
    /// as required by RFC 8555, and evaluates the returned [`OrderStatus`].
    ///
    /// The polling loop continues until:
    /// - The order becomes `Ready`, in which case it can be finalized, or
    /// - The order becomes `Invalid`, indicating a failed authorization, or
    /// - The provided [`RetryPolicy`] signals a timeout.
    ///
    /// The server’s `Retry-After` header is respected between attempts when present.
    ///
    /// # ACME Context
    /// ACME order resources are asynchronous. After creating an order, clients must
    /// poll the order endpoint until it transitions from `pending` to either:
    /// - `ready`: all required authorizations are satisfied
    /// - `processing`: certificate issuance is in progress
    /// - `valid`: certificate has been issued (terminal success)
    /// - `invalid`: one or more challenges failed (terminal failure)
    ///
    /// This method only returns early for `Ready` or `Invalid`. Other states will
    /// continue polling.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A network or HTTP error occurs while polling the order endpoint.
    /// - Request signing or authentication fails.
    /// - The server response cannot be parsed into an [`Order`].
    /// - The `Retry-After` header is present but invalid or unparseable.
    /// - The retry policy is exhausted, resulting in an [`Error::Timeout`].
    ///
    /// Any error from the underlying HTTP client, header parsing, JSON decoding,
    /// or retry policy state machine is propagated.
    pub async fn poll_ready(
        account: &Account,
        order_url: &Url,
        retry_policy: &RetryPolicy,
    ) -> Result<Self> {
        let mut retrying = retry_policy.state();

        loop {
            let response = account
                .client
                .post(
                    order_url,
                    &account.credentials.key,
                    account.auth_kid(),
                    &EmptyString,
                )
                .await?;
            let retry_after = extract_retry_after(response.headers())?;
            let order = response.json::<Self>().await?;

            if let OrderStatus::Ready | OrderStatus::Invalid = order.status {
                break Ok(order);
            }

            if let ControlFlow::Break(err) = retrying.wait(Some(retry_after)).await {
                return Err(err);
            }
        }
    }

    /// Finalizes an ACME order by generating a domain key, building a CSR,
    /// and submitting it to the server's `finalize` endpoint.
    ///
    /// This step is performed after all required authorizations have been completed
    /// and the order is in the `ready` state.
    ///
    /// A CSR encoding the parameters for the certificate being requested
    /// [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986)
    ///
    /// # ACME Context
    /// In RFC 8555, finalization is the step where the client proves control over
    /// the requested identifiers by submitting a Certificate Signing Request (CSR).
    /// The CA uses this CSR to issue the final X.509 certificate.
    ///
    /// This function:
    /// - Constructs a CSR containing all identifiers in the order
    /// - Encodes the CSR in base64url format
    /// - Submits it to the ACME server's `finalize` endpoint
    ///
    /// # Returns
    /// Returns the generated [`X509Req`] representing the CSR that was submitted.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - CSR generation from the domain key and identifiers fails.
    /// - CSR encoding to DER fails.
    /// - Base64url encoding of the CSR fails (if applicable).
    /// - The POST request to the `finalize` endpoint fails (network, TLS, or signing issues).
    /// - The ACME server rejects the request or returns an error response.
    ///
    /// Any error from cryptographic operations, CSR construction, encoding,
    /// or HTTP communication is propagated as [Error].
    pub async fn finalize(&self, account: &Account, domain_key: &Key) -> Result<X509Req> {
        #[derive(Serialize)]
        pub(crate) struct FinalizeRequest {
            csr: String,
        }

        let identifier_values = self
            .identifiers
            .iter()
            .map(|v| match v {
                Identifier::Dns(d) => Ok(d.clone()),
                // TODO:
                Identifier::Ip(ip) => Ok(ip.to_string()),
                // Identifier::Ip(_) => unimplemented!("Only DNS identifier supported"),
                //
                // _ => return Err(Error::Unsupported("Only DNS identifier supported")),
            })
            .collect::<Result<Vec<String>>>()?;

        let csr = csr::generate_csr(domain_key, &identifier_values)?;
        let csr_der_bytes = csr.to_der().map_err(|_| Error::Crypto("CSR to der"))?;
        let csr_der_encoded = b64::b64u_encode(csr_der_bytes);

        let body = FinalizeRequest {
            csr: csr_der_encoded,
        };

        account
            .client
            .post(
                &self.finalize,
                &account.credentials.key,
                account.auth_kid(),
                &body,
            )
            .await?;

        Ok(csr)
    }

    /// Downloads the issued certificate for this ACME order using a
    /// POST-as-GET request to the certificate URL.
    ///
    /// This is the final step of the ACME issuance flow, where the client
    /// retrieves the signed certificate chain once the order is marked as
    /// `valid`.
    ///
    ///
    /// If the cached order state is in `ready` or `processing` state, this will poll the server
    /// for the latest state. If the order is still in `processing` state after that, this will
    /// return `Ok(None)`. If the order is in `valid` state, this will attempt to retrieve
    /// the certificate from the server and return it as a `String`. If the order contains
    /// an error or ends up in any state other than `valid` or `processing`, return an error.
    ///
    /// # ACME Context
    /// In [RFC 8555 §7.4.2], the certificate URL provided in the finalized order
    /// is used to fetch the issued certificate. The request is performed as a
    /// POST-as-GET authenticated request using the account key.
    ///
    /// The response is typically a PEM-encoded certificate chain, usually with
    /// content type:
    /// `application/pem-certificate-chain; charset=utf-8`
    ///
    /// Some servers MAY also provide alternative representations via
    /// `Link` headers with relation `"alternate"`.
    ///
    /// # Returns
    /// A PEM-encoded certificate chain as a `String`.
    ///
    /// # Errors
    ///
    /// TODO: error
    ///
    /// [RFC 8555 §7.4.2]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.4.2
    pub async fn certificate(&self, account: &Account) -> Result<Option<String>> {
        if let Some(error) = &self.error {
            return Err(Error::Problem(error.clone()));
        } else if self.status == OrderStatus::Processing {
            return Ok(None);
        } else if self.status != OrderStatus::Valid {
            return Err(Error::Str("Order state not `valid`"));
        }

        let Some(url) = &self.certificate else {
            return Err(Error::CertificateUrlNotPresent);
        };

        // TODO: Check in RFC if there is a accept header. If present add to mime type in api::handle_response_error
        // response "content-type": "application/pem-certificate-chain; charset=utf-8",

        // TODO: The default format of the certificate is application/pem-certificate-
        // chain [RFC 8555 §7.4.2].
        //
        // TODO: The server MAY provide one or more link relation header fields
        // [RFC8288] with relation "alternate". [RFC 8555 §7.4.2]
        let response = account
            .client
            .post(
                url,
                &account.credentials.key,
                account.auth_kid(),
                &EmptyString,
            )
            .await?;

        let cert = response.text().await?;

        Ok(Some(cert))
    }

    /// Poll the certificate with the given [`RetryPolicy`]
    ///
    /// Yields the PEM encoded certificate chain for this order if the order state becomes
    /// `Valid`. The function keeps polling as long as the order state is `Processing`.
    /// An error is returned immediately: if the order state is `Invalid`, if polling runs
    /// into a timeout, or if the ACME CA suggest to retry at a later time.
    ///
    /// # Errors
    ///
    /// TODO:
    pub async fn poll_certificate(
        &self,
        account: &Account,
        retries: &RetryPolicy,
    ) -> Result<String> {
        let mut retrying = retries.state();

        loop {
            if let Some(error) = &self.error {
                return Err(Error::Problem(error.clone()));
            } else if let OrderStatus::Valid | OrderStatus::Invalid = self.status {
                return self
                    .certificate(account)
                    .await?
                    .ok_or(Error::Str("no certificates received from ACME CA"));
            }

            // TODO:
            // let retry_after = extract_retry_after(response.headers())?;
            //
            if let ControlFlow::Break(err) = retrying.wait(None).await {
                return Err(err);
            }
        }
    }
}
