use serde::{Serialize, ser::SerializeMap as _};

use crate::{Result, account::Account, b64};

/// A DER-encoded X.509 certificate; as specified in [RFC 5280]
///
/// Certificates are identified in PEM context as `CERTIFICATE` and when stored in a
/// file usually use a `.pem`, `.cer` or `.crt` extension. For more on PEM files, refer to the
/// crate documentation.
///
/// Defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CertificateDer(Vec<u8>);

impl CertificateDer {
    /// A constructor to create a `CertificateDer` from a slice of DER.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_owned())
    }
}

/// The reason for a certificate revocation
///
/// Defined in [RFC 5280 §5.3.1](https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1)
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl Serialize for RevocationReason {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_u8(*self as u8)
    }
}

/// Payload for a certificate revocation request
///
/// See in [RFC 8555 §7.6](https://datatracker.ietf.org/doc/html/rfc8555#section-7.6)
#[derive(Debug)]
pub struct RevocationRequest<'a> {
    /// The certificate to revoke
    pub certificate: &'a CertificateDer,
    /// Reason for revocation
    pub reason: Option<RevocationReason>,
}

impl Serialize for RevocationRequest<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let base64 = b64::b64u_encode(&self.certificate.0);
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("certificate", &base64)?;
        if let Some(reason) = &self.reason {
            map.serialize_entry("reason", reason)?;
        }
        map.end()
    }
}

/// TODO:
#[derive(Debug)]
pub struct Certificate<'a> {
    /// The certificate to revoke
    pub certificate: &'a CertificateDer,
}

impl Certificate<'_> {
    /// Revokes a previously issued certificate
    ///
    /// # Errors
    /// TODO:
    ///
    /// [RFC 8555 §7.6]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.6
    pub async fn revoke(&self, account: &Account, reason: Option<RevocationReason>) -> Result<()> {
        let url = &account.client.directory.revoke_cert;

        let revocation_request = RevocationRequest {
            certificate: self.certificate,
            reason,
        };

        account
            .client
            .post(
                url,
                &account.credentials.key,
                account.auth_kid(),
                &revocation_request,
            )
            .await?;

        Ok(())
    }
}
