use serde::Serialize;

use crate::{
    Key,
    crypto::{ec::EcSigningAlgorithm, okp::OkpSigningAlgorithm, rsa::RsaSigningAlgorithm},
};

#[allow(dead_code)]
pub(crate) trait Jwa {
    type Error;

    /// Returns the JSON Web Algorithm (JWA) identifier for this value.
    ///
    /// # Context
    /// In JOSE (JWS/JWE/JWK), algorithms are represented as standardized
    /// string identifiers (e.g., `"RS256"`, `"ES256"`). This method provides
    /// the canonical string form used in protocol messages and headers.
    ///
    /// # Returns
    /// A static string slice representing the JWA name for this algorithm.
    ///
    /// This value is suitable for use in JOSE headers such as the `"alg"` field.
    fn to_jwa(&self) -> &'static str;

    /// Attempts to construct a value from its JSON Web Algorithm (JWA)
    /// string representation.
    ///
    /// # Context
    /// In JOSE (JWS/JWE/JWK), algorithms are identified by standardized
    /// string values (e.g., `"RS256"`, `"ES256"`). This method parses such
    /// a string into a strongly-typed representation.
    ///
    /// # Parameters
    /// - `value`: The JWA string identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided string does not correspond to a supported or known JWA value.
    /// - The value is malformed or does not match the expected format.
    /// - The algorithm is recognized but not supported by this implementation.
    ///
    /// The specific error type is defined by [`Self::Error`].
    fn from_jwa(value: &str) -> std::result::Result<Self, Self::Error>
    where
        Self: std::marker::Sized;
}

/// JSON Web Signature (JWS) signing algorithms.
///
/// This enum represents the set of supported signing algorithms used in
/// JOSE (JWS/JWK) and ACME request authentication. Each variant groups
/// algorithms by key type.
///
/// # JOSE / ACME Context
/// In JWS ([RFC 7515]), the `"alg"` header parameter specifies the algorithm
/// used to sign a payload. This enum provides a strongly-typed abstraction
/// over those algorithm identifiers.
///
/// ACME uses JWS extensively to authenticate requests:
/// - Account creation (JWK-based)
/// - Subsequent requests (kid-based)
///
/// # Variants
/// - [`Self::Rsa`]: RSA-based algorithms (RSASSA-PKCS1-v1_5 with SHA-2)
/// - [`Self::Ec`]: Elliptic Curve algorithms (ECDSA with NIST curves)
/// - [`Self::Okp`]: Octet Key Pair algorithms (e.g., `EdDSA`)
///
/// # Serialization
/// This enum is serialized in an *untagged* form, meaning the inner algorithm
/// string (e.g., `"RS256"`, `"ES256"`, `"EdDSA"`) is emitted directly as the
/// `"alg"` value in JWS headers.
///
/// # Notes
/// - The enum is marked `non_exhaustive` to allow future expansion as new
///   algorithms are standardized.
/// - Case-insensitive parsing is supported via `strum`.
///
/// # References
/// - [RFC 7515] (JSON Web Signature)
/// - [RFC 7518 §3.1] (JSON Web Algorithms - "alg" values)
///
/// [RFC 7515]: https://datatracker.ietf.org/doc/html/rfc7515,
/// [RFC 7518 §3.1]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
#[derive(Debug, Copy, Clone, Serialize, strum_macros::Display, PartialEq, Eq)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
#[serde(untagged)]
#[serde(rename_all = "UPPERCASE")]
pub enum SigningAlgorithm {
    /// RSA-based signing algorithms.
    Rsa(RsaSigningAlgorithm),

    /// Elliptic Curve (ECDSA) signing algorithms.
    Ec(EcSigningAlgorithm),

    /// Octet Key Pair (OKP) signing algorithms (e.g., `EdDSA`).
    Okp(OkpSigningAlgorithm),
}

impl From<RsaSigningAlgorithm> for SigningAlgorithm {
    fn from(value: RsaSigningAlgorithm) -> Self {
        Self::Rsa(value)
    }
}
impl From<EcSigningAlgorithm> for SigningAlgorithm {
    fn from(value: EcSigningAlgorithm) -> Self {
        Self::Ec(value)
    }
}
impl From<OkpSigningAlgorithm> for SigningAlgorithm {
    fn from(value: OkpSigningAlgorithm) -> Self {
        Self::Okp(value)
    }
}

impl From<&Key> for SigningAlgorithm {
    fn from(value: &Key) -> Self {
        match value {
            Key::Rsa(rsa_key) => RsaSigningAlgorithm::from(rsa_key).into(),
            Key::Ec(ec_key) => EcSigningAlgorithm::from(ec_key).into(),
            Key::Okp(okp_key) => OkpSigningAlgorithm::from(okp_key).into(),
        }
    }
}

impl From<SigningAlgorithm> for &'static str {
    fn from(value: SigningAlgorithm) -> Self {
        match value {
            SigningAlgorithm::Rsa(v) => v.into(),
            SigningAlgorithm::Ec(v) => v.into(),
            SigningAlgorithm::Okp(v) => v.into(),
        }
    }
}

impl Jwa for SigningAlgorithm {
    type Error = String;

    fn to_jwa(&self) -> &'static str {
        (*self).into()
    }

    fn from_jwa(value: &str) -> std::result::Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        RsaSigningAlgorithm::from_jwa(value)
            .map(Self::Rsa)
            .or_else(|_| EcSigningAlgorithm::from_jwa(value).map(Self::Ec))
            .or_else(|_| OkpSigningAlgorithm::from_jwa(value).map(Self::Okp))
            .map_err(|_| format!("{value} cannot be converted to SigningAlgorithm"))
    }
}
