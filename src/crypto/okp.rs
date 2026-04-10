use serde::{Deserialize, Serialize};

use crate::crypto::jwa::Jwa;

/// Octet Key Pair (OKP) curves used for modern elliptic-curve cryptography.
///
/// This enum currently represents supported OKP curves for use in JWK/JWS
/// and ACME operations. OKP keys are defined in [RFC 8037] and are primarily
/// used with `EdDSA` signature schemes.
///
/// # Curve ↔ Algorithm Mapping
///
/// | [``OkpCurve``] | [``crate::crypto::jwa::SigningAlgorithm``] |
/// | -------------- | ---------------------- |
/// | Ed25519        | `EdDSA`                |
///
/// # JOSE / ACME Context
/// In JSON Web Key (JWK) format ([RFC 7517]), OKP keys specify their curve
/// using the `"crv"` field. For EdDSA-based signatures, the curve must be
/// compatible with the `"alg": "EdDSA"` JWS header.
///
/// Ed25519 is the most commonly used OKP curve in ACME due to its:
/// - High performance
/// - Strong security guarantees
/// - Deterministic signatures
///
/// # Security Notes
/// - Ed25519 is designed for high-speed signing and verification with strong
///   security margins.
/// - It is generally preferred over traditional ECDSA in modern protocols
///   where supported.
///
/// # References
/// - [RFC 8037] (CFRG Elliptic Curve Diffie-Hellman and Signatures in JOSE)
/// - [RFC 7517] (JSON Web Key)
///
/// [RFC 8037]: https://datatracker.ietf.org/doc/html/rfc8037
/// [RFC 7517]: https://datatracker.ietf.org/doc/html/rfc7517
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, strum_macros::Display, PartialEq, Eq,
)]
#[non_exhaustive]
pub enum OkpCurve {
    #[serde(rename = "Ed25519")]
    #[strum(serialize = "Ed25519")]
    #[default]
    Ed25519,
}

/// Signing algorithms for Octet Key Pair (OKP) keys.
///
/// # JOSE / ACME Context
/// OKP keys are defined in RFC 8037 and are commonly used with modern
/// elliptic curve signature schemes such as Ed25519.
///
/// In JOSE, these algorithms are represented using the `"alg"` field
/// in JWS headers.
///
/// # References
/// - [RFC 8037 §3.1] (``Self::EdDSA``)
///
/// [RFC 8037 §3.1]: https://datatracker.ietf.org/doc/html/rfc8037#section-3.1
#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Default, strum_macros::Display, PartialEq, Eq,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
#[serde(rename_all = "UPPERCASE")]
pub enum OkpSigningAlgorithm {
    /// Edwards-curve Digital Signature Algorithm (`EdDSA`).
    ///
    /// In JOSE, this is represented as `"EdDSA"` and is used with OKP keys
    /// such as Ed25519 and Ed448.
    ///
    /// # Notes
    /// - The canonical JWA string is `"EdDSA"` (case-sensitive).
    /// - This is currently the only standardized signing algorithm for OKP keys.
    ///
    /// # References
    /// -  [RFC 8037 §3.1](https://datatracker.ietf.org/doc/html/rfc8037#section-3.1)
    #[default]
    EdDSA,
}

impl From<OkpCurve> for OkpSigningAlgorithm {
    fn from(value: OkpCurve) -> Self {
        match value {
            OkpCurve::Ed25519 => Self::EdDSA,
        }
    }
}

impl From<OkpSigningAlgorithm> for &'static str {
    fn from(value: OkpSigningAlgorithm) -> Self {
        match value {
            OkpSigningAlgorithm::EdDSA => "EdDSA",
        }
    }
}

impl Jwa for OkpSigningAlgorithm {
    type Error = String;

    fn to_jwa(&self) -> &'static str {
        (*self).into()
    }

    fn from_jwa(value: &str) -> std::result::Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        match value {
            "EdDSA" => Ok(Self::EdDSA),
            v => Err(format!("Cannot convert `{v}` to OkpSigningAlgorithm")),
        }
    }
}
