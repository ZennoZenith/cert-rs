use openssl::{ec::EcKey, nid::Nid};
use serde::{Deserialize, Serialize};

use crate::{Error, Result, crypto::jwa::Jwa};

pub(crate) fn detect_ec_curve(key: &EcKey<openssl::pkey::Private>) -> Result<EcCurve> {
    let group = key.group();
    let nid = group.curve_name().ok_or(Error::Crypto("Unknown Elliptic Curve"))?;

    match nid {
        Nid::X9_62_PRIME256V1 => Ok(EcCurve::P256),
        Nid::SECP384R1 => Ok(EcCurve::P384),
        Nid::SECP521R1 => Ok(EcCurve::P521),
        _ => Err(Error::Str("Unsupported Elliptic Curve")),
    }
}

pub(crate) fn ecdsa_der_to_raw(der: &[u8], crv: EcCurve) -> Result<Vec<u8>> {
    use openssl::ecdsa::EcdsaSig;

    let sig =
        EcdsaSig::from_der(der).map_err(|_| Error::Crypto("Cannot convert der to EcdsaSig"))?;

    let size = match crv {
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
        EcCurve::P521 => 66,
    };

    let mut r = sig.r().to_vec();
    let mut s = sig.s().to_vec();

    // left-pad with zeros
    if r.len() < size {
        r = [vec![0; size - r.len()], r].concat();
    }
    if s.len() < size {
        s = [vec![0; size - s.len()], s].concat();
    }

    Ok([r, s].concat())
}

/// Elliptic Curve (EC) groups used for cryptographic key generation.
///
/// This enum represents NIST prime curves used in ECDSA-based signing and
/// are commonly used in JOSE (JWK/JWS) and ACME protocols.
///
/// # Curve ↔ Signing Algorithm Mapping
///
/// | [``EcCurve``] | [``crate::crypto::jwa::SigningAlgorithm``] |
/// | ------------- | ---------------------- |
/// | P-256         | ES256                  |
/// | P-384         | ES384                  |
/// | P-521         | ES512                  |
///
/// # JOSE / ACME Context
/// In JWK ([RFC 7517]), EC keys specify their curve using the `"crv"` field.
/// The curve determines the cryptographic strength and must match the
/// corresponding JWS `"alg"` value when signing requests.
///
/// These curves are defined in:
/// - [RFC 7518 §6.2] (JWA Elliptic Curve parameters)
///
/// # Security Notes
/// - P-256 is the most widely supported and commonly used in ACME.
/// - P-384 provides higher security margins at a performance cost.
/// - P-521 offers the highest NIST curve security level but is less commonly used.
///
/// # Serialization
/// Values are serialized using standard JWK curve names (e.g., `"P-256"`).
///
/// # References
/// - [RFC 7517] (JSON Web Key)
/// - [RFC 7518 §6.2] (EC Key Parameters)
///
/// [RFC 7517]: https://datatracker.ietf.org/doc/html/rfc7517
/// [RFC 7518 §6.2]: https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, strum_macros::Display, PartialEq, Eq,
)]
#[non_exhaustive]
pub enum EcCurve {
    #[serde(rename = "P-256")]
    #[strum(serialize = "P-256")]
    #[default]
    P256,

    #[serde(rename = "P-384")]
    #[strum(serialize = "P-384")]
    P384,

    #[serde(rename = "P-521")]
    #[strum(serialize = "P-521")]
    P521,
}

impl From<EcCurve> for Nid {
    /// `Nid::X9_62_PRIME256V1` -> `P256`
    /// `Nid::SECP384R1` -> `P384`
    /// `Nid::SECP521R1` -> `P521`
    fn from(value: EcCurve) -> Self {
        match value {
            EcCurve::P256 => Self::X9_62_PRIME256V1,
            EcCurve::P384 => Self::SECP384R1,
            EcCurve::P521 => Self::SECP521R1,
        }
    }
}

/// Elliptic Curve (EC) signing algorithms as defined by JSON Web Algorithms (JWA).
///
/// # JOSE / ACME Context
/// These algorithms are used in JWS for signing payloads with Elliptic Curve
/// keys, including ACME request authentication. They correspond to ECDSA
/// signatures over specific NIST curves paired with SHA-2 hash functions.
///
/// The string representations (e.g., `"ES256"`) are used in the `"alg"`
/// field of JOSE headers.
///
/// # Notes
/// - Each algorithm binds a specific curve and hash function:
///   - P-256 → SHA-256
///   - P-384 → SHA-384
///   - P-521 → SHA-512
/// - ECDSA signatures in JOSE use a fixed-size concatenated `(r || s)` format,
///   not DER encoding.
/// - `ES256` is the most commonly used and widely supported option in ACME.
///
/// # References
/// - [RFC 7518 §3.4] (JSON Web Algorithms - ECDSA)
///
/// [RFC 7518 §3.4]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Default, strum_macros::Display, PartialEq, Eq,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
#[serde(rename_all = "UPPERCASE")]
pub enum EcSigningAlgorithm {
    /// ECDSA using the P-256 curve and SHA-256.
    ///
    /// JWA identifier: `"ES256"`.
    ///
    /// This is the default and most widely supported EC signing algorithm
    /// in JOSE and ACME.
    #[default]
    Es256,

    /// ECDSA using the P-384 curve and SHA-384.
    ///
    /// JWA identifier: `"ES384"`.
    ///
    /// Provides a higher security margin than ES256 with increased
    /// computational cost.
    Es384,

    /// ECDSA using the P-521 curve and SHA-512.
    ///
    /// JWA identifier: `"ES512"`.
    ///
    /// Uses the largest standard NIST curve and strongest SHA-2 variant
    /// among the ECDSA options.
    Es512,
}

impl From<EcCurve> for EcSigningAlgorithm {
    /// | EcCurve       | SigningAlgorithm      |
    /// | ------------- | --------------------- |
    /// | P-256         | ES256                 |
    /// | P-384         | ES384                 |
    /// | P-521         | ES512                 |
    fn from(value: EcCurve) -> Self {
        match value {
            EcCurve::P256 => Self::Es256,
            EcCurve::P384 => Self::Es384,
            EcCurve::P521 => Self::Es512,
        }
    }
}

impl From<EcSigningAlgorithm> for &'static str {
    fn from(value: EcSigningAlgorithm) -> Self {
        match value {
            EcSigningAlgorithm::Es256 => "ES256",
            EcSigningAlgorithm::Es384 => "ES384",
            EcSigningAlgorithm::Es512 => "ES512",
        }
    }
}

impl Jwa for EcSigningAlgorithm {
    type Error = String;

    fn to_jwa(&self) -> &'static str {
        (*self).into()
    }

    fn from_jwa(value: &str) -> std::result::Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        match value {
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            "ES512" => Ok(Self::Es512),
            v => Err(format!("Cannot convert `{v}` to EcSigningAlgorithm")),
        }
    }
}
