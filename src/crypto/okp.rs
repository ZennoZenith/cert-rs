use pkcs8::{DecodePrivateKey as _, LineEnding};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result, b64,
    crypto::{
        jwa::Jwa,
        key::{Curve, FromDerPemPkcs8, Signer, ToDerPemPkcs8},
    },
};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum OkpKey {
    Ed25519(ed25519_dalek::SigningKey),
}

impl OkpKey {
    #[must_use]
    pub fn b64_public_key(&self) -> Box<str> {
        match self {
            Self::Ed25519(key) => {
                let verifying_key = key.verifying_key();
                b64::b64u_encode(verifying_key.to_bytes()).into_boxed_str()
            }
        }
    }
}

impl FromDerPemPkcs8 for OkpKey {
    fn from_pkcs8_der(der: &[u8]) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let curve = Curve::from_pkcs8_der(der)?;

        if !matches!(curve, Curve::Okp(..)) {
            return Err(Error::Crypto("Is not a Okp key."));
        }

        ed25519_dalek::SigningKey::from_pkcs8_der(der)
            .map(Self::Ed25519)
            .map_err(|_| Error::Crypto("Invlaid Okp pkcs8 der."))
    }

    fn from_pkcs8_pem(pem: &str) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let curve = Curve::from_pkcs8_pem(pem)?;

        if !matches!(curve, Curve::Okp(..)) {
            return Err(Error::Crypto("Is not a Okp key."));
        }

        ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map(Self::Ed25519)
            .map_err(|_| Error::Crypto("Invlaid Okp pkcs8 pem."))
    }
}

impl ToDerPemPkcs8 for OkpKey {
    fn to_pkcs8_der(&self) -> crate::Result<Box<[u8]>> {
        match self {
            Self::Ed25519(signing_key) => pkcs8::EncodePrivateKey::to_pkcs8_der(signing_key)
                .map(|v| <std::vec::Vec<u8> as Clone>::clone(&v.to_bytes()).into_boxed_slice())
                .map_err(|_| Error::Crypto("Cannot convert okp key Ed25519 to pkcs8 der")),
        }
    }

    fn to_pkcs8_pem(&self, line_ending: LineEnding) -> crate::Result<Box<str>> {
        match self {
            Self::Ed25519(signing_key) => {
                pkcs8::EncodePrivateKey::to_pkcs8_pem(signing_key, line_ending)
                    .map(|v| <std::string::String as Clone>::clone(&v).into_boxed_str())
                    .map_err(|_| Error::Crypto("Cannot convert okp key Ed25519 to pkcs8 pem"))
            }
        }
    }
}

impl Signer for OkpKey {
    type Signature = Box<[u8]>;

    fn sign(&self, payload: &[u8]) -> Self::Signature {
        match self {
            Self::Ed25519(signing_key) => {
                use ed25519_dalek::Signer;
                signing_key.sign(payload).to_vec().into_boxed_slice()
            }
        }
    }
}

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
    Debug,
    Default,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    strum_macros::Display,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[non_exhaustive]
pub enum OkpCurve {
    #[serde(rename = "Ed25519")]
    #[strum(serialize = "Ed25519")]
    #[default]
    Ed25519,
}

impl From<&OkpKey> for OkpCurve {
    fn from(value: &OkpKey) -> Self {
        match value {
            OkpKey::Ed25519(_) => Self::Ed25519,
        }
    }
}

impl From<OkpKey> for OkpCurve {
    fn from(value: OkpKey) -> Self {
        Self::from(&value)
    }
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

impl From<&OkpKey> for OkpSigningAlgorithm {
    /// | EcCurve       | SigningAlgorithm      |
    /// | ------------- | --------------------- |
    /// | P-256         | ES256                 |
    /// | P-384         | ES384                 |
    /// | P-521         | ES512                 |
    fn from(value: &OkpKey) -> Self {
        match value {
            OkpKey::Ed25519(_) => Self::EdDSA,
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
