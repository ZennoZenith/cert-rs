use elliptic_curve::sec1::ToEncodedPoint as _;
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
pub enum EcKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

impl EcKey {
    /// # Errors
    ///
    /// - Cannot extract `x` coordinate from Ec P-256 key.
    /// - Cannot extract `y` coordinate from Ec P-256 key.
    ///
    /// - Cannot extract `x` coordinate from Ec P-384 key.
    /// - Cannot extract `y` coordinate from Ec P-384 key.
    ///
    /// - Cannot extract `x` coordinate from Ec P-521 key.
    /// - Cannot extract `y` coordinate from Ec P-521 key.
    pub fn b64_coordinate_x_y(&self) -> Result<(Box<str>, Box<str>)> {
        match self {
            Self::P256(key) => {
                let public = key.public_key();
                let encoded = public.to_encoded_point(false); // uncompressed
                let x = b64::b64u_encode(encoded.x().ok_or(Error::Crypto(
                    "Cannot extract `x` coordinate from Ec P-256 key.",
                ))?)
                .into_boxed_str();
                let y = b64::b64u_encode(encoded.y().ok_or(Error::Crypto(
                    "Cannot extract `y` coordinate from Ec P-256 key.",
                ))?)
                .into_boxed_str();

                Ok((x, y))
            }
            Self::P384(key) => {
                let public = key.public_key();
                let encoded = public.to_encoded_point(false); // uncompressed
                let x = b64::b64u_encode(encoded.x().ok_or(Error::Crypto(
                    "Cannot extract `x` coordinate from Ec P-384 key.",
                ))?)
                .into_boxed_str();
                let y = b64::b64u_encode(encoded.y().ok_or(Error::Crypto(
                    "Cannot extract `y` coordinate from Ec P-384 key.",
                ))?)
                .into_boxed_str();

                Ok((x, y))
            }
            Self::P521(key) => {
                let public = key.public_key();
                let encoded = public.to_encoded_point(false); // uncompressed
                let x = b64::b64u_encode(encoded.x().ok_or(Error::Crypto(
                    "Cannot extract `x` coordinate from Ec P-521 key.",
                ))?)
                .into_boxed_str();
                let y = b64::b64u_encode(encoded.y().ok_or(Error::Crypto(
                    "Cannot extract `y` coordinate from Ec P-521 key.",
                ))?)
                .into_boxed_str();

                Ok((x, y))
            }
        }
    }
}

impl FromDerPemPkcs8 for EcKey {
    fn from_pkcs8_der(der: &[u8]) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let Curve::Ec(ec_curve) = Curve::from_pkcs8_der(der)? else {
            // TODO: better message
            return Err(Error::Crypto("Is not a ec key."));
        };

        match ec_curve {
            EcCurve::P256 => p256::SecretKey::from_pkcs8_der(der)
                .map(Self::P256)
                .map_err(|_| Error::Crypto("Invlaid EC P-256 pkcs8 der.")),
            EcCurve::P384 => p384::SecretKey::from_pkcs8_der(der)
                .map(Self::P384)
                .map_err(|_| Error::Crypto("Invlaid EC P-384 pkcs8 der.")),
            EcCurve::P521 => p521::SecretKey::from_pkcs8_der(der)
                .map(Self::P521)
                .map_err(|_| Error::Crypto("Invlaid EC P-521 pkcs8 der.")),
        }
    }

    fn from_pkcs8_pem(pem: &str) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let Curve::Ec(ec_curve) = Curve::from_pkcs8_pem(pem)? else {
            // TODO: better message
            return Err(Error::Crypto("Is not a ec key."));
        };

        match ec_curve {
            EcCurve::P256 => p256::SecretKey::from_pkcs8_pem(pem)
                .map(Self::P256)
                .map_err(|_| Error::Crypto("Invlaid EC P-256 pkcs8 pem.")),
            EcCurve::P384 => p384::SecretKey::from_pkcs8_pem(pem)
                .map(Self::P384)
                .map_err(|_| Error::Crypto("Invlaid EC P-384 pkcs8 pem.")),
            EcCurve::P521 => p521::SecretKey::from_pkcs8_pem(pem)
                .map(Self::P521)
                .map_err(|_| Error::Crypto("Invlaid EC P-521 pkcs8 pem.")),
        }
    }
}

impl ToDerPemPkcs8 for EcKey {
    fn to_pkcs8_der(&self) -> crate::Result<Box<[u8]>> {
        match self {
            Self::P256(secret_key) => pkcs8::EncodePrivateKey::to_pkcs8_der(secret_key)
                .map(|v| <std::vec::Vec<u8> as Clone>::clone(&v.to_bytes()).into_boxed_slice())
                .map_err(|_| Error::Crypto("Cannot convert ec key P-256 to pkcs8 der")),
            Self::P384(secret_key) => pkcs8::EncodePrivateKey::to_pkcs8_der(secret_key)
                .map(|v| <std::vec::Vec<u8> as Clone>::clone(&v.to_bytes()).into_boxed_slice())
                .map_err(|_| Error::Crypto("Cannot convert ec key P-384 to pkcs8 der")),
            Self::P521(secret_key) => pkcs8::EncodePrivateKey::to_pkcs8_der(secret_key)
                .map(|v| <std::vec::Vec<u8> as Clone>::clone(&v.to_bytes()).into_boxed_slice())
                .map_err(|_| Error::Crypto("Cannot convert ec key P-521 to pkcs8 der")),
        }
    }

    fn to_pkcs8_pem(&self, line_ending: LineEnding) -> crate::Result<Box<str>> {
        match self {
            Self::P256(secret_key) => {
                pkcs8::EncodePrivateKey::to_pkcs8_pem(secret_key, line_ending)
                    .map(|v| <std::string::String as Clone>::clone(&v).into_boxed_str())
                    .map_err(|_| Error::Crypto("Cannot convert ec P-256 key to pkcs8 pem"))
            }
            Self::P384(secret_key) => {
                pkcs8::EncodePrivateKey::to_pkcs8_pem(secret_key, line_ending)
                    .map(|v| <std::string::String as Clone>::clone(&v).into_boxed_str())
                    .map_err(|_| Error::Crypto("Cannot convert ec P-384 key to pkcs8 pem"))
            }
            Self::P521(secret_key) => {
                pkcs8::EncodePrivateKey::to_pkcs8_pem(secret_key, line_ending)
                    .map(|v| <std::string::String as Clone>::clone(&v).into_boxed_str())
                    .map_err(|_| Error::Crypto("Cannot convert ec P-521 key to pkcs8 pem"))
            }
        }
    }
}

impl Signer for EcKey {
    type Signature = Box<[u8]>;

    fn sign(&self, payload: &[u8]) -> Self::Signature {
        match self {
            Self::P256(secret_key) => {
                let signing_key: p256::ecdsa::SigningKey = secret_key.into();
                let sig: p256::ecdsa::Signature =
                    p256::ecdsa::signature::Signer::sign(&signing_key, payload);
                sig.to_vec().into_boxed_slice()
            }
            Self::P384(secret_key) => {
                let signing_key: p384::ecdsa::SigningKey = secret_key.into();
                let sig: p384::ecdsa::Signature =
                    p384::ecdsa::signature::Signer::sign(&signing_key, payload);
                sig.to_vec().into_boxed_slice()
            }
            Self::P521(secret_key) => {
                let signing_key: ecdsa::SigningKey<p521::NistP521> = secret_key.into();
                let signing_key: p521::ecdsa::SigningKey = signing_key.into();
                let sig: p521::ecdsa::Signature =
                    p521::ecdsa::signature::Signer::sign(&signing_key, b"payload");
                sig.to_vec().into_boxed_slice()
            }
        }
    }
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

impl From<&EcKey> for EcCurve {
    fn from(value: &EcKey) -> Self {
        match value {
            EcKey::P256(_) => Self::P256,
            EcKey::P384(_) => Self::P384,
            EcKey::P521(_) => Self::P521,
        }
    }
}

impl From<EcKey> for EcCurve {
    fn from(value: EcKey) -> Self {
        Self::from(&value)
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

impl From<&EcKey> for EcSigningAlgorithm {
    /// | EcCurve       | SigningAlgorithm      |
    /// | ------------- | --------------------- |
    /// | P-256         | ES256                 |
    /// | P-384         | ES384                 |
    /// | P-521         | ES512                 |
    fn from(value: &EcKey) -> Self {
        match value {
            EcKey::P256(_) => Self::Es256,
            EcKey::P384(_) => Self::Es384,
            EcKey::P521(_) => Self::Es512,
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
