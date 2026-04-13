use pkcs8::{DecodePrivateKey as _, LineEnding};
use rsa::{
    pkcs1v15::SigningKey,
    sha2::{Sha256, Sha384, Sha512},
    traits::PublicKeyParts as _,
};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result, b64,
    crypto::{
        jwa::Jwa,
        key::{Curve, FromDerPemPkcs8, Signer, ToDerPemPkcs8},
    },
};

#[derive(Debug, Clone)]
pub struct RsaKey {
    /// The underlying private key material.
    pub(crate) key: rsa::RsaPrivateKey,

    /// The signing algorithm associated with this RSA key.
    pub(crate) signing_algo: RsaSigningAlgorithm,

    /// The RSA modulus size (key strength).
    #[allow(dead_code)]
    pub(crate) bits: RsaKeySize,
}

impl RsaKey {
    /// # Errors
    ///
    /// See [``crate::Error::Crypto``]
    pub fn from_pkcs8_der_with_signing_algo(
        der: &[u8],
        signing_algo: RsaSigningAlgorithm,
    ) -> Result<Self> {
        Ok(Self {
            signing_algo,
            ..(Self::from_pkcs8_der(der)?)
        })
    }

    /// # Errors
    ///
    /// See [``crate::Error::Crypto``]
    pub fn from_pkcs8_pem_with_signing_algo(
        pem: &str,
        signing_algo: RsaSigningAlgorithm,
    ) -> Result<Self> {
        Ok(Self {
            signing_algo,
            ..(Self::from_pkcs8_pem(pem)?)
        })
    }

    pub const fn set_signing_algo(&mut self, signing_algo: RsaSigningAlgorithm) {
        self.signing_algo = signing_algo;
    }

    #[must_use]
    pub fn with_signing_algo(self, signing_algo: RsaSigningAlgorithm) -> Self {
        Self {
            signing_algo,
            ..self
        }
    }

    #[must_use]
    pub fn b64_modulus(&self) -> Box<str> {
        b64::b64u_encode(self.key.n().to_bytes_be()).into_boxed_str()
    }

    #[must_use]
    pub fn b64_exponent(&self) -> Box<str> {
        b64::b64u_encode(self.key.e().to_bytes_be()).into_boxed_str()
    }
}

impl FromDerPemPkcs8 for RsaKey {
    /// Default signing algorithm (i.e. [``cert_rs::crypto::rsa::RsaSigningAlgorithm::default()``])
    /// is being used.
    ///
    /// Use [``Self::from_rsa_pkcs8_der()``] to provide signing algorithm explictly.
    fn from_pkcs8_der(der: &[u8]) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let curve = Curve::from_pkcs8_der(der)?;
        if !matches!(curve, Curve::Rsa) {
            return Err(Error::Crypto("Is not a rsa key."));
        }

        let key = rsa::RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|_| Error::Crypto("Invlaid RSA pkcs8 der."))?;
        let key_size_bits = key.size() * 8;
        let bits = RsaKeySize::try_from(key_size_bits)?;

        Ok(Self {
            key,
            bits,
            signing_algo: RsaSigningAlgorithm::default(),
        })
    }

    /// Default signing algorithm (i.e. [``cert_rs::crypto::rsa::RsaSigningAlgorithm::default()``])
    /// is being used.
    ///
    /// Use [``Self::from_rsa_pkcs8_pem()``] to provide signing algorithm explictly.
    fn from_pkcs8_pem(pem: &str) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        let curve = Curve::from_pkcs8_pem(pem)?;
        if !matches!(curve, Curve::Rsa) {
            return Err(Error::Crypto("Is not a rsa key."));
        }

        let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|_| Error::Crypto("Invlaid RSA pkcs8 der."))?;
        let key_size_bits = key.size() * 8;
        let bits = RsaKeySize::try_from(key_size_bits)?;

        Ok(Self {
            key,
            bits,
            signing_algo: RsaSigningAlgorithm::default(),
        })
    }
}

impl ToDerPemPkcs8 for RsaKey {
    fn to_pkcs8_der(&self) -> crate::Result<Box<[u8]>> {
        pkcs8::EncodePrivateKey::to_pkcs8_der(&self.key)
            .map(|v| <std::vec::Vec<u8> as Clone>::clone(&v.to_bytes()).into_boxed_slice())
            .map_err(|_| Error::Crypto("Cannot convert rsa key to pkcs8 der"))
    }

    fn to_pkcs8_pem(&self, line_ending: LineEnding) -> crate::Result<Box<str>> {
        pkcs8::EncodePrivateKey::to_pkcs8_pem(&self.key, line_ending)
            .map(|v| <std::string::String as Clone>::clone(&v).into_boxed_str())
            .map_err(|_| Error::Crypto("Cannot convert rsa key to pkcs8 pem"))
    }
}

impl Signer for RsaKey {
    type Signature = Box<[u8]>;

    fn sign(&self, payload: &[u8]) -> Self::Signature {
        match self.signing_algo {
            RsaSigningAlgorithm::RS256 => {
                let signing_key = SigningKey::<Sha256>::new(self.key.clone());
                rsa::signature::Signer::sign(&signing_key, payload).into()
            }
            RsaSigningAlgorithm::RS384 => {
                let signing_key = SigningKey::<Sha384>::new(self.key.clone());
                rsa::signature::Signer::sign(&signing_key, payload).into()
            }
            RsaSigningAlgorithm::RS512 => {
                let signing_key = SigningKey::<Sha512>::new(self.key.clone());
                rsa::signature::Signer::sign(&signing_key, payload).into()
            }
        }
    }
}

/// RSA key size options used for key generation.
///
/// This enum defines the supported bit lengths for RSA private keys used
/// in cryptographic operations such as ACME account keys or certificate
/// signing requests (CSR).
///
/// # JOSE / ACME Context
/// RSA key strength is determined by its modulus size. In ACME and JOSE
/// systems, RSA keys are commonly used with RSASSA-PKCS1-v1_5 signing
/// algorithms (e.g., `RS256`, `RS384`, `RS512`).
///
/// # Security Considerations
/// - Larger key sizes provide stronger security but increase computation cost.
/// - 2048-bit keys are widely supported and considered the minimum secure
///   baseline in modern TLS/ACME deployments.
/// - 4096-bit keys provide higher security margins and are often used for
///   long-lived certificates or higher-security requirements.
///
/// # Defaults
/// - Default: `4096 bits`
///
/// # References
/// - NIST SP 800-57 (Key Management Recommendations)
/// - [RFC 8017] (PKCS #1: RSA Cryptography Specifications)
///
/// [RFC 8017]: https://datatracker.ietf.org/doc/html/rfc8017
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RsaKeySize {
    /// 2048-bit RSA key.
    Bits2048,

    /// 3072-bit RSA key.
    Bits3072,

    /// 4096-bit RSA key (default).
    #[default]
    Bits4096,

    /// 8192-bit RSA key.
    Bits8192,
}

impl RsaKeySize {
    #[must_use]
    pub const fn as_usize(self) -> usize {
        match self {
            Self::Bits2048 => 2048,
            Self::Bits3072 => 3072,
            Self::Bits4096 => 4096,
            Self::Bits8192 => 8192,
        }
    }

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Bits2048 => 2048,
            Self::Bits3072 => 3072,
            Self::Bits4096 => 4096,
            Self::Bits8192 => 8192,
        }
    }
}

impl TryFrom<usize> for RsaKeySize {
    type Error = Error;

    fn try_from(value: usize) -> std::result::Result<Self, Self::Error> {
        match value {
            2048 => Ok(Self::Bits2048),
            3072 => Ok(Self::Bits3072),
            4096 => Ok(Self::Bits4096),
            8192 => Ok(Self::Bits8192),
            _ => Err(Error::Crypto(
                "Only 2048, 3072, 4096, 8192 bit rsa key supported.",
            )),
        }
    }
}

impl TryFrom<u32> for RsaKeySize {
    type Error = Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            2048 => Ok(Self::Bits2048),
            3072 => Ok(Self::Bits3072),
            4096 => Ok(Self::Bits4096),
            8192 => Ok(Self::Bits8192),
            _ => Err(Error::Crypto(
                "Only 2048, 3072, 4096, 8192 bit rsa key supported.",
            )),
        }
    }
}

/// RSA-based signing algorithms as defined by JSON Web Algorithms (JWA).
///
/// # JOSE / ACME Context
/// These algorithms are used in JWS for signing payloads with RSA keys,
/// including ACME request authentication. They correspond to the
/// RSASSA-PKCS1-v1_5 signature scheme with different SHA-2 hash functions.
///
/// The string representations (e.g., `"RS256"`) are used in the `"alg"`
/// field of JOSE headers.
///
/// # Notes
/// - These algorithms use PKCS#1 v1.5 padding (not PSS).
/// - Widely supported across ACME servers and JOSE implementations.
/// - Security strength increases with larger hash sizes, though `RS256`
///   is the most commonly used and broadly compatible option.
///
/// # References
/// - [RFC 7518 §3.3] (JSON Web Algorithms - RSA using SHA-2)
///
/// [RFC 7518 §3.3]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Default, strum_macros::Display, PartialEq, Eq,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
#[serde(rename_all = "UPPERCASE")]
pub enum RsaSigningAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    ///
    /// JWA identifier: `"RS256"`.
    ///
    /// This is the default and most commonly used RSA signing algorithm
    /// in JOSE and ACME.
    #[default]
    RS256,

    /// RSASSA-PKCS1-v1_5 using SHA-384.
    ///
    /// JWA identifier: `"RS384"`.
    ///
    /// Provides a higher security margin than RS256 at the cost of slightly
    /// increased computational overhead.
    RS384,

    /// RSASSA-PKCS1-v1_5 using SHA-512.
    ///
    /// JWA identifier: `"RS512"`.
    ///
    /// Uses the strongest SHA-2 variant among the RSASSA-PKCS1-v1_5 options.
    RS512,
}

impl From<&RsaKey> for RsaSigningAlgorithm {
    fn from(value: &RsaKey) -> Self {
        value.signing_algo
    }
}

impl From<RsaSigningAlgorithm> for &'static str {
    fn from(value: RsaSigningAlgorithm) -> Self {
        match value {
            RsaSigningAlgorithm::RS256 => "RS256",
            RsaSigningAlgorithm::RS384 => "RS384",
            RsaSigningAlgorithm::RS512 => "RS512",
        }
    }
}

impl Jwa for RsaSigningAlgorithm {
    type Error = String;

    fn to_jwa(&self) -> &'static str {
        (*self).into()
    }

    fn from_jwa(value: &str) -> std::result::Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        match value {
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            v => Err(format!("Cannot convert `{v}` to RsaSigningAlgorithm")),
        }
    }
}
