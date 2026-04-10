use serde::{Deserialize, Serialize};

use crate::{Error, crypto::jwa::Jwa};

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
pub enum RsaKeyBits {
    /// 2048-bit RSA key.
    Bits2048,

    /// 4096-bit RSA key (default).
    #[default]
    Bits4096,
}

impl RsaKeyBits {
    #[must_use]
    pub const fn as_usize(self) -> usize {
        match self {
            Self::Bits2048 => 2048,
            Self::Bits4096 => 4096,
        }
    }

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Bits2048 => 2048,
            Self::Bits4096 => 4096,
        }
    }
}

impl TryFrom<usize> for RsaKeyBits {
    type Error = Error;

    fn try_from(value: usize) -> std::result::Result<Self, Self::Error> {
        match value {
            2048 => Ok(Self::Bits2048),
            4096 => Ok(Self::Bits4096),
            b => Err(Error::Unimplemented(
                format!("Unknown number of rsa bits: {b}").into(),
            )),
        }
    }
}

impl TryFrom<u32> for RsaKeyBits {
    type Error = Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            2048 => Ok(Self::Bits2048),
            4096 => Ok(Self::Bits4096),
            b => Err(Error::Unimplemented(
                format!("Unknown number of rsa bits: {b}").into(),
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
    Rs256,

    /// RSASSA-PKCS1-v1_5 using SHA-384.
    ///
    /// JWA identifier: `"RS384"`.
    ///
    /// Provides a higher security margin than RS256 at the cost of slightly
    /// increased computational overhead.
    Rs384,

    /// RSASSA-PKCS1-v1_5 using SHA-512.
    ///
    /// JWA identifier: `"RS512"`.
    ///
    /// Uses the strongest SHA-2 variant among the RSASSA-PKCS1-v1_5 options.
    Rs512,
}

impl From<RsaSigningAlgorithm> for &'static str {
    fn from(value: RsaSigningAlgorithm) -> Self {
        match value {
            RsaSigningAlgorithm::Rs256 => "RS256",
            RsaSigningAlgorithm::Rs384 => "RS384",
            RsaSigningAlgorithm::Rs512 => "RS512",
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
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            v => Err(format!("Cannot convert `{v}` to RsaSigningAlgorithm")),
        }
    }
}
