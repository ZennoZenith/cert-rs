use serde::{Deserialize, Serialize};

use crate::{EcCurve, OkpCurve};

#[allow(dead_code)]
pub trait Jwa {
    type Error;

    fn to_jwa(&self) -> &'static str;

    /// # Errors
    ///
    /// TODO: Write error docs
    fn from_jwa(value: &str) -> std::result::Result<Self, Self::Error>
    where
        Self: std::marker::Sized;
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Default, strum_macros::Display, PartialEq, Eq,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
#[serde(rename_all = "UPPERCASE")]
pub enum RsaSigningAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256
    #[default]
    Rs256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    Rs384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
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

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Default, strum_macros::Display, PartialEq, Eq,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
#[serde(rename_all = "UPPERCASE")]
pub enum EcSigningAlgorithm {
    /// ECDSA using P-256 and SHA-256
    #[default]
    Es256,
    /// ECDSA using P-384 and SHA-384
    Es384,
    /// ECDSA using P-521 and SHA-512
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

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Default, strum_macros::Display, PartialEq, Eq,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
#[serde(rename_all = "UPPERCASE")]
pub enum OkpSigningAlgorithm {
    /// TODO: Display: `EdDSA` ? EDDSA
    ///
    /// TODO: See [RFC 8037 §3.1](https://datatracker.ietf.org/doc/html/rfc8037#section-3.1)
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

/// JWS Signning alogrithm
///
/// See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515),
/// [RFC 7518 §3.1](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1)
#[derive(Debug, Copy, Clone, Serialize, strum_macros::Display, PartialEq, Eq)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
#[serde(untagged)]
#[serde(rename_all = "UPPERCASE")]
pub enum SigningAlgorithm {
    Rsa(RsaSigningAlgorithm),
    Ec(EcSigningAlgorithm),
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
