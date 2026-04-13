use pkcs8::LineEnding;
use serde::{Deserialize, Serialize};

use crate::{
    Error, Key, Result,
    crypto::{
        ec::EcCurve,
        key::ToDerPemPkcs8 as _,
        okp::OkpCurve,
        rsa::{RsaKeySize, RsaSigningAlgorithm},
    },
};

/// Versioned Key Data Transfer Object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedKeyDto {
    version: u8,
    #[serde(flatten)]
    pub(crate) key: KeyDto,
}

impl VersionedKeyDto {
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }
}

/// Key Data Transfer Object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kty")] // discriminant field
#[serde(rename_all = "UPPERCASE")]
pub enum KeyDto {
    #[serde(rename_all = "camelCase")]
    Rsa {
        signing_algo: RsaSigningAlgorithm,
        bits: RsaKeySize,
        pkcs8_pem: Box<str>,
    },

    #[serde(rename_all = "camelCase")]
    Ec { crv: EcCurve, pkcs8_pem: Box<str> },

    #[serde(rename_all = "camelCase")]
    Okp { crv: OkpCurve, pkcs8_pem: Box<str> },
}

impl TryFrom<&Key> for VersionedKeyDto {
    type Error = Error;

    fn try_from(value: &Key) -> Result<Self> {
        match value {
            Key::Rsa(rsa_key) => Ok(Self {
                version: 1,
                key: KeyDto::Rsa {
                    signing_algo: rsa_key.signing_algo,
                    bits: rsa_key.bits,
                    pkcs8_pem: rsa_key.to_pkcs8_pem(LineEnding::default())?,
                },
            }),
            Key::Ec(ec_key) => Ok(Self {
                version: 1,
                key: KeyDto::Ec {
                    crv: EcCurve::from(ec_key),
                    pkcs8_pem: ec_key.to_pkcs8_pem(LineEnding::default())?,
                },
            }),
            Key::Okp(okp_key) => Ok(Self {
                version: 1,
                key: KeyDto::Okp {
                    crv: OkpCurve::from(okp_key),
                    pkcs8_pem: okp_key.to_pkcs8_pem(LineEnding::default())?,
                },
            }),
        }
    }
}

impl TryFrom<Key> for VersionedKeyDto {
    type Error = Error;

    fn try_from(value: Key) -> Result<Self> {
        Self::try_from(&value)
    }
}
