use serde::{Deserialize, Serialize};

use crate::{
    Key,
    crypto::{
        ec::EcCurve,
        okp::OkpCurve,
        rsa::{RsaKeySize, RsaSigningAlgorithm},
    },
};

/// Versioned Key Data Transfer Object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedKeyDto {
    version: u8,
    #[serde(flatten)]
    key: KeyDto,
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
        pkcs8_pem: String,
    },

    #[serde(rename_all = "camelCase")]
    Ec { crv: EcCurve, pkcs8_pem: String },

    #[serde(rename_all = "camelCase")]
    Okp { crv: OkpCurve, pkcs8_pem: String },
}

impl From<&Key> for VersionedKeyDto {
    fn from(_value: &Key) -> Self {
        // TODO:
        unimplemented!()
    }
}

impl From<Key> for VersionedKeyDto {
    fn from(value: Key) -> Self {
        Self::from(&value)
    }
}
