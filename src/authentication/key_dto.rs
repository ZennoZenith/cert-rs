use serde::{Deserialize, Serialize};

use super::{EcCurve, Key, OkpCurve, RsaKeyBits};
use crate::{Error, Result};

/// Versioned Key Data Transfer Object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedKeyDto {
    version: u8,
    #[serde(flatten)]
    key: KeyDto,
}

/// Key Data Transfer Object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kty")] // discriminant field
#[serde(rename_all = "UPPERCASE")]
pub enum KeyDto {
    Rsa {
        signing_algo: super::RsaSigningAlgorithm,
        bits: RsaKeyBits,
        pem: String,
    },

    Ec {
        crv: EcCurve,
        pem: String,
    },

    Okp {
        crv: OkpCurve,
        pem: String,
    },
}

impl TryFrom<&Key> for VersionedKeyDto {
    type Error = Error;

    fn try_from(value: &Key) -> Result<Self> {
        let pem = String::from_utf8(value.to_pem()?)
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        match value {
            Key::Rsa {
                signing_algo, bits, ..
            } => Ok(Self {
                version: 1,
                key: KeyDto::Rsa {
                    signing_algo: *signing_algo,
                    bits: *bits,
                    pem,
                },
            }),

            Key::Ec { crv, .. } => Ok(Self {
                version: 1,
                key: KeyDto::Ec { crv: *crv, pem },
            }),
            Key::Okp { crv, .. } => Ok(Self {
                version: 1,
                key: KeyDto::Okp { crv: *crv, pem },
            }),
        }
    }
}

impl TryFrom<VersionedKeyDto> for Key {
    type Error = Error;

    fn try_from(dto: VersionedKeyDto) -> Result<Self> {
        if dto.version != 1 {
            return Err(Error::Unimplemented(
                format!("Unsupported version: {}", dto.version).into(),
            ));
        }

        match dto.key {
            KeyDto::Rsa {
                signing_algo,
                bits,
                pem,
            } => {
                let key = openssl::rsa::Rsa::private_key_from_pem(pem.as_bytes())
                    .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

                Ok(Self::Rsa {
                    signing_algo,
                    bits,
                    key,
                })
            }

            KeyDto::Ec { crv, pem } => {
                let key = openssl::ec::EcKey::private_key_from_pem(pem.as_bytes())
                    .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

                Ok(Self::Ec { crv, key })
            }

            KeyDto::Okp { crv, pem } => {
                let key = openssl::pkey::PKey::private_key_from_pem(pem.as_bytes())
                    .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

                Ok(Self::Okp { crv, key })
            }
        }
    }
}
