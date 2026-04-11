use serde::{Deserialize, Serialize};

use crate::{
    Error, Key, Result,
    crypto::{
        ec::EcCurve,
        okp::OkpCurve,
        rsa::{RsaKeyBits, RsaSigningAlgorithm},
    },
};

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
        signing_algo: RsaSigningAlgorithm,
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
        let (pem, _) = value.to_pem()?;

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
            return Err(Error::Str("Unsupported KeyDto version"));
        }

        match dto.key {
            KeyDto::Rsa {
                signing_algo,
                bits,
                pem,
            } => {
                let key = openssl::rsa::Rsa::private_key_from_pem(pem.as_bytes())
                    .map_err(|_| Error::Crypto("Cannot parse Rsa private_key_from_pem"))?;

                Ok(Self::Rsa {
                    signing_algo,
                    bits,
                    key,
                })
            }

            KeyDto::Ec { crv, pem } => {
                let key = openssl::ec::EcKey::private_key_from_pem(pem.as_bytes())
                    .map_err(|_| Error::Crypto("Cannot parse Ec private_key_from_pem"))?;

                Ok(Self::Ec { crv, key })
            }

            KeyDto::Okp { crv, pem } => {
                let key = openssl::pkey::PKey::private_key_from_pem(pem.as_bytes())
                    .map_err(|_| Error::Crypto("Cannot parse Okp private_key_from_pem"))?;

                Ok(Self::Okp { crv, key })
            }
        }
    }
}
