use pkcs8::{LineEnding, PrivateKeyInfo, der::Decode as _};
use rcgen::{
    CertificateParams, CertificateSigningRequest, DistinguishedName, DnType, KeyPair, SanType,
};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    crypto::{
        ec::{EcCurve, EcKey},
        key_dto::{KeyDto, VersionedKeyDto},
        okp::{OkpCurve, OkpKey},
        rsa::{RsaKey, RsaSigningAlgorithm},
    },
};

pub trait FromDerPemPkcs8 {
    /// # Errors
    ///
    /// See [``crate::Error::Crypto``]
    fn from_pkcs8_der(der: &[u8]) -> crate::Result<Self>
    where
        Self: std::marker::Sized;

    /// # Errors
    ///
    /// See [``crate::Error::Crypto``]
    fn from_pkcs8_pem(pem: &str) -> crate::Result<Self>
    where
        Self: std::marker::Sized;
}

pub trait ToDerPemPkcs8 {
    /// # Errors
    ///
    /// See [``crate::Error::Crypto``]
    fn to_pkcs8_der(&self) -> crate::Result<Box<[u8]>>;

    /// # Errors
    ///
    /// See [``crate::Error::Crypto``]
    fn to_pkcs8_pem(&self, line_ending: LineEnding) -> crate::Result<Box<str>>;
}

pub(crate) trait Signer {
    type Signature: AsRef<[u8]>;

    fn sign(&self, payload: &[u8]) -> Self::Signature;
}

#[derive(
    Debug,
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
#[serde(rename_all = "UPPERCASE")]
pub enum Curve {
    #[strum(serialize = "RSA")]
    Rsa,

    #[strum(transparent)]
    Ec(EcCurve),

    #[strum(transparent)]
    Okp(OkpCurve),
}

impl FromDerPemPkcs8 for Curve {
    fn from_pkcs8_der(der: &[u8]) -> crate::Result<Self>
    where
        Self: std::marker::Sized,
    {
        let info =
            PrivateKeyInfo::from_der(der).map_err(|_| Error::Crypto("Cannot parse pkcs8 der"))?;
        let oid = info.algorithm.oid;

        let curve: Self = match oid.to_string().as_str() {
            "1.2.840.10045.2.1" => {
                // EC key — check the named curve parameter
                let curve_oid = info
                    .algorithm
                    .parameters_oid()
                    .map_err(|_| Error::Crypto("Cannot parse parameters_oid from pkcs8 der"))?;
                match curve_oid.to_string().as_str() {
                    "1.2.840.10045.3.1.7" => Self::Ec(EcCurve::P256),
                    "1.3.132.0.34" => Self::Ec(EcCurve::P384),
                    "1.3.132.0.35" => Self::Ec(EcCurve::P521),
                    _ => return Err(Error::Crypto("Unknown EC curve")),
                }
            }
            "1.3.101.112" => Self::Okp(OkpCurve::Ed25519),
            // "1.3.101.113" => "Ed448",
            "1.2.840.113549.1.1.1" => Self::Rsa,
            _ => return Err(Error::Crypto("Unknown curve")),
        };

        Ok(curve)
    }

    fn from_pkcs8_pem(pem: &str) -> crate::Result<Self>
    where
        Self: std::marker::Sized,
    {
        use pkcs8::der::pem::PemLabel;

        let (label, der) = pkcs8::der::pem::decode_vec(pem.as_bytes())
            .map_err(|_| Error::Crypto("Cannot decode pem"))?;

        if label != PrivateKeyInfo::PEM_LABEL {
            return Err(Error::Crypto("Not a private key PEM"));
        }

        Self::from_pkcs8_der(&der)
    }
}

/// A cryptographic private key used for ACME / JOSE operations.
///
/// This enum wraps supported key types used for:
/// - ACME account authentication
/// - JWS signing of requests
/// - CSR generation and certificate issuance flows
///
/// # ACME / JOSE Context
/// ACME ([RFC 8555]) uses asymmetric cryptography for all authenticated requests.
/// Keys are represented in JWK format and used to sign JWS payloads.
///
/// This type supports:
/// - RSA keys (RS256/RS384/RS512)
/// - Elliptic Curve keys (ES256/ES384/ES512)
/// - Octet Key Pair keys (`EdDSA` via Ed25519)
///
/// Each variant stores both the raw private key material and the associated
/// metadata required for correct JOSE representation.
///
/// # Variants
/// - `Rsa`: RSA private key with configurable bit size and signing algorithm.
/// - `Ec`: ECDSA private key over NIST curves (P-256, P-384, P-521).
/// - `Okp`: Octet Key Pair (e.g., Ed25519) used with `EdDSA`.
///
/// # Security Notes
/// - Keys must be kept confidential; leaking them compromises the ACME account.
/// - RSA is widely supported but slower and larger.
/// - EC provides a balance of performance and security.
/// - OKP (Ed25519) is preferred in modern systems when supported.
///
/// # References
/// - [RFC 8555] (ACME)
/// - [RFC 7517] (JWK)
/// - [RFC 7518] (JWA)
/// - [RFC 8037] (`EdDSA` / OKP keys)
///
/// [RFC 8555]: https://datatracker.ietf.org/doc/html/rfc8555
/// [RFC 7517]: https://datatracker.ietf.org/doc/html/rfc7517
/// [RFC 7518]: https://datatracker.ietf.org/doc/html/rfc7518
/// [RFC 8037]: https://datatracker.ietf.org/doc/html/rfc8037
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Key {
    /// RSA private key used with RSASSA-PKCS1-v1_5 signing algorithms.
    Rsa(RsaKey),

    /// Elliptic Curve (ECDSA) private key over NIST prime curves.
    Ec(EcKey),

    /// Octet Key Pair (OKP) private key (typically Ed25519).
    Okp(OkpKey),
}

impl FromDerPemPkcs8 for Key {
    /// If Rsa key is provided, default signing algorithm (i.e. [``cert_rs::crypto::rsa::RsaSigningAlgorithm::default()``]) will be choosen.
    ///
    /// Use [``Self::from_rsa_pkcs8_der()``] to provide signing algorithm explictly.
    fn from_pkcs8_der(der: &[u8]) -> crate::Result<Self>
    where
        Self: std::marker::Sized,
    {
        let curve = Curve::from_pkcs8_der(der)?;
        match curve {
            Curve::Rsa => Ok(Self::from(RsaKey::from_pkcs8_der(der)?)),
            Curve::Ec(_) => Ok(Self::from(EcKey::from_pkcs8_der(der)?)),
            Curve::Okp(_) => Ok(Self::from(OkpKey::from_pkcs8_der(der)?)),
        }
    }

    /// If Rsa key is provided, default signing algorithm (i.e. [``cert_rs::crypto::rsa::RsaSigningAlgorithm::default()``]) will be choosen.
    ///
    /// Use [``Self::from_rsa_pkcs8_pem()``] to provide signing algorithm explictly.
    fn from_pkcs8_pem(pem: &str) -> crate::Result<Self>
    where
        Self: std::marker::Sized,
    {
        let curve = Curve::from_pkcs8_pem(pem)?;
        match curve {
            Curve::Rsa => Ok(Self::from(RsaKey::from_pkcs8_pem(pem)?)),
            Curve::Ec(_) => Ok(Self::from(EcKey::from_pkcs8_pem(pem)?)),
            Curve::Okp(_) => Ok(Self::from(OkpKey::from_pkcs8_pem(pem)?)),
        }
    }
}

impl ToDerPemPkcs8 for Key {
    fn to_pkcs8_der(&self) -> crate::Result<Box<[u8]>> {
        match self {
            Self::Rsa(rsa_key) => rsa_key.to_pkcs8_der(),
            Self::Ec(ec_key) => ec_key.to_pkcs8_der(),
            Self::Okp(okp_key) => okp_key.to_pkcs8_der(),
        }
    }

    fn to_pkcs8_pem(&self, line_ending: LineEnding) -> crate::Result<Box<str>> {
        match self {
            Self::Rsa(rsa_key) => rsa_key.to_pkcs8_pem(line_ending),
            Self::Ec(ec_key) => ec_key.to_pkcs8_pem(line_ending),
            Self::Okp(okp_key) => okp_key.to_pkcs8_pem(line_ending),
        }
    }
}

impl Signer for Key {
    type Signature = Box<[u8]>;

    fn sign(&self, payload: &[u8]) -> Self::Signature {
        match self {
            Self::Rsa(key) => key.sign(payload),
            Self::Ec(key) => key.sign(payload),
            Self::Okp(key) => key.sign(payload),
        }
    }
}

impl From<RsaKey> for Key {
    fn from(value: RsaKey) -> Self {
        Self::Rsa(value)
    }
}

impl From<EcKey> for Key {
    fn from(value: EcKey) -> Self {
        Self::Ec(value)
    }
}

impl From<OkpKey> for Key {
    fn from(value: OkpKey) -> Self {
        Self::Okp(value)
    }
}

impl Key {
    /// # Errors
    ///
    /// See [``crate::Error::Crypto``]
    pub fn from_rsa_pkcs8_der_with_signing_algo(
        der: &[u8],
        signing_algo: RsaSigningAlgorithm,
    ) -> Result<Self> {
        Ok(Self::Rsa(RsaKey::from_pkcs8_der_with_signing_algo(
            der,
            signing_algo,
        )?))
    }

    /// # Errors
    ///
    /// See [``crate::Error::Crypto``]
    pub fn from_rsa_pkcs8_pem_with_signing_algo(
        pem: &str,
        signing_algo: RsaSigningAlgorithm,
    ) -> Result<Self> {
        Ok(Self::Rsa(RsaKey::from_pkcs8_pem_with_signing_algo(
            pem,
            signing_algo,
        )?))
    }

    /// # Errors
    ///
    /// See [``crate::Error::Crypto``]
    pub fn generate_csr(&self, domains: &[&str]) -> Result<CertificateSigningRequest> {
        let key_pem = self.to_pkcs8_pem(LineEnding::LF)?;
        let key_pair = KeyPair::from_pem(key_pem.as_ref())
            .map_err(|_| Error::Crypto("While generating csr, Cannot generate KeyPair."))?;

        // Build CSR params
        let mut params =
            CertificateParams::new(domains.iter().map(ToString::to_string).collect::<Vec<_>>())
                .map_err(|_| Error::Crypto("While generating csr, Failed to create cert params"))?;

        // Set distinguished name (required by most ACME providers)
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domains[0]);
        params.distinguished_name = dn;

        // Add SANs explicitly
        params.subject_alt_names = domains
            .iter()
            .map(|d| {
                d.to_string()
                    .try_into()
                    .map(SanType::DnsName)
                    .map_err(|_| Error::Crypto("While generating csr, Failed to set SanType"))
            })
            .collect::<Result<Vec<SanType>>>()?;

        // Generate the CSR
        params
            .serialize_request(&key_pair)
            .map_err(|_| Error::Crypto("While generating csr, Failed to generate CSR"))
    }
}

impl TryFrom<&VersionedKeyDto> for Key {
    type Error = Error;

    fn try_from(value: &VersionedKeyDto) -> Result<Self> {
        if value.version() != 1 {
            return Err(Error::Str("Unsupported KeyDto version"));
        }

        match &value.key {
            KeyDto::Rsa {
                signing_algo,
                pkcs8_pem,
                ..
            } => Ok(Self::from(RsaKey::from_pkcs8_pem_with_signing_algo(
                pkcs8_pem,
                *signing_algo,
            )?)),
            KeyDto::Ec { pkcs8_pem, .. } => Ok(Self::from(EcKey::from_pkcs8_pem(pkcs8_pem)?)),

            KeyDto::Okp { pkcs8_pem, .. } => Ok(Self::from(OkpKey::from_pkcs8_pem(pkcs8_pem)?)),
        }
    }
}

impl TryFrom<VersionedKeyDto> for Key {
    type Error = Error;

    fn try_from(value: VersionedKeyDto) -> Result<Self> {
        Self::try_from(&value)
    }
}
