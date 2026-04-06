#![allow(dead_code)]

mod kid;

pub use kid::Kid;

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{Id, PKey, Private},
    rsa::Rsa,
};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct as _};
use url::Url;

use crate::{Error, Result, b64};

#[derive(
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
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

#[derive(
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
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

#[derive(
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
#[serde(rename_all = "UPPERCASE")]
pub enum OkpSigningAlgorithm {
    // /// TODO: See [RFC 8037 §3.1](https://datatracker.ietf.org/doc/html/rfc8037#section-3.1)
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

/// JWS Signning alogrithm
///
/// See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515),
/// [RFC 7518 §3.1](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1)
#[derive(
    Debug,
    Copy,
    Clone,
    Serialize,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
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

// impl From<Rsa<Public>> for Jwk {
//     fn from(value: Rsa<Public>) -> Self {
//         let modulus = Box::from(b64::b64u_encode(value.n().to_vec()));
//         let exponent = Box::from(b64::b64u_encode(value.e().to_vec()));
//         let key_type = KeyType::Rsa;

//         let jwk = format!(r#"{{"e":"{exponent}","kty":"{key_type}","n":"{modulus}"}}"#);

//         #[cfg(debug_assertions)]
//         #[allow(clippy::expect_used)]
//         {
//             assert_eq!(
//                 jwk,
//                 serde_json::to_string(&serde_json::json!({
//                     "e":exponent,
//                     "kty":key_type,
//                     "n":modulus
//                 }))
//                 .expect("should never fail")
//             );
//         }

//         let hash = Sha256::digest(jwk).to_vec();
//         let thumbprint = Box::from(b64::b64u_encode(hash));

//         Self {
//             exponent,
//             key_type,
//             modulus,
//             thumbprint,
//         }
//     }
// }

/// TODO: Document
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[non_exhaustive]
pub enum EcCurve {
    #[serde(rename = "P-256")]
    #[default]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
}

/// TODO: Document
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[non_exhaustive]
pub enum OkpCurve {
    #[serde(rename = "Ed25519")]
    #[default]
    Ed25519,
}

impl From<EcCurve> for Nid {
    /// `Nid::X9_62_PRIME256V1` -> `P256`
    /// `Nid::SECP384R1` -> `P384`
    /// `Nid::SECP521R1` -> `P521`
    fn from(value: EcCurve) -> Self {
        match value {
            EcCurve::P256 => Self::X9_62_PRIME256V1,
            EcCurve::P384 => Self::SECP384R1,
            EcCurve::P521 => Self::SECP521R1,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RsaKeyBits {
    Bits2048,
    #[default]
    Bits4096,
}

impl RsaKeyBits {
    pub const fn as_usize(self) -> usize {
        match self {
            Self::Bits2048 => 2048,
            Self::Bits4096 => 4096,
        }
    }

    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Bits2048 => 2048,
            Self::Bits4096 => 4096,
        }
    }
}

/// TODO: Document
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Key {
    Rsa {
        signing_algo: RsaSigningAlgorithm,
        bits: RsaKeyBits,
        key: Rsa<Private>,
    },

    /// TODO: Document
    Ec {
        crv: EcCurve,
        key: EcKey<Private>,
    },
    Okp {
        crv: OkpCurve,
        key: PKey<Private>,
    },
}

impl Key {
    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn new_rsa(bits: RsaKeyBits, signing_algo: RsaSigningAlgorithm) -> Result<Self> {
        let key = Rsa::generate(bits.as_u32())
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        Ok(Self::Rsa {
            bits,
            signing_algo,
            key,
        })
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn new_rsa_from_parts(
        key: Rsa<Private>,
        signing_algo: RsaSigningAlgorithm,
    ) -> Result<Self> {
        let bits = key.n().num_bits();

        let bits = match bits {
            2048 => RsaKeyBits::Bits2048,
            4096 => RsaKeyBits::Bits4096,
            b => {
                return Err(Error::Unimplemented(
                    format!("Unknown number of rsa bits: {b}").into(),
                ));
            }
        };

        Ok(Self::Rsa {
            bits,
            signing_algo,
            key,
        })
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn new_ec(curve: EcCurve) -> Result<Self> {
        let group = EcGroup::from_curve_name(curve.into())
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        let ec_key =
            EcKey::generate(&group).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        Ok(Self::Ec {
            crv: curve,
            key: ec_key,
        })
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn new_ec_from_parts(key: EcKey<Private>) -> Result<Self> {
        let crv = detect_ec_curve(&key)?;
        Ok(Self::Ec { crv, key })
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn new_okp() -> Result<Self> {
        let pkey =
            PKey::generate_ed25519().map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        Ok(Self::Okp {
            key: pkey,
            crv: OkpCurve::Ed25519,
        })
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn new_okp_from_pem(pem: &[u8]) -> Result<Self> {
        let pkey = PKey::private_key_from_pem(pem)
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        println!("{:#?}", pkey.id());

        if pkey.id() != Id::ED25519 {
            return Err(Error::Unimplemented(Box::from("Not an ED25519 key")));
        }

        Ok(Self::Okp {
            key: pkey,
            crv: OkpCurve::Ed25519,
        })
    }
    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn new_okp_from_der(der: &[u8]) -> Result<Self> {
        let pkey = PKey::private_key_from_der(der)
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        if pkey.id() != Id::ED25519 {
            return Err(Error::Unimplemented(Box::from("Not an ED25519 key")));
        }

        Ok(Self::Okp {
            key: pkey,
            crv: OkpCurve::Ed25519,
        })
    }

    pub fn to_pem(&self) -> Result<Vec<u8>> {
        let pem = match self {
            Self::Rsa { key, .. } => key
                .private_key_to_pem()
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?,
            Self::Ec { key, .. } => key
                .private_key_to_pem()
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?,
            Self::Okp { key, .. } => key
                .private_key_to_pem_pkcs8()
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?,
        };

        Ok(pem)
    }

    #[cfg(debug_assertions)]
    pub fn to_pem_2(&self) -> Result<(String, String)> {
        let pkey = match self {
            Self::Rsa { key, .. } => PKey::from_rsa(key.to_owned())
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?,
            Self::Ec { key, .. } => PKey::from_ec_key(key.to_owned())
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?,
            Self::Okp { key, .. } => key.to_owned(),
        };

        let private_pem = pkey
            .private_key_to_pem_pkcs8()
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
        let public_pem = pkey
            .public_key_to_pem()
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        let private_key = String::from_utf8(private_pem)
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
        let public_key = String::from_utf8(public_pem)
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        // println!("Private Key:\n{private_key}\n\nPublic Key:\n{public_key}");
        Ok((private_key, public_key))
    }

    fn save_key_to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let der = match self {
            Self::Rsa { key, .. } => key
                .private_key_to_der()
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?,
            Self::Ec { key, .. } => key
                .private_key_to_der()
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?,
            Self::Okp { key, .. } => key
                .private_key_to_der()
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?,
        };

        Ok(der)
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        todo!()
    }
}

/// # Example
///
/// ```json
/// {
///   "kty": "RSA",
///   "n": "<modulus>",
///   "e": "<exponent>"
/// }
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(tag = "kty")]
pub enum Jwk {
    Rsa {
        /// Public key exponent base64 url encoded no pad
        #[serde(rename = "e")]
        exponent: Box<str>,

        /// Public key modulus base64 url encoded no pad
        #[serde(rename = "n")]
        modulus: Box<str>,
    },

    /// TODO: Document
    Ec {
        crv: EcCurve,
        x: Box<str>,
        y: Box<str>,
    },
    Okp {
        crv: OkpCurve, // Only possible Value "Ed25519",

        /// Public key bytes base64 url encoded no pad
        #[serde(rename = "x")]
        public_key: Box<str>,
    },
}

impl Jwk {
    /// jwk -> to json -> sha256 hash -> base64url
    ///
    /// See: [RFC 7638 §7.3](https://datatracker.ietf.org/doc/html/rfc7638), [RFC 8555 §8.1](https://datatracker.ietf.org/doc/html/rfc8555#section-8.1)
    #[allow(clippy::unnecessary_literal_bound, clippy::unused_self)]
    pub fn thumbprint(&self) -> Box<str> {
        use openssl::sha::sha256;

        let jwk_thumbprint_input = match self {
            Self::Rsa { exponent, modulus } => {
                format!(r#"{{"e":"{exponent}","kty":"RSA","n":"{modulus}"}}"#)
            }

            Self::Ec { crv, x, y } => {
                format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }

            Self::Okp { crv, public_key } => {
                format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{public_key}"}}"#)
            }
        };

        let digest = sha256(jwk_thumbprint_input.as_bytes());

        b64::b64u_encode(digest).into_boxed_str()
    }
}

impl TryFrom<&Key> for Jwk {
    type Error = Error;

    fn try_from(value: &Key) -> Result<Self> {
        match value {
            Key::Rsa { key, .. } => {
                let n = key.n(); // modulus
                let e = key.e(); // exponent

                let modulus = Box::from(b64::b64u_encode(n.to_vec()));
                let exponent = Box::from(b64::b64u_encode(e.to_vec()));

                // // TODO:
                // let jwk = format!(r#"{{"e":"{exponent}","kty":"RSA","n":"{modulus}"}}"#);

                // #[cfg(debug_assertions)]
                // #[allow(clippy::expect_used)]
                // {
                //     assert_eq!(
                //         jwk,
                //         serde_json::to_string(&serde_json::json!({
                //             "e":exponent,
                //             "kty":key_type,
                //             "n":modulus
                //         }))
                //         .expect("should never fail")
                //     );
                // }

                // TODO: should is use signing algorithm here?
                // let hash = Sha256::digest(jwk).to_vec();
                // let thumbprint = Box::from(b64::b64u_encode(hash));

                Ok(Self::Rsa { exponent, modulus })
            }
            Key::Ec { crv, key } => {
                let group = key.group();
                let point = key.public_key();

                let mut ctx = BigNumContext::new()
                    .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
                let mut x =
                    BigNum::new().map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
                let mut y =
                    BigNum::new().map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

                point
                    .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
                    .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

                let x = Box::from(b64::b64u_encode(x.to_vec()));
                let y = Box::from(b64::b64u_encode(y.to_vec()));

                Ok(Self::Ec { crv: *crv, x, y })
            }
            Key::Okp { key, crv } => {
                let pub_bytes = key
                    .raw_public_key()
                    .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

                let public_key = Box::from(b64::b64u_encode(pub_bytes));

                Ok(Self::Okp {
                    crv: *crv,
                    public_key,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JwkOrKid<'a> {
    /// jwk is used before acme account creation
    Jwk(Jwk),
    /// kid is used after acme account creation
    Kid(&'a Kid),
}

/// | JWK Type      | ``SigningAlgorithm``        |
/// | ------------- | --------------------------- |
/// | RSA           | `RS256` / `RS384` / `RS512` |
/// | EC (P-256)    | `ES256`                     |
/// | EC (P-384)    | `ES384`                     |
/// | EC (P-521)    | `ES512`                     |
/// | OKP (Ed25519) | `EdDSA`                     |
///
/// # Example
///
/// ```json
/// {
///   "alg": "ES256",
///   "nonce": "...",
///   "url": "...",
///   "jwk": { ... }  // OR "kid": "account-url"
/// }
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct JwsProtectedHeaders<'a> {
    /// For key rollover inner [``JwsProtectedHeaders``] does not have nonce,
    pub nonce: Option<&'a str>,

    pub url: &'a Url,
    #[serde(rename = "alg")]
    pub signing_algorithm: SigningAlgorithm,
    #[serde(flatten)]
    pub auth: JwkOrKid<'a>,
}

impl<'a> JwsProtectedHeaders<'a> {
    pub fn new(key: &'a Key, url: &'a Url, auth: JwkOrKid<'a>, nonce: Option<&'a str>) -> Self {
        let signing_algorithm: SigningAlgorithm = match key {
            Key::Rsa { signing_algo, .. } => SigningAlgorithm::from(*signing_algo),
            Key::Ec { crv, .. } => SigningAlgorithm::from(EcSigningAlgorithm::from(*crv)),
            Key::Okp { crv, .. } => SigningAlgorithm::from(OkpSigningAlgorithm::from(*crv)),
        };

        Self {
            nonce,
            url,
            signing_algorithm,
            auth,
        }
    }
}

/// Signature calculated at serializaion time
///
/// # Example
///
/// ```json
/// {
///   "protected": "<base64url>",
///   "payload": "<base64url>",
///   "signature": "<base64url>"
/// }
/// ```
///
/// See: [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
#[derive(Debug, Clone)]
pub struct Jws<'a, T: Serialize> {
    /// Require to create signature (`{protected_b64}.{payload_b64}`)
    key: &'a Key,

    protected: JwsProtectedHeaders<'a>,
    payload: T,
}

impl<'a, T: Serialize> Jws<'a, T> {
    pub const fn new(key: &'a Key, jws_protected_header: JwsProtectedHeaders<'a>, body: T) -> Self {
        Self {
            key,
            protected: jws_protected_header,
            payload: body,
        }
    }
}

impl<T> Serialize for Jws<'_, T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // serialize protected
        let protected_json =
            serde_json::to_vec(&self.protected).map_err(serde::ser::Error::custom)?;
        let protected_b64 = b64::b64u_encode(protected_json);

        // IMPORTANT: Serialize EmptyString as ""
        let payload_json = serde_json::to_vec(&self.payload).map_err(serde::ser::Error::custom)?;
        let payload_b64 = b64::b64u_encode(payload_json);

        // signing input
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let signing_input_bytes = signing_input.as_bytes();

        // sign
        let signature = sign(self.key, signing_input_bytes).map_err(serde::ser::Error::custom)?;

        let signature_b64 = b64::b64u_encode(signature);

        let mut state = serializer.serialize_struct("Jws", 3)?;
        state.serialize_field("protected", &protected_b64)?;
        state.serialize_field("payload", &payload_b64)?;
        state.serialize_field("signature", &signature_b64)?;
        state.end()
    }
}

fn ecdsa_der_to_raw(der: &[u8], crv: EcCurve) -> Result<Vec<u8>> {
    use openssl::ecdsa::EcdsaSig;

    let sig =
        EcdsaSig::from_der(der).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

    let size = match crv {
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
        EcCurve::P521 => 66,
    };

    let mut r = sig.r().to_vec();
    let mut s = sig.s().to_vec();

    // left-pad with zeros
    if r.len() < size {
        r = [vec![0; size - r.len()], r].concat();
    }
    if s.len() < size {
        s = [vec![0; size - s.len()], s].concat();
    }

    Ok([r, s].concat())
}

fn detect_ec_curve(key: &EcKey<openssl::pkey::Private>) -> Result<EcCurve> {
    let group = key.group();
    let nid = group
        .curve_name()
        .ok_or(Error::Unimplemented(Box::from(String::from(
            "UnknownCurve",
        ))))
        .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

    match nid {
        Nid::X9_62_PRIME256V1 => Ok(EcCurve::P256),
        Nid::SECP384R1 => Ok(EcCurve::P384),
        Nid::SECP521R1 => Ok(EcCurve::P521),

        _ => Err(Error::Unimplemented(Box::from(format!(
            "UnsupportedCurve: {nid:?}"
        )))),
    }
}

fn sign(key: &Key, msg: &[u8]) -> Result<Vec<u8>> {
    match key {
        Key::Rsa {
            signing_algo, key, ..
        } => {
            use openssl::hash::MessageDigest;
            use openssl::sign::Signer;

            let md = match signing_algo {
                RsaSigningAlgorithm::Rs256 => MessageDigest::sha256(),
                RsaSigningAlgorithm::Rs384 => MessageDigest::sha384(),
                RsaSigningAlgorithm::Rs512 => MessageDigest::sha512(),
            };

            // Optimise:
            let keypair = PKey::from_rsa(key.clone())
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

            let mut signer = Signer::new(md, &keypair)
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

            signer
                .update(msg)
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

            Ok(signer
                .sign_to_vec()
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?)
        }

        Key::Ec { crv, key } => {
            use openssl::hash::MessageDigest;
            use openssl::sign::Signer;

            let md = match crv {
                EcCurve::P256 => MessageDigest::sha256(),
                EcCurve::P384 => MessageDigest::sha384(),
                EcCurve::P521 => MessageDigest::sha512(),
            };

            // Optimise:
            let keypair = PKey::from_ec_key(key.clone())
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

            let mut signer = Signer::new(md, &keypair)
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

            signer
                .update(msg)
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

            let der_sig = signer
                .sign_to_vec()
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

            // IMPORTANT: convert DER → raw (r || s)
            Ok(ecdsa_der_to_raw(&der_sig, *crv)
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?)
        }

        Key::Okp { key, .. } => {
            use openssl::sign::Signer;

            let mut signer = Signer::new_without_digest(key)
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

            let signature = signer
                .sign_oneshot_to_vec(msg)
                .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

            Ok(signature)
        }
    }
}

// region:    --- Tests
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    use std::sync::OnceLock;

    pub type Result<T> = std::result::Result<T, Error>;
    pub type Error = Box<dyn std::error::Error>; // For tests.

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(rename_all = "UPPERCASE")]
    enum KeyFixtureType {
        #[serde(rename_all = "camelCase")]
        Rsa {
            bits: RsaKeyBits,
            signing_algo: RsaSigningAlgorithm,
            exponent: Box<str>,
            modulus: Box<str>,
        },
        #[serde(rename_all = "camelCase")]
        Ec {
            curve: EcCurve,
            signing_algo: EcSigningAlgorithm,
            x: Box<str>,
            y: Box<str>,
        },
        #[serde(rename_all = "camelCase")]
        Okp {
            curve: OkpCurve,
            signing_algo: OkpSigningAlgorithm,
            x: Box<str>,
        },
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KeyFixture {
        #[serde(flatten)]
        typ: KeyFixtureType,
        private_key_pem: String,
        public_key_pem: String,
        jwk: Box<str>,
        jwk_thumbprint: Box<str>,
        url: Url,
        nonce: Box<str>,
        body: Box<str>,
        jws_protected_header: Box<str>,
        jws: Box<str>,
    }

    enum GenFixtureKey {
        Rsa(RsaKeyBits, RsaSigningAlgorithm),
        Ec(EcCurve),
        Okp,
    }

    #[allow(clippy::needless_pass_by_value)]
    fn gen_key_fixture(typ: GenFixtureKey) -> KeyFixture {
        let (key, fixture_key_type) = match typ {
            GenFixtureKey::Rsa(bits, signing_algo) => {
                let key = Key::new_rsa(bits, signing_algo).unwrap();
                let jwk = Jwk::try_from(&key).unwrap();

                let Jwk::Rsa { exponent, modulus } = jwk else {
                    panic!()
                };

                (
                    key,
                    KeyFixtureType::Rsa {
                        bits,
                        signing_algo,
                        exponent,
                        modulus,
                    },
                )
            }
            GenFixtureKey::Ec(curve) => {
                let key = Key::new_ec(curve).unwrap();
                let jwk = Jwk::try_from(&key).unwrap();

                let Jwk::Ec { crv, x, y } = jwk else { panic!() };

                let signing_algo = curve.into();

                (
                    key,
                    KeyFixtureType::Ec {
                        curve: crv,
                        signing_algo,
                        x,
                        y,
                    },
                )
            }
            GenFixtureKey::Okp => {
                let key = Key::new_okp().unwrap();
                let jwk = Jwk::try_from(&key).unwrap();

                let Jwk::Okp { crv, public_key } = jwk else {
                    panic!()
                };

                let signing_algo = crv.into();

                (
                    key,
                    KeyFixtureType::Okp {
                        curve: crv,
                        signing_algo,
                        x: public_key,
                    },
                )
            }
        };

        let (private_key_pem, public_key_pem) = key.to_pem_2().unwrap();
        let jwk = Jwk::try_from(&key).unwrap();
        let jwk_thumbprint = jwk.thumbprint();
        let jwk_json = serde_json::to_string(&jwk).unwrap().into_boxed_str();
        let url = Url::parse("https://example.com").unwrap();
        let auth = JwkOrKid::Jwk(jwk);
        let nonce = Box::from("test-nonce");
        let body = Box::from("test-body");
        let jws_protected_header = JwsProtectedHeaders::new(&key, &url, auth, Some(&nonce));
        let jws_protected_header_json =
            serde_json::to_string(&jws_protected_header).unwrap().into_boxed_str();
        let jws = Jws::new(&key, jws_protected_header, &body);
        let jws_str = serde_json::to_string(&jws).unwrap().into_boxed_str();

        KeyFixture {
            typ: fixture_key_type,
            private_key_pem,
            public_key_pem,
            jwk: jwk_json,
            jwk_thumbprint,
            url,
            nonce,
            body,
            jws_protected_header: jws_protected_header_json,
            jws: jws_str,
        }
    }

    fn gen_all_fixtures() {
        let key_fixtures = [
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits2048,
                RsaSigningAlgorithm::Rs256,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits2048,
                RsaSigningAlgorithm::Rs384,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits2048,
                RsaSigningAlgorithm::Rs512,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits4096,
                RsaSigningAlgorithm::Rs256,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits4096,
                RsaSigningAlgorithm::Rs384,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits4096,
                RsaSigningAlgorithm::Rs512,
            )),
            gen_key_fixture(GenFixtureKey::Ec(EcCurve::P256)),
            gen_key_fixture(GenFixtureKey::Ec(EcCurve::P384)),
            gen_key_fixture(GenFixtureKey::Ec(EcCurve::P521)),
            gen_key_fixture(GenFixtureKey::Okp),
        ];

        for (index, fixture) in key_fixtures.iter().enumerate().map(|(v, w)| (v + 1, w)) {
            let s = toml::to_string_pretty(&fixture).unwrap();
            // println!("{s}");
            std::fs::write(format!("tests/FIXTURE_KEY_{index:0>2}.toml"), s).unwrap();
        }
    }

    fn setup() -> &'static [KeyFixture] {
        static INSTANCE: OnceLock<Box<[KeyFixture]>> = OnceLock::new();
        use glob::glob;

        INSTANCE.get_or_init(|| {
            let should_gen_fixtures = std::env::var("GEN_FIXTURE_KEY").is_ok();

            if should_gen_fixtures {
                gen_all_fixtures();
            }

            let fixtures = glob("./tests/FIXTURE_KEY*")
                .unwrap()
                .map(|entry| {
                    let file_content = std::fs::read(entry.unwrap()).unwrap();
                    let fixture: KeyFixture = toml::from_slice(&file_content).unwrap();
                    fixture
                })
                .collect::<Vec<KeyFixture>>();

            Box::from(fixtures)
        })
    }

    #[test]
    fn rsa() {
        let fixtures = setup().iter().filter(|v| {
            let KeyFixtureType::Rsa { .. } = v.typ else {
                return false;
            };
            true
        });

        for fixture in fixtures {
            let KeyFixtureType::Rsa {
                bits,
                signing_algo,
                exponent: fixture_exponent,
                modulus: fixture_modulus,
            } = &fixture.typ
            else {
                panic!()
            };

            let rsa_private_key =
                Rsa::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();
            assert_eq!(
                bits.as_u32(),
                rsa_private_key.n().num_bits().cast_unsigned()
            );

            let key = Key::new_rsa_from_parts(rsa_private_key, *signing_algo).unwrap();

            let jwk = Jwk::try_from(&key).unwrap();
            let jwk_json = serde_json::to_string(&jwk).unwrap().into_boxed_str();

            assert_eq!(fixture.jwk, jwk_json, "Rsa Jwk Serialized are not equal");

            let Jwk::Rsa { exponent, modulus } = jwk else {
                panic!("Jwk not of type Rsa")
            };

            assert_eq!(fixture_modulus, &modulus);
            assert_eq!(fixture_exponent, &exponent);
        }
    }

    #[test]
    fn ec() {
        let fixtures = setup().iter().filter(|v| {
            let KeyFixtureType::Ec { .. } = v.typ else {
                return false;
            };
            true
        });

        for fixture in fixtures {
            let KeyFixtureType::Ec {
                curve: fixture_curve,
                signing_algo: fixture_signing_algo,
                x: fixture_x,
                y: fixture_y,
            } = &fixture.typ
            else {
                panic!()
            };

            let ec_private_key =
                EcKey::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();
            let curve = detect_ec_curve(&ec_private_key).unwrap();
            assert_eq!(*fixture_curve, curve);

            let key = Key::new_ec_from_parts(ec_private_key).unwrap();

            let jwk = Jwk::try_from(&key).unwrap();
            let jwk_json = serde_json::to_string(&jwk).unwrap().into_boxed_str();

            assert_eq!(fixture.jwk, jwk_json, "Ec Jwk Serialized are not equal");

            let Jwk::Ec { crv, x, y } = jwk else {
                panic!("Jwk not of type Ec")
            };

            let signing_algo = EcSigningAlgorithm::from(crv);

            assert_eq!(*fixture_signing_algo, signing_algo);
            assert_eq!(fixture_x, &x);
            assert_eq!(fixture_y, &y);
        }
    }

    #[test]
    fn okp() {
        let fixtures = setup().iter().filter(|v| {
            let KeyFixtureType::Okp { .. } = v.typ else {
                return false;
            };
            true
        });

        for fixture in fixtures {
            let KeyFixtureType::Okp {
                curve: fixture_curve,
                signing_algo: fixture_signing_algo,
                x: fixture_x,
            } = &fixture.typ
            else {
                panic!()
            };

            let key = Key::new_okp_from_pem(fixture.private_key_pem.as_bytes()).unwrap();

            let jwk = Jwk::try_from(&key).unwrap();
            let jwk_json = serde_json::to_string(&jwk).unwrap().into_boxed_str();

            assert_eq!(fixture.jwk, jwk_json, "Okp Jwk Serialized are not equal");

            let Jwk::Okp { crv, public_key: x } = jwk else {
                panic!("Jwk not of type Okp")
            };

            let signing_algo = OkpSigningAlgorithm::from(crv);

            assert_eq!(*fixture_curve, crv);
            assert_eq!(*fixture_signing_algo, signing_algo);
            assert_eq!(fixture_x, &x);
        }
    }

    #[test]
    fn jws_rsa() {
        let fixtures = setup().iter().filter(|v| {
            let KeyFixtureType::Rsa { .. } = v.typ else {
                return false;
            };
            true
        });

        for fixture in fixtures {
            let KeyFixtureType::Rsa { signing_algo, .. } = &fixture.typ else {
                panic!()
            };

            let rsa_private_key =
                Rsa::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();

            let key = Key::new_rsa_from_parts(rsa_private_key, *signing_algo).unwrap();

            let jwk = Jwk::try_from(&key).unwrap();
            let url = &fixture.url;
            let auth = JwkOrKid::Jwk(jwk);
            let nonce = fixture.nonce.as_ref();
            let body = fixture.body.as_ref();

            let jws_protected_header = JwsProtectedHeaders::new(&key, url, auth, Some(nonce));
            let jws_protected_header_json =
                serde_json::to_string(&jws_protected_header).unwrap().into_boxed_str();

            assert_eq!(
                fixture.jws_protected_header, jws_protected_header_json,
                "Rsa Jws Protected Header Serialized are not equal"
            );

            let jws = Jws::new(&key, jws_protected_header, body);
            let jws_json = serde_json::to_string(&jws).unwrap().into_boxed_str();

            assert_eq!(fixture.jws, jws_json, "Rsa Jws Serialized are not equal");
        }
    }

    #[test]
    fn jwk_thumbprint() {
        let fixtures = setup();

        for fixture in fixtures {
            let key = match &fixture.typ {
                KeyFixtureType::Rsa { signing_algo, .. } => {
                    let rsa_private_key =
                        Rsa::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();

                    Key::new_rsa_from_parts(rsa_private_key, *signing_algo).unwrap()
                }
                KeyFixtureType::Ec { .. } => {
                    let ec_private_key =
                        EcKey::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();
                    Key::new_ec_from_parts(ec_private_key).unwrap()
                }
                KeyFixtureType::Okp { .. } => {
                    Key::new_okp_from_pem(fixture.private_key_pem.as_bytes()).unwrap()
                }
            };

            let jwk = Jwk::try_from(&key).unwrap();
            assert_eq!(fixture.jwk_thumbprint, jwk.thumbprint());
        }
    }
}
// endregion: --- Tests
