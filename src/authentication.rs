use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    sign::Signer,
};
use serde::{Deserialize, Serialize, Serializer, de, ser::SerializeStruct as _};
use sha2::{Digest as _, Sha256};
use std::{fmt, str::FromStr};
use url::Url;

use crate::{Error, Result, b64};

pub fn rsa_private_to_rsa_public(
    private_key: &Rsa<Private>,
) -> std::result::Result<Rsa<Public>, openssl::error::ErrorStack> {
    let public_key_pem = private_key.public_key_to_pem()?;

    Rsa::public_key_from_pem(&public_key_pem)
}

/// Signature calculated at serializaion time
///
/// See: [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
#[derive(Debug, Clone)]
pub struct Jws<'a, T: Serialize> {
    /// Require to create signature (`{protected_b64}.{payload_b64}`)
    private_key: &'a PrivateKey,

    protected: JwsProtectedHeaders<'a>,
    payload: T,
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

        // serialize payload
        let payload_json = serde_json::to_vec(&self.payload).map_err(serde::ser::Error::custom)?;

        // IMPORTANT: Serialize EmptyString as ""
        let payload_b64 = if payload_json == [b'"', b'"'] {
            String::new()
        } else {
            b64::b64u_encode(payload_json)
        };

        // signing input
        let signing_input = format!("{protected_b64}.{payload_b64}");

        // sign
        let keypair = PKey::from_rsa(self.private_key.rsa_key().clone())
            .map_err(|e| serde::ser::Error::custom(e.to_string()))?;

        let mut signer = Signer::new(MessageDigest::sha256(), &keypair)
            .map_err(|e| serde::ser::Error::custom(e.to_string()))?;

        signer
            .update(signing_input.as_bytes())
            .map_err(|e| serde::ser::Error::custom(e.to_string()))?;

        let signature = signer
            .sign_to_vec()
            .map_err(|e| serde::ser::Error::custom(e.to_string()))?;

        let signature_b64 = b64::b64u_encode(signature);

        let mut state = serializer.serialize_struct("Jws", 3)?;
        state.serialize_field("protected", &protected_b64)?;
        state.serialize_field("payload", &payload_b64)?;
        state.serialize_field("signature", &signature_b64)?;
        state.end()
    }
}

impl<'a, T> Jws<'a, T>
where
    T: Serialize,
{
    pub const fn new(
        private_key: &'a PrivateKey,
        jws_protected_headers: JwsProtectedHeaders<'a>,
        body: T,
    ) -> Self {
        Self {
            private_key,
            protected: jws_protected_headers,
            payload: body,
        }
    }

    pub const fn new_from_parts(
        private_key: &'a PrivateKey,
        url: &'a Url,
        auth: JwkOrKid<'a>,
        nonce: Option<&'a str>,
        body: T,
    ) -> Self {
        let jws_protected_headers = JwsProtectedHeaders {
            algorithm: JwsAlgorithm::RS256,
            url,
            auth,
            nonce,
        };

        Self::new(private_key, jws_protected_headers, body)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JwsProtectedHeaders<'a> {
    #[serde(rename = "alg")]
    pub algorithm: JwsAlgorithm,
    pub url: &'a Url,
    #[serde(flatten)]
    pub auth: JwkOrKid<'a>,

    /// For key rollover inner `JwsProtectedHeaders` does not have nonce,
    pub nonce: Option<&'a str>,
}

#[derive(
    Debug,
    Copy,
    Clone,
    Serialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
pub enum JwsAlgorithm {
    #[default]
    #[serde(rename = "RS256")]
    #[strum(serialize = "RS256")]
    RS256,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JwkOrKid<'a> {
    /// jwk is used before acme account creation
    Jwk(Jwk),
    /// kid is used after acme account creation
    Kid(&'a Kid),
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    /// Public key exponent base64 url encoded no pad
    #[serde(rename = "e")]
    pub(crate) exponent: Box<str>,
    /// Key type
    #[serde(rename = "kty")]
    pub(crate) key_type: KeyType,
    /// Public key modulus base64 url encoded no pad
    #[serde(rename = "n")]
    pub(crate) modulus: Box<str>,

    /// jwk -> to json -> sha256 hash -> base64url
    ///
    /// See: [RFC 7638 §7.3](https://datatracker.ietf.org/doc/html/rfc7638), [RFC 8555 §8.1](https://datatracker.ietf.org/doc/html/rfc8555#section-8.1)
    #[serde(skip_serializing)]
    thumbprint: Box<str>,
}

impl Jwk {
    /// jwk -> to json -> sha256 hash -> base64url
    ///
    /// See: [RFC 7638 §7.3](https://datatracker.ietf.org/doc/html/rfc7638), [RFC 8555 §8.1](https://datatracker.ietf.org/doc/html/rfc8555#section-8.1)
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }
}

impl From<Rsa<Public>> for Jwk {
    fn from(value: Rsa<Public>) -> Self {
        let modulus = Box::from(b64::b64u_encode(value.n().to_vec()));
        let exponent = Box::from(b64::b64u_encode(value.e().to_vec()));
        let key_type = KeyType::Rsa;

        let jwk = format!(r#"{{"e":"{exponent}","kty":"{key_type}","n":"{modulus}"}}"#);

        #[cfg(debug_assertions)]
        #[allow(clippy::expect_used)]
        {
            assert_eq!(
                jwk,
                serde_json::to_string(&serde_json::json!({
                    "e":exponent,
                    "kty":key_type,
                    "n":modulus
                }))
                .expect("should never fail")
            );
        }

        let hash = Sha256::digest(jwk).to_vec();
        let thumbprint = Box::from(b64::b64u_encode(hash));

        Self {
            exponent,
            key_type,
            modulus,
            thumbprint,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrivateKey(Rsa<Private>);

impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let pem = self.to_pkcs8_der_base64().map_err(serde::ser::Error::custom)?;

        serializer.serialize_str(&pem)
    }
}

impl<'de> serde::de::Deserialize<'de> for PrivateKey {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let private_key = String::deserialize(deserializer)?; // base64url PKCS#8 DER

        let private_key = Self::from_pkcs8_der_base64(&private_key).map_err(de::Error::custom)?;

        Ok(private_key)
    }
}

impl PrivateKey {
    #[must_use]
    pub const fn rsa_key(&self) -> &Rsa<Private> {
        &self.0
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn new() -> Result<Self> {
        // TODO: could this be created without throwing error?
        let private_key =
            Rsa::generate(4096).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
        Ok(Self(private_key))
    }

    /// Export as PKCS#1 DER (RSA-specific)
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>> {
        self.0
            .private_key_to_der()
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))
    }

    /// Export as PKCS#8 DER
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let pkey = PKey::from_rsa(self.0.clone())
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        pkey.private_key_to_der()
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))
    }

    /// Export as PKCS#8 DER Base64 encoded
    ///
    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn to_pkcs8_der_base64(&self) -> Result<String> {
        Ok(b64::b64u_encode(self.to_pkcs8_der()?))
    }

    /// # Errors
    ///
    /// TODO: Write error docs
    pub fn from_pkcs8_der_base64(value: &str) -> Result<Self> {
        // Decode base64 → DER bytes
        let der =
            b64::b64u_decode(value).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        // Parse PKCS#8 → PKey → RSA
        let pkey = PKey::private_key_from_der(&der)
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

        let rsa = pkey
            .rsa()
            .map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;
        Ok(Self(rsa))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[must_use]
pub struct Kid(Url);

impl Kid {
    #[must_use = "Kid is must use"]
    pub const fn new(url: Url) -> Self {
        Self(url)
    }

    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> Url {
        self.0
    }
}

impl std::ops::Deref for Kid {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Url> for Kid {
    fn as_ref(&self) -> &Url {
        &self.0
    }
}

impl std::borrow::Borrow<Url> for Kid {
    fn borrow(&self) -> &Url {
        &self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Url> for Kid {
    fn from(url: Url) -> Self {
        Self(url)
    }
}

impl From<Kid> for Url {
    fn from(id: Kid) -> Self {
        id.0
    }
}

impl std::str::FromStr for Kid {
    type Err = url::ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(Url::parse(s)?))
    }
}

impl TryFrom<&str> for Kid {
    type Error = url::ParseError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Ok(Self(Url::parse(value)?))
    }
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum KeyType {
    #[default]
    #[serde(rename = "RSA")]
    #[strum(serialize = "RSA")]
    Rsa,
}

impl From<String> for KeyType {
    fn from(value: String) -> Self {
        Self::from_str(&value).unwrap_or_default()
    }
}
