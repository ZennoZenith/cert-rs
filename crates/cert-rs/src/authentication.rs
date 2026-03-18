use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    sign::Signer,
};
use serde::{Serialize, Serializer, ser::SerializeStruct as _};
use sha2::{Digest as _, Sha256};
use std::{ops::Deref, str::FromStr};
use url::Url;

use crate::{account::AccountId, api::AcmeApiBody, b64};

/// # Errors
///
/// TODO: Write error docs
pub fn rsa_private_to_rsa_public(
    private_key: &Rsa<Private>,
) -> std::result::Result<Rsa<Public>, openssl::error::ErrorStack> {
    let public_key_pem = private_key.public_key_to_pem()?;

    Rsa::public_key_from_pem(&public_key_pem)
}

#[derive(Debug, Serialize)]
pub struct Base64uEncoded<T>(T);

#[derive(Debug)]
pub struct Jws<'a, T: Serialize + Clone> {
    /// TODO: Require to create signature (`{protected_b64}.{payload_b64}`)
    private_key: Rsa<Private>,
    protected: Base64uEncoded<JwsProtectedHeaders<'a>>,
    payload: Base64uEncoded<AcmeApiBody<T>>,
    // TODO: Document signature format
    // signature: calculated at serializaion time,
}

impl<T> Serialize for Jws<'_, T>
where
    T: Serialize + Clone,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // serialize protected
        let protected_json =
            serde_json::to_vec(&self.protected.0).map_err(serde::ser::Error::custom)?;
        let protected_b64 = b64::b64u_encode(protected_json);

        // IMPORTANT: Serialize EmptyString as ""
        // serialize payload
        let payload_b64 = if matches!(self.payload.0, AcmeApiBody::EmptyString) {
            String::new()
        } else {
            let payload_json =
                serde_json::to_vec(&self.payload.0).map_err(serde::ser::Error::custom)?;
            b64::b64u_encode(payload_json)
        };

        // signing input
        let signing_input = format!("{protected_b64}.{payload_b64}");

        // sign
        let keypair = PKey::from_rsa(self.private_key.clone())
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
    T: Serialize + Clone,
{
    pub const fn new(
        private_key: Rsa<Private>,
        jws_protected_headers: JwsProtectedHeaders<'a>,
        body: AcmeApiBody<T>,
    ) -> Self {
        Self {
            private_key,
            protected: Base64uEncoded(jws_protected_headers),
            payload: Base64uEncoded(body),
        }
    }

    pub const fn new_from_parts(
        private_key: Rsa<Private>,
        url: &'a Url,
        auth: JwkOrKid,
        nonce: &'a str,
        body: AcmeApiBody<T>,
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

#[derive(Debug, Serialize)]
pub struct JwsProtectedHeaders<'a> {
    #[serde(rename = "alg")]
    pub algorithm: JwsAlgorithm,
    pub url: &'a Url,
    #[serde(flatten)]
    pub auth: JwkOrKid,
    pub nonce: &'a str,
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
#[non_exhaustive]
pub enum JwsAlgorithm {
    #[default]
    #[serde(rename = "RS256")]
    #[strum(serialize = "RS256")]
    RS256,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JwkOrKid {
    /// jwk is used before acme account creation
    Jwk(Jwk),
    /// kid is used after acme account creation
    Kid(AccountId),
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
}

impl From<Rsa<Public>> for Jwk {
    fn from(value: Rsa<Public>) -> Self {
        let modulus = Box::from(b64::b64u_encode(value.n().to_vec()));
        let exponent = Box::from(b64::b64u_encode(value.e().to_vec()));
        let key_type = KeyType::Rsa;

        Self {
            exponent,
            key_type,
            modulus,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Kid(Url);

impl From<Url> for Kid {
    fn from(kid: Url) -> Self {
        Self(kid)
    }
}

impl From<&Url> for Kid {
    fn from(kid: &Url) -> Self {
        Self(kid.clone())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwkThumbprint(Box<str>);

impl From<Rsa<Public>> for JwkThumbprint {
    fn from(value: Rsa<Public>) -> Self {
        let modulus = Box::<str>::from(b64::b64u_encode(value.n().to_vec()));
        let exponent = Box::<str>::from(b64::b64u_encode(value.e().to_vec()));
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

        Self(Box::from(b64::b64u_encode(hash)))
    }
}

impl AsRef<str> for JwkThumbprint {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for JwkThumbprint {
    type Target = Box<str>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Jwk> for JwkThumbprint {
    fn from(value: Jwk) -> Self {
        let Jwk {
            exponent,
            key_type,
            modulus,
        } = value;

        let jwk = format!(r#"{{"e":"{exponent}","kty":"{key_type}","n":"{modulus}"}}"#);

        let hash = Sha256::digest(jwk).to_vec();
        Self(Box::from(b64::b64u_encode(hash)))
    }
}

// region:    --- Tests
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    pub type Result<T> = std::result::Result<T, Error>;
    pub type Error = Box<dyn std::error::Error>; // For tests.

    use openssl::pkey::{PKey, Public};

    use super::*;

    const FIXTURE_PRIVATE_KEY: &str = include_str!("../../../tests/FIXTURE_PRIVATE_KEY.pem");

    const FIXTURE_PUBLIC_KEY: &str = include_str!("../../../tests/FIXTURE_PUBLIC_KEY.pem");

    #[test]
    fn public_key_from_private_key() {
        let private_key = Rsa::private_key_from_pem(FIXTURE_PRIVATE_KEY.as_bytes())
            .expect("Cannot parse Rsa Private key from fixture");
        let public_key = PKey::from_rsa(private_key)
            .expect("Cannot parse Rsa Public key from fixture")
            .public_key_to_pem()
            .expect("Cannot convert Rsa Public key to pem format");

        let public_key_str =
            String::from_utf8(public_key).expect("public key contains invalid utf-8 chracters");
        assert_eq!(public_key_str, FIXTURE_PUBLIC_KEY);
    }

    #[test]
    fn public_key_modulus() -> Result<()> {
        const FIXTURE_MODULUS_HEX: &str = "B3ED0EFE7E93A896B6C66B3F91D6D42FC717392DFD58CF6C83E438164EFF497B486740002152A9A9AC0F08CBF30F1657F609D528C633218322825EC5B491DF17848F9EB4162D8CB480CE4402A269E308F8FB2CE60F1B55391D17E3C5551A24B5344AEF2EE4A83275941DD7355EEB2ECB9A4A5C7ED373EABD3580695719FE44BDA466E1B5F663D7E4387977DA6620D6352F9BA6558209979A6D72B31113F4238EBC25459C44060F53C9BA96DCB2479C2A0D2D58CD20EE23AEE1B313C55C44A798FB222870C3F41E6F2F34963903E2264393D146B909EC231F9C6DF0C7BE86844A325AE5368C6A39DFAD2DF0D18B22A80CF828DE19576FB74D13107420B45902D57F51CE2D6BF77EB03E5FAE0526ADEA54FE6059E7C18C02989A0855C505C5A92DACD82BD82ADF27873A546A46C58BD3BB9CBD7132E5959EC1B1A36E05FA066928DAEC70A724CA9A2ED1AC27AA6FCEDB9FC691AC3BEB82552317306D2F4EFEADE640CFAAE7B688DAD00789688BE80DB2C88D325B7599980BCC341297D09AA8187053AA53B6962615C2C9BD0699D4FE9503CC85BB1A13BD1B7C6B09B847C0C681E44845741F9433F1B2FC925F7D59371FD2E96209D67AA04BBE43CC5A36E13787FE775619F89A029E9FE4C2836C2A76D874A6E69383561855112BD907C2ACBDB5C8908F40C9AE8AA62BB50D37CF71452141E0A8E6D510911578777F5A80B8D71C77";

        const FIXTURE_MODULUS_BASE64_URL_NOPAD: &str = "s-0O_n6TqJa2xms_kdbUL8cXOS39WM9sg-Q4Fk7_SXtIZ0AAIVKpqawPCMvzDxZX9gnVKMYzIYMigl7FtJHfF4SPnrQWLYy0gM5EAqJp4wj4-yzmDxtVOR0X48VVGiS1NErvLuSoMnWUHdc1Xusuy5pKXH7Tc-q9NYBpVxn-RL2kZuG19mPX5Dh5d9pmINY1L5umVYIJl5ptcrMRE_QjjrwlRZxEBg9TybqW3LJHnCoNLVjNIO4jruGzE8VcRKeY-yIocMP0Hm8vNJY5A-ImQ5PRRrkJ7CMfnG3wx76GhEoyWuU2jGo5360t8NGLIqgM-CjeGVdvt00TEHQgtFkC1X9Rzi1r936wPl-uBSat6lT-YFnnwYwCmJoIVcUFxaktrNgr2CrfJ4c6VGpGxYvTu5y9cTLllZ7BsaNuBfoGaSja7HCnJMqaLtGsJ6pvztufxpGsO-uCVSMXMG0vTv6t5kDPque2iNrQB4loi-gNssiNMlt1mZgLzDQSl9CaqBhwU6pTtpYmFcLJvQaZ1P6VA8yFuxoTvRt8awm4R8DGgeRIRXQflDPxsvySX31ZNx_S6WIJ1nqgS75DzFo24TeH_ndWGfiaAp6f5MKDbCp22HSm5pODVhhVESvZB8KsvbXIkI9Aya6Kpiu1DTfPcUUhQeCo5tUQkRV4d39agLjXHHc";

        let public_key = Rsa::<Public>::public_key_from_pem(FIXTURE_PUBLIC_KEY.as_bytes())?;

        let modulus = public_key
            .n()
            .to_hex_str()
            .expect("Cannot convert public modulus key to hex str")
            .to_string();
        // println!("modulus: {modulus}");
        assert_eq!(FIXTURE_MODULUS_HEX, modulus);

        let Jwk { modulus, .. } = public_key.into();

        // println!("modulus: {}", modulus);
        assert_eq!(FIXTURE_MODULUS_BASE64_URL_NOPAD, &*modulus);

        Ok(())
    }

    #[test]
    fn public_key_exponent() -> Result<()> {
        const FIXTURE_EXPONENT_BASE64_URL_NOPAD: &str = "AQAB";

        let public_key = Rsa::<Public>::public_key_from_pem(FIXTURE_PUBLIC_KEY.as_bytes())?;

        let Jwk { exponent, .. } = public_key.into();
        // println!("exponent_base64: {}", exponent);

        assert_eq!(FIXTURE_EXPONENT_BASE64_URL_NOPAD, &*exponent);

        Ok(())
    }

    #[test]
    fn serialize_jws() {
        let private_key = Rsa::private_key_from_pem(FIXTURE_PRIVATE_KEY.as_bytes())
            .expect("Cannot parse Rsa Private key from fixture");
        let jws_protected_headers = JwsProtectedHeaders {
            algorithm: JwsAlgorithm::RS256,
            url: &Url::from_str("https://example.com").expect("Invalid url"),
            auth: JwkOrKid::Kid(AccountId::from_str("https://example.com").expect("Invalid url")),
            nonce: "some-nonce",
        };

        let body = AcmeApiBody::EMPTY_STRING;

        let json = serde_json::to_string(&Jws::new(private_key, jws_protected_headers, body))
            .expect("Cannot convert jws to json string");

        assert_eq!(
            json,
            r#"{"protected":"eyJhbGciOiJSUzI1NiIsInVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vIiwia2lkIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS8iLCJub25jZSI6InNvbWUtbm9uY2UifQ","payload":"","signature":"ellGfPsgUEBhcjFPv45pws9jtGXeEyz-9H3C9dzFmQr1PFrULcvplq76oonjX1zBFP5Njwdm3kV2mn3JmewCl1_CNWQieKDMK4YHYzELIL2IAwHzEk11lRNxC53oXULnxlJWTUpL5kCFfQr7Udh8fK8CvGHvobvBG4UJHM0m8LASTfcDplXOVA3r04qmcXLFCKn2_H2urpbUYpuNboI2dV0f47-Q9asn2vRbnf-l4jW03rbLL19lU1Wex3knRYmOK4ndsM-WSPW-IHOe0OQsnduUxjCwwWud0X8iOgnKuAgvhpshYd9QxkydVJjMkMXyg-STku__GlGlejbb8ID0g4yagExuTKijecbercTPY_H6RrAg7V75k1KjWle3IJ-1Afd3GLmZgsO8mOlGCdDHa2zHuuVdJ8oFd7sVkqC_GeFbirP_K5defNRX73MZ8ElC0gMvrV_eJOpDwTBYc0MIoEhmFHNn3r8WR9VNaE-MuLTcUoLj1WKNG1XBCJsgGTrCphCdHBhMgXYkK1FIsR1uYjHQ5tjIlVsbdMIizwyiWIa7X4YXsZCeHOZSN9RdHkvtEZnW6klJJ7rZrqRvFKPiHB7fauX2UFVwSo6uiYC9PTWjVbfjXWkm_wTDAffd96Y83daZz2cwLdEbbsIdvS5gkCwGxu9Gnusn6uRP7IlDz2s"}"#
        );
    }

    #[test]
    fn jwk_thumbprint() -> Result<()> {
        const FIXTURE_JWK_THUMBPRINT: &str = "5BSQDxzIIoXmaszdh9jW9XDkJwWFrC8u0x-2o4yt2sM";

        let public_key = Rsa::<Public>::public_key_from_pem(FIXTURE_PUBLIC_KEY.as_bytes())?;

        let jwk_thumbprint: JwkThumbprint = public_key.into();

        // println!("jwk_thumbprint: {}", jwk_thumbprint.as_ref());
        assert_eq!(FIXTURE_JWK_THUMBPRINT, jwk_thumbprint.as_ref());

        Ok(())
    }
}
// endregion: --- Tests
