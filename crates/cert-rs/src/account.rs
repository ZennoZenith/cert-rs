use std::{ops::Deref, str::FromStr};

use crate::b64;

use color_eyre::Result;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    sign::Signer,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::api::AcmeApiBody;

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountCreate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<serde_json::Value>,
}

#[derive(
    Debug,
    Clone,
    Deserialize,
    Serialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum AccountStatus {
    #[default]
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub status: AccountStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,
    // TODO: external_account_binding object type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<serde_json::Value>,
    /// A Url from which a list of orders submitted by this acocount can be fetched
    pub orders: Url,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountOrdersList {
    /// List of order url created by the account
    pub orders: Vec<Url>,
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
    Jwk {
        /// Public key exponent base64 url encoded no pad
        #[serde(rename = "e")]
        exponent: Box<str>,
        /// Key type
        #[serde(rename = "kty")]
        key_type: KeyType,
        /// Public key modulus base64 url encoded no pad
        #[serde(rename = "n")]
        modulus: Box<str>,
    },
    /// kid is used after acme account creation
    Kid(Url),
}

impl From<Url> for JwkOrKid {
    fn from(kid: Url) -> Self {
        Self::Kid(kid)
    }
}

impl From<&Url> for JwkOrKid {
    fn from(kid: &Url) -> Self {
        Self::Kid(kid.clone())
    }
}

impl From<Rsa<Public>> for JwkOrKid {
    fn from(value: Rsa<Public>) -> Self {
        let modulus = Box::from(b64::b64u_encode(value.n().to_vec()));
        let exponent = Box::from(b64::b64u_encode(value.e().to_vec()));
        let key_type = KeyType::Rsa;

        Self::Jwk {
            exponent,
            key_type,
            modulus,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwkThumbprint(Box<str>);

impl From<Rsa<Public>> for JwkThumbprint {
    fn from(value: Rsa<Public>) -> Self {
        let modulus = Box::<str>::from(b64::b64u_encode(value.n().to_vec()));
        let exponent = Box::<str>::from(b64::b64u_encode(value.e().to_vec()));
        let key_type = KeyType::Rsa;

        let jwk = format!(
            r#"{{"e":"{exponent}","kty":"{key_type}","n":"{modulus}"}}"#
        );

        #[cfg(test)]
        {
            assert_eq!(
                jwk,
                serde_json::to_string(&serde_json::json!({
                    "e":exponent,
                    "kty":key_type,
                    "n":modulus
                }))
                .unwrap()
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

impl TryFrom<JwkOrKid> for JwkThumbprint {
    type Error = &'static str;

    fn try_from(value: JwkOrKid) -> std::result::Result<Self, Self::Error> {
        let JwkOrKid::Jwk {
            exponent,
            key_type,
            modulus,
        } = value
        else {
            return Err("JwkOrKid must have been jwk");
        };

        let jwk = format!(
            r#"{{"e":"{exponent}","kty":"{key_type}","n":"{modulus}"}}"#
        );

        let hash = Sha256::digest(jwk).to_vec();
        Ok(Self(Box::from(b64::b64u_encode(hash))))
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

#[derive(Debug, Serialize)]
pub struct Jws {
    protected: String,
    payload: String,
    signature: String,
}

impl Jws {
    pub fn new<T: Serialize + Clone>(
        private_key: Rsa<Private>,
        jws_protected_headers: &JwsProtectedHeaders,
        body: AcmeApiBody<T>,
    ) -> Result<Self> {
        let protected = b64::b64u_encode(
            serde_json::to_string(&jws_protected_headers)
                .expect("Unable to serialize jws_protected_headers"),
        );

        // If body is present serialize to string else set empty string
        let serialized_body = match body {
            AcmeApiBody::EmptyString => String::from(""),
            AcmeApiBody::EmptyObject => String::from("{}"),
            AcmeApiBody::Other(b) => {
                serde_json::to_string(&b).expect("Unable to serialize body")
            }
        };

        let payload = b64::b64u_encode(serialized_body);
        let signature = format!("{protected}.{payload}");

        let keypair = PKey::from_rsa(private_key)?;

        let mut signer = Signer::new(MessageDigest::sha256(), &keypair)?;
        signer.update(signature.as_bytes())?;
        let signature = signer.sign_to_vec()?;

        let signature = b64::b64u_encode(signature);

        Ok(Self {
            protected,
            payload,
            signature,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnRegisteredAccount;

#[derive(Debug, Clone)]
pub struct RegisteredAccount {
    account_id: Url,
    private_key: Rsa<Private>,
    /// jwk -> to json -> sha256 hash -> base64url
    jwk_thumbprint: JwkThumbprint,
}

impl RegisteredAccount {
    pub fn new(
        account_id: Url,
        private_key: Rsa<Private>,
    ) -> RegisteredAccount {
        let public_key_pem = private_key.public_key_to_pem().expect(
            "Unable to convert rsa private key to public_key_pem format",
        );
        let public_key = Rsa::public_key_from_pem(&public_key_pem)
            .expect("Unable to convert public_key_pem to public_key");

        let jwk_thumbprint = public_key.into();

        Self {
            account_id,
            private_key,
            jwk_thumbprint,
        }
    }

    pub fn account_id(&self) -> &Url {
        &self.account_id
    }

    pub fn private_key(&self) -> &Rsa<Private> {
        &self.private_key
    }

    pub fn jwk_thumbprint(&self) -> &str {
        &self.jwk_thumbprint
    }
}

// region:    --- Tests
#[cfg(test)]
mod tests {
    pub type Result<T> = std::result::Result<T, Error>;
    pub type Error = Box<dyn std::error::Error>; // For tests.

    use std::ops::Deref;

    use openssl::pkey::PKey;

    use super::*;

    const FIXTURE_PRIVATE_KEY: &str =
        include_str!("../../../tests/FIXTURE_PRIVATE_KEY.pem");

    const FIXTURE_PUBLIC_KEY: &str =
        include_str!("../../../tests/FIXTURE_PUBLIC_KEY.pem");

    #[test]
    fn public_key_from_private_key() -> Result<()> {
        let private_key =
            Rsa::private_key_from_pem(FIXTURE_PRIVATE_KEY.as_bytes()).unwrap();
        let public_key =
            PKey::from_rsa(private_key).unwrap().public_key_to_pem().unwrap();

        let public_key_str = String::from_utf8(public_key).unwrap();
        assert_eq!(public_key_str, FIXTURE_PUBLIC_KEY);

        Ok(())
    }

    #[test]
    fn public_key_modulus() -> Result<()> {
        let public_key =
            Rsa::<Public>::public_key_from_pem(FIXTURE_PUBLIC_KEY.as_bytes())?;

        const FIXTURE_MODULUS_HEX: &str = "B3ED0EFE7E93A896B6C66B3F91D6D42FC717392DFD58CF6C83E438164EFF497B486740002152A9A9AC0F08CBF30F1657F609D528C633218322825EC5B491DF17848F9EB4162D8CB480CE4402A269E308F8FB2CE60F1B55391D17E3C5551A24B5344AEF2EE4A83275941DD7355EEB2ECB9A4A5C7ED373EABD3580695719FE44BDA466E1B5F663D7E4387977DA6620D6352F9BA6558209979A6D72B31113F4238EBC25459C44060F53C9BA96DCB2479C2A0D2D58CD20EE23AEE1B313C55C44A798FB222870C3F41E6F2F34963903E2264393D146B909EC231F9C6DF0C7BE86844A325AE5368C6A39DFAD2DF0D18B22A80CF828DE19576FB74D13107420B45902D57F51CE2D6BF77EB03E5FAE0526ADEA54FE6059E7C18C02989A0855C505C5A92DACD82BD82ADF27873A546A46C58BD3BB9CBD7132E5959EC1B1A36E05FA066928DAEC70A724CA9A2ED1AC27AA6FCEDB9FC691AC3BEB82552317306D2F4EFEADE640CFAAE7B688DAD00789688BE80DB2C88D325B7599980BCC341297D09AA8187053AA53B6962615C2C9BD0699D4FE9503CC85BB1A13BD1B7C6B09B847C0C681E44845741F9433F1B2FC925F7D59371FD2E96209D67AA04BBE43CC5A36E13787FE775619F89A029E9FE4C2836C2A76D874A6E69383561855112BD907C2ACBDB5C8908F40C9AE8AA62BB50D37CF71452141E0A8E6D510911578777F5A80B8D71C77";

        const FIXTURE_MODULUS_BASE64_URL_NOPAD: &str = "s-0O_n6TqJa2xms_kdbUL8cXOS39WM9sg-Q4Fk7_SXtIZ0AAIVKpqawPCMvzDxZX9gnVKMYzIYMigl7FtJHfF4SPnrQWLYy0gM5EAqJp4wj4-yzmDxtVOR0X48VVGiS1NErvLuSoMnWUHdc1Xusuy5pKXH7Tc-q9NYBpVxn-RL2kZuG19mPX5Dh5d9pmINY1L5umVYIJl5ptcrMRE_QjjrwlRZxEBg9TybqW3LJHnCoNLVjNIO4jruGzE8VcRKeY-yIocMP0Hm8vNJY5A-ImQ5PRRrkJ7CMfnG3wx76GhEoyWuU2jGo5360t8NGLIqgM-CjeGVdvt00TEHQgtFkC1X9Rzi1r936wPl-uBSat6lT-YFnnwYwCmJoIVcUFxaktrNgr2CrfJ4c6VGpGxYvTu5y9cTLllZ7BsaNuBfoGaSja7HCnJMqaLtGsJ6pvztufxpGsO-uCVSMXMG0vTv6t5kDPque2iNrQB4loi-gNssiNMlt1mZgLzDQSl9CaqBhwU6pTtpYmFcLJvQaZ1P6VA8yFuxoTvRt8awm4R8DGgeRIRXQflDPxsvySX31ZNx_S6WIJ1nqgS75DzFo24TeH_ndWGfiaAp6f5MKDbCp22HSm5pODVhhVESvZB8KsvbXIkI9Aya6Kpiu1DTfPcUUhQeCo5tUQkRV4d39agLjXHHc";

        let modulus = public_key.n().to_hex_str().unwrap().to_string();
        // println!("modulus: {modulus}");
        assert_eq!(FIXTURE_MODULUS_HEX, modulus);

        let JwkOrKid::Jwk { modulus, .. } = public_key.clone().into() else {
            panic!("JwkOrKid not of type Jwk")
        };
        // println!("modulus: {}", modulus);
        assert_eq!(FIXTURE_MODULUS_BASE64_URL_NOPAD, modulus.deref());

        Ok(())
    }

    #[test]
    fn public_key_exponent() -> Result<()> {
        let public_key =
            Rsa::<Public>::public_key_from_pem(FIXTURE_PUBLIC_KEY.as_bytes())?;

        const FIXTURE_EXPONENT_BASE64_URL_NOPAD: &str = "AQAB";

        let JwkOrKid::Jwk { exponent, .. } = public_key.clone().into() else {
            panic!("JwkOrKid not of type Jwk")
        };
        // println!("exponent_base64: {}", exponent);
        assert_eq!(FIXTURE_EXPONENT_BASE64_URL_NOPAD, exponent.deref());

        Ok(())
    }

    #[test]
    fn jwk_thumbprint() -> Result<()> {
        let public_key =
            Rsa::<Public>::public_key_from_pem(FIXTURE_PUBLIC_KEY.as_bytes())?;

        const FIXTURE_JWK_THUMBPRINT: &str =
            "5BSQDxzIIoXmaszdh9jW9XDkJwWFrC8u0x-2o4yt2sM";

        let jwk_thumbprint: JwkThumbprint = public_key.into();

        // println!("jwk_thumbprint: {}", jwk_thumbprint.as_ref());
        assert_eq!(FIXTURE_JWK_THUMBPRINT, jwk_thumbprint.as_ref());

        Ok(())
    }
}
// endregion: --- Tests
