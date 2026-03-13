use http::{HeaderMap, HeaderValue, header::CONTENT_TYPE};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    sign::Signer,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{ops::Deref, str::FromStr};
use url::Url;

use crate::{
    Error, Result,
    api::{AcmeApiBody, AcmeClient, reqwest_client_builder},
    b64,
    directory::Directory,
};

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
    pub(crate) status: AccountStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) contact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) terms_of_service_agreed: Option<bool>,
    // TODO: external_account_binding object type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) external_account_binding: Option<serde_json::Value>,
    /// A Url from which a list of orders submitted by this acocount can be fetched
    pub(crate) orders: Url,
}

impl Account {
    /// # Errors
    ///
    /// TODO: Write error docs
    pub async fn new(directory: &Directory, account_create: AccountCreate) -> Result<Self> {
        let url = &directory.new_account;

        let reqwest_client = reqwest_client_builder()?;
        let acme_client = AcmeClient::new(reqwest_client);

        let private_key = Rsa::generate(4096).map_err(|e| Error::Unimplemented(e.to_string()))?;
        let public_key_pem = private_key
            .public_key_to_pem()
            .map_err(|e| Error::Unimplemented(e.to_string()))?;
        let public_key = Rsa::public_key_from_pem(&public_key_pem)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let jwk: Jwk = public_key.into();

        loop {
            // OPTIMIZE: new directly from array without mut
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/jose+json"),
            );
            let nonce = acme_client.nonce(directory.new_nonce.clone()).await?;

            let jws_protected_headers = JwsProtectedHeaders {
                algorithm: JwsAlgorithm::RS256,
                url,
                auth: JwkOrKid::Jwk(jwk.clone()),
                nonce: &nonce,
            };

            let body = AcmeApiBody::Other(account_create.clone());

            let jws = Jws::new(private_key.clone(), &jws_protected_headers, body.clone())?;

            // let response = acme_client
            //     .post(PostRequest {
            //         url: url.clone(),
            //         header: Some(headers),
            //         body: (),
            //     })
            //     .headers(headers)
            //     .json(&jws)
            //     .send()
            //     .await?;
        }

        // let ApiResponse { headers, .. }: ApiResponse<Account> = self
        //     .client
        //     .post(
        //         url,
        //         private_key.clone(),
        //         auth,
        //         AcmeApiBody::Other(account_create),
        //     )
        //     .await?;

        // let account_id: Url = extract_location_header(&headers)?;

        // let account = RegisteredAccount::new(account_id, private_key);

        // Ok(self.into_registerd(account))

        // response
        //     .json()
        //     .await
        //     .map_err(|e| Error::ResponseToText(e.to_string()))
        //
        let response = acme_client.get(directory.new_account.clone()).await?;
        dbg!(response);
        todo!()
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
pub struct Jwk {
    /// Public key exponent base64 url encoded no pad
    #[serde(rename = "e")]
    exponent: Box<str>,
    /// Key type
    #[serde(rename = "kty")]
    key_type: KeyType,
    /// Public key modulus base64 url encoded no pad
    #[serde(rename = "n")]
    modulus: Box<str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Kid(Url);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JwkOrKid {
    /// jwk is used before acme account creation
    Jwk(Jwk),
    /// kid is used after acme account creation
    Kid(Url),
}

impl From<Url> for Kid {
    fn from(kid: Url) -> Self {
        Kid(kid)
    }
}

impl From<&Url> for Kid {
    fn from(kid: &Url) -> Self {
        Kid(kid.clone())
    }
}

impl From<Rsa<Public>> for Jwk {
    fn from(value: Rsa<Public>) -> Self {
        let modulus = Box::from(b64::b64u_encode(value.n().to_vec()));
        let exponent = Box::from(b64::b64u_encode(value.e().to_vec()));
        let key_type = KeyType::Rsa;

        Jwk {
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

        let jwk = format!(r#"{{"e":"{exponent}","kty":"{key_type}","n":"{modulus}"}}"#);

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
            AcmeApiBody::Other(b) => serde_json::to_string(&b).expect("Unable to serialize body"),
        };

        let payload = b64::b64u_encode(serialized_body);
        let signature = format!("{protected}.{payload}");

        let keypair =
            PKey::from_rsa(private_key).map_err(|e| Error::Unimplemented(e.to_string()))?;

        let mut signer = Signer::new(MessageDigest::sha256(), &keypair)
            .map_err(|e| Error::Unimplemented(e.to_string()))?;
        signer
            .update(signature.as_bytes())
            .map_err(|e| Error::Unimplemented(e.to_string()))?;
        let signature = signer
            .sign_to_vec()
            .map_err(|e| Error::Unimplemented(e.to_string()))?;

        let signature = b64::b64u_encode(signature);

        Ok(Self {
            protected,
            payload,
            signature,
        })
    }
}
