use serde::{Serialize, Serializer, ser::SerializeStruct as _};
use url::Url;

use crate::{
    b64,
    crypto::{
        jwa::SigningAlgorithm,
        jwk::JwkOrKid,
        key::{Key, Signer},
    },
};

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
    pub auth: &'a JwkOrKid<'a>,
}

impl<'a> JwsProtectedHeaders<'a> {
    #[must_use]
    pub fn new(key: &'a Key, url: &'a Url, auth: &'a JwkOrKid<'a>, nonce: Option<&'a str>) -> Self {
        let signing_algorithm: SigningAlgorithm = SigningAlgorithm::from(key);

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
    payload: &'a T,
}

impl<'a, T: Serialize> Jws<'a, T> {
    pub const fn new(
        key: &'a Key,
        jws_protected_header: JwsProtectedHeaders<'a>,
        body: &'a T,
    ) -> Self {
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
        let signing_input_bytes = signing_input.as_bytes();

        // sign
        let signature = self.key.sign(signing_input_bytes);

        let signature_b64 = b64::b64u_encode(signature);

        let mut state = serializer.serialize_struct("Jws", 3)?;
        state.serialize_field("protected", &protected_b64)?;
        state.serialize_field("payload", &payload_b64)?;
        state.serialize_field("signature", &signature_b64)?;
        state.end()
    }
}
