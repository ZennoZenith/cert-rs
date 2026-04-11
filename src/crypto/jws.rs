use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Serialize, Serializer, ser::SerializeStruct as _};
use url::Url;

use crate::{
    Error, Result, b64,
    crypto::{
        ec::{EcCurve, EcSigningAlgorithm, ecdsa_der_to_raw},
        jwa::SigningAlgorithm,
        jwk::JwkOrKid,
        key::Key,
        okp::OkpSigningAlgorithm,
        rsa::RsaSigningAlgorithm,
    },
};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Returns the appropriate message digest for signing the CSR.
///
/// - RSA:     matches the key's declared signing algorithm (SHA-256/384/512)
/// - EC P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512  (RFC 5480)
/// - Ed25519: intrinsic hash, OpenSSL uses `MessageDigest::null()`
pub fn key_digest(key: &Key) -> MessageDigest {
    match key {
        Key::Rsa { signing_algo, .. } => match signing_algo {
            RsaSigningAlgorithm::RS256 => MessageDigest::sha256(),
            RsaSigningAlgorithm::RS384 => MessageDigest::sha384(),
            RsaSigningAlgorithm::RS512 => MessageDigest::sha512(),
        },
        Key::Ec { crv, .. } => match crv {
            EcCurve::P256 => MessageDigest::sha256(),
            EcCurve::P384 => MessageDigest::sha384(),
            EcCurve::P521 => MessageDigest::sha512(),
        },
        Key::Okp { .. } => MessageDigest::null(),
    }
}

fn sign(key: &Key, msg: &[u8]) -> Result<Vec<u8>> {
    let md = key_digest(key);

    match key {
        Key::Rsa { key, .. } => {
            // Optimise:
            let keypair = PKey::from_rsa(key.clone())
                .map_err(|_| Error::Crypto("Cannot create PKey<Private> from RSA"))?;

            let mut signer =
                Signer::new(md, &keypair).map_err(|_| Error::Crypto("Signing Failed"))?;

            signer.update(msg).map_err(|_| Error::Crypto("Signing Failed"))?;

            Ok(signer.sign_to_vec().map_err(|_| Error::Crypto("Signing Failed"))?)
        }

        Key::Ec { crv, key } => {
            // Optimise:
            let keypair = PKey::from_ec_key(key.clone())
                .map_err(|_| Error::Crypto("Cannot create PKey<Private> from EC"))?;

            let mut signer =
                Signer::new(md, &keypair).map_err(|_| Error::Crypto("Signing Failed"))?;

            signer.update(msg).map_err(|_| Error::Crypto("Signing Failed"))?;

            let der_sig = signer.sign_to_vec().map_err(|_| Error::Crypto("Signing Failed"))?;

            // IMPORTANT: convert DER → raw (r || s)
            Ok(ecdsa_der_to_raw(&der_sig, *crv).map_err(|_| Error::Crypto("Signing Failed"))?)
        }

        Key::Okp { key, .. } => {
            let mut signer = Signer::new_without_digest(key)
                .map_err(|_| Error::Crypto("Cannot create PKey<Private> from OKP"))?;

            let signature = signer
                .sign_oneshot_to_vec(msg)
                .map_err(|_| Error::Crypto("Signing Failed"))?;

            Ok(signature)
        }
    }
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
    #[must_use]
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
        let signature = sign(self.key, signing_input_bytes).map_err(serde::ser::Error::custom)?;

        let signature_b64 = b64::b64u_encode(signature);

        let mut state = serializer.serialize_struct("Jws", 3)?;
        state.serialize_field("protected", &protected_b64)?;
        state.serialize_field("payload", &payload_b64)?;
        state.serialize_field("signature", &signature_b64)?;
        state.end()
    }
}
