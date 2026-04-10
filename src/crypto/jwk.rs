use openssl::bn::{BigNum, BigNumContext};
use serde::Serialize;

use crate::{
    Error, Key, Result, b64,
    crypto::{
        ec::EcCurve,
        key::{big_num_to_b64_padded, ec_coord_len},
        kid::Kid,
        okp::OkpCurve,
    },
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JwkOrKid<'a> {
    /// jwk is used before acme account creation
    Jwk(Jwk),
    /// kid is used after acme account creation
    Kid(&'a Kid),
}

/// JSON Web Key (JWK) representation used for ACME and JOSE operations.
///
/// This enum represents public key material in the JWK format as defined in
/// [RFC 7517]. It is used for:
/// - ACME account authentication ([RFC 8555])
/// - JWS request signing ([RFC 7515])
/// - Public key exchange in certificate workflows
///
/// # JOSE / ACME Context
/// ACME servers use JWKs to identify and verify account keys. Each key type
/// includes a `"kty"` field indicating the key family, along with additional
/// parameters depending on the algorithm.
///
/// All key parameters are base64url-encoded without padding, as required by
/// [RFC 7518].
///
/// # Variants
/// - `Rsa`: RSA public key parameters (`n`, `e`)
/// - `Ec`: Elliptic Curve public key parameters (`crv`, `x`, `y`)
/// - `Okp`: Octet Key Pair (e.g., Ed25519) public key parameter (`x`)
///
/// # Example (RSA)
/// ```json
/// {
///   "kty": "RSA",
///   "n": "<modulus>",
///   "e": "<exponent>"
/// }
/// ```
///
/// # Security Notes
/// - JWKs contain only public key material and are safe to share.
/// - The encoding must strictly follow base64url (no padding).
/// - Curve and algorithm consistency must be enforced when constructing JWS.
///
/// # References
/// - [RFC 7517] (JSON Web Key)
/// - [RFC 7518] (JSON Web Algorithms)
///
/// [RFC 7515]: https://datatracker.ietf.org/doc/html/rfc7515
/// [RFC 7517]: https://datatracker.ietf.org/doc/html/rfc7517
/// [RFC 7518]: https://datatracker.ietf.org/doc/html/rfc7518
/// [RFC 8555]: https://datatracker.ietf.org/doc/html/rfc8555
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(tag = "kty")]
pub enum Jwk {
    /// RSA public key parameters.
    Rsa {
        /// Public exponent (base64url-encoded, no padding).
        #[serde(rename = "e")]
        exponent: Box<str>,

        /// Modulus (base64url-encoded, no padding).
        #[serde(rename = "n")]
        modulus: Box<str>,
    },

    /// Elliptic Curve public key parameters.
    Ec {
        /// Curve type (e.g., P-256, P-384, P-521).
        crv: EcCurve,

        /// X coordinate (base64url-encoded).
        x: Box<str>,

        /// Y coordinate (base64url-encoded).
        y: Box<str>,
    },

    /// Octet Key Pair (OKP) public key parameters (e.g., Ed25519).
    Okp {
        /// Curve type (currently only Ed25519 supported).
        crv: OkpCurve,

        /// Public key bytes (base64url-encoded).
        #[serde(rename = "x")]
        public_key: Box<str>,
    },
}

impl Jwk {
    /// Computes the [RFC 7638] JWK thumbprint of this public key.
    ///
    /// jwk -> to json -> sha256 hash -> base64url
    ///
    /// The thumbprint is a deterministic identifier derived from the JWK
    /// representation of the key. It is used in ACME ([RFC 8555]) as the
    /// `keyAuthorization` binding mechanism for challenges.
    ///
    /// # Algorithm
    /// 1. Construct a **canonical JSON representation** of the JWK:
    ///    - Include only required members
    ///    - Use **lexicographically ordered** members (as required by [RFC 7638])
    /// 2. Compute SHA-256 hash of the canonical JSON string
    /// 3. Encode the hash using base64url (no padding)
    ///
    /// # ACME / JOSE Context
    /// In ACME, the JWK thumbprint is used in:
    /// - `keyAuthorization = token || "." || base64url(thumbprint)`
    /// - HTTP-01 and DNS-01 challenge validation
    ///
    /// This ensures proof-of-possession of the private key corresponding to
    /// the public JWK.
    ///
    /// # Security Notes
    /// - The thumbprint uniquely identifies a key without revealing private data.
    /// - Any change in key parameters produces a completely different thumbprint.
    /// - Must strictly follow [RFC 7638] canonicalization rules to avoid mismatches.
    ///
    /// # Returns
    /// A base64url-encoded SHA-256 digest of the canonical JWK JSON.
    ///
    /// # References
    /// - [RFC 7638] (JSON Web Key (JWK) Thumbprint)
    /// - [RFC 8555 §8.1] (Key Authorization in ACME)
    ///
    /// [RFC 7638]: https://datatracker.ietf.org/doc/html/rfc7638
    /// [RFC 8555]: https://datatracker.ietf.org/doc/html/rfc8555
    /// [RFC 8555 §8.1]: https://datatracker.ietf.org/doc/html/rfc8555#section-8.1
    #[must_use]
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

impl TryFrom<Key> for Jwk {
    type Error = Error;

    fn try_from(value: Key) -> Result<Self> {
        Self::try_from(&value)
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

                let coord_len = ec_coord_len(group);

                let x = big_num_to_b64_padded(&x, coord_len);
                let y = big_num_to_b64_padded(&y, coord_len);

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
