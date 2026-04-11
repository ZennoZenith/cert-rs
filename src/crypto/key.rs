use openssl::{bn::BigNum, ec::EcGroupRef, nid::Nid};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use openssl::{
    ec::{EcGroup, EcKey},
    pkey::{Id, PKey, Private},
    rsa::Rsa,
};

use crate::{
    Error, Result, b64,
    crypto::{
        ec::{EcCurve, detect_ec_curve},
        okp::OkpCurve,
        rsa::{RsaKeyBits, RsaSigningAlgorithm},
    },
};

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
    Rsa {
        /// The signing algorithm associated with this RSA key.
        signing_algo: RsaSigningAlgorithm,

        /// The RSA modulus size (key strength).
        bits: RsaKeyBits,

        /// The underlying RSA private key material.
        key: Rsa<Private>,
    },

    /// Elliptic Curve (ECDSA) private key over NIST prime curves.
    Ec {
        /// The curve used for this EC key (P-256, P-384, P-521).
        crv: EcCurve,

        /// The underlying EC private key material.
        key: EcKey<Private>,
    },

    /// Octet Key Pair (OKP) private key (typically Ed25519).
    Okp {
        /// The curve type for this OKP key (e.g., Ed25519).
        crv: OkpCurve,

        /// The underlying private key material.
        key: PKey<Private>,
    },
}

impl Key {
    /// Generates a new RSA private key for ACME / JOSE usage.
    ///
    /// This constructor creates a fresh RSA key pair with the specified key size
    /// and associates it with a signing algorithm used for JWS operations.
    ///
    /// # ACME / JOSE Context
    /// RSA keys are commonly used in ACME for account authentication and CSR
    /// signing. The key is later represented as a JWK and used in JWS-signed
    /// requests ([RFC 8555], [RFC 7517], [RFC 7518]).
    ///
    /// The selected `signing_algo` determines the `"alg"` field in JWS headers
    /// (e.g., `"RS256"`).
    ///
    /// # Parameters
    /// - `bits`: The RSA key size (e.g., 2048 or 4096 bits).
    /// - `signing_algo`: The JWA signing algorithm associated with this key.
    ///
    /// # Returns
    /// A new [`Self::Rsa`] variant containing the generated private key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - RSA key generation fails due to cryptographic library failure.
    /// - The system RNG is unavailable or insufficient for secure key generation.
    /// - The requested key size is unsupported by the underlying cryptographic backend.
    ///
    /// Any error from the underlying RSA generation is propagated as [`Error`].
    ///
    /// [RFC 8555]: https://datatracker.ietf.org/doc/html/rfc8555
    /// [RFC 7517]: https://datatracker.ietf.org/doc/html/rfc7517
    /// [RFC 7518]: https://datatracker.ietf.org/doc/html/rfc7518
    pub fn new_rsa(bits: RsaKeyBits, signing_algo: RsaSigningAlgorithm) -> Result<Self> {
        let key =
            Rsa::generate(bits.as_u32()).map_err(|_| Error::Crypto("Rsa key generation failed"))?;

        Ok(Self::Rsa {
            bits,
            signing_algo,
            key,
        })
    }

    /// Constructs an RSA key from existing key material and infers its parameters.
    ///
    /// This is used when loading or importing an existing RSA private key rather
    /// than generating a new one.
    ///
    /// # ACME / JOSE Context
    /// RSA keys used in ACME must be represented as JWKs and are associated with
    /// a specific signing algorithm (e.g., RS256). This constructor attaches the
    /// required metadata to an existing key so it can be used in JWS signing and
    /// ACME authentication flows.
    ///
    /// The key size (`bits`) is derived from the RSA modulus.
    ///
    /// # Parameters
    /// - `key`: The existing RSA private key material.
    /// - `signing_algo`: The JWA signing algorithm to associate with this key.
    ///
    /// # Returns
    /// A [`Self::Rsa`] variant wrapping the provided key and inferred metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The RSA modulus size cannot be determined or is invalid.
    /// - The modulus bit length cannot be converted into a supported [``RsaKeyBits``] variant.
    /// - The key is malformed or incomplete.
    /// - An overflow or conversion failure occurs while computing the bit size.
    ///
    /// Any error during key inspection or type conversion is propagated as [`Error`].
    pub fn new_rsa_from_parts(
        key: Rsa<Private>,
        signing_algo: RsaSigningAlgorithm,
    ) -> Result<Self> {
        let bits = key.n().num_bits().cast_unsigned().try_into()?;

        Ok(Self::Rsa {
            bits,
            signing_algo,
            key,
        })
    }

    /// Generates a new Elliptic Curve (EC) private key for ACME / JOSE usage.
    ///
    /// This constructor creates a fresh ECDSA key pair over the specified NIST
    /// curve and prepares it for use in JWS signing and ACME authentication flows.
    ///
    /// # ACME / JOSE Context
    /// EC keys are widely used in ACME for account authentication and CSR signing.
    /// In JOSE ([RFC 7517] / [RFC 7518]), EC keys are represented as JWKs and signed
    /// using ECDSA algorithms such as ES256, ES384, or ES512 depending on the curve.
    ///
    /// The selected curve determines both the cryptographic strength and the
    /// required JWS `"alg"` value.
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve to use (P-256, P-384, or P-521).
    ///
    /// # Returns
    /// A new [`Self::Ec`] variant containing the generated EC private key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The specified curve name is not supported by the underlying cryptographic backend.
    /// - The EC group cannot be constructed from the given curve.
    /// - Key generation fails due to system RNG failure or cryptographic backend errors.
    /// - The underlying OpenSSL operations fail during key generation.
    ///
    /// Any error from EC group creation or key generation is propagated as [`Error`].
    ///
    /// [RFC 7517]: https://datatracker.ietf.org/doc/html/rfc7517
    /// [RFC 7518]: https://datatracker.ietf.org/doc/html/rfc7518
    pub fn new_ec(curve: EcCurve) -> Result<Self> {
        let group = EcGroup::from_curve_name(curve.into())
            .map_err(|_| Error::Crypto("Unsupported Elliptic Curve"))?;

        let ec_key =
            EcKey::generate(&group).map_err(|_| Error::Crypto("EC key generation failed"))?;

        Ok(Self::Ec {
            crv: curve,
            key: ec_key,
        })
    }

    /// Constructs an Elliptic Curve (EC) key from existing key material and
    /// infers the associated curve.
    ///
    /// This is used when loading or importing an existing EC private key rather
    /// than generating a new one.
    ///
    /// # ACME / JOSE Context
    /// EC keys used in ACME must be represented as JWKs and include the curve
    /// identifier (`"crv"`). This constructor inspects the provided key to
    /// determine the correct curve (e.g., P-256, P-384, P-521) so it can be
    /// correctly serialized and used in JWS signing.
    ///
    /// # Parameters
    /// - `key`: The existing EC private key material.
    ///
    /// # Returns
    /// A [`Self::Ec`] variant containing the provided key and the detected curve.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The curve cannot be determined from the provided EC key.
    /// - The key is malformed or does not correspond to a supported NIST curve.
    /// - The key uses an unsupported or unrecognized elliptic curve.
    /// - Internal cryptographic inspection of the key fails.
    ///
    /// Any error from curve detection or key inspection is propagated as [`Error`].
    pub fn new_ec_from_parts(key: EcKey<Private>) -> Result<Self> {
        let crv = detect_ec_curve(&key)?;
        Ok(Self::Ec { crv, key })
    }

    /// Generates a new Octet Key Pair (OKP) private key for ACME / JOSE usage.
    ///
    /// This constructor creates a fresh Ed25519 key pair, which is the only
    /// currently supported OKP curve in this implementation.
    ///
    /// # ACME / JOSE Context
    /// OKP keys (RFC 8037) are used in JOSE for EdDSA-based signatures.
    /// In ACME, they provide a modern alternative to RSA and ECDSA keys,
    /// offering high performance and strong security guarantees.
    ///
    /// The generated key is intended for use with the `"EdDSA"` JWS algorithm
    /// and is represented in JWK format with `"crv": "Ed25519"`.
    ///
    /// # Returns
    /// A new [`Self::Okp`] variant containing an Ed25519 private key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying cryptographic backend fails to generate an Ed25519 key pair.
    /// - The system RNG is unavailable or insufficient for secure key generation.
    /// - The OpenSSL (or equivalent) provider does not support Ed25519.
    ///
    /// Any error from key generation is propagated as [`Error`].
    pub fn new_okp() -> Result<Self> {
        let pkey =
            PKey::generate_ed25519().map_err(|_| Error::Crypto("Okp key generation failed"))?;

        Ok(Self::Okp {
            key: pkey,
            crv: OkpCurve::Ed25519,
        })
    }

    /// Loads an Octet Key Pair (OKP) private key from PEM-encoded data.
    ///
    /// This constructor parses a PEM-formatted private key and validates that
    /// it is an Ed25519 key suitable for use in JOSE/ACME operations.
    ///
    /// # ACME / JOSE Context
    /// OKP keys (RFC 8037) are used with `EdDSA` signatures in JWS. In ACME,
    /// Ed25519 is the primary supported OKP curve and must be represented in
    /// JWK form with `"crv": "Ed25519"`.
    ///
    /// This function ensures that only Ed25519 keys are accepted, rejecting
    /// any other key types.
    ///
    /// # Parameters
    /// - `pem`: PEM-encoded private key bytes.
    ///
    /// # Returns
    /// A [`Self::Okp`] variant containing the parsed Ed25519 private key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The PEM data cannot be parsed into a valid private key.
    /// - The key is not an Ed25519 key (`Id::ED25519` check fails).
    /// - The underlying cryptographic library fails to decode the key.
    /// - The key format is unsupported or malformed.
    ///
    /// Any error from PEM parsing or validation is propagated as [`Error`].
    pub fn new_okp_from_pem(pem: &[u8]) -> Result<Self> {
        let pkey = PKey::private_key_from_pem(pem)
            .map_err(|_| Error::Crypto("Cannot parse pem to Okp key"))?;

        println!("{:#?}", pkey.id());

        if pkey.id() != Id::ED25519 {
            return Err(Error::Crypto("Not an ED25519 key"));
        }

        Ok(Self::Okp {
            key: pkey,
            crv: OkpCurve::Ed25519,
        })
    }

    /// TODO: ???
    fn _new_okp_from_der(der: &[u8]) -> Result<Self> {
        let pkey = PKey::private_key_from_der(der)
            .map_err(|_| Error::Crypto("Cannot parse der to Okp key"))?;

        if pkey.id() != Id::ED25519 {
            return Err(Error::Crypto("Not an ED25519 key"));
        }

        Ok(Self::Okp {
            key: pkey,
            crv: OkpCurve::Ed25519,
        })
    }

    /// Serializes the key pair into PEM-encoded private and public key strings.
    ///
    /// This function converts the internal key representation into a pair of
    /// PEM-formatted strings suitable for storage, export, or interoperability
    /// with external TLS/PKI tooling.
    ///
    /// # ACME / JOSE Context
    /// Although ACME primarily uses JWK (JSON Web Key) format for signing and
    /// authentication, PEM encoding is often used for:
    /// - Persisting keys on disk
    /// - Interfacing with OpenSSL-based tooling
    /// - Exporting keys for external certificate workflows
    ///
    /// The function produces:
    /// - A private key in PKCS#8 PEM format
    /// - A corresponding public key in PEM `SubjectPublicKeyInfo` format
    ///
    /// # Returns
    /// A tuple containing:
    /// - `String`: PEM-encoded private key
    /// - `String`: PEM-encoded public key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying key cannot be converted into an OpenSSL `PKey` type.
    /// - PEM encoding of the private or public key fails.
    /// - The key type does not support the required export operations.
    /// - UTF-8 conversion of PEM output fails.
    /// - The cryptographic backend encounters an internal error during serialization.
    ///
    /// Any error from key conversion, PEM encoding, or string conversion is
    /// propagated as [`Error`].
    pub fn to_pem(&self) -> Result<(String, String)> {
        let pkey = match self {
            Self::Rsa { key, .. } => PKey::from_rsa(key.to_owned())
                .map_err(|_| Error::Crypto("Cannot convert Rsa<Private> to PKey"))?,
            Self::Ec { key, .. } => PKey::from_ec_key(key.to_owned())
                .map_err(|_| Error::Crypto("Cannot convert Ec<Private> to PKey"))?,
            Self::Okp { key, .. } => key.to_owned(),
        };

        let private_pem = pkey
            .private_key_to_pem_pkcs8()
            .map_err(|_| Error::Crypto("Cannot convert PKey to private_key_to_pem_pkcs8"))?;
        let public_pem = pkey
            .public_key_to_pem()
            .map_err(|_| Error::Crypto("Cannot convert PKey to pem public_key_to_pem"))?;

        let private_key = String::from_utf8(private_pem)
            .map_err(|_| Error::Crypto("Cannot convert private_pem to string"))?;
        let public_key = String::from_utf8(public_pem)
            .map_err(|_| Error::Crypto("Cannot convert public_pem to string"))?;

        // println!("Private Key:\n{private_key}\n\nPublic Key:\n{public_key}");
        Ok((private_key, public_key))
    }

    /// Serializes the private key into PKCS#8 DER format and returns it as a `String`.
    ///
    /// TODO: test
    ///
    /// This function exports the underlying private key into PKCS#8 DER encoding,
    /// which is a binary format commonly used for interoperable key storage.
    ///
    /// # ACME / JOSE Context
    /// While ACME and JOSE primarily operate with JWK (JSON Web Key) representations,
    /// PKCS#8 DER is often used for:
    /// - Storing private keys in a standardized binary format
    /// - Interfacing with cryptographic libraries and tooling
    /// - Key import/export between systems that do not use PEM/JWK directly
    ///
    /// # ⚠️ Important Note
    /// PKCS#8 DER is a **binary format**, not UTF-8 text. Converting raw DER bytes
    /// into a `String` is generally invalid and may produce malformed data or runtime
    /// errors unless the bytes are explicitly encoded (e.g., base64) beforehand.
    ///
    /// # Returns
    /// A `String` containing the DER-encoded key bytes (as implemented in this function).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key cannot be converted into DER format by the underlying crypto backend.
    /// - The key type does not support DER serialization.
    /// - UTF-8 conversion fails because DER output is not valid UTF-8.
    /// - The cryptographic provider encounters an internal failure.
    ///
    /// Any error from DER serialization or string conversion is propagated as [`Error`].
    ///
    /// # Recommendation
    /// Consider returning `Vec<u8>` instead of `String` for correct binary handling.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let der = match self {
            Self::Rsa { key, .. } => key.private_key_to_der(),
            Self::Ec { key, .. } => key.private_key_to_der(),
            Self::Okp { key, .. } => key.private_key_to_der(),
        };
        let der = der.map_err(|_| Error::Crypto("Cannot convert PKey to private_key_to_der"))?;
        Ok(der)
    }
}

#[must_use]
pub(crate) fn big_num_to_b64_padded(n: &BigNum, byte_len: usize) -> Box<str> {
    let bytes = n.to_vec();
    if bytes.len() >= byte_len {
        return b64::b64u_encode(&bytes).into_boxed_str();
    }
    // Left-pad with zeros to the required field element size
    let mut padded = vec![0u8; byte_len - bytes.len()];
    padded.extend_from_slice(&bytes);
    b64::b64u_encode(&padded).into_boxed_str()
}

/// Will return `0` if bits cannot be converted to [usize]
#[must_use]
pub(crate) fn ec_coord_len(group: &EcGroupRef) -> usize {
    let bits = group.order_bits();
    bits.div_ceil(8).try_into().unwrap_or_default() // ceil(bits / 8)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty", rename_all = "UPPERCASE")]
enum JwkRepr {
    /// RSA private key
    #[serde(rename = "RSA")]
    Rsa {
        // Public
        n: String,
        e: String,
        // Private
        d: String,
        p: String,
        q: String,
        dp: String,
        dq: String,
        qi: String,
        // Algorithm metadata
        alg: RsaSigningAlgorithm,
    },
    /// Elliptic-curve (P-256 / P-384 / P-521) private key
    #[serde(rename = "EC")]
    Ec {
        crv: EcCurve,
        x: String,
        y: String,
        d: String,
    },
    /// Octet key pair – Ed25519 / X25519 (OKP)
    #[serde(rename = "OKP")]
    Okp { crv: OkpCurve, x: String, d: String },
}

fn big_num_from_base64(s: &str) -> Result<BigNum> {
    let decoded =
        b64::b64u_decode(s).map_err(|_| Error::Crypto("cannot decode, big_num_from_base64"))?;

    BigNum::from_slice(&decoded).map_err(|_| Error::Crypto("Cannot convert base64 to BigNum"))
}

// ── Serialize ────────────────────────────────────────────────────────────────

impl Serialize for Key {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        #![allow(clippy::many_single_char_names)]

        use serde::ser::Error as _;

        let repr = match self {
            // ── RSA ──────────────────────────────────────────────────────────
            Self::Rsa {
                signing_algo, key, ..
            } => {
                let n = key.n();
                let e = key.e();
                let d = key.d();
                let p = key.p().ok_or_else(|| S::Error::custom("missing p"))?;
                let q = key.q().ok_or_else(|| S::Error::custom("missing q"))?;
                let dp = key.dmp1().ok_or_else(|| S::Error::custom("missing dp"))?;
                let dq = key.dmq1().ok_or_else(|| S::Error::custom("missing dq"))?;
                let qi = key.iqmp().ok_or_else(|| S::Error::custom("missing qi"))?;

                JwkRepr::Rsa {
                    n: b64::b64u_encode(n.to_vec()),
                    e: b64::b64u_encode(e.to_vec()),
                    d: b64::b64u_encode(d.to_vec()),
                    p: b64::b64u_encode(p.to_vec()),
                    q: b64::b64u_encode(q.to_vec()),
                    dp: b64::b64u_encode(dp.to_vec()),
                    dq: b64::b64u_encode(dq.to_vec()),
                    qi: b64::b64u_encode(qi.to_vec()),
                    alg: *signing_algo,
                }
            }

            // ── EC ───────────────────────────────────────────────────────────
            Self::Ec { crv, key } => {
                let group = key.group();
                let pubkey = key.public_key();
                let mut cx = openssl::bn::BigNumContext::new()
                    .map_err(|e| S::Error::custom(e.to_string()))?;
                let mut x = BigNum::new().map_err(|e| S::Error::custom(e.to_string()))?;
                let mut y = BigNum::new().map_err(|e| S::Error::custom(e.to_string()))?;

                pubkey
                    .affine_coordinates_gfp(group, &mut x, &mut y, &mut cx)
                    .map_err(|e| S::Error::custom(e.to_string()))?;

                let d = key
                    .private_key()
                    .to_owned()
                    .map_err(|e| S::Error::custom(e.to_string()))?;

                let coord_len = ec_coord_len(group);

                JwkRepr::Ec {
                    crv: *crv,
                    x: big_num_to_b64_padded(&x, coord_len).into_string(),
                    y: big_num_to_b64_padded(&y, coord_len).into_string(),
                    d: big_num_to_b64_padded(&d, coord_len).into_string(),
                }
            }

            // ── OKP (Ed25519 / X25519) ───────────────────────────────────────
            Self::Okp { crv, key } => {
                // OpenSSL stores raw key bytes via raw_private_key / raw_public_key
                let d_bytes = key.raw_private_key().map_err(|e| S::Error::custom(e.to_string()))?;
                let x_bytes = key.raw_public_key().map_err(|e| S::Error::custom(e.to_string()))?;

                JwkRepr::Okp {
                    crv: *crv,
                    x: b64::b64u_encode(&x_bytes),
                    d: b64::b64u_encode(&d_bytes),
                }
            }
        };

        repr.serialize(ser)
    }
}

// ── Deserialize ──────────────────────────────────────────────────────────────

impl<'de> Deserialize<'de> for Key {
    /// OKP x on deserialize — the public x field is intentionally ignored during
    /// deserialization because OpenSSL derives it automatically from the raw private
    /// key bytes, so there's no risk of a mismatch. Key validation — ``EcKey::check_key()``
    /// is called after reconstruction to verify the point lies on the curve.
    ///
    /// RSA consistency is enforced internally by ``Rsa::from_private_components``.
    ///
    /// OKP has no equivalent check in OpenSSL's Rust bindings.
    fn deserialize<D: Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        use openssl::{
            bn::BigNumContext,
            ec::{EcGroup, EcKey, EcPoint},
            pkey::PKey,
            rsa::Rsa,
        };
        use serde::de::Error as _;

        let repr = JwkRepr::deserialize(de)?;

        match repr {
            // ── RSA ──────────────────────────────────────────────────────────
            JwkRepr::Rsa {
                n,
                e,
                d,
                p,
                q,
                dp,
                dq,
                qi,
                alg,
            } => {
                let key = Rsa::from_private_components(
                    big_num_from_base64(&n).map_err(D::Error::custom)?,
                    big_num_from_base64(&e).map_err(D::Error::custom)?,
                    big_num_from_base64(&d).map_err(D::Error::custom)?,
                    big_num_from_base64(&p).map_err(D::Error::custom)?,
                    big_num_from_base64(&q).map_err(D::Error::custom)?,
                    big_num_from_base64(&dp).map_err(D::Error::custom)?,
                    big_num_from_base64(&dq).map_err(D::Error::custom)?,
                    big_num_from_base64(&qi).map_err(D::Error::custom)?,
                )
                .map_err(D::Error::custom)?;

                let bits = RsaKeyBits::try_from(key.n().num_bits().cast_unsigned())
                    .map_err(D::Error::custom)?;
                let signing_algo = alg;

                Ok(Self::Rsa {
                    signing_algo,
                    bits,
                    key,
                })
            }

            // ── EC ───────────────────────────────────────────────────────────
            JwkRepr::Ec { crv, x, y, d } => {
                let ec_crv = crv;
                let nid: Nid = ec_crv.into();
                let group = EcGroup::from_curve_name(nid).map_err(D::Error::custom)?;

                let x_bn = big_num_from_base64(&x).map_err(D::Error::custom)?;
                let y_bn = big_num_from_base64(&y).map_err(D::Error::custom)?;
                let d_bn = big_num_from_base64(&d).map_err(D::Error::custom)?;

                let mut cx = BigNumContext::new().map_err(D::Error::custom)?;
                let mut point = EcPoint::new(&group).map_err(D::Error::custom)?;
                point
                    .set_affine_coordinates_gfp(&group, &x_bn, &y_bn, &mut cx)
                    .map_err(D::Error::custom)?;

                let key = EcKey::from_private_components(&group, &d_bn, &point)
                    .map_err(D::Error::custom)?;
                key.check_key().map_err(D::Error::custom)?;

                Ok(Self::Ec { crv: ec_crv, key })
            }

            // ── OKP ──────────────────────────────────────────────────────────
            JwkRepr::Okp { crv, d, .. } => {
                let okp_crv = crv;
                let d_bytes = b64::b64u_decode(&d).map_err(D::Error::custom)?;

                let key = match okp_crv {
                    OkpCurve::Ed25519 => {
                        PKey::private_key_from_raw_bytes(&d_bytes, openssl::pkey::Id::ED25519)
                    }
                }
                .map_err(D::Error::custom)?;

                Ok(Self::Okp { crv: okp_crv, key })
            }
        }
    }
}
