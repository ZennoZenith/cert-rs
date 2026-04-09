//! OKP x on deserialize — the public x field is intentionally ignored during
//! deserialization because OpenSSL derives it automatically from the raw private
//! key bytes, so there's no risk of a mismatch. Key validation — ``EcKey::check_key()``
//! is called after reconstruction to verify the point lies on the curve.
//!
//! RSA consistency is enforced internally by ``Rsa::from_private_components``.
//!
//! OKP has no equivalent check in OpenSSL's Rust bindings.

use openssl::{bn::BigNum, ec::EcGroupRef};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{EcCurve, Key, Nid, OkpCurve, RsaKeyBits, RsaSigningAlgorithm};
use crate::{Error, Result, b64};

#[must_use]
pub fn big_num_to_b64_padded(n: &BigNum, byte_len: usize) -> Box<str> {
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
pub fn ec_coord_len(group: &EcGroupRef) -> usize {
    let bits = group.order_bits();
    bits.div_ceil(8).try_into().unwrap_or_default() // ceil(bits / 8)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty", rename_all = "UPPERCASE")]
pub enum JwkRepr {
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
        b64::b64u_decode(s).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))?;

    BigNum::from_slice(&decoded).map_err(|e| Error::Unimplemented(Box::from(e.to_string())))
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
