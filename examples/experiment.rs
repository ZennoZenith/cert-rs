#![allow(dead_code, clippy::unwrap_used, unused)]

use base64::{
    DecodeError,
    engine::{Engine, general_purpose},
};
use elliptic_curve::sec1::ToEncodedPoint as _;
use pkcs8::EncodePrivateKey;
use pkcs8::{DecodePrivateKey as _, PrivateKeyInfo, der::Decode};
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts as _};

const RSA_4096_DER: &[u8] = include_bytes!("../tests/keys/rsa/rsa_4096_private_key.der");
const RSA_4096_PEM: &str = include_str!("../tests/keys/rsa/rsa_4096_private_key_pkcs8.pem");

const EC_P256_DER: &[u8] = include_bytes!("../tests/keys/ec/ec_private_p256_pkcs8.der");
const EC_P256_PEM: &str = include_str!("../tests/keys/ec/ec_private_p256_pkcs8.pem");

const EC_P384_DER: &[u8] = include_bytes!("../tests/keys/ec/ec_private_p384_pkcs8.der");
const EC_P384_PEM: &str = include_str!("../tests/keys/ec/ec_private_p384_pkcs8.pem");

const EC_P521_DER: &[u8] = include_bytes!("../tests/keys/ec/ec_private_p521_pkcs8.der");
const EC_P521_PEM: &str = include_str!("../tests/keys/ec/ec_private_p521_pkcs8.pem");

const ED25519_DER: &[u8] = include_bytes!("../tests/keys/ed25519/ed25519_private.der");
const ED25519_PEM: &str = include_str!("../tests/keys/ed25519/ed25519_private_pkcs8.pem");

fn b64u_encode(content: impl AsRef<[u8]>) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(content)
}

fn b64u_decode(content: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(content)
}

fn detect_curve(der: &[u8]) -> Option<&'static str> {
    let info = PrivateKeyInfo::from_der(der).ok()?;
    let oid = info.algorithm.oid;

    let curve: &'static str = match oid.to_string().as_str() {
        "1.2.840.10045.2.1" => {
            // EC key — check the named curve parameter
            let curve_oid = info.algorithm.parameters_oid().unwrap();
            match curve_oid.to_string().as_str() {
                "1.2.840.10045.3.1.7" => "P-256",
                "1.3.132.0.34" => "P-384",
                "1.3.132.0.35" => "P-521",
                _ => "Unknown EC curve",
            }
        }
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "1.2.840.113549.1.1.1" => "RSA",
        _ => return None,
    };

    Some(curve)
}

fn rsa_to_jwk() {
    let rsa_4096_der = rsa::RsaPrivateKey::from_pkcs8_der(RSA_4096_DER).unwrap();
    let rsa_4096_pem = rsa::RsaPrivateKey::from_pkcs8_pem(RSA_4096_PEM).unwrap();

    assert_eq!(rsa_4096_der, rsa_4096_pem);

    let key_priv = rsa_4096_der;

    let key_pub = key_priv.to_public_key();
    let priv_size = key_priv.size() * 8;
    let priv_n = b64u_encode(key_priv.n().to_bytes_be());
    let priv_e = b64u_encode(key_priv.e().to_bytes_be());

    let pub_size = key_pub.size() * 8;
    let pub_n = b64u_encode(key_pub.n().to_bytes_be());
    let pub_e = b64u_encode(key_pub.e().to_bytes_be());

    assert_eq!(priv_size, pub_size);
    assert_eq!(priv_e, pub_e);
    assert_eq!(priv_n, pub_n);

    println!("Key size(bits): {priv_size}");
    println!("Modulus       : {priv_n}");
    println!("Exponent      : {priv_e}");

    let to_pkcs1_pem = key_priv.to_pkcs1_pem(pkcs8::LineEnding::LF).unwrap();
    println!("to_pkcs1_pem:\n{}", *to_pkcs1_pem);
    let to_pkcs8_pem = key_priv.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
    println!("to_pkcs8_pem:\n{}", *to_pkcs8_pem);
    let to_pkcs8_der = key_priv.to_pkcs8_der().unwrap();
    to_pkcs8_der.to_bytes();
}

fn p256_to_jwk() {
    // let ec_p256_der = p256::ecdsa::SigningKey::from_pkcs8_der(EC_P256_DER).unwrap();
    // let ec_p256_pem = p256::ecdsa::SigningKey::from_pkcs8_pem(EC_P256_PEM).unwrap();
    // let public = ec_p256_pem.verifying_key();

    let ec_p256_der = p256::SecretKey::from_pkcs8_der(EC_P256_DER).unwrap();
    let ec_p256_pem = p256::SecretKey::from_pkcs8_pem(EC_P256_PEM).unwrap();
    let public = ec_p256_der.public_key();

    assert_eq!(ec_p256_der, ec_p256_pem);

    let key_priv = ec_p256_der;

    let encoded = public.to_encoded_point(false); // uncompressed

    let x = b64u_encode(encoded.x().unwrap());
    let y = b64u_encode(encoded.y().unwrap());

    println!("x      : {x}");
    println!("y      : {y}");

    let to_sec1_pem = key_priv.to_sec1_pem(pkcs8::LineEnding::LF).unwrap();
    println!("to_sec1_pem:\n{}", *to_sec1_pem);
    let to_pkcs8_pem = key_priv.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
    println!("to_pkcs8_pem:\n{}", *to_pkcs8_pem);
}

fn p384_to_jwk() {
    let ec_p384_der = p384::SecretKey::from_pkcs8_der(EC_P384_DER).unwrap();
    let ec_p384_pem = p384::SecretKey::from_pkcs8_pem(EC_P384_PEM).unwrap();

    assert_eq!(ec_p384_der, ec_p384_pem);

    let key_priv = ec_p384_der;
    let public = key_priv.public_key();

    let encoded = public.to_encoded_point(false); // uncompressed

    let x = b64u_encode(encoded.x().unwrap());
    let y = b64u_encode(encoded.y().unwrap());

    println!("x      : {x}");
    println!("y      : {y}");

    let to_sec1_pem = key_priv.to_sec1_pem(pkcs8::LineEnding::LF).unwrap();
    println!("to_sec1_pem:\n{}", *to_sec1_pem);
    let to_pkcs8_pem = key_priv.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
    println!("to_pkcs8_pem:\n{}", *to_pkcs8_pem);
}

fn p521_to_jwk() {
    let ec_p521_der = p521::SecretKey::from_pkcs8_der(EC_P521_DER).unwrap();
    let ec_p521_pem = p521::SecretKey::from_pkcs8_pem(EC_P521_PEM).unwrap();

    assert_eq!(ec_p521_der, ec_p521_pem);

    let key_priv = ec_p521_der;
    let public = key_priv.public_key();

    let encoded = public.to_encoded_point(false); // uncompressed

    let x = b64u_encode(encoded.x().unwrap());
    let y = b64u_encode(encoded.y().unwrap());

    println!("x      : {x}");
    println!("y      : {y}");

    let to_sec1_pem = key_priv.to_sec1_pem(pkcs8::LineEnding::LF).unwrap();
    println!("to_sec1_pem:\n{}", *to_sec1_pem);
    let to_pkcs8_pem = key_priv.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
    println!("to_pkcs8_pem:\n{}", *to_pkcs8_pem);
}

fn ed25519_to_jwk() {
    let ed_25519_der = ed25519_dalek::SigningKey::from_pkcs8_der(ED25519_DER).unwrap();
    let ed_25519_pem = ed25519_dalek::SigningKey::from_pkcs8_pem(ED25519_PEM).unwrap();

    assert_eq!(ed_25519_der, ed_25519_pem);

    let signing_key = ed_25519_der;
    let verifying_key = signing_key.verifying_key();
    let x = b64u_encode(verifying_key.to_bytes());

    println!("x      : {x}");

    // let to_pkcs1_pem = signing_key.to_pkcs1_pem(pkcs8::LineEnding::LF).unwrap();
    // println!("to_pkcs1_pem:\n{}", *to_pkcs1_pem);
    let to_pkcs8_pem = signing_key.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
    println!("to_pkcs8_pem:\n{}", *to_pkcs8_pem);
}

fn gen_keys() {
    use rcgen::{
        KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512,
        PKCS_ED25519, PKCS_RSA_SHA256, RsaKeySize,
    };

    let rsa_key_2048 = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let rsa_key_3072 = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_3072).unwrap();
    let rsa_key_4096 = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_4096).unwrap();
    let p256_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let p384_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let p521_key = KeyPair::generate_for(&PKCS_ECDSA_P521_SHA512).unwrap();
    let ed25519_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();

    // Serialize to PEM/DER for any of them
    // let der = p256_key.serialize_der();
    let rsa_2048_pem = rsa_key_2048.serialize_pem();
    let rsa_3072_pem = rsa_key_3072.serialize_pem();
    let rsa_4096_pem = rsa_key_4096.serialize_pem();
    let p256_pem = p256_key.serialize_pem();
    let p384_pem = p384_key.serialize_pem();
    let p521_pem = p521_key.serialize_pem();
    let ed25519_pem = ed25519_key.serialize_pem();

    println!("rsa_2048_pem pkcs pem:\n{rsa_2048_pem}");
    println!("rsa_3072_pem pkcs pem:\n{rsa_3072_pem}");
    println!("rsa_4096_pem pkcs pem:\n{rsa_4096_pem}");
    println!("p256_pem pkcs pem:\n{p256_pem}");
    println!("p384_pem pkcs pem:\n{p384_pem}");
    println!("p521_pem pkcs pem:\n{p521_pem}");
    println!("ed25519_pem pkcs pem:\n{ed25519_pem}");
}

fn main() -> color_eyre::eyre::Result<()> {
    rsa_to_jwk();
    p256_to_jwk();
    p384_to_jwk();
    p521_to_jwk();
    ed25519_to_jwk();

    println!("{:?}", detect_curve(RSA_4096_DER));
    println!("{:?}", detect_curve(EC_P256_DER));
    println!("{:?}", detect_curve(EC_P384_DER));
    println!("{:?}", detect_curve(EC_P521_DER));
    println!("{:?}", detect_curve(ED25519_DER));
    println!("{:?}", detect_curve(b"Hello"));

    // gen_keys();

    Ok(())
}
