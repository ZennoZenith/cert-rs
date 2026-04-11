use rcgen::{
    KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512, PKCS_ED25519,
    PKCS_RSA_SHA256,
};

use crate::{Error, Result, crypto::rsa::RsaKeySize};

/// # Errors
///
/// If `key_size` is [``crate::crypto::rsa::RsaKeySize::Bits8192``]
///
/// [rcgen] doen not support rsa 8192 key size
pub fn rsa_key_pem(key_size: RsaKeySize) -> Result<String> {
    let key = match key_size {
        RsaKeySize::Bits2048 => {
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .map_err(|e| Error::KeyGeneration(e.into()))
        }
        RsaKeySize::Bits3072 => {
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, rcgen::RsaKeySize::_3072)
                .map_err(|e| Error::KeyGeneration(e.into()))
        }
        RsaKeySize::Bits4096 => {
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, rcgen::RsaKeySize::_4096)
                .map_err(|e| Error::KeyGeneration(e.into()))
        }
        RsaKeySize::Bits8192 => {
            return Err(Error::KeyGeneration(
                "rcgen does not support 8192 key size for rsa".into(),
            ));
        }
    }?;

    Ok(key.serialize_pem())
}

/// # Errors
///
pub fn p256_key_pem() -> Result<String> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::KeyGeneration(e.into()))?;

    Ok(key.serialize_pem())
}

/// # Errors
///
pub fn p984() -> Result<String> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
        .map_err(|e| Error::KeyGeneration(e.into()))?;

    Ok(key.serialize_pem())
}

/// # Errors
///
pub fn p521_key_pem() -> Result<String> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P521_SHA512)
        .map_err(|e| Error::KeyGeneration(e.into()))?;

    Ok(key.serialize_pem())
}

/// # Errors
///
pub fn ed25519_key_pem() -> Result<String> {
    let key = KeyPair::generate_for(&PKCS_ED25519).map_err(|e| Error::KeyGeneration(e.into()))?;

    Ok(key.serialize_pem())
}
