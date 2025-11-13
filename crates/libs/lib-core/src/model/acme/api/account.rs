use std::sync::Arc;

pub use error::Error;

use lib_utils::b64;
use openssl::{
    pkey::{Private, Public},
    rsa::Rsa,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::model::acme::account::{AcmeAccount, KeyType};

pub type Result<T> = std::result::Result<T, Error>;

mod error {
    use serde::Serialize;
    use serde_with::serde_as;

    #[serde_as]
    #[derive(thiserror::Error, Debug, Serialize, strum_macros::Display)]
    pub enum Error {
        PrivateKeyGeneration(String),
        DomainKeyGeneration(String),
        PublicKeyFromPem(String),
        PrivateKeyFromPem(String),
        DomainKeyFromPem(String),
    }
}

pub struct AccountCert {
    pub(crate) private_key: Rsa<Private>,
    pub(crate) public_key: Rsa<Public>,
    pub(crate) domain_key: Rsa<Private>,
    pub(crate) key_type: KeyType,
}

impl AccountCert {
    pub fn new() -> Result<Self> {
        let private_key = Rsa::generate(4096)
            .map_err(|e| Error::PrivateKeyGeneration(e.to_string()))?;

        let public_key_pem = private_key
            .public_key_to_pem()
            .expect("Unable to get public key pair from private key");

        let public_key = Rsa::public_key_from_pem(&public_key_pem)
            .map_err(|e| Error::PublicKeyFromPem(e.to_string()))?;

        let domain_key = Rsa::generate(4096)
            .map_err(|e| Error::DomainKeyGeneration(e.to_string()))?;

        Ok(Self {
            private_key,
            public_key,
            domain_key,
            key_type: KeyType::Rsa,
        })
    }

    pub fn from_blob(
        private_key: &[u8],
        public_key: &[u8],
        domain_key: &[u8],
    ) -> Result<Self> {
        let public_key = Rsa::<Public>::public_key_from_pem(public_key)
            .map_err(|e| Error::PublicKeyFromPem(e.to_string()))?;

        let domain_key = Rsa::<Private>::private_key_from_pem(domain_key)
            .map_err(|e| Error::DomainKeyFromPem(e.to_string()))?;

        let private_key = Rsa::<Private>::private_key_from_pem(private_key)
            .map_err(|e| Error::PrivateKeyFromPem(e.to_string()))?;

        Ok(Self {
            private_key,
            public_key,
            domain_key,
            key_type: KeyType::Rsa,
        })
    }

    // pub fn private_key(&self) -> &Rsa<Private> {
    //     &self.private_key
    // }

    // pub fn public_key(&self) -> &Rsa<Public> {
    //     &self.public_key
    // }

    // pub fn domain_key(&self) -> &Rsa<Private> {
    //     &self._domain_key
    // }
}

impl TryFrom<AcmeAccount> for AccountCert {
    type Error = &'static str;

    fn try_from(value: AcmeAccount) -> std::result::Result<Self, Self::Error> {
        let AcmeAccount {
            private_key_pem,
            public_key_pem,
            domain_key_pem,
            ..
        } = value;

        AccountCert::from_blob(
            &private_key_pem,
            &public_key_pem,
            &domain_key_pem,
        )
        .map_err(|_| "error")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    /// Public key exponent base64 url encoded no pad
    #[serde(rename = "e")]
    exponent: Arc<str>,
    /// Key type
    #[serde(rename = "kty")]
    key_type: KeyType,
    /// Public key modulus base64 url encoded no pad
    #[serde(rename = "n")]
    modulus: Arc<str>,

    #[serde(skip)]
    /// self -> to json -> to hex -> base64url
    _jwk_thumbprint: Arc<str>,
}

impl From<&AccountCert> for Jwk {
    fn from(value: &AccountCert) -> Self {
        let modulus =
            Arc::from(b64::b64u_encode(value.public_key.n().to_vec()));
        let exponent =
            Arc::from(b64::b64u_encode(value.public_key.e().to_vec()));
        let key_type = value.key_type.clone();

        let jwk = serde_json::to_string(&json!({
           "e": exponent,
           "kty": key_type,
           "n": modulus,
        }))
        .expect("Failed to serialize jwk");

        let hash = Sha256::digest(jwk).to_vec();
        let jwk_thumbprint = Arc::from(b64::b64u_encode(hash));

        Self {
            exponent,
            key_type,
            modulus,
            _jwk_thumbprint: jwk_thumbprint,
        }
    }
}

impl From<AccountCert> for Jwk {
    fn from(value: AccountCert) -> Self {
        Jwk::from(&value)
    }
}

// impl Jwk {
//     pub fn jwk_thumbprint(&self) -> &str {
//         &self.jwk_thumbprint
//     }
// }

// region:    --- Tests
#[cfg(test)]
mod tests {
    pub type Result<T> = std::result::Result<T, Error>;
    pub type Error = Box<dyn std::error::Error>; // For tests.

    use std::ops::Deref;

    use openssl::pkey::PKey;

    use super::*;

    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
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
zWpbOc/sKcKGY8weNnAqEgqup3NC
-----END PRIVATE KEY-----
";

    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs+0O/n6TqJa2xms/kdbU
L8cXOS39WM9sg+Q4Fk7/SXtIZ0AAIVKpqawPCMvzDxZX9gnVKMYzIYMigl7FtJHf
F4SPnrQWLYy0gM5EAqJp4wj4+yzmDxtVOR0X48VVGiS1NErvLuSoMnWUHdc1Xusu
y5pKXH7Tc+q9NYBpVxn+RL2kZuG19mPX5Dh5d9pmINY1L5umVYIJl5ptcrMRE/Qj
jrwlRZxEBg9TybqW3LJHnCoNLVjNIO4jruGzE8VcRKeY+yIocMP0Hm8vNJY5A+Im
Q5PRRrkJ7CMfnG3wx76GhEoyWuU2jGo5360t8NGLIqgM+CjeGVdvt00TEHQgtFkC
1X9Rzi1r936wPl+uBSat6lT+YFnnwYwCmJoIVcUFxaktrNgr2CrfJ4c6VGpGxYvT
u5y9cTLllZ7BsaNuBfoGaSja7HCnJMqaLtGsJ6pvztufxpGsO+uCVSMXMG0vTv6t
5kDPque2iNrQB4loi+gNssiNMlt1mZgLzDQSl9CaqBhwU6pTtpYmFcLJvQaZ1P6V
A8yFuxoTvRt8awm4R8DGgeRIRXQflDPxsvySX31ZNx/S6WIJ1nqgS75DzFo24TeH
/ndWGfiaAp6f5MKDbCp22HSm5pODVhhVESvZB8KsvbXIkI9Aya6Kpiu1DTfPcUUh
QeCo5tUQkRV4d39agLjXHHcCAwEAAQ==
-----END PUBLIC KEY-----
";

    #[test]
    fn public_key_from_private_key() -> Result<()> {
        let private_key =
            Rsa::private_key_from_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
        let public_key = PKey::from_rsa(private_key)
            .unwrap()
            .public_key_to_pem()
            .unwrap();

        let public_key_str = String::from_utf8(public_key).unwrap();
        assert_eq!(public_key_str, TEST_PUBLIC_KEY);

        Ok(())
    }

    #[test]
    fn public_key_modulus() -> Result<()> {
        let domain_key =
            Rsa::generate(4096).unwrap().private_key_to_pem().unwrap();

        let account_cert = AccountCert::from_blob(
            TEST_PRIVATE_KEY.as_bytes(),
            TEST_PUBLIC_KEY.as_bytes(),
            &domain_key,
        )
        .unwrap();

        const FIXTURE_MODULUS_HEX: &str = "B3ED0EFE7E93A896B6C66B3F91D6D42FC717392DFD58CF6C83E438164EFF497B486740002152A9A9AC0F08CBF30F1657F609D528C633218322825EC5B491DF17848F9EB4162D8CB480CE4402A269E308F8FB2CE60F1B55391D17E3C5551A24B5344AEF2EE4A83275941DD7355EEB2ECB9A4A5C7ED373EABD3580695719FE44BDA466E1B5F663D7E4387977DA6620D6352F9BA6558209979A6D72B31113F4238EBC25459C44060F53C9BA96DCB2479C2A0D2D58CD20EE23AEE1B313C55C44A798FB222870C3F41E6F2F34963903E2264393D146B909EC231F9C6DF0C7BE86844A325AE5368C6A39DFAD2DF0D18B22A80CF828DE19576FB74D13107420B45902D57F51CE2D6BF77EB03E5FAE0526ADEA54FE6059E7C18C02989A0855C505C5A92DACD82BD82ADF27873A546A46C58BD3BB9CBD7132E5959EC1B1A36E05FA066928DAEC70A724CA9A2ED1AC27AA6FCEDB9FC691AC3BEB82552317306D2F4EFEADE640CFAAE7B688DAD00789688BE80DB2C88D325B7599980BCC341297D09AA8187053AA53B6962615C2C9BD0699D4FE9503CC85BB1A13BD1B7C6B09B847C0C681E44845741F9433F1B2FC925F7D59371FD2E96209D67AA04BBE43CC5A36E13787FE775619F89A029E9FE4C2836C2A76D874A6E69383561855112BD907C2ACBDB5C8908F40C9AE8AA62BB50D37CF71452141E0A8E6D510911578777F5A80B8D71C77";

        const FIXTURE_MODULUS_BASE64_URL_NOPAD: &str = "s-0O_n6TqJa2xms_kdbUL8cXOS39WM9sg-Q4Fk7_SXtIZ0AAIVKpqawPCMvzDxZX9gnVKMYzIYMigl7FtJHfF4SPnrQWLYy0gM5EAqJp4wj4-yzmDxtVOR0X48VVGiS1NErvLuSoMnWUHdc1Xusuy5pKXH7Tc-q9NYBpVxn-RL2kZuG19mPX5Dh5d9pmINY1L5umVYIJl5ptcrMRE_QjjrwlRZxEBg9TybqW3LJHnCoNLVjNIO4jruGzE8VcRKeY-yIocMP0Hm8vNJY5A-ImQ5PRRrkJ7CMfnG3wx76GhEoyWuU2jGo5360t8NGLIqgM-CjeGVdvt00TEHQgtFkC1X9Rzi1r936wPl-uBSat6lT-YFnnwYwCmJoIVcUFxaktrNgr2CrfJ4c6VGpGxYvTu5y9cTLllZ7BsaNuBfoGaSja7HCnJMqaLtGsJ6pvztufxpGsO-uCVSMXMG0vTv6t5kDPque2iNrQB4loi-gNssiNMlt1mZgLzDQSl9CaqBhwU6pTtpYmFcLJvQaZ1P6VA8yFuxoTvRt8awm4R8DGgeRIRXQflDPxsvySX31ZNx_S6WIJ1nqgS75DzFo24TeH_ndWGfiaAp6f5MKDbCp22HSm5pODVhhVESvZB8KsvbXIkI9Aya6Kpiu1DTfPcUUhQeCo5tUQkRV4d39agLjXHHc";

        let modulus = account_cert
            .public_key
            .n()
            .to_hex_str()
            .unwrap()
            .to_string();
        // println!("modulus: {modulus}");
        assert_eq!(FIXTURE_MODULUS_HEX, modulus);

        let jwk = Jwk::from(account_cert);
        println!("modulus: {}", jwk.modulus);
        assert_eq!(FIXTURE_MODULUS_BASE64_URL_NOPAD, jwk.modulus.deref());

        Ok(())
    }

    #[test]
    fn public_key_exponent() -> Result<()> {
        let domain_key =
            Rsa::generate(4096).unwrap().private_key_to_pem().unwrap();

        let account_cert = AccountCert::from_blob(
            TEST_PRIVATE_KEY.as_bytes(),
            TEST_PUBLIC_KEY.as_bytes(),
            &domain_key,
        )
        .unwrap();

        const FIXTURE_EXPONENT_BASE64_URL_NOPAD: &str = "AQAB";

        let jwk = Jwk::from(account_cert);
        println!("exponent_base64: {}", jwk.exponent);
        assert_eq!(FIXTURE_EXPONENT_BASE64_URL_NOPAD, jwk.exponent.deref());

        Ok(())
    }
}
// endregion: --- Tests
