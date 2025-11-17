use color_eyre::Result;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    stack::Stack,
    x509::{
        X509NameBuilder, X509Req, X509ReqBuilder,
        extension::SubjectAlternativeName,
    },
};

///```sh
///$subject_alt_name = "subjectAltName = DNS:test.com, DNS:*.test.com"
///## subjectAltName = DNS:yoursite.com, DNS:www.yoursite.com
///openssl req -new -sha256 -key $domain_private_key_file -subj "/" -addext $subject_alt_name
///```
pub fn generate_csr(
    domain_private_key: PKey<Private>,
    domains: &[String],
) -> Result<X509Req> {
    // === Build empty subject (equivalent to "-subj /") ===
    let name_builder = X509NameBuilder::new()?;
    // No fields added → empty subject
    let name = name_builder.build();

    // === Build CSR ===
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_version(0)?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(&domain_private_key)?;

    // === Add SAN extension (equivalent to -addext subjectAltName=DNS:... ) ===
    let mut san_ext = SubjectAlternativeName::new();

    for domain in domains {
        san_ext.dns(domain);
    }
    let san_ext = san_ext.build(&req_builder.x509v3_context(None))?;

    // CSR extensions must be put into a stack
    let mut ext_stack = Stack::new()?;
    ext_stack.push(san_ext)?;

    req_builder.add_extensions(&ext_stack)?;

    // === Sign CSR using SHA256 (equivalent to -sha256) ===
    req_builder.sign(&domain_private_key, MessageDigest::sha256())?;

    let csr: X509Req = req_builder.build();

    Ok(csr)
}

// ///```sh
// ///openssl req -in $csf_file -inform PEM -outform DER
// ///```
// pub fn encode_csr_to_der(csr: X509Req) {
//     let der_bytes = csr.to_der()?;
// }

// region:    --- Tests
#[cfg(test)]
mod tests {
    pub type Result<T> = std::result::Result<T, Error>;
    pub type Error = Box<dyn std::error::Error>; // For tests.

    use lib_utils::b64;
    use openssl::pkey::PKey;

    use super::*;

    const FIXTURE_DOMAIN_KEY_PEM: &str =
        include_str!("../tests/FIXTURE_DOMAIN_KEY.pem");

    const FIXTURE_CSR_PEM: &str = include_str!("../tests/FIXTURE_CSR.pem");

    #[test]
    fn csr_ok() -> Result<()> {
        let domain_private_key =
            PKey::private_key_from_pem(FIXTURE_DOMAIN_KEY_PEM.as_bytes())?;

        let domains = [String::from("test.com"), String::from("*.test.com")];

        let csr = generate_csr(domain_private_key, &domains).unwrap();

        let csr = String::from_utf8(csr.to_pem()?)?;

        assert_eq!(csr, FIXTURE_CSR_PEM);

        Ok(())
    }

    #[test]
    fn csr_base64_encode_ok() -> Result<()> {
        let domain_private_key =
            PKey::private_key_from_pem(FIXTURE_DOMAIN_KEY_PEM.as_bytes())?;

        let domains = [String::from("test.com"), String::from("*.test.com")];

        let csr = generate_csr(domain_private_key, &domains).unwrap();

        let csr_der_bytes = csr.to_der()?;
        let csr_der_base64 = b64::b64u_encode(csr_der_bytes);

        // println!("{}", csr_der_base64);

        const FIXTURE_CSR_PEM_BASE64: &str = "MIIEdzCCAl8CAQAwADCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMVToUrl1gkTzexlNCVZT7SqRCTRDR7WlVU5tE_yJGMbw-8QGQQ4dvlAmdVo0aYCfBsrK3lDaQzbYfrxOPdNgvVVlZ0G3gdN-NxnmtCSxm3wgcV3lxRlgMwxuQA62jkCf8rCKCe0jcubxqu0-zaqTlEqgg7b9UOh4jcry-7cPNmj-O_7goWO09VhxL7PBxi2cId2sa1c0eRihPRM1AbNKCZNkCCNXwsUKGLhDyI1Ccidlmfy_1rYkwk6p3toEMsaygwrDJflJjvBDeLrjPs3N0UvzzBoNNoSQbxfbWozfAOB9hkBwm9QN5q6BmAAzUNzYC_sT4nVNgSZ20y36TDeA_LIMIzVIitKcWQzsV7MQ1w39sMeUZfK6UKDk1v6ViGwznz9FSbNJzFEdoWjTJOmGDVaLTEMbHBXyyZ0ajVRPo_04wtjzqGa4PM1oJtyjA-IHeZz3MujIlLY2anbS0f9MpVgWltfZI5vP6orTQ9Fi3gOxRSVPkiwNNJf6ZCuRz4tDhMRA9nrFQFybFdx90ffFNnUiYJhjWTfa8qiTcCbWuT3bAn9HZszbvyiTNsGbEEau8enN4Zr71lgXffxvNsYQzwBtix70ECMqUjO2HycLWKk_C3Mll01uU6vP5pO7SHXrK6X0mDzfuI3cCOQS6_neJmSyO0P4rmxyYxZJkNl-jH5AgMBAAGgMjAwBgkqhkiG9w0BCQ4xIzAhMB8GA1UdEQQYMBaCCHRlc3QuY29tggoqLnRlc3QuY29tMA0GCSqGSIb3DQEBCwUAA4ICAQBQSD4rYWa4XgQedxb-3f4IQe6YAx2umX8J8OtfTw-kd0UtpASu5E5U7ktocEJP8G2ZREvTOVtwhdXsQShsOsVjeO3AHVYICdTCHSrNdstyRLsGbj-2fTzlY-F-GbchLGk4XDpEsJ2RKbySPoIzYskQ1-jQB_0eEs-T5OGXbM7kd62CCSw9fzdiURwTTp-qUccer1YWZpzILwuhrvMFl5Rx7v8JwFdNwIYsQcSVg_2gm4WjvPW7XRrZ6ivArgHyDCx_S0e4N-n385TBolzvvVGQesoQen3jA6BW9Pas9HAAKATZrVyD9QQ7UiVGnPbeUOpJM9fAIifHM8AFMm3DENMk58PggQAYMV1-ICdvEe6uN6ZKxWnlR94SNN1pHlws8l6mvgtPg8LIk8gejYuk-ZLHxzflcXYZeS9DyxXZXHMmW1HforJklByc0P_xIODi55IeRj8WkncjZZMpZzWRA6P7GOcusTZEW8mFLNiOaNZG1ljDaWEfdNMjyI_WmBIpfqArqtZZhAqJkicFNbRcmH2IEMg7Z_esngf1DIbK8z4zX-73IasJGCin38oIyCLEMbi_p70HzkexJYmZxJGfIATTDeSdsLG5JyiuIUaLI3PILepgdFwNMEuiofIv8H5ohdw7meFXGVeTgJ-FESI6SINWlamUt-BXmvyDI_5GwgCVKA";

        assert_eq!(csr_der_base64, FIXTURE_CSR_PEM_BASE64);

        Ok(())
    }
}

// endregion: --- Tests
