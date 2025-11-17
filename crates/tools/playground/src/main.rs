use color_eyre::Result;
use lib_utils::b64;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    stack::Stack,
    x509::{
        X509NameBuilder, X509Req, X509ReqBuilder,
        extension::SubjectAlternativeName,
    },
};

fn main() -> Result<()> {
    color_eyre::install()?;

    const FIXTURE_DOMAIN_KEY_PEM: &str =
        include_str!("../../../libs/lib-acme/tests/FIXTURE_DOMAIN_KEY.pem");
    const FIXTURE_CSR_PEM: &str =
        include_str!("../../../libs/lib-acme/tests/FIXTURE_CSR.pem");

    let pkey = PKey::private_key_from_pem(FIXTURE_DOMAIN_KEY_PEM.as_bytes())?;

    // === Build empty subject (equivalent to "-subj /") ===
    let name_builder = X509NameBuilder::new()?;
    // No fields added → empty subject
    let name = name_builder.build();

    // === Build CSR ===
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_version(0)?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(&pkey)?;

    // === Add SAN extension (equivalent to -addext subjectAltName=DNS:... ) ===
    let san_ext = SubjectAlternativeName::new()
        .dns("test.com")
        .dns("*.test.com")
        .build(&req_builder.x509v3_context(None))?;

    // CSR extensions must be put into a stack
    let mut ext_stack = Stack::new()?;
    ext_stack.push(san_ext)?;

    req_builder.add_extensions(&ext_stack)?;

    // === Sign CSR using SHA256 (equivalent to -sha256) ===
    req_builder.sign(&pkey, MessageDigest::sha256())?;

    let csr: X509Req = req_builder.build();

    let csr_pem = String::from_utf8(csr.to_pem()?)?;

    // println!("{}", csr_pem);

    assert_eq!(csr_pem, FIXTURE_CSR_PEM);

    let csr_der_bytes = csr.to_der()?;
    let csr_der_base64 = b64::b64u_encode(csr_der_bytes);

    // println!("{}", csr_der_base64);

    const FIXTURE_CSR_PEM_BASE64: &str = "MIIEdzCCAl8CAQAwADCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMVToUrl1gkTzexlNCVZT7SqRCTRDR7WlVU5tE_yJGMbw-8QGQQ4dvlAmdVo0aYCfBsrK3lDaQzbYfrxOPdNgvVVlZ0G3gdN-NxnmtCSxm3wgcV3lxRlgMwxuQA62jkCf8rCKCe0jcubxqu0-zaqTlEqgg7b9UOh4jcry-7cPNmj-O_7goWO09VhxL7PBxi2cId2sa1c0eRihPRM1AbNKCZNkCCNXwsUKGLhDyI1Ccidlmfy_1rYkwk6p3toEMsaygwrDJflJjvBDeLrjPs3N0UvzzBoNNoSQbxfbWozfAOB9hkBwm9QN5q6BmAAzUNzYC_sT4nVNgSZ20y36TDeA_LIMIzVIitKcWQzsV7MQ1w39sMeUZfK6UKDk1v6ViGwznz9FSbNJzFEdoWjTJOmGDVaLTEMbHBXyyZ0ajVRPo_04wtjzqGa4PM1oJtyjA-IHeZz3MujIlLY2anbS0f9MpVgWltfZI5vP6orTQ9Fi3gOxRSVPkiwNNJf6ZCuRz4tDhMRA9nrFQFybFdx90ffFNnUiYJhjWTfa8qiTcCbWuT3bAn9HZszbvyiTNsGbEEau8enN4Zr71lgXffxvNsYQzwBtix70ECMqUjO2HycLWKk_C3Mll01uU6vP5pO7SHXrK6X0mDzfuI3cCOQS6_neJmSyO0P4rmxyYxZJkNl-jH5AgMBAAGgMjAwBgkqhkiG9w0BCQ4xIzAhMB8GA1UdEQQYMBaCCHRlc3QuY29tggoqLnRlc3QuY29tMA0GCSqGSIb3DQEBCwUAA4ICAQBQSD4rYWa4XgQedxb-3f4IQe6YAx2umX8J8OtfTw-kd0UtpASu5E5U7ktocEJP8G2ZREvTOVtwhdXsQShsOsVjeO3AHVYICdTCHSrNdstyRLsGbj-2fTzlY-F-GbchLGk4XDpEsJ2RKbySPoIzYskQ1-jQB_0eEs-T5OGXbM7kd62CCSw9fzdiURwTTp-qUccer1YWZpzILwuhrvMFl5Rx7v8JwFdNwIYsQcSVg_2gm4WjvPW7XRrZ6ivArgHyDCx_S0e4N-n385TBolzvvVGQesoQen3jA6BW9Pas9HAAKATZrVyD9QQ7UiVGnPbeUOpJM9fAIifHM8AFMm3DENMk58PggQAYMV1-ICdvEe6uN6ZKxWnlR94SNN1pHlws8l6mvgtPg8LIk8gejYuk-ZLHxzflcXYZeS9DyxXZXHMmW1HforJklByc0P_xIODi55IeRj8WkncjZZMpZzWRA6P7GOcusTZEW8mFLNiOaNZG1ljDaWEfdNMjyI_WmBIpfqArqtZZhAqJkicFNbRcmH2IEMg7Z_esngf1DIbK8z4zX-73IasJGCin38oIyCLEMbi_p70HzkexJYmZxJGfIATTDeSdsLG5JyiuIUaLI3PILepgdFwNMEuiofIv8H5ohdw7meFXGVeTgJ-FESI6SINWlamUt-BXmvyDI_5GwgCVKA";

    assert_eq!(csr_der_base64, FIXTURE_CSR_PEM_BASE64);

    Ok(())
}
