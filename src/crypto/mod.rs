//! Key, Jwk, Signing algorithm, etc.
//!
pub(crate) mod jwk;
pub(crate) mod jws;

pub mod ec;
pub mod jwa;
pub mod key;
pub mod key_dto;
pub mod kid;
pub mod okp;
pub mod rsa;

// region:    --- Tests
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::OnceLock;

    use openssl::ec::EcKey;
    use openssl::rsa::Rsa;
    use serde::{Deserialize, Serialize};
    use url::Url;

    use super::ec::*;
    use super::jwk::*;
    use super::jws::*;
    use super::key::*;
    use super::okp::*;
    use super::rsa::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(rename_all = "UPPERCASE")]
    enum KeyFixtureType {
        #[serde(rename_all = "camelCase")]
        Rsa {
            bits: RsaKeyBits,
            signing_algo: RsaSigningAlgorithm,
            exponent: Box<str>,
            modulus: Box<str>,
        },
        #[serde(rename_all = "camelCase")]
        Ec {
            curve: EcCurve,
            signing_algo: EcSigningAlgorithm,
            x: Box<str>,
            y: Box<str>,
        },
        #[serde(rename_all = "camelCase")]
        Okp {
            curve: OkpCurve,
            signing_algo: OkpSigningAlgorithm,
            x: Box<str>,
        },
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KeyFixture {
        #[serde(flatten)]
        typ: KeyFixtureType,
        private_key_pem: String,
        public_key_pem: String,
        jwk: Box<str>,
        jwk_thumbprint: Box<str>,
        url: Url,
        nonce: Box<str>,
        body: Box<str>,
        jws_protected_header: Box<str>,
        jws: Box<str>,
    }

    enum GenFixtureKey {
        Rsa(RsaKeyBits, RsaSigningAlgorithm),
        Ec(EcCurve),
        Okp,
    }

    #[allow(clippy::needless_pass_by_value)]
    fn gen_key_fixture(typ: GenFixtureKey) -> KeyFixture {
        let (key, fixture_key_type) = match typ {
            GenFixtureKey::Rsa(bits, signing_algo) => {
                let key = Key::new_rsa(bits, signing_algo).unwrap();
                let jwk = Jwk::try_from(&key).unwrap();

                let Jwk::Rsa { exponent, modulus } = jwk else {
                    panic!()
                };

                (
                    key,
                    KeyFixtureType::Rsa {
                        bits,
                        signing_algo,
                        exponent,
                        modulus,
                    },
                )
            }
            GenFixtureKey::Ec(curve) => {
                let key = Key::new_ec(curve).unwrap();
                let jwk = Jwk::try_from(&key).unwrap();

                let Jwk::Ec { crv, x, y } = jwk else { panic!() };

                let signing_algo = curve.into();

                (
                    key,
                    KeyFixtureType::Ec {
                        curve: crv,
                        signing_algo,
                        x,
                        y,
                    },
                )
            }
            GenFixtureKey::Okp => {
                let key = Key::new_okp().unwrap();
                let jwk = Jwk::try_from(&key).unwrap();

                let Jwk::Okp { crv, public_key } = jwk else {
                    panic!()
                };

                let signing_algo = crv.into();

                (
                    key,
                    KeyFixtureType::Okp {
                        curve: crv,
                        signing_algo,
                        x: public_key,
                    },
                )
            }
        };

        let (private_key_pem, public_key_pem) = key.to_pem().unwrap();
        let jwk = Jwk::try_from(&key).unwrap();
        let jwk_thumbprint = jwk.thumbprint();
        let jwk_json = serde_json::to_string(&jwk).unwrap().into_boxed_str();
        let url = Url::parse("https://example.com").unwrap();
        let auth = JwkOrKid::Jwk(&jwk);
        let nonce = Box::from("test-nonce");
        let body = Box::from("test-body");
        let jws_protected_header = JwsProtectedHeaders::new(&key, &url, &auth, Some(&nonce));
        let jws_protected_header_json =
            serde_json::to_string(&jws_protected_header).unwrap().into_boxed_str();
        let jws = Jws::new(&key, jws_protected_header, &body);
        let jws_str = serde_json::to_string(&jws).unwrap().into_boxed_str();

        KeyFixture {
            typ: fixture_key_type,
            private_key_pem,
            public_key_pem,
            jwk: jwk_json,
            jwk_thumbprint,
            url,
            nonce,
            body,
            jws_protected_header: jws_protected_header_json,
            jws: jws_str,
        }
    }

    fn gen_all_fixtures() {
        let key_fixtures = [
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits2048,
                RsaSigningAlgorithm::RS256,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits2048,
                RsaSigningAlgorithm::RS384,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits2048,
                RsaSigningAlgorithm::RS512,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits4096,
                RsaSigningAlgorithm::RS256,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits4096,
                RsaSigningAlgorithm::RS384,
            )),
            gen_key_fixture(GenFixtureKey::Rsa(
                RsaKeyBits::Bits4096,
                RsaSigningAlgorithm::RS512,
            )),
            gen_key_fixture(GenFixtureKey::Ec(EcCurve::P256)),
            gen_key_fixture(GenFixtureKey::Ec(EcCurve::P384)),
            gen_key_fixture(GenFixtureKey::Ec(EcCurve::P521)),
            gen_key_fixture(GenFixtureKey::Okp),
        ];

        for (index, fixture) in key_fixtures.iter().enumerate().map(|(v, w)| (v + 1, w)) {
            let s = toml::to_string_pretty(&fixture).unwrap();
            // println!("{s}");
            std::fs::write(format!("tests/FIXTURE_KEY_{index:0>2}.toml"), s).unwrap();
        }
    }

    fn setup() -> &'static [KeyFixture] {
        static INSTANCE: OnceLock<Box<[KeyFixture]>> = OnceLock::new();
        use glob::glob;

        INSTANCE.get_or_init(|| {
            let should_gen_fixtures = std::env::var("GEN_FIXTURE_KEY").is_ok();

            if should_gen_fixtures {
                gen_all_fixtures();
            }

            let fixtures = glob("./tests/FIXTURE_KEY*")
                .unwrap()
                .map(|entry| {
                    let file_content = std::fs::read(entry.unwrap()).unwrap();
                    let fixture: KeyFixture = toml::from_slice(&file_content).unwrap();
                    fixture
                })
                .collect::<Vec<KeyFixture>>();

            Box::from(fixtures)
        })
    }

    #[test]
    fn rsa() {
        let fixtures = setup().iter().filter(|v| {
            let KeyFixtureType::Rsa { .. } = v.typ else {
                return false;
            };
            true
        });

        for fixture in fixtures {
            let KeyFixtureType::Rsa {
                bits,
                signing_algo,
                exponent: fixture_exponent,
                modulus: fixture_modulus,
            } = &fixture.typ
            else {
                panic!()
            };

            let rsa_private_key =
                Rsa::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();
            assert_eq!(
                bits.as_u32(),
                rsa_private_key.n().num_bits().cast_unsigned()
            );

            let key = Key::new_rsa_from_parts(rsa_private_key, *signing_algo).unwrap();

            let jwk = Jwk::try_from(&key).unwrap();
            let jwk_json = serde_json::to_string(&jwk).unwrap().into_boxed_str();

            assert_eq!(fixture.jwk, jwk_json, "Rsa Jwk Serialized are not equal");

            let Jwk::Rsa { exponent, modulus } = jwk else {
                panic!("Jwk not of type Rsa")
            };

            assert_eq!(fixture_modulus, &modulus);
            assert_eq!(fixture_exponent, &exponent);
        }
    }

    #[test]
    fn ec() {
        let fixtures = setup().iter().filter(|v| {
            let KeyFixtureType::Ec { .. } = v.typ else {
                return false;
            };
            true
        });

        for fixture in fixtures {
            let KeyFixtureType::Ec {
                curve: fixture_curve,
                signing_algo: fixture_signing_algo,
                x: fixture_x,
                y: fixture_y,
            } = &fixture.typ
            else {
                panic!()
            };

            let ec_private_key =
                EcKey::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();
            let curve = detect_ec_curve(&ec_private_key).unwrap();
            assert_eq!(*fixture_curve, curve);

            let key = Key::new_ec_from_parts(ec_private_key).unwrap();

            let jwk = Jwk::try_from(&key).unwrap();
            let jwk_json = serde_json::to_string(&jwk).unwrap().into_boxed_str();

            assert_eq!(fixture.jwk, jwk_json, "Ec Jwk Serialized are not equal");

            let Jwk::Ec { crv, x, y } = jwk else {
                panic!("Jwk not of type Ec")
            };

            let signing_algo = EcSigningAlgorithm::from(crv);

            assert_eq!(*fixture_signing_algo, signing_algo);
            assert_eq!(fixture_x, &x);
            assert_eq!(fixture_y, &y);
        }
    }

    #[test]
    fn okp() {
        let fixtures = setup().iter().filter(|v| {
            let KeyFixtureType::Okp { .. } = v.typ else {
                return false;
            };
            true
        });

        for fixture in fixtures {
            let KeyFixtureType::Okp {
                curve: fixture_curve,
                signing_algo: fixture_signing_algo,
                x: fixture_x,
            } = &fixture.typ
            else {
                panic!()
            };

            let key = Key::new_okp_from_pem(fixture.private_key_pem.as_bytes()).unwrap();

            let jwk = Jwk::try_from(&key).unwrap();
            let jwk_json = serde_json::to_string(&jwk).unwrap().into_boxed_str();

            assert_eq!(fixture.jwk, jwk_json, "Okp Jwk Serialized are not equal");

            let Jwk::Okp { crv, public_key: x } = jwk else {
                panic!("Jwk not of type Okp")
            };

            let signing_algo = OkpSigningAlgorithm::from(crv);

            assert_eq!(*fixture_curve, crv);
            assert_eq!(*fixture_signing_algo, signing_algo);
            assert_eq!(fixture_x, &x);
        }
    }

    #[test]
    fn jws_rsa() {
        let fixtures = setup().iter().filter(|v| {
            let KeyFixtureType::Rsa { .. } = v.typ else {
                return false;
            };
            true
        });

        for fixture in fixtures {
            let KeyFixtureType::Rsa { signing_algo, .. } = &fixture.typ else {
                panic!()
            };

            let rsa_private_key =
                Rsa::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();

            let key = Key::new_rsa_from_parts(rsa_private_key, *signing_algo).unwrap();

            let jwk = Jwk::try_from(&key).unwrap();
            let url = &fixture.url;
            let auth = JwkOrKid::Jwk(&jwk);
            let nonce = fixture.nonce.as_ref();
            let body = Box::<str>::from(fixture.body.as_ref());

            let jws_protected_header = JwsProtectedHeaders::new(&key, url, &auth, Some(nonce));
            let jws_protected_header_json =
                serde_json::to_string(&jws_protected_header).unwrap().into_boxed_str();

            assert_eq!(
                fixture.jws_protected_header, jws_protected_header_json,
                "Rsa Jws Protected Header Serialized are not equal"
            );

            let jws = Jws::new(&key, jws_protected_header, &body);
            let jws_json = serde_json::to_string(&jws).unwrap().into_boxed_str();

            assert_eq!(fixture.jws, jws_json, "Rsa Jws Serialized are not equal");
        }
    }

    #[test]
    fn jwk_thumbprint() {
        let fixtures = setup();

        for fixture in fixtures {
            let key = match &fixture.typ {
                KeyFixtureType::Rsa { signing_algo, .. } => {
                    let rsa_private_key =
                        Rsa::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();

                    Key::new_rsa_from_parts(rsa_private_key, *signing_algo).unwrap()
                }
                KeyFixtureType::Ec { .. } => {
                    let ec_private_key =
                        EcKey::private_key_from_pem(fixture.private_key_pem.as_bytes()).unwrap();
                    Key::new_ec_from_parts(ec_private_key).unwrap()
                }
                KeyFixtureType::Okp { .. } => {
                    Key::new_okp_from_pem(fixture.private_key_pem.as_bytes()).unwrap()
                }
            };

            let jwk = Jwk::try_from(&key).unwrap();
            assert_eq!(fixture.jwk_thumbprint, jwk.thumbprint());
        }
    }
}
// endregion: --- Tests
