#![deny(clippy::all)]
#![deny(clippy::expect_used)]
#![deny(clippy::unwrap_used)]
#![warn(clippy::cargo)]
#![warn(clippy::complexity)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::perf)]
#![allow(clippy::multiple_crate_versions)] // FIX:
// #![allow(dead_code)] // FIX: For exploratory dev.
#![allow(unused)] // FIX: For exploratory dev.

use std::net::IpAddr;

use cert_rs::{
    Client, Error, Key, LetsEncrypt, RetryPolicy,
    account::{Account, NewAccount},
    authorization::Authorization,
    challenge::{Challenge, Dns01Challenge, Http01Challenge, KnownChallenge, TlsAlpn01Challenge},
    crypto::key::FromDerPemPkcs8,
    order::{Identifier, NewOrder, Order, OrderStatus},
};
use chrono::Duration;
use clap::Parser;
use colored::Colorize;
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Parser, Debug, Clone)]
#[command(name = "cert-rs-cli", about = "", long_about = "")]
pub struct Config {
    /// ACME Directory url
    #[arg(short, long)]
    pub url: Option<Url>,

    /// Skip TLS certificate verification (for self-signed certs)
    #[arg(long, default_value = "false")]
    pub insecure: bool,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    pub timeout: u64,

    /// Show verbose output (full response bodies)
    #[arg(short, long)]
    pub verbose: bool,

    /// Output test results as JSON
    #[arg(long)]
    pub json: bool,
}

fn print_banner() {
    println!(
        "{}",
        "
  ╔═══════════════════════════════════════════════════╗
  ║        REVERSE PROXY TEST CLIENT  v0.1.0          ║
  ║        Rust • clap • tokio • reqwest              ║
  ╚═══════════════════════════════════════════════════╝"
            .cyan()
    );
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    tracing_subscriber::fmt()
        .without_time() // For early local development.
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let config = Config::parse();
    // dbg!(&config);

    print_banner();

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.insecure)
        .build()?;

    let directory_url = config.url.unwrap_or_else(|| {
        #[allow(clippy::expect_used)]
        Url::try_from(LetsEncrypt::Staging).expect("NOT A URL")
    });

    let nonce_retry_policy = RetryPolicy::new(Duration::zero(), 1.0, Duration::seconds(5));
    let client = Client::new(client, directory_url, Some(nonce_retry_policy)).await?;
    // dbg!(&client.directory());

    let account_create = NewAccount {
        terms_of_service_agreed: Some(true),
        contacts: Some(vec![String::from("mailto:test@example.com")]),
        // only_return_existing: Some(true),
        ..Default::default()
    };

    let key_1_pem = cert_rs::generate::rsa_key_pem(cert_rs::crypto::rsa::RsaKeySize::Bits2048)?;
    let key_2_pem = cert_rs::generate::p256_key_pem()?;

    let key_1 = Key::from_pkcs8_pem(&key_1_pem)?;
    let key_2 = Key::from_pkcs8_pem(&key_2_pem)?;

    let account = Account::create(client, key_1, account_create).await?;

    let account = account.key_rollover(key_2).await?;
    // //// OR
    // // account.key_rollover_mut(key_2).await?;
    // println!("{}", &serde_json::to_string_pretty(&account.credentials())?);

    //// Account deactivated
    // let account_cred = account.credentials().to_owned();
    // account.deactivate().await?;
    // let account = Account::load(arc_client.clone(), account_cred);

    let domains: Vec<String> =
        vec![String::from("abc.zennozenith.com"), String::from("*.zennozenith.com")];
    let new_order = NewOrder::from_domains(domains);

    // let ips: Vec<IpAddr> = vec![IpAddr::from([127, 0, 0, 1])];
    // let new_order = NewOrder::from_ips(ips);

    let (order_url, _order) = Order::create(&account, new_order).await?;

    let order = Order::status(&account, &order_url).await?;

    let mut challenge_urls = vec![];
    for authz_url in order.authorizations {
        let authorization = Authorization::get(&account, &authz_url).await?;

        let wildcard = authorization.wildcard.unwrap_or(false);

        let identifier_value = match &authorization.identifier {
            Identifier::Dns(v) => v.to_owned(),
            Identifier::Ip(ip_addr) => ip_addr.to_string(),
            v => panic!("{v} identifier not supported."),
        };

        let Some((base, token)) = authorization.challenges.iter().find_map(|v| match v {
            Challenge::Known(KnownChallenge::Http01(Http01Challenge { base, token }))
                if !wildcard =>
            {
                Some((base, token))
            }
            // Challenge::Known(KnownChallenge::TlsAlpn01(TlsAlpn01Challenge { base, token }))
            //     if !wildcard =>
            // {
            //     Some((base, token))
            // }
            Challenge::Known(KnownChallenge::Dns01(Dns01Challenge { base, token })) if wildcard => {
                Some((base, token))
            }

            _ => None,
        }) else {
            return Err(color_eyre::eyre::eyre!(
                "Cannot respond to unknown challenge"
            ));
        };
        let challenge_url = base.url.clone();

        let sha_256_keyauth = Authorization::gen_sha_256_keyauth(&account, token);
        let keyauth = Authorization::gen_keyauth(&account, token);
        if wildcard {
            handle_dns_01_challenge(&identifier_value, &sha_256_keyauth).await?;
        } else {
            handle_http_01_challenge(token, &keyauth).await?;
            // handle_tls_alpn_01_challenge(&identifier_value, &keyauth).await?;
        }

        challenge_urls.push(challenge_url);
    }

    println!("Responding to challenge in 3 seconds");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    for challenge_url in &challenge_urls {
        let challenge = KnownChallenge::respond(&account, challenge_url).await?;
        dbg!(challenge);
    }

    let order = loop {
        let order = Order::status(&account, &order_url).await?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        match order.status {
            OrderStatus::Pending | OrderStatus::Processing => {
                println!("Order {}. Continuing...", order.status);
            }
            OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid => {
                println!("Order {}. Breaking...", order.status);
                break order;
            }
        }
    };

    dbg!(&order);

    let domain_key_pem = cert_rs::generate::p256_key_pem()?;
    let domain_key = Key::from_pkcs8_pem(&domain_key_pem)?;

    let csr = order.finalize(&account, &domain_key).await?;
    let csr_pem = csr.pem()?;
    println!("CSR PEM:\n{csr_pem}");

    let cert = loop {
        let order = Order::status(&account, &order_url).await?;
        match order.poll_certificate(&account, &RetryPolicy::default()).await {
            Ok(cert) => break cert,
            Err(e @ Error::CertificateUrlNotPresent) => {
                println!("{e}. trying again.");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e)?,
        }
    };

    println!("Certificate:\n{cert}");

    Ok(())
}

async fn handle_http_01_challenge(
    challenge_token: &str,
    keyauth: &str,
) -> color_eyre::eyre::Result<()> {
    let chall_test_srv: Url = std::env::var("TEST_CHALL_TEST_SRV")
        .unwrap_or_else(|_| String::from("http://localhost:8055"))
        .parse()?;

    #[allow(clippy::expect_used)]
    let http_01_url = chall_test_srv
        .join("add-http01")
        .expect("Cannot join url path")
        .to_string();

    #[allow(clippy::expect_used)]
    let clear_http_01 = chall_test_srv
        .join("del-http01")
        .expect("Cannot join url path")
        .to_string();

    // clear http_01 challenges
    reqwest::Client::new()
        .post(&clear_http_01)
        .json(&serde_json::json!({
            "token": challenge_token
        }))
        .send()
        .await?;

    reqwest::Client::new()
        .post(&http_01_url)
        .json(&serde_json::json!({
            "token": challenge_token,
            "content": keyauth
        }))
        .send()
        .await?;

    Ok(())
}

async fn handle_dns_01_challenge(
    domain: &str,
    sha_256_keyauth: &str,
) -> color_eyre::eyre::Result<()> {
    let chall_test_srv: Url = std::env::var("TEST_CHALL_TEST_SRV")
        .unwrap_or_else(|_| String::from("http://localhost:8055"))
        .parse()?;

    #[allow(clippy::expect_used)]
    let dns_01_url = chall_test_srv
        .join("set-txt")
        .expect("Cannot join url path")
        .to_string();

    #[allow(clippy::expect_used)]
    let clear_dns_01 = chall_test_srv
        .join("clear-txt")
        .expect("Cannot join url path")
        .to_string();

    // dns_01 challenges
    let host = format!("_acme-challenge.{domain}.");

    reqwest::Client::new()
        .post(&clear_dns_01)
        .json(&serde_json::json!({
            "host": host
        }))
        .send()
        .await?;

    reqwest::Client::new()
        .post(&dns_01_url)
        .json(&serde_json::json!({
            "host": host,
            "value": sha_256_keyauth
        }))
        .send()
        .await?;
    Ok(())
}

async fn handle_tls_alpn_01_challenge(
    domain: &str,
    sha_256_keyauth: &str,
) -> color_eyre::eyre::Result<()> {
    let chall_test_srv: Url = std::env::var("TEST_CHALL_TEST_SRV")
        .unwrap_or_else(|_| String::from("http://localhost:8055"))
        .parse()?;

    #[allow(clippy::expect_used)]
    let tls_alpn_01_url = chall_test_srv
        .join("add-tlsalpn01")
        .expect("Cannot join url path")
        .to_string();

    #[allow(clippy::expect_used)]
    let clear_tls_alpn_01 = chall_test_srv
        .join("del-tlsalpn01")
        .expect("Cannot join url path")
        .to_string();

    // dns_01 challenges

    reqwest::Client::new()
        .post(&clear_tls_alpn_01)
        .json(&serde_json::json!({
            "host": domain
        }))
        .send()
        .await?;

    reqwest::Client::new()
        .post(&tls_alpn_01_url)
        .json(&serde_json::json!({
            "host": domain,
            "content": sha_256_keyauth
        }))
        .send()
        .await?;
    Ok(())
}
