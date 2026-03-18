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

use cert_rs::{
    AcmeClient, Error,
    account::{Account, AccountCreate},
    authorization::Authorization,
    challenge::{Challenge, Dns01Challenge, Http01Challenge, KnownChallenge},
    directory::Directory,
    order::{Order, OrderStatus},
};
use clap::Parser;
use colored::Colorize;
use reqwest::Client;
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
    let config = Config::parse();
    // dbg!(&config);

    print_banner();

    let client = Client::builder()
        .danger_accept_invalid_certs(config.insecure)
        .build()?;

    let directory = match config.url {
        Some(url) => Directory::new_from_url_with_client(&client, url).await?,
        None => Directory::lets_encrypt_staging().await?,
    };
    // dbg!(&directory);

    let acme_client = AcmeClient::new(client, directory);

    let account_create = AccountCreate {
        terms_of_service_agreed: Some(true),
        contacts: Some(vec![String::from("mailto:test@example.com")]),
        // only_return_existing: Some(true),
        ..Default::default()
    };

    let account = Account::create(&acme_client, account_create).await?;
    // dbg!(&account);

    let domains: Vec<String> =
        vec![String::from("abc.zennozenith.com"), String::from("*.zennozenith.com")];

    let (order_url, _order) = Order::create(&acme_client, &account, domains).await?;

    let order = Order::status(&acme_client, &account, &order_url).await?;

    let mut challenge_urls = vec![];
    for authz_url in order.authorizations {
        let authorization = Authorization::get(&acme_client, &account, &authz_url).await?;

        let wildcard = authorization.wildcard.unwrap_or(false);

        let domain = authorization.identifier.value.as_str();

        let Some((base, token)) = authorization.challenges.iter().find_map(|v| match v {
            Challenge::Known(KnownChallenge::Http01(Http01Challenge { base, token }))
                if !wildcard =>
            {
                Some((base, token))
            }
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

        if wildcard {
            let sha_256_keyauth =
                authorization.gen_sha_256_keyauth(token, account.jwk_thumbprint());
            handle_dns_01_challenge(domain, &sha_256_keyauth).await?;
        } else {
            let keyauth = authorization.gen_keyauth(token, account.jwk_thumbprint());
            handle_http_01_challenge(token, &keyauth).await?;
        }

        challenge_urls.push(challenge_url);
    }

    println!("Responding to challenge in 3 seconds");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    for challenge_url in &challenge_urls {
        let challenge = KnownChallenge::respond(&acme_client, &account, challenge_url).await?;
        dbg!(challenge);
    }

    let order = loop {
        let order = Order::status(&acme_client, &account, &order_url).await?;
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

    let csr = order.finalize(&acme_client, &account).await?;
    let csr_pem = csr.to_pem().map(|v| String::from_utf8_lossy(&v).into_owned())?;
    println!("CSR PEM:\n{csr_pem}");

    let cert = loop {
        let order = Order::status(&acme_client, &account, &order_url).await?;
        match order.download_cert(&acme_client, &account).await {
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
