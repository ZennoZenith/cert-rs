#![deny(clippy::all)]
#![deny(clippy::expect_used)]
#![deny(clippy::unwrap_used)]
#![warn(clippy::cargo)]
#![warn(clippy::complexity)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::perf)]
#![allow(clippy::multiple_crate_versions)] // FIX: For exploratory dev.
// #![allow(dead_code)] // FIX: For exploratory dev.

use cert_rs::{
    AcmeClient,
    account::{Account, AccountCreate},
    directory::Directory,
    reqwest_client_builder,
};
use clap::Parser;
use colored::Colorize;
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

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    let config = Config::parse();
    // dbg!(&config);

    print_banner();

    let reqwest_client = reqwest_client_builder()?;

    let acme_client = AcmeClient::new(reqwest_client);

    let directory = match config.url {
        Some(url) => Directory::new_from_url(&acme_client, url).await?,
        None => Directory::lets_encrypt_staging(&acme_client).await?,
    };

    // dbg!(&directory);

    let account_create = AccountCreate {
        terms_of_service_agreed: Some(true),
        contacts: Some(vec![String::from("mailto:test@example.com")]),
        // only_return_existing: Some(true),
        ..Default::default()
    };

    let account = Account::create(&acme_client, &directory, account_create).await?;
    dbg!(&account);

    // tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let account = Account::fetch_account(
        &acme_client,
        &directory,
        account.account_id(),
        account.private_key().clone(),
    )
    .await?;
    dbg!(account);

    Ok(())
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
