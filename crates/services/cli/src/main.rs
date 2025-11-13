use std::path::PathBuf;
use std::sync::OnceLock;

use clap::{Parser, command};
use color_eyre::eyre::{Result, eyre};
use lib_acme::handler::acme_account_setup;
use lib_core::{
    ctx::Ctx,
    model::{ModelManager, acme::api::AcmeApi},
};
use reqwest::Client;
use tracing::info;
use tracing_subscriber::EnvFilter;
use url::Url;

// const PRODUCTION_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
// const STAGING_URI: &str =
//     "https://acme-staging-v02.api.letsencrypt.org/directory";
const PRODUCTION_URL: &str = "https://0.0.0.0:24000/dir";
const STAGING_URI: &str = "https://0.0.0.0:24000/dir";

pub fn reqwest_client() -> &'static Client {
    static INSTANCE: OnceLock<Client> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        Client::builder()
            // WARN:
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Unable to build reqwest client")
    })
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<Vec<String>>,

    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Use staging environment
    #[arg(long)]
    staging: bool,

    /// Custom directory uri
    #[arg(long, value_name = "DIRECTORY_URI")]
    uri: Option<Url>,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    tracing_subscriber::fmt()
        .without_time() // For early local development.
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let Some(domain) = cli.domain else {
        return Err(eyre!("No domain provided"));
    };

    if domain.is_empty() {
        return Err(eyre!("No domain provided"));
    }

    let domains = domain
        .into_iter()
        .flat_map(|v| {
            v.split(",").map(ToOwned::to_owned).collect::<Vec<String>>()
        })
        .collect::<Vec<String>>();

    info!("Value for domain: {:?}", domains);

    if let Some(config_path) = cli.config.as_deref() {
        println!("Value for config: {}", config_path.display());
    }

    let acme_uri = match cli.uri {
        Some(uri) => {
            tracing::info!("Using custom acme uri: {}", uri.as_str());
            uri
        }
        None => match cli.staging {
            true => {
                info!("Using staging url");
                Url::parse(STAGING_URI)
                    .expect("Cannot parse Hardcoded STAGING_URI")
            }
            _ => Url::parse(PRODUCTION_URL)
                .expect("Cannot parse Hardcoded PRODUCTION_URL"),
        },
    };

    info!("acme_uri: {acme_uri}");

    let cli_ctx = Ctx::cli_ctx();

    let model_manager = ModelManager::new().await?;
    let acme_api =
        AcmeApi::new_from_client(acme_uri, reqwest_client().to_owned()).await?;

    acme_account_setup(&cli_ctx, &acme_api, &model_manager).await?;
    Ok(())
}
