use cert_rs::{AcmeApi, challenge::ChallengeType};
use color_eyre::Result;
use reqwest::Client;
use tracing_subscriber::EnvFilter;
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    tracing_subscriber::fmt()
        .without_time() // For early local development.
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let acme_uri: Url = std::env::var("TEST_ACME_DIR")
        .unwrap_or(String::from("https://localhost:24000/dir"))
        .parse()?;
    tracing::debug!("Acme dir url: {}", acme_uri);

    let chall_test_srv: Url = std::env::var("TEST_CHALL_TEST_SRV")
        .unwrap_or(String::from("http://localhost:8055"))
        .parse()?;

    let http_01_url = chall_test_srv.join("add-http01").unwrap().to_string();
    let dns_01_url = chall_test_srv.join("set-txt").unwrap().to_string();

    let clear_http_01 = chall_test_srv.join("del-http01").unwrap().to_string();
    let clear_dns_01 = chall_test_srv.join("clear-txt").unwrap().to_string();

    let domains: Vec<String> = vec!["test.com".into(), "*.test.com".into()];

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Unable to build reqwest client");

    let acme_api = AcmeApi::new_from_client(acme_uri, client).await?;

    let acme_api = acme_api.register_account().await?;

    let _orders = acme_api.orders().await?;

    let (order_url, _) = acme_api.create_order(domains).await?;

    let order_status = acme_api.order_status(&order_url).await?;

    let authorization_with_urls = acme_api.challenges(&order_status).await?;

    let challange_responders =
        acme_api.clean_challenges(&authorization_with_urls).await?;

    // http_01 challanges
    for challenge_token in challange_responders
        .iter()
        .filter(|v| v.r#type == ChallengeType::Http01)
    {
        // clear http_01 challanges
        reqwest::Client::new()
            .post(&clear_http_01)
            .json(&serde_json::json!({
                "token": challenge_token.token
            }))
            .send()
            .await?;

        reqwest::Client::new()
            .post(&http_01_url)
            .json(&serde_json::json!({
                "token": challenge_token.token,
                "content": challenge_token.keyauth
            }))
            .send()
            .await?;
    }

    // dns_01 challanges
    for challenge_token in challange_responders
        .iter()
        .filter(|v| v.r#type == ChallengeType::Dns01)
    {
        // clear dns_01 challanges
        let host = format!("_acme-challenge.{}.", challenge_token.domain);
        reqwest::Client::new()
            .post(&clear_dns_01)
            .json(&serde_json::json!({
                "host": host
            }))
            .send()
            .await?;

        let host = format!("_acme-challenge.{}.", challenge_token.domain);
        reqwest::Client::new()
            .post(&dns_01_url)
            .json(&serde_json::json!({
                "host": host,
                "value": challenge_token.sha_256_keyauth
            }))
            .send()
            .await?;
    }

    let _authorization_with_urls =
        acme_api.respond_to_challanges(&authorization_with_urls).await?;

    for sec in 4..6 {
        tokio::time::sleep(std::time::Duration::from_secs(sec)).await;
        acme_api.order_status(&order_url).await?;
    }

    acme_api.finalize_order(&order_status).await?;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let order_status = acme_api.order_status(&order_url).await?;

    acme_api.download_cert(&order_status).await?;

    Ok(())
}
