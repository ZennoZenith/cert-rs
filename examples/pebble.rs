use cert_rs::{
    AcmeApi,
    account::AccountCreate,
    challenge::{ChallengeResponder, ChallengeType},
    directory::AcmeDirectory,
};
use color_eyre::Result;
use fake::{
    Fake,
    faker::internet::en::{DomainSuffix, Username},
};
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

    let domains: Vec<String> = (0..2)
        .map(|_| {
            let domain_suffix: String = DomainSuffix().fake();
            let name: String = Username().fake();

            format!("{name}.{domain_suffix}")
        })
        .collect();

    let acme_dir = AcmeDirectory::new_from_url(acme_uri).await?;

    let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

    let account_create = AccountCreate {
        terms_of_service_agreed: Some(true),
        contacts: Some(vec![String::from("mailto:test@example.com")]),
        ..Default::default()
    };

    let acme_api =
        acme_api_unregistered.register_account(account_create).await?;

    let (order_url, _) = acme_api.create_order(domains).await?;

    let order_status = acme_api.order_status(&order_url).await?;

    let authorization_with_urls = acme_api.challenges(&order_status).await?;

    let challenge_responders =
        acme_api.clean_challenges(&authorization_with_urls).await?;

    handle_http_01_challenge(&challenge_responders).await?;
    handle_dns_01_challenge(&challenge_responders).await?;

    let _authorization_with_urls =
        acme_api.respond_to_challenges(&authorization_with_urls).await?;

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

async fn handle_http_01_challenge(
    challenge_responders: &[ChallengeResponder],
) -> Result<()> {
    let chall_test_srv: Url = std::env::var("TEST_CHALL_TEST_SRV")
        .unwrap_or(String::from("http://localhost:8055"))
        .parse()?;
    let http_01_url = chall_test_srv.join("add-http01").unwrap().to_string();
    let clear_http_01 = chall_test_srv.join("del-http01").unwrap().to_string();

    // http_01 challenges
    for challenge_token in challenge_responders
        .iter()
        .filter(|v| v.r#type == ChallengeType::Http01)
    {
        // clear http_01 challenges
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

    Ok(())
}

async fn handle_dns_01_challenge(
    challenge_responders: &[ChallengeResponder],
) -> Result<()> {
    let chall_test_srv: Url = std::env::var("TEST_CHALL_TEST_SRV")
        .unwrap_or(String::from("http://localhost:8055"))
        .parse()?;

    let dns_01_url = chall_test_srv.join("set-txt").unwrap().to_string();
    let clear_dns_01 = chall_test_srv.join("clear-txt").unwrap().to_string();

    // dns_01 challenges
    for challenge_token in challenge_responders
        .iter()
        .filter(|v| v.r#type == ChallengeType::Dns01)
    {
        // clear dns_01 challenges
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
    Ok(())
}
