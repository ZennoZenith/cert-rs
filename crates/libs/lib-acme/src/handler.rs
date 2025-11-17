use color_eyre::Result;
use reqwest::Client;
use url::Url;

use crate::{AcmeApi, challenge::ChallengeType};

pub async fn init(acme_uri: Url, client: Client) -> Result<()> {
    // if let Ok(account) =
    //     AcmeAccountBmc::get_first(&self.model_manager).await
    // {
    //     let account: Account = account.try_into()?;
    //     return Ok(self.into_registerd(account));
    // }

    // Save acount to database
    // AcmeAccountBmc::create(&self.model_manager, &account).await?;

    let acme_api = AcmeApi::new_from_client(acme_uri, client).await?;

    let acme_api = acme_api.register_account().await?;

    let _orders = acme_api.orders().await?;

    let domains: Vec<String> = vec![
        // "example.com".into(),
        // "*.example.com".into(),
        "test.com".into(),
        "*.test.com".into(),
    ];

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
        reqwest::Client::new()
            .post("http://localhost:8055/add-http01")
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
        let host = format!("_acme-challenge.{}.", challenge_token.domain);
        reqwest::Client::new()
            .post("http://localhost:8055/set-txt")
            .json(&serde_json::json!({
                "host": host,
                "value": challenge_token.sha_256_keyauth
            }))
            .send()
            .await?;
    }

    let _authorization_with_urls = acme_api
        .respond_to_challanges(&authorization_with_urls)
        .await?;

    for sec in 4..6 {
        tokio::time::sleep(std::time::Duration::from_secs(sec)).await;
        acme_api.order_status(&order_url).await?;
    }

    // http_01 challanges
    for challenge_token in challange_responders
        .iter()
        .filter(|v| v.r#type == ChallengeType::Http01)
    {
        reqwest::Client::new()
            .post("http://localhost:8055/del-http01")
            .json(&serde_json::json!({
                "token": challenge_token.token
            }))
            .send()
            .await?;
    }

    // dns_01 challanges clear
    for challenge_token in challange_responders
        .iter()
        .filter(|v| v.r#type == ChallengeType::Dns01)
    {
        let host = format!("_acme-challenge.{}.", challenge_token.domain);
        reqwest::Client::new()
            .post("http://localhost:8055/clear-txt")
            .json(&serde_json::json!({
                "host": host
            }))
            .send()
            .await?;
    }

    acme_api.finalize_order(&order_status).await?;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let order_status = acme_api.order_status(&order_url).await?;

    acme_api.download_cert(&order_status).await?;

    Ok(())
}
