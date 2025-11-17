use color_eyre::Result;
use reqwest::Client;
use url::Url;

use crate::AcmeApi;

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

    acme_api.orders().await?;

    let (order_url, _) = acme_api.create_order().await?;

    let order_status = acme_api.order_status(&order_url).await?;

    let orders = acme_api.challenges(order_status).await?;

    let challenge_tokens = acme_api.clean_challenges(orders).await?;

    // // http_01 challanges
    // for challenge_token in challenge_tokens.iter() {
    //     reqwest::Client::new()
    //         .post("http://localhost:8055/add-http01")
    //         .json(&serde_json::json!({
    //             "token": challenge_token.token,
    //             "content": challenge_token.keyauth
    //         }))
    //         .send()
    //         .await?;
    // }

    // dns_01 challanges
    for challenge_token in challenge_tokens.iter() {
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

    for challenge_token in challenge_tokens.iter() {
        acme_api.prove_challenge(challenge_token).await?
    }

    for challenge_token in challenge_tokens.iter() {
        for sec in 4..6 {
            tokio::time::sleep(std::time::Duration::from_secs(sec)).await;
            acme_api.poll_challange(challenge_token).await?;
        }

        // tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // acme_api.poll_challange(challenge_token).await?;
    }

    // // http_01 challanges
    // for challenge_token in challenge_tokens.iter() {
    //     reqwest::Client::new()
    //         .post("http://localhost:8055/del-http01")
    //         .json(&serde_json::json!({
    //             "token": challenge_token.token
    //         }))
    //         .send()
    //         .await?;
    // }

    // // dns_01 challanges clear
    // for challenge_token in challenge_tokens.iter() {
    //     let host = format!("_acme-challenge.{}.", challenge_token.domain);
    //     reqwest::Client::new()
    //         .post("http://localhost:8055/clear-txt")
    //         .json(&serde_json::json!({
    //             "host": host
    //         }))
    //         .send()
    //         .await?;
    // }

    Ok(())
}
