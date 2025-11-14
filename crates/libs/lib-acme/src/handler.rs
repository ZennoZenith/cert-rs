use color_eyre::Result;
use lib_core::model::ModelManager;
use reqwest::Client;
use tracing::debug;
use url::Url;

use crate::{account::Account, api::AcmeApi};

pub async fn init(
    acme_uri: Url,
    client: Client,
    model_manager: ModelManager,
) -> Result<Account> {
    let acme_api =
        AcmeApi::new_from_client(acme_uri, model_manager, client).await?;

    let account = acme_api.create_new_account().await?;

    debug!("account_id: {}", account.account_id());

    Ok(account)
}
