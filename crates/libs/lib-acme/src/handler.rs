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
) -> Result<()> {
    let acme_api =
        AcmeApi::new_from_client(acme_uri, model_manager, client).await?;

    let acme_api = acme_api.register_account().await?;
    // debug!("account_id: {}", account.account_id());

    let _account_info = acme_api.account_info().await?;

    // acme_api.create_order();

    Ok(())
}
