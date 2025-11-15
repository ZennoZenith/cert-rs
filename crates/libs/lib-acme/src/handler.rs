use color_eyre::Result;
use lib_core::model::ModelManager;
use reqwest::Client;
use url::Url;

use crate::AcmeApi;

pub async fn init(
    acme_uri: Url,
    client: Client,
    model_manager: ModelManager,
) -> Result<()> {
    // if let Ok(account) =
    //     AcmeAccountBmc::get_first(&self.model_manager).await
    // {
    //     let account: Account = account.try_into()?;
    //     return Ok(self.into_registerd(account));
    // }

    // Save acount to database
    // AcmeAccountBmc::create(&self.model_manager, &account).await?;

    let acme_api =
        AcmeApi::new_from_client(acme_uri, model_manager, client).await?;

    let acme_api = acme_api.register_account().await?;

    acme_api.orders().await?;

    let order_url = acme_api.create_order().await?;

    acme_api.order_status(&order_url).await?;

    Ok(())
}
