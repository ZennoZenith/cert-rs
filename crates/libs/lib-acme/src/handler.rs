use color_eyre::Result;
use lib_core::{
    ctx::Ctx,
    model::{
        ModelManager,
        acme::{account::AcmeAccountBmc, api::AcmeApi},
    },
};

#[derive(thiserror::Error, Debug)]
pub enum Error {}

pub async fn acme_account_setup(
    ctx: &Ctx,
    acme_api: &AcmeApi,
    mm: &ModelManager,
) -> Result<()> {
    let maybe_account = AcmeAccountBmc::get_first(ctx, mm).await;

    let account_c = acme_api.create_new_account().await?;

    AcmeAccountBmc::create(ctx, mm, account_c).await?;

    Ok(())
}
