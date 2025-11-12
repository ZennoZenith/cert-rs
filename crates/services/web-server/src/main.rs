use lib_web::web_config;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> web_server::Result<()> {
    tracing_subscriber::fmt()
        .without_time() // For early local development.
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // region:    --- Start Server
    // Note: For this block, ok to unwrap.
    let listener = TcpListener::bind(web_config().HOST_PORT).await.unwrap();
    info!("{:<12} - {:?}\n", "LISTENING", listener.local_addr());
    let routes = web_server::routes().await?;
    axum::serve(listener, routes.into_make_service())
        .await
        .unwrap();
    // endregion: --- Start Server

    Ok(())
}
