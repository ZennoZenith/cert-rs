use std::sync::Arc;

use axum::{
    extract::{WebSocketUpgrade, ws::WebSocket},
    routing::get,
};
use lib_web::web_config;
use tokio::sync::broadcast::Sender;
use tokio::{net::TcpListener, sync::broadcast};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "hot_reload")]
#[tokio::main]
async fn main() -> web_server::Result<()> {
    use lib_hotreload::run_watcher;

    tracing_subscriber::fmt()
        .without_time() // For early local development.
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let (tx, _) = broadcast::channel(16);

    let tx = Arc::new(tx);

    let routes = web_server::routes().await?;

    let move_tx = tx.clone();

    let routes = routes.clone().route(
        "/live-server-ws",
        get(|ws: WebSocketUpgrade| async move {
            ws.on_failed_upgrade(|error| {
                tracing::error!("Failed to upgrade websocket: {error}");
            })
            .on_upgrade(|socket: WebSocket| {
                on_websocket_upgrade(socket, move_tx)
            })
        }),
    );

    // region:    --- Start Server
    // Note: For this block, ok to unwrap.
    let listener = TcpListener::bind(web_config().HOST_PORT).await.unwrap();
    info!("{:<12} - {:?}\n", "LISTENING", listener.local_addr());

    let file_watcher_future = tokio::spawn(run_watcher(tx.clone()));
    let mut rx = tx.subscribe();

    let file_recv_future = tokio::spawn(async move {
        while rx.recv().await.is_ok() {
            use lib_web::tera::reload_tera;

            // tracing::info!("Files changed");
            let _ = reload_tera();
        }
    });

    let server_future = tokio::spawn(async move {
        axum::serve(listener, routes.into_make_service())
            .await
            .unwrap()
    });

    tokio::try_join!(file_watcher_future, file_recv_future, server_future)
        .unwrap();

    Ok(())
}

#[cfg(feature = "hot_reload")]
async fn on_websocket_upgrade(
    socket: axum::extract::ws::WebSocket,
    tx: Arc<Sender<()>>,
) {
    use axum::extract::ws::Message;
    use futures::{sink::SinkExt, stream::StreamExt};

    let (mut sender, mut receiver) = socket.split();
    let mut rx = tx.subscribe();
    let mut send_task = tokio::spawn(async move {
        while rx.recv().await.is_ok() {
            // tracing::info!("Files changed in web_socket");
            sender
                .send(Message::Text(String::new().into()))
                .await
                .unwrap();
        }
    });
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(_)) = receiver.next().await {}
    });
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
}
