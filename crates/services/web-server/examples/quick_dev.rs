#![allow(unused)] // For example code.

pub type Result<T> = std::result::Result<T, Error>;
pub type Error = Box<dyn std::error::Error>; // For examples.

use serde_json::{Value, json};

#[tokio::main]
async fn main() -> Result<()> {
    let hc = httpc_test::new_client("http://localhost:8080")?;

    // -- Login
    let req_login = hc.do_post(
        "/api/login",
        json!({
            "email": "demo1@example.com",
            "pwd": "welcome"
        }),
    );
    req_login.await?.print().await?;

    // -- Logoff
    let req_logoff = hc.do_post(
        "/api/logoff",
        json!({
            "logoff": true
        }),
    );
    req_logoff.await?.print().await?;

    Ok(())
}
