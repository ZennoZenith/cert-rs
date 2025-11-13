use std::sync::Arc;

use crate::error::Result;
use crate::error::{ClientError, Error};
use crate::middleware::mw_req_stamp::ReqStamp;
use axum::http::{Method, Uri};
use chrono::Duration;
use lib_core::ctx::Ctx;
use lib_utils::time::TimeRfc3339;
use serde::Serialize;
use serde_json::{Value, json};
use serde_with::skip_serializing_none;
use tracing::debug;

pub async fn log_request(
    http_method: Method,
    uri: Uri,
    req_stamp: ReqStamp,
    ctx: Option<Ctx>,
    web_error: Option<&Error>,
    client_error: Option<ClientError>,
) -> Result<()> {
    // -- Prep error
    let error_type = web_error.map(|se| se.as_ref().to_string());
    let error_data = serde_json::to_value(web_error)
        .ok()
        .and_then(|mut v| v.get_mut("data").map(|v| v.take()));

    // -- Prep Req Information
    let ReqStamp { uuid, time_in } = req_stamp;
    let now = TimeRfc3339::now_utc();
    let duration: Duration = now.inner() - time_in.inner();
    // duration_ms in milliseconds with microseconds precision.
    let duration_ms = (duration.as_seconds_f64() * 1_000_000.).floor() / 1_000.;

    // Create the RequestLogLine
    let log_line = RequestLogLine {
        uuid: uuid.to_string(),
        timestamp: now.format_time(), // LogLine timestamp ("time_out")
        time_in: time_in.format_time(),
        duration_ms,

        http_path: uri.to_string(),
        http_method: http_method.to_string(),

        user_id: ctx.map(|c| Arc::from(c.user_id())),

        client_error_type: client_error.map(|e| e.as_ref().to_string()),

        error_type,
        error_data,
    };

    debug!("REQUEST LOG LINE:\n{}\n", json!(log_line));

    // TODO - Send to cloud-watch and/or have a `pack_and_send` logic as well (newline json and/or parquet file)

    Ok(())
}

#[skip_serializing_none]
#[derive(Serialize)]
struct RequestLogLine {
    uuid: String,      // uuid string formatted
    timestamp: String, // (Rfc3339)
    time_in: String,   // (Rfc3339)
    duration_ms: f64,

    // -- User and context attributes.
    user_id: Option<Arc<str>>,

    // -- http request attributes.
    http_path: String,
    http_method: String,

    // -- Errors attributes.
    client_error_type: Option<String>,
    error_type: Option<String>,
    error_data: Option<Value>,
}
