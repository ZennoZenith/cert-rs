use crate::error::{Error, Result};
use crate::utils::token;

use axum::extract::rejection::JsonRejection;
use axum::{Json, extract::State};
use lib_auth::pwd::{self, ContentToHash, SchemeStatus};
use lib_core::ctx::Ctx;
use lib_core::model::user::{UserBmc, UserForCreate};
use lib_core::model::{self, ModelManager};
use serde::Deserialize;
use serde_json::{Value, json};
use tower_cookies::Cookies;
use tracing::debug;

// region:    --- Login
#[derive(Debug, Deserialize)]
pub struct LoginPayload {
    email: String,
    password: String,
}

pub async fn api_login_handler(
    State(mm): State<ModelManager>,
    cookies: Cookies,
    payload_or_error: std::result::Result<Json<LoginPayload>, JsonRejection>,
) -> Result<Json<Value>> {
    debug!("{:<12} - api_login_handler", "HANDLER");

    let payload = payload_or_error?.0;

    let LoginPayload {
        email,
        password: pwd_clear,
    } = payload;

    let root_ctx = Ctx::root_ctx();

    // -- Get the user.
    let user = UserBmc::get_by_email(&root_ctx, &mm, &email)
        .await
        .map_err(model::Error::from)?;
    let user_id = user.user_id;

    // -- Validate the password.
    let pwd = user.pwd;

    let scheme_status = pwd::validate_pwd(
        ContentToHash {
            salt: user.pwd_salt,
            content: pwd_clear.clone(),
        },
        pwd,
    )
    .await
    .map_err(|_| Error::LoginFailPwdNotMatching {
        user_id: user_id.clone(),
    })?;

    // -- Update password scheme if needed
    if let SchemeStatus::Outdated = scheme_status {
        debug!("pwd encrypt scheme outdated, upgrading.");
        UserBmc::update_pwd(&root_ctx, &mm, &user_id, &pwd_clear)
            .await
            .map_err(model::Error::from)?;
    }

    // -- Set web token.
    token::set_token_cookie(&cookies, &user_id, user.token_salt)?;

    // Create the success body.
    let body = Json(json!({
     "result": {
      "success": true
     }
    }));

    Ok(body)
}
// endregion: --- Login

// region:    --- Logoff
pub async fn api_logoff_handler(
    cookies: Cookies,
    Json(payload): Json<LogoffPayload>,
) -> Result<Json<Value>> {
    debug!("{:<12} - api_logoff_handler", "HANDLER");
    let should_logoff = payload.logoff;

    if should_logoff {
        token::remove_token_cookie(&cookies)?;
    }

    // Create the success body.
    let body = Json(json!({
     "result": {
      "logged_off": should_logoff
     }
    }));

    Ok(body)
}

#[derive(Debug, Deserialize)]
pub struct LogoffPayload {
    logoff: bool,
}
// endregion: --- Logoff

// region:    --- Register
pub async fn api_register_handler(
    State(mm): State<ModelManager>,
    payload_or_error: std::result::Result<Json<UserForCreate>, JsonRejection>,
) -> Result<Json<Value>> {
    debug!("{:<12} - api_login_handler", "HANDLER");

    let payload = payload_or_error?.0;

    let root_ctx = Ctx::root_ctx();

    // -- Get the user id.
    let user_id = UserBmc::create(&root_ctx, &mm, payload)
        .await
        .map_err(model::Error::from)?;
    tracing::debug!("User id: {user_id}");

    // Create the success body.
    let body = Json(json!({
     "result": {
      "success": true
     }
    }));

    Ok(body)
}
// endregion: --- Register
