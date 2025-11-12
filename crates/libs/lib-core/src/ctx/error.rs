use serde::Serialize;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug, Serialize, strum_macros::Display)]
pub enum Error {
    CtxCannotNewRootCtx,
}
