// region:    --- Modules

mod error;

use std::sync::Arc;

pub use self::error::{Error, Result};

// endregion: --- Modules

#[derive(Clone, Debug)]
pub struct Ctx {
    user_id: Arc<str>,
}

// Constructors.
impl Ctx {
    pub fn root_ctx() -> Self {
        Ctx {
            user_id: Arc::from("root"),
        }
    }

    pub fn cli_ctx() -> Self {
        Ctx {
            user_id: Arc::from("cli"),
        }
    }

    pub fn new(user_id: &str) -> Result<Self> {
        if "root" == user_id {
            Err(Error::CtxCannotNewRootCtx)
        } else {
            Ok(Self {
                user_id: Arc::from(user_id),
            })
        }
    }
}

// Property Accessors.
impl Ctx {
    pub fn user_id(&self) -> &str {
        self.user_id.as_ref()
    }
}
