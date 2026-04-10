use std::fmt;

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[must_use]
pub struct Kid(Url);

impl Kid {
    #[must_use = "Kid is must use"]
    pub const fn new(url: Url) -> Self {
        Self(url)
    }

    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> Url {
        self.0
    }
}

impl std::ops::Deref for Kid {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Url> for Kid {
    fn as_ref(&self) -> &Url {
        &self.0
    }
}

impl std::borrow::Borrow<Url> for Kid {
    fn borrow(&self) -> &Url {
        &self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Url> for Kid {
    fn from(url: Url) -> Self {
        Self(url)
    }
}

impl From<Kid> for Url {
    fn from(id: Kid) -> Self {
        id.0
    }
}

impl std::str::FromStr for Kid {
    type Err = url::ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(Url::parse(s)?))
    }
}

impl TryFrom<&str> for Kid {
    type Error = url::ParseError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Ok(Self(Url::parse(value)?))
    }
}
