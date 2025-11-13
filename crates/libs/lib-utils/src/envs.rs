use crate::b64::b64u_decode;
use std::env;
use std::str::FromStr;

// region:    --- Error

pub trait DefaultIfMissing<T> {
    fn default_if_missing(self) -> Result<T>;
}

pub trait IfMissing<T> {
    fn if_missing(self, value: T) -> Result<T>;
}

pub type Result<T> = std::result::Result<T, Error>;

impl<T: Default> DefaultIfMissing<T> for Result<T> {
    fn default_if_missing(self) -> Result<T> {
        match self {
            Err(Error::MissingEnv(env_name)) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    "{:<12} - {}, using default",
                    "MISSING-ENV",
                    env_name
                );

                Ok(T::default())
            }
            _ => self,
        }
    }
}
impl<T> IfMissing<T> for Result<T> {
    fn if_missing(self, value: T) -> Result<T> {
        match self {
            Err(Error::MissingEnv(env_name)) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    "{:<12} - {}, using value from code",
                    "MISSING-ENV",
                    env_name
                );

                Ok(value)
            }
            _ => self,
        }
    }
}

#[derive(thiserror::Error, Debug, strum_macros::Display)]
pub enum Error {
    MissingEnv(&'static str),
    WrongFormat(&'static str),
}

// endregion: --- Error

pub fn get_env(name: &'static str) -> Result<String> {
    env::var(name).map_err(|_| Error::MissingEnv(name))
}

pub fn get_env_parse<T: FromStr>(name: &'static str) -> Result<T> {
    let val = get_env(name)?;
    val.parse::<T>().map_err(|_| Error::WrongFormat(name))
}

pub fn get_env_b64u_as_u8s(name: &'static str) -> Result<Vec<u8>> {
    b64u_decode(&get_env(name)?).map_err(|_| Error::WrongFormat(name))
}
