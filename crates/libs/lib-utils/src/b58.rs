use base58::{FromBase58, ToBase58};

// region:    --- Error

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug, strum_macros::Display)]
pub enum Error {
    FailToB58uDecode,
}

// endregion: --- Error

pub fn b58_encode(content: impl AsRef<[u8]>) -> String {
    content.as_ref().to_base58()
}

pub fn b58_decode(b58u: &str) -> Result<Vec<u8>> {
    FromBase58::from_base58(b58u).map_err(|_| Error::FailToB58uDecode)
}

pub fn b58_decode_to_string(b58u: &str) -> Result<String> {
    b58_decode(b58u)
        .ok()
        .and_then(|r| String::from_utf8(r).ok())
        .ok_or(Error::FailToB58uDecode)
}
