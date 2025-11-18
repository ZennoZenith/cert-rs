use base64::engine::{Engine, general_purpose};

// region:    --- Error

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug, strum_macros::Display)]
pub enum Error {
    FailToB64uDecode,
}

// endregion: --- Error

pub fn b64u_encode(content: impl AsRef<[u8]>) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(content)
}

pub fn b64u_decode(b64u: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(b64u)
        .map_err(|_| Error::FailToB64uDecode)
}

pub fn b64u_decode_to_string(b64u: &str) -> Result<String> {
    b64u_decode(b64u)
        .ok()
        .and_then(|r| String::from_utf8(r).ok())
        .ok_or(Error::FailToB64uDecode)
}
