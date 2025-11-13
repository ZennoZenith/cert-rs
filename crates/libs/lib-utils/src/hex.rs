// region:    --- Error

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug, strum_macros::Display)]
pub enum Error {
    /// An invalid character was found. Valid ones are: `0...9`, `a...f`
    /// or `A...F`.
    InvalidHexCharacter { c: char, index: usize },

    /// A hex string's length needs to be even, as two digits correspond to
    /// one byte.
    OddLength,

    /// If the hex string is decoded into a fixed sized container, such as an
    /// array, the hex string's length * 2 has to match the container's
    /// length.
    InvalidStringLength,

    /// If hex decoded bytes not utf-8
    FailToHexDecodeToString,
}

impl From<hex::FromHexError> for Error {
    fn from(value: hex::FromHexError) -> Self {
        use hex::FromHexError as he;
        match value {
            he::InvalidHexCharacter { c, index } => {
                Self::InvalidHexCharacter { c, index }
            }
            he::OddLength => Self::OddLength,
            he::InvalidStringLength => Self::InvalidStringLength,
        }
    }
}

// endregion: --- Error

pub fn hex_encode(content: impl AsRef<[u8]>) -> String {
    hex::encode(content)
}

pub fn hex_encode_upper(content: impl AsRef<[u8]>) -> String {
    hex::encode_upper(content)
}

pub fn hex_decode(content: &str) -> Result<Vec<u8>> {
    hex::decode(content).map_err(Error::from)
}

pub fn hex_decode_to_string(content: &str) -> Result<String> {
    hex_decode(content)
        .map(|r| String::from_utf8(r).ok())?
        .ok_or(Error::FailToHexDecodeToString)
}
