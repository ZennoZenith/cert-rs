use base64::{
    DecodeError,
    engine::{Engine, general_purpose},
};

pub fn b64u_encode(content: impl AsRef<[u8]>) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(content)
}

pub fn b64u_decode(content: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(content)
}

// region:    --- Tests
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn encode_empty() {
        let encoded = b64u_encode([]);
        assert_eq!(encoded, "");
    }

    #[test]
    fn encode_simple_string() {
        let encoded = b64u_encode("hello");
        assert_eq!(encoded, "aGVsbG8");
    }

    #[test]
    fn encode_rfc_example() {
        let encoded = b64u_encode("foobar");
        assert_eq!(encoded, "Zm9vYmFy");
    }

    #[test]
    fn encode_binary_bytes() {
        let data = [0xff, 0xee, 0xdd, 0xcc];
        let encoded = b64u_encode(data);
        assert_eq!(encoded, "_-7dzA");
    }

    #[test]
    fn no_padding_is_present() {
        let encoded = b64u_encode("f");
        assert_eq!(encoded, "Zg");
        assert!(!encoded.contains('='));
    }

    #[test]
    fn url_safe_characters() {
        let data = [251, 255, 255];
        let encoded = b64u_encode(data);

        assert!(encoded.contains('-') || encoded.contains('_'));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_decode_valid_base64url() {
        let input = "SGVsbG8"; // "Hello"
        let decoded = b64u_decode(input).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_decode_empty_input() {
        let input = "";
        let decoded = b64u_decode(input).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_with_url_safe_chars() {
        // URL-safe Base64 example
        let original = b"\xfb\xef\xff";
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(original);

        let decoded = b64u_decode(encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_invalid_input() {
        let input = "!!!not_base64!!!";
        let result = b64u_decode(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_missing_padding_ok() {
        // URL_SAFE_NO_PAD should accept unpadded input
        let input = "U29tZVRleHQ"; // "SomeText"
        let decoded = b64u_decode(input).unwrap();
        assert_eq!(decoded, b"SomeText");
    }

    #[test]
    fn test_decode_binary_data_roundtrip() {
        let data = vec![0, 159, 255, 42, 100];
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&data);

        let decoded = b64u_decode(encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_rejects_standard_base64_chars() {
        // '+' and '/' are not valid in URL-safe variant
        let input = "SGVsbG8+";
        let result = b64u_decode(input);
        assert!(result.is_err());
    }
}
// endregion: --- Tests
