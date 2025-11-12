pub type Result<T> = std::result::Result<T, Error>;
pub type Error = Box<dyn std::error::Error>; // Ok for tools.

use lib_utils::b64::b64u_encode;
use rand::RngCore;

fn main() -> Result<()> {
    let mut key = [0u8; 64]; // 512 bits = 64 bytes
    rand::rng().fill_bytes(&mut key);

    let b64u = b64u_encode(key);
    println!("\nKey b64u encoded:\n{b64u}");
    println!("\nKey lenght: {}", b64u.len());

    Ok(())
}
