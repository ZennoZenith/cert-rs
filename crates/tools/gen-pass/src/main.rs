pub type Result<T> = std::result::Result<T, Error>;
pub type Error = Box<dyn std::error::Error>; // Ok for tools.

use uuid::Uuid;

fn main() -> Result<()> {
    let password = rpassword::prompt_password("Password: ")
        .expect("Unable to read password");
    let password_again = rpassword::prompt_password("Retype password: ")
        .expect("Unable to read password");

    if password != password_again {
        println!("Password does not match");
        return Ok(());
    }

    let salt = Uuid::new_v4();

    println!("Hashing password using scheme 2...");

    let hash_pwd = lib_auth::pwd::hash_pwd_sync(lib_auth::pwd::ContentToHash {
        content: password,
        salt,
    })
    .unwrap();

    let hashed = hash_pwd;
    println!("  Salt: {salt}");
    println!("Hashed: {hashed}");

    Ok(())
}
