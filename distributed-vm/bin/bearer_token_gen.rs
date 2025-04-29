use base64::{engine::general_purpose, Engine};
use rand::{rngs::OsRng, TryRngCore};
fn main() {
    const BUFFER_LEN: usize = 32;
    let mut buffer = vec![0u8; BUFFER_LEN];
    OsRng.try_fill_bytes(&mut buffer).unwrap();

    let token = general_purpose::URL_SAFE_NO_PAD.encode(&buffer);

    println!("Bearer {}", token);
}
