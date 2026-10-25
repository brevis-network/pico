use base64::{engine::general_purpose, Engine};
use rand::{rngs::SysRng, TryRng};

fn main() {
    const BUFFER_LEN: usize = 32;
    let mut buffer = vec![0u8; BUFFER_LEN];
    SysRng
        .try_fill_bytes(&mut buffer)
        .expect("operating-system randomness is available");

    let token = general_purpose::URL_SAFE_NO_PAD.encode(&buffer);

    println!("Bearer {}", token);
}
