use common::run_proof;

fn main() {
    // SHA-256 chained 66000 times from [3; 32], committed as a Vec so bincode prefixes its
    // 8-byte length: upstream sha2 0.10.9 on the host.
    run_proof!(
        [SHA_EXTEND, SHA_COMPRESS],
        commits = common::hex(concat!(
            "2000000000000000",
            "1d449d67589670d2355cb3223fe53b6011f30fdc19df0863aa8b037df7fbc0ac",
        )),
        [3u8; 32],
    );
}
