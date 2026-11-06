//! Writes `SOURCE_FINGERPRINT`, an FNV-1a hash of `src/lib.rs`, for `lib.rs` to include.

/// 64-bit FNV-1a offset basis: the hash's starting value.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// 64-bit FNV-1a prime: each byte is XORed in, then the hash is multiplied by it.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    let source = std::fs::read("src/lib.rs").expect("src/lib.rs");
    let hash = source.iter().fold(FNV_OFFSET_BASIS, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    });
    let out =
        std::path::Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("fingerprint.rs");
    std::fs::write(
        out,
        format!("pub const SOURCE_FINGERPRINT: u64 = {hash:#018x};\n"),
    )
    .expect("fingerprint.rs");
}
