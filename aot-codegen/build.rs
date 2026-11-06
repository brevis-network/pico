//! Hashes this crate's source into `PICO_AOT_CODEGEN_FINGERPRINT` (FNV-1a over `src/`, in path
//! order).

use std::{fs, path::Path};

/// 64-bit FNV-1a offset basis: the hash's starting value.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// 64-bit FNV-1a prime: each byte is XORed in, then the hash is multiplied by it.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("src/").flatten() {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=src");
    let mut files = Vec::new();
    sources(Path::new("src"), &mut files);
    files.sort();
    let mut hash = FNV_OFFSET_BASIS;
    for file in files {
        for byte in file
            .to_string_lossy()
            .bytes()
            .chain(fs::read(&file).expect("source"))
        {
            hash = (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
        }
    }
    println!("cargo:rustc-env=PICO_AOT_CODEGEN_FINGERPRINT={hash:016x}");
}
