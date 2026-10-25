use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap();
    println!(
        "cargo:rustc-link-arg=-Wl,-rpath,{}",
        workspace_root.display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        workspace_root.display()
    );
    println!("cargo:rustc-link-lib=dylib=gpu_api");
}
