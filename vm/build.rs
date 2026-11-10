use std::{env, path::PathBuf};

fn main() {
    // Only the GPU build links the `gpu_api` shared library that `pico-gpu-api` builds.
    if env::var_os("CARGO_FEATURE_CUDA").is_none() {
        return;
    }
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

    // `cudaMemLocation.id` is a plain field in the CUDA 12 bindings and a member of an anonymous
    // union in CUDA 13's. `cuda_adaptor::resource_pool::mem_pool` sets it by hand, so it switches on
    // the same `cuda_13` cfg era-cuda's cudart does, detected the same way: the `CUDA_VERSION`
    // override, else the toolkit's version.json.
    println!("cargo:rustc-check-cfg=cfg(cuda_13)");
    println!("cargo:rerun-if-env-changed=CUDA_VERSION");
    println!("cargo:rerun-if-changed=/usr/local/cuda/version.json");
    if cuda_version().is_some_and(|v| v.starts_with("13.")) {
        println!("cargo:rustc-cfg=cuda_13");
    }
}

/// The toolkit version: `CUDA_VERSION` if set, else the `"version"` of the `"cuda"` entry in
/// `/usr/local/cuda/version.json`. `None` without a toolkit.
fn cuda_version() -> Option<String> {
    if let Ok(v) = env::var("CUDA_VERSION") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let text = std::fs::read_to_string("/usr/local/cuda/version.json").ok()?;
    let rest = &text[text.find("\"cuda\"")?..];
    let rest = &rest[rest.find("\"version\"")? + "\"version\"".len()..];
    let start = rest.find('"')? + 1;
    let end = start + rest[start..].find('"')?;
    Some(rest[start..end].to_string())
}
