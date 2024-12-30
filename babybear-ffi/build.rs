fn main() {
    println!("start compile babybear ffi");
    println!("cargo:rustc-link-lib=dylib=dl");
}
