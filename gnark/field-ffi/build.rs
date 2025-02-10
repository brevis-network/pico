fn main() {
    println!("start compile field ffi");
    println!("cargo:rustc-link-lib=dylib=dl");
}
