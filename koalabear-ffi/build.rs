fn main() {
    println!("start compile koalabear ffi");
    println!("cargo:rustc-link-lib=dylib=dl");
}
