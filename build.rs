use std::env;
use std::path::Path;

fn main() {
    if !Path::new("/usr/lib/libnss3.so").exists() {
        let lib_dir = env::var("NSS_LIB_DIR").expect("Please set NSS_LIB_DIR");
        println!("cargo:rustc-link-search=native={}", lib_dir);
    }
}
