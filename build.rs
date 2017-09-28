use std::env;

fn main() {
    let lib_dir = env::var("NSS_LIB_DIR").expect("Please set NSS_LIB_DIR");
    println!("cargo:rustc-link-search=native={}", lib_dir);
}
