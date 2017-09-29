use std::env;

fn main() {
    // Use NSS_LIB_DIR lazily. If it's not set and we can't find NSS in the path,
    // the build will fail.
    let lib_dir = env::var("NSS_LIB_DIR");
    if lib_dir.is_ok() {
        println!("cargo:rustc-link-search=native={}", lib_dir.unwrap());
    }
}
