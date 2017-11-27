use std::env;

fn main() {
    // Use NSS_LIB_DIR lazily. If it's not set and we can't find NSS in the path,
    // the build will fail.
    if let Ok(lib_dir) = env::var("NSS_LIB_DIR") {
        println!("cargo:rustc-link-search={}", lib_dir);
    }
}
