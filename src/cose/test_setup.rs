use std::os::raw;
use std::ptr;
use std::sync::{Once, ONCE_INIT};
static START: Once = ONCE_INIT;

type SECStatus = raw::c_int;
const SEC_SUCCESS: SECStatus = 0;
// TODO: ugh this will probably have a platform-specific name...
#[link(name="nss3")]
extern {
    fn NSS_NoDB_Init(configdir: *const u8) -> SECStatus;
}

pub fn setup() {
    START.call_once(|| {
        let null_ptr: *const u8 = ptr::null();
        unsafe {
            assert!(NSS_NoDB_Init(null_ptr) == SEC_SUCCESS);
        }
    });
}
