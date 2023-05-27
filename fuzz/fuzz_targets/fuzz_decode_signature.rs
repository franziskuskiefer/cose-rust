#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate cose;

fuzz_target!(|signature_bytes: &[u8]| {
    let _ = cose::decoder::decode_signature(signature_bytes, &[]);
});
