#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate cose;
use cose::cose::cose::{verify_signature};

fuzz_target!(|data: &[u8]| {
    verify_signature(data, data.to_vec());
});
