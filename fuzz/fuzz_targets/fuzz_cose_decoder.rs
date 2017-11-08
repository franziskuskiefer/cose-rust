#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate cose;
use cose::cose::decoder::decode_signature;

fuzz_target!(|data: &[u8]| {
    decode_signature(data.to_vec(), data);
});
