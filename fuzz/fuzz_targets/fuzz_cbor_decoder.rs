#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate cose;
use cose::cbor::decoder::{decode};

fuzz_target!(|data: &[u8]| {
    decode(data.to_vec());
});
