extern crate cose;

use cose::cbor;
use std::env;
use std::process;

fn string_to_vec(data: String) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < data.len() - 1 {
        let b = match data.get(i..i + 2) {
            Some(x) => x,
            None => "",
        };
        bytes.push(u8::from_str_radix(b, 16).unwrap());
        i += 2;
    }
    bytes
}

pub fn main() {
    if let Some(arg1) = env::args().nth(1) {
        if arg1 != "--decode" {
            println!("Only --decode is supported as first argument.");
            process::exit(1);
        }
        if let Some(data) = env::args().nth(2) {
            if data.len() % 2 != 0 {
                println!("This is not a valid byte string.");
                process::exit(1);
            }
            let bytes = string_to_vec(data);
            let result = cbor::decoder::decode(bytes).unwrap();
            println!("Encoded: {:?}", result);
        } else {
            println!("--decode requires a value.");
            process::exit(1);
        }
    }
}
