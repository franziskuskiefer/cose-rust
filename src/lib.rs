#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[cfg(test)]
#[macro_use(defer)]
extern crate scopeguard;

#[macro_use]
pub mod cbor;
pub mod cose;

// This is the C API we expose.
mod capi;
pub use capi::*;
