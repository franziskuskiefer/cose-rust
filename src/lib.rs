#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use(defer)]
extern crate scopeguard;

#[macro_use]
pub mod cbor;
pub mod cose;
