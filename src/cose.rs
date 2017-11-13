//! This module implements COSE using the `cose::decoder` and `cose::nss` bindings.

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[cfg(test)]
#[macro_use(defer)]
extern crate scopeguard;

#[macro_use]
pub mod cbor;
pub mod decoder;
mod util;

#[cfg(test)]
mod nss;
#[cfg(test)]
mod test_setup;
#[cfg(test)]
mod test_nss;
#[cfg(test)]
mod util_test;
#[cfg(test)]
mod test_cose;


#[derive(Debug, PartialEq)]
pub enum CoseError {
    DecodingFailure,
    LibraryFailure,
    MalformedInput,
    MissingHeader,
    UnexpectedHeaderValue,
    UnexpectedTag,
    UnexpectedType,
    Unimplemented,
    VerificationFailed,
    UnknownSignatureScheme,
    SigningFailed,
    InvalidArgument,
}

#[derive(Debug)]
pub struct SignatureParameters<'a> {
    certificate: &'a [u8],
    algorithm: SignatureAlgorithm,
    pkcs8: &'a [u8],
}

#[derive(Debug)]
pub struct Signature<'a> {
    parameter: &'a SignatureParameters<'a>,
    signature_bytes: Vec<u8>,
}

/// An enum identifying supported signature algorithms. Currently only ECDSA with SHA256 (ES256) and
/// RSASSA-PSS with SHA-256 (PS256) are supported. Note that with PS256, the salt length is defined
/// to be 32 bytes.
#[derive(Debug)]
#[derive(PartialEq)]
pub enum SignatureAlgorithm {
    ES256,
    ES384,
    ES512,
    PS256,
}
