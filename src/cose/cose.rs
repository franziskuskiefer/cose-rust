//! This module implements COSE using the `cose::decoder` and `cose::nss` bindings.

use cose::nss;
use cose::decoder::*;

#[derive(Debug)]
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
}

/// Verify a COSE signature.
pub fn verify_signature(payload: &[u8], cose_signature: Vec<u8>) -> Result<(), CoseError> {
    // Parse COSE signature.
    let cose_signatures = decode_signature(cose_signature, payload)?;
    if cose_signatures.len() != 1 {
        return Err(CoseError::LibraryFailure);
    }
    let signature_type = &cose_signatures[0].signature_type;
    let signature_algorithm = match *signature_type {
        CoseSignatureType::ES256 => nss::SignatureAlgorithm::ES256,
        _ => return Err(CoseError::LibraryFailure),
    };
    let signature_bytes = &cose_signatures[0].signature;
    let real_payload = &cose_signatures[0].to_verify;

    // Verify the parsed signature.
    let verify_result = nss::verify_signature(
        &signature_algorithm,
        &cose_signatures[0].signer_cert,
        real_payload,
        signature_bytes,
    );
    if !verify_result.is_ok() {
        return Err(CoseError::VerificationFailed);
    }
    Ok(())
}

/// Sign the payload and return a serialised `COSE_Sign` object.
#[allow(unused_variables)]
pub fn sign(payload: &[u8]) -> Result<Vec<u8>, CoseError> {
    unimplemented!()
}
