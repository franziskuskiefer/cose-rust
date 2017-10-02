//! This module implements COSE using the cose::decoder and cose::nss bindings.

use cose::nss;
use cose::decoder::*;

#[derive(Debug)]
pub enum CoseError {
    CoseParsingFailed,
    VerificationFailed,
    SigningFailed,
}

/// Verify a COSE signature.
pub fn verify_signature(payload: &[u8], cose_signature: Vec<u8>) -> Result<(), CoseError> {
    // Parse COSE signature.
    let cose_signature = decode_signature(cose_signature, payload).unwrap();
    if cose_signature.values.len() != 1 {
        return Err(CoseError::CoseParsingFailed);
    }
    let signature_type = &cose_signature.values[0].signature_type;
    let signature_algorithm = match signature_type {
        &CoseSignatureType::ES256 => nss::SignatureAlgorithm::ES256,
        _ => return Err(CoseError::CoseParsingFailed),
    };
    let signature_bytes = &cose_signature.values[0].signature;
    if signature_bytes.len() != 64 {
        // XXX: We expect an ES256 signature
        return Err(CoseError::CoseParsingFailed);
    }
    let real_payload = &cose_signature.values[0].to_verify;
    if real_payload.len() < payload.len() {
        // XXX: We can probably make a better check here.
        return Err(CoseError::CoseParsingFailed);
    }

    // Verify the parsed signature.
    let verify_result = nss::verify_signature(
        signature_algorithm,
        &cose_signature.values[0].signer_cert,
        real_payload,
        signature_bytes,
    );
    if !verify_result.is_ok() {
        return Err(CoseError::VerificationFailed);
    }
    Ok(())
}

/// Sign the payload and return a serialised COSE_Sign object.
#[allow(unused_variables)]
pub fn sign(payload: &[u8]) -> Result<Vec<u8>, CoseError> {
    unimplemented!()
}
