//! This module implements COSE using the `cose::decoder` and `cose::nss` bindings.

#[cfg(test)]
pub mod decoder;
#[cfg(test)]
mod util;

#[cfg(test)]
mod nss;
#[cfg(test)]
mod test_setup;
mod test_nss_verify;
mod test_nss_sign;
mod test_decoder;
#[cfg(test)]
mod cose_sign;
#[cfg(test)]
mod test_cose;

#[cfg(test)]
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
    UnkownSignatureScheme,
    SigningFailed,
}

/// Verify a COSE signature.
#[cfg(test)]
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
