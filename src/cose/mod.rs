//! This module implements COSE using the `cose::decoder` and `cose::nss` bindings.

#[cfg(test)]
pub mod decoder;
#[cfg(test)]
mod util;

#[cfg(test)]
mod nss;
#[cfg(test)]
mod test_setup;
#[cfg(test)]
mod test_nss;
#[cfg(test)]
mod cose_sign;
#[cfg(test)]
mod test_cose;

#[cfg(test)]
use cose::decoder::*;

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
}

/// An enum identifying supported signature algorithms. Currently only ECDSA with SHA256 (ES256) and
/// RSASSA-PSS with SHA-256 (PS256) are supported. Note that with PS256, the salt length is defined
/// to be 32 bytes.
#[derive(Debug)]
#[derive(PartialEq)]
pub enum SignatureAlgorithm {
    ES256,
    PS256,
}

/// Verify a COSE signature.
#[cfg(test)]
pub fn verify_signature(payload: &[u8], cose_signature: Vec<u8>) -> Result<(), CoseError> {
    // Parse COSE signature.
    let cose_signatures = decode_signature(cose_signature, payload)?;
    if cose_signatures.len() < 1 {
        return Err(CoseError::MalformedInput);
    }

    for signature in cose_signatures {
        let signature_algorithm = &signature.signature_type;
        let signature_bytes = &signature.signature;
        let real_payload = &signature.to_verify;

        println!("Verifying signature {:?}", signature_algorithm);

        // Verify the parsed signatures.
        // We ignore the certs field here because we don't verify the certificate.
        let verify_result = nss::verify_signature(
            &signature_algorithm,
            &signature.signer_cert,
            real_payload,
            signature_bytes,
        );
        if !verify_result.is_ok() {
            return Err(CoseError::VerificationFailed);
        }
    }
    Ok(())
}
