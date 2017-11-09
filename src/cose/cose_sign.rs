/// We don't need COSE signing at the moment. But we need to generate test files.
/// This module implements basic COSE signing.
use cose::nss;
use cose::CoseError;
use cose::util::{build_cose_signature, build_protected_header, build_protected_sig_header,
                 get_sig_struct_bytes};
use cose::{Signature, SignatureParameters};

pub fn sign(
    payload: &[u8],
    cert_chain: &[&[u8]],
    parameters: &Vec<SignatureParameters>,
) -> Result<Vec<u8>, CoseError> {
    assert!(parameters.len() > 0);
    if parameters.len() < 1 {
        return Err(CoseError::InvalidArgument);
    }

    let mut signatures: Vec<Signature> = Vec::new();
    for param in parameters {
        // Build the signature structure containing the protected headers and the
        // payload to generate the payload that is actually signed.
        let protected_sig_header_serialized =
            build_protected_sig_header(param.certificate, &param.algorithm);
        let protected_header_serialized = build_protected_header(cert_chain);
        let payload = get_sig_struct_bytes(
            protected_header_serialized,
            protected_sig_header_serialized,
            payload,
        );

        let signature_bytes = match nss::sign(&param.algorithm, &param.pkcs8, &payload) {
            Err(_) => return Err(CoseError::SigningFailed),
            Ok(signature) => signature,
        };
        let signature = Signature {
            parameter: param,
            signature_bytes: signature_bytes,
        };
        signatures.push(signature);
    }

    assert!(signatures.len() > 0);
    if signatures.len() < 1 {
        return Err(CoseError::MalformedInput);
    }

    let cose_signature = build_cose_signature(cert_chain, &signatures);
    Ok(cose_signature)
}
