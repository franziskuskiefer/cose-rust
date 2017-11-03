/// We don't need COSE signing at the moment. But we need to generate test files.
/// This module implements basic COSE signing.
use cose::nss;
use cose::CoseError;
use cose::util::{build_cose_signature, build_protected_header, build_protected_sig_header,
                 get_sig_struct_bytes};
use cose::SignatureAlgorithm;

pub fn sign(
    payload: &[u8],
    algorithms: &[SignatureAlgorithm],
    ee_certs: &[&[u8]],
    cert_chain: &[&[u8]],
    pkcs8: &[&[u8]],
) -> Result<Vec<u8>, CoseError> {
    assert_eq!(pkcs8.len(), ee_certs.len());
    assert_eq!(algorithms.len(), ee_certs.len());
    let mut signatures: Vec<Vec<u8>> = Vec::new();
    for ((ref ee_cert, ref algorithm), ref pk8) in
        ee_certs.iter().zip(algorithms.iter()).zip(pkcs8.iter())
    {
        // Build the signature structure containing the protected headers and the
        // payload to generate the payload that is actually signed.
        let protected_sig_header_serialized = build_protected_sig_header(ee_cert, algorithm);
        let protected_header_serialized = build_protected_header(cert_chain);
        let payload = get_sig_struct_bytes(
            protected_header_serialized,
            protected_sig_header_serialized,
            payload,
        );

        let signature = match nss::sign(algorithm, &pk8, &payload) {
            Err(_) => return Err(CoseError::SigningFailed),
            Ok(signature) => signature,
        };
        signatures.push(signature.clone());
    }
    let cose_signature = build_cose_signature(cert_chain, ee_certs, &signatures, algorithms);
    Ok(cose_signature)
}
