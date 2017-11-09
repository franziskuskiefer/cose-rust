use std::slice;
use cose::decoder::decode_signature;
use cose::SignatureAlgorithm;

unsafe fn from_raw(ptr: *const u8, len: usize) -> Vec<u8> {
    slice::from_raw_parts(ptr, len).to_vec()
}

type VerifyCallback = extern "C" fn(*const u8, /* payload */
                                    usize, /* payload len */
                                    *const*const u8, /* cert_chain */
                                    usize, /* # certs */
                                    *const usize, /* cert lengths in cert_chain */
                                    *const u8, /* signer cert */
                                    usize, /* signer cert len */
                                    *const u8, /* signature bytes */
                                    usize, /* signature len */
                                    u8 /* signature algorithm */)
                                    -> bool;

#[no_mangle]
pub unsafe extern "C" fn verify_signature_with_cpp(
    payload: *const u8,
    payload_len: usize,
    cose_signature: *const u8,
    cose_signature_len: usize,
    verify_callback: VerifyCallback,
) -> bool {
    if payload.is_null() || cose_signature.is_null() || payload_len == 0 ||
        cose_signature_len == 0
    {
        return false;
    }

    // Build Rust variables from C parameters.
    let payload = from_raw(payload, payload_len);
    let cose_signature = from_raw(cose_signature, cose_signature_len);

    // Parse the incoming signature.
    let cose_signatures = decode_signature(cose_signature, &payload);
    let cose_signatures = match cose_signatures {
        Ok(signature) => signature,
        Err(_) => Vec::new(),
    };
    if cose_signatures.len() < 1 {
        return false;
    }

    let mut result = true;
    for cose_signature in cose_signatures {
        let signature_type = cose_signature.signature_type;
        // ES256 = 0, ES384 = 1, ES521 = 2, PS256 = 3
        let signature_type = match signature_type {
            SignatureAlgorithm::ES256 => 0,
            SignatureAlgorithm::ES384 => 1,
            SignatureAlgorithm::ES512 => 2,
            SignatureAlgorithm::PS256 => 3,
        };
        let signature_bytes = cose_signature.signature;
        let real_payload = cose_signature.to_verify;

        // Build cert chain params.
        let mut cert_lens:Vec<usize> = Vec::new();
        let mut certs:Vec<*const u8> = Vec::new();
        for cert in &cose_signature.certs {
            cert_lens.push(cert.len());
            certs.push(cert.as_ptr());
        }

        // Call callback to verify the parsed signatures.
        result &= verify_callback(
            real_payload.as_ptr(),
            real_payload.len(),
            certs.as_ptr(),
            cose_signature.certs.len(),
            cert_lens.as_ptr(),
            cose_signature.signer_cert.as_ptr(),
            cose_signature.signer_cert.len(),
            signature_bytes.as_ptr(),
            signature_bytes.len(),
            signature_type,
        );

        // We can stop early. The cose_signature is not valid.
        if !result {
            return result;
        }
    }

    result
}
