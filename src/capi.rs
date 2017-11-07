use std::slice;
use cose::decoder::decode_signature;
use cose::CoseSignatureType;

unsafe fn from_raw(ptr: *const u8, len: usize) -> Vec<u8> {
    slice::from_raw_parts(ptr, len).to_vec()
}

type VerifyCallback = extern "C" fn(*const u8, /* payload */
                                    usize, /* payload len */
                                    *const u8, /* cert_chain */
                                    usize, /* cert_chain len */
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
    let signature_type = &cose_signatures[0].signature_type;
    // ES256 = 0, ES384 = 1, ES521 = 2, PS256 = 3
    let signature_type = match *signature_type {
        CoseSignatureType::ES256 => 0,
        _ => return false,
    };
    let signature_bytes = &cose_signatures[0].signature;
    let real_payload = &cose_signatures[0].to_verify;

    // Call callback to verify the parsed signatures.
    let result = verify_callback(
        real_payload.as_ptr(),
        real_payload.len(),
        cose_signatures[0].certs.as_ptr(),
        cose_signatures[0].certs.len(),
        cose_signatures[0].signer_cert.as_ptr(),
        cose_signatures[0].signer_cert.len(),
        signature_bytes.as_ptr(),
        signature_bytes.len(),
        signature_type
    );

    result
}
