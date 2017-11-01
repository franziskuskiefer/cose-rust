use cose::test_setup as test;
use cose::*;
use cose::cose_sign::sign;

// All keys here are from pykey.py/pycert.py from mozilla-central.
// Certificates can be generated with tools/certs/certs.sh and mozilla-central.

#[test]
fn test_cose_sign_verify() {
    test::setup();
    let payload = b"This is the content.";
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let cose_signature = sign(
        payload,
        CoseSignatureType::ES256,
        &test::P256_EE,
        &certs,
        &test::PKCS8_P256_EE,
    );
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();

    // Verify signature.
    assert!(verify_signature(payload, cose_signature).is_ok());
}

#[test]
fn test_cose_sign_verify_modified_payload() {
    test::setup();
    let payload = b"This is the content.";
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let cose_signature = sign(
        payload,
        CoseSignatureType::ES256,
        &test::P256_EE,
        &certs,
        &test::PKCS8_P256_EE,
    );
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();

    // Verify signature.
    let payload = b"This is the content!";
    let verify_result = verify_signature(payload, cose_signature);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}

#[test]
fn test_cose_sign_verify_wrong_cert() {
    test::setup();
    let payload = b"This is the content.";
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let cose_signature = sign(
        payload,
        CoseSignatureType::ES256,
        &test::P384_EE,
        &certs,
        &test::PKCS8_P256_EE,
    );
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();

    // Verify signature.
    let verify_result = verify_signature(payload, cose_signature);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}
