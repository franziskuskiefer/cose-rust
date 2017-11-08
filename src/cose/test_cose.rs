use cose::test_setup as test;
use cose::*;
use cose::cose_sign::sign;
use cose::SignatureAlgorithm;

#[test]
fn test_cose_decode() {
    let payload = b"This is the content.";
    let cose_signatures = decode_signature(test::COSE_SIGNATURE_BYTES.to_vec(), payload).unwrap();
    assert_eq!(cose_signatures.len(), 1);
    assert_eq!(cose_signatures[0].signature_type, SignatureAlgorithm::ES256);
    assert_eq!(cose_signatures[0].signature, test::SIGNATURE_BYTES.to_vec());
}

// All keys here are from pykey.py/pycert.py from mozilla-central.
// Certificates can be generated with tools/certs/certs.sh and mozilla-central.

const P256_PARAMS: SignatureParameters = SignatureParameters {
    certificate: &test::P256_EE,
    algorithm: SignatureAlgorithm::ES256,
    pkcs8: &test::PKCS8_P256_EE,
};

#[test]
fn test_cose_sign_verify() {
    test::setup();
    let payload = b"This is the content.";
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let params_vec = vec![P256_PARAMS];
    let cose_signature = sign(payload, &certs, &params_vec);
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
    let params_vec = vec![P256_PARAMS];
    let cose_signature = sign(payload, &certs, &params_vec);
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
    let params = SignatureParameters {
        certificate: &test::P384_EE,
        algorithm: SignatureAlgorithm::ES256,
        pkcs8: &test::PKCS8_P256_EE,
    };
    let params_vec = vec![params];
    let cose_signature = sign(payload, &certs, &params_vec);
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();

    // Verify signature.
    let verify_result = verify_signature(payload, cose_signature);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}

#[test]
fn test_cose_sign_verify_tampered_signature() {
    test::setup();
    let payload = b"This is the content.";
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let params_vec = vec![P256_PARAMS];
    let cose_signature = sign(payload, &certs, &params_vec);
    assert!(cose_signature.is_ok());
    let mut cose_signature = cose_signature.unwrap();

    // Tamper with the cose signature.
    cose_signature[15] = cose_signature[15] ^ cose_signature[15];

    // Verify signature.
    let verify_result = verify_signature(payload, cose_signature);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}

const RSA_PARAMS: SignatureParameters = SignatureParameters {
    certificate: &test::RSA_EE,
    algorithm: SignatureAlgorithm::PS256,
    pkcs8: &test::PKCS8_RSA_EE,
};

#[test]
fn test_cose_sign_verify_rsa() {
    test::setup();
    let payload = b"This is the RSA-signed content.";
    let certs: [&[u8]; 2] = [&test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![RSA_PARAMS];
    let cose_signature = sign(payload, &certs, &params_vec);
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();
    assert!(verify_signature(payload, cose_signature).is_ok());
}

#[test]
fn test_cose_sign_verify_rsa_modified_payload() {
    test::setup();
    let payload = b"This is the RSA-signed content.";
    let certs: [&[u8]; 2] = [&test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![RSA_PARAMS];
    let cose_signature = sign(payload, &certs, &params_vec);
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();
    let payload = b"This is the modified RSA-signed content.";
    let verify_result = verify_signature(payload, cose_signature);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}

#[test]
fn test_cose_sign_verify_rsa_tampered_signature() {
    test::setup();
    let payload = b"This is the RSA-signed content.";
    let certs: [&[u8]; 2] = [&test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![RSA_PARAMS];
    let cose_signature = sign(payload, &certs, &params_vec);
    assert!(cose_signature.is_ok());
    let mut cose_signature = cose_signature.unwrap();
    cose_signature[45] = !cose_signature[45];
    let verify_result = verify_signature(payload, cose_signature);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}

#[test]
fn test_cose_sign_verify_two_signatures() {
    test::setup();
    let payload = b"This is the content.";
    let certs: [&[u8]; 4] = [&test::P256_ROOT,
                             &test::P256_INT,
                             &test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![P256_PARAMS,
                          RSA_PARAMS];
    let cose_signature = sign(payload, &certs, &params_vec);
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();

    // Verify signature.
    assert!(verify_signature(payload, cose_signature).is_ok());
}

#[test]
fn test_cose_sign_verify_two_signatures_tampered_payload() {
    test::setup();
    let payload = b"This is the content.";
    let certs: [&[u8]; 4] = [&test::P256_ROOT,
                             &test::P256_INT,
                             &test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![P256_PARAMS,
                          RSA_PARAMS];
    let cose_signature = sign(payload, &certs, &params_vec);
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();

    // Verify signature.
    let payload = b"This is the content!";
    let verify_result = verify_signature(payload, cose_signature);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}

#[test]
fn test_cose_sign_verify_two_signatures_tampered_signature() {
    test::setup();
    let payload = b"This is the content.";
    let certs: [&[u8]; 4] = [&test::P256_ROOT,
                             &test::P256_INT,
                             &test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![P256_PARAMS,
                          RSA_PARAMS];
    let cose_signature = sign(payload, &certs, &params_vec);
    assert!(cose_signature.is_ok());
    let mut cose_signature = cose_signature.unwrap();
    cose_signature[45] = !cose_signature[45];

    // Verify signature.
    let verify_result = verify_signature(payload, cose_signature);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}
