use test_setup as test;
use util_test::{sign, verify_signature};
use {CoseError, SignatureAlgorithm, SignatureParameters};
use std::str::FromStr;
use decoder::decode_signature;

use std::env;
use std::path::Path;
use std::fs::File;
use std::error::Error;
use std::io::prelude::*;

#[test]
fn test_cose_decode() {
    let payload = b"This is the content.";
    let cose_signatures = decode_signature(&test::COSE_SIGNATURE_BYTES, payload).unwrap();
    assert_eq!(cose_signatures.len(), 1);
    assert_eq!(cose_signatures[0].signature_type, SignatureAlgorithm::ES256);
    assert_eq!(cose_signatures[0].signature, test::SIGNATURE_BYTES.to_vec());
    assert_eq!(cose_signatures[0].certs[0], test::P256_ROOT.to_vec());
    assert_eq!(cose_signatures[0].certs[1], test::P256_INT.to_vec());
}

// All keys here are from pykey.py/pycert.py from mozilla-central.
// Certificates can be generated with tools/certs/certs.sh and mozilla-central.

const P256_PARAMS: SignatureParameters = SignatureParameters {
    certificate: &test::P256_EE,
    algorithm: SignatureAlgorithm::ES256,
    pkcs8: &test::PKCS8_P256_EE,
};
const P384_PARAMS: SignatureParameters = SignatureParameters {
    certificate: &test::P384_EE,
    algorithm: SignatureAlgorithm::ES384,
    pkcs8: &test::PKCS8_P384_EE,
};
const P521_PARAMS: SignatureParameters = SignatureParameters {
    certificate: &test::P521_EE,
    algorithm: SignatureAlgorithm::ES512,
    pkcs8: &test::PKCS8_P521_EE,
};

fn write_bytes(file_name: String, bytes: &[u8]) {
    let path = Path::new(&file_name);
    let mut file = match File::create(&path) {
        Err(why) => panic!("Couldn't open {}: {}", path.display(), why.description()),
        Ok(file) => file,
    };
    match file.write_all(bytes) {
        Err(why) => {
            panic!(
                "Couldn't write to {}: {}",
                path.display(),
                why.description()
            )
        }
        Ok(_) => println!("Successfully wrote to {}", path.display()),
    }
}

fn test_verify(
    payload: &[u8],
    cert_chain: &[&[u8]],
    params_vec: Vec<SignatureParameters>,
    hash_payload: bool,
) {
    test::setup();
    let cose_signature = sign(payload, cert_chain, &params_vec, hash_payload);
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();
    if let Ok(sig_file) = env::var("COSE_SIGNATURE_FILE") {
        write_bytes(sig_file, &cose_signature);
    }

    // Verify signature.
    assert!(verify_signature(payload, cose_signature, hash_payload).is_ok());
}

fn test_verify_modified_payload(
    payload: &mut [u8],
    cert_chain: &[&[u8]],
    params_vec: Vec<SignatureParameters>,
) {
    test::setup();
    let cose_signature = sign(payload, cert_chain, &params_vec, true);
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();

    // Verify signature.
    payload[0] = !payload[0];
    let verify_result = verify_signature(payload, cose_signature, true);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}

fn test_verify_modified_signature(
    payload: &[u8],
    cert_chain: &[&[u8]],
    params_vec: Vec<SignatureParameters>,
) {
    test::setup();
    let cose_signature = sign(payload, cert_chain, &params_vec, true);
    assert!(cose_signature.is_ok());
    let mut cose_signature = cose_signature.unwrap();

    // Tamper with the cose signature.
    let len = cose_signature.len();
    cose_signature[len - 15] = !cose_signature[len - 15];

    // Verify signature.
    let verify_result = verify_signature(payload, cose_signature, true);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}

// This can be used with inconsistent parameters that make the verification fail.
// In particular, the signing key does not match the certificate used to verify.
#[cfg(test)]
fn test_verify_verification_fails(
    payload: &[u8],
    cert_chain: &[&[u8]],
    params_vec: Vec<SignatureParameters>,
) {
    test::setup();
    let cose_signature = sign(payload, cert_chain, &params_vec, true);
    assert!(cose_signature.is_ok());
    let cose_signature = cose_signature.unwrap();

    // Verify signature.
    let verify_result = verify_signature(payload, cose_signature, true);
    assert!(verify_result.is_err());
    assert_eq!(verify_result, Err(CoseError::VerificationFailed));
}

#[test]
fn test_cose_sign_verify() {
    let payload = b"This is the content.";

    // P256
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let params_vec = vec![P256_PARAMS];
    test_verify(payload, &certs, params_vec, true);

    // P384
    let params_vec = vec![P384_PARAMS];
    test_verify(payload, &certs, params_vec, true);

    // P521
    let params_vec = vec![P521_PARAMS];
    test_verify(payload, &certs, params_vec, true);
}

#[test]
fn test_cose_sign_verify_xpi() {
    let payload: [u8; 32] = [0xe2, 0xa1, 0x3a, 0x50, 0x83, 0x1d, 0x8e, 0x94, 0x5d, 0x9e, 0x7b,
                             0x6f, 0x7b, 0x88, 0xe5, 0x7d, 0xfd, 0x1e, 0xe3, 0x71, 0x85, 0x05,
                             0x1d, 0x65, 0x48, 0x98, 0xc7, 0x0e, 0xe2, 0x0d, 0x8e, 0xa3];

    // xpc shell test cert (p256 - int - root)
    let certs: [&[u8]; 2] = [&test::XPCSHELL_TEST_ROOT,
                             &test::XPCSHELL_TEST_INT];
    let params = SignatureParameters {
        certificate: &test::XPCSHELL_TEST_P256_INT_SIGNED,
        algorithm: SignatureAlgorithm::ES256,
        pkcs8: &test::PKCS8_P256_EE,
    };
    let params_vec = vec![params];
    test_verify(&payload, &certs, params_vec, false);
}

#[test]
fn test_cose_sign_verify_modified_payload() {
    let mut payload = String::from_str("This is the content.")
        .unwrap()
        .into_bytes();
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let params_vec = vec![P256_PARAMS];
    test_verify_modified_payload(&mut payload, &certs, params_vec);
}

#[test]
fn test_cose_sign_verify_wrong_cert_type() {
    let payload = b"This is the content.";
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let params = SignatureParameters {
        certificate: &test::P384_EE,
        algorithm: SignatureAlgorithm::ES256,
        pkcs8: &test::PKCS8_P256_EE,
    };
    let params_vec = vec![params];
    test_verify_verification_fails(payload, &certs, params_vec);
}

#[test]
fn test_cose_sign_verify_wrong_cert() {
    let payload = b"This is the content.";
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let params = SignatureParameters {
        certificate: &test::P256_EE,
        algorithm: SignatureAlgorithm::ES256,
        pkcs8: &test::PKCS8_P256_OTHER_EE,
    };
    let params_vec = vec![params];
    test_verify_verification_fails(payload, &certs, params_vec);
}

#[test]
fn test_cose_sign_verify_tampered_signature() {
    let payload = b"This is the content.";
    let certs: [&[u8]; 2] = [&test::P256_ROOT,
                             &test::P256_INT];
    let params_vec = vec![P256_PARAMS];
    test_verify_modified_signature(payload, &certs, params_vec);
}

const RSA_PARAMS: SignatureParameters = SignatureParameters {
    certificate: &test::RSA_EE,
    algorithm: SignatureAlgorithm::PS256,
    pkcs8: &test::PKCS8_RSA_EE,
};

#[test]
fn test_cose_sign_verify_rsa() {
    let payload = b"This is the RSA-signed content.";
    let certs: [&[u8]; 2] = [&test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![RSA_PARAMS];
    test_verify(payload, &certs, params_vec, true);
}

#[test]
fn test_cose_sign_verify_rsa_modified_payload() {
    let mut payload = String::from_str("This is the RSA-signed content.")
        .unwrap()
        .into_bytes();
    let certs: [&[u8]; 2] = [&test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![RSA_PARAMS];
    test_verify_modified_payload(&mut payload, &certs, params_vec);
}

#[test]
fn test_cose_sign_verify_rsa_tampered_signature() {
    let payload = b"This is the RSA-signed content.";
    let certs: [&[u8]; 2] = [&test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![RSA_PARAMS];
    test_verify_modified_signature(payload, &certs, params_vec);
}

#[test]
fn test_cose_sign_verify_two_signatures() {
    let payload = b"This is the content.";
    let certs: [&[u8]; 4] = [&test::P256_ROOT,
                             &test::P256_INT,
                             &test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![P256_PARAMS,
                          RSA_PARAMS];
    test_verify(payload, &certs, params_vec, true);
}

#[test]
fn test_cose_sign_verify_two_signatures_tampered_payload() {
    let mut payload = String::from_str("This is the content.")
        .unwrap()
        .into_bytes();
    let certs: [&[u8]; 4] = [&test::P256_ROOT,
                             &test::P256_INT,
                             &test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![P256_PARAMS,
                          RSA_PARAMS];
    test_verify_modified_payload(&mut payload, &certs, params_vec);
}

#[test]
fn test_cose_sign_verify_two_signatures_tampered_signature() {
    let payload = b"This is the content.";
    let certs: [&[u8]; 4] = [&test::P256_ROOT,
                             &test::P256_INT,
                             &test::RSA_ROOT,
                             &test::RSA_INT];
    let params_vec = vec![P256_PARAMS,
                          RSA_PARAMS];
    test_verify_modified_signature(payload, &certs, params_vec);
}
