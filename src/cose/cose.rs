//! This module implements COSE using the cose::decoder and cose::nss bindings.

use cose::nss;
use cose::decoder::*;
use cbor::cbor::CborType;
use std::collections::BTreeMap;

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
    SigningFailed,
    UnkownSignatureScheme,
}

/// Verify a COSE signature.
pub fn verify_signature(payload: &[u8], cose_signature: Vec<u8>) -> Result<(), CoseError> {
    // Parse COSE signature.
    let cose_signatures = decode_signature(cose_signature, payload)?;
    if cose_signatures.len() != 1 {
        return Err(CoseError::LibraryFailure);
    }
    let signature_type = &cose_signatures[0].signature_type;
    let signature_algorithm = match signature_type {
        &CoseSignatureType::ES256 => nss::SignatureAlgorithm::ES256,
        _ => return Err(CoseError::LibraryFailure),
    };
    let signature_bytes = &cose_signatures[0].signature;
    let real_payload = &cose_signatures[0].to_verify;

    // Verify the parsed signature.
    let verify_result = nss::verify_signature(
        signature_algorithm,
        &cose_signatures[0].signer_cert,
        real_payload,
        signature_bytes,
    );
    if !verify_result.is_ok() {
        return Err(CoseError::VerificationFailed);
    }
    Ok(())
}

// XXX: This works only with P256 for now!
fn build_pkcs8(public_key: &[u8], secret_key: &[u8]) -> Vec<u8> {
    let mut pkcs8: Vec<u8> =
        vec![
      0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
      0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
      0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
      // Private key: len, bytes.
      // Public key (uncompressed EC point for now): 0xa1, len, type, len, 0x00, bytes.
      ];
    pkcs8.extend_from_slice(secret_key);
    pkcs8.push(0xa1);
    let len = (public_key.len() + 4 - 1) as u8;
    pkcs8.push(len);
    pkcs8.push(0x03);
    pkcs8.push(len - 2);
    pkcs8.push(0x00);
    pkcs8.extend_from_slice(public_key);

    return pkcs8;
}

/// RFC 8152 Section 4.4
///    Sig_structure = [
///        context : "Signature" / "Signature1" / "CounterSignature",
///        body_protected : empty_or_serialized_map,
///        ? sign_protected : empty_or_serialized_map,
///        external_aad : bstr,
///        payload : bstr
///    ]
fn build_signature_structure(payload: &[u8], alg: CoseSignatureType) -> Vec<u8> {
    let mut sig_structure: Vec<CborType> = Vec::new();
    sig_structure.push(CborType::String("Signature".to_string()));
    // TODO: add the protected body header here.
    sig_structure.push(CborType::Bytes(vec![]));

    // Encode values into the protected_sig_header, which is a byte array
    // encoding a map.
    if alg != CoseSignatureType::ES256 {
        // TODO: we only accept ES256 for now.
        return Vec::new();
    }
    let mut header_map: BTreeMap<CborType, CborType> = BTreeMap::new();
    header_map.insert(CborType::Integer(1), CborType::SignedInteger(-7));
    let header_map = CborType::Map(header_map).serialize();
    sig_structure.push(CborType::Bytes(header_map));

    // XXX: We don't hande external_aad here.
    sig_structure.push(CborType::Bytes(vec![]));

    sig_structure.push(CborType::Bytes(payload.to_vec()));

    let sig_structure = CborType::Array(sig_structure);
    sig_structure.serialize()
}

fn build_spki(key: &[u8]) -> Vec<u8> {
    let mut spki = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                        0x42, 0x00];
    spki.extend_from_slice(key);
    spki
}

/// The key has to be an uncrompressed curve point on the point specified in alg.
pub fn sign(
    payload: &[u8],
    alg: CoseSignatureType,
    public_key: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>, CoseError> {
    let nss_alg = match alg {
        CoseSignatureType::ES256 => nss::SignatureAlgorithm::ES256,
        _ => return Err(CoseError::UnkownSignatureScheme),
    };
    let pkcs8 = build_pkcs8(public_key, secret_key);

    // The protected signature header contains
    //  * the signature algorithm
    //  * XXX: the DER encoded EE certificate (not yet)
    let payload = build_signature_structure(payload, alg);

    let signature = nss::sign(nss_alg, &pkcs8, &payload);
    if !signature.is_ok() {
        return Err(CoseError::SigningFailed);
    }
    let signature = signature.unwrap();

    let mut cose_signature: Vec<CborType> = Vec::new();
    // TODO: add intermediate certificates to the protected header.
    cose_signature.push(CborType::Bytes(vec![]));

    // No body headers
    cose_signature.push(CborType::Map(BTreeMap::new()));

    // The payload is empty (TODO: it should be nil)
    cose_signature.push(CborType::Bytes(vec![]));

    // Build the signature item.
    let mut signature_item: Vec<CborType> = Vec::new();

    // Protected signature header
    let mut header_map: BTreeMap<CborType, CborType> = BTreeMap::new();
    // TODO: make algorithm flexible.
    header_map.insert(CborType::Integer(1), CborType::SignedInteger(-7));
    let header_map = CborType::Map(header_map).serialize();
    signature_item.push(CborType::Bytes(header_map));

    // Unprotected signature header
    let mut header_map: BTreeMap<CborType, CborType> = BTreeMap::new();
    // TODO: Get certificates in here.
    header_map.insert(
        CborType::Integer(4),
        CborType::Bytes(build_spki(public_key)),
    );
    signature_item.push(CborType::Map(header_map));

    // And finally the signature bytes.
    signature_item.push(CborType::Bytes(signature));
    let signature_item = CborType::Array(signature_item);

    // Pack the signature item and add everything to the cose signature object.
    let signatures = vec![signature_item];
    cose_signature.push(CborType::Array(signatures));

    // Tag the cose_signature array and serialize the result.
    let cose_sign_tag: u64 = 98;
    let result = CborType::Tag(cose_sign_tag, Box::new(CborType::Array(cose_signature)))
        .serialize();
    Ok(result)
}
