/// We don't need COSE signing at the moment. But we need to generate test files.
/// This module implements basic COSE signing.

#[cfg(test)]
use cose::nss;
#[cfg(test)]
use cose::decoder::*;
#[cfg(test)]
use cose::cose::{CoseError};
#[cfg(test)]
use cbor::cbor::CborType;
#[cfg(test)]
use std::collections::BTreeMap;

// This works only with P256!
#[cfg(test)]
fn build_p256_pkcs8(public_key: &[u8], secret_key: &[u8]) -> Vec<u8> {
    let mut pkcs8: Vec<u8> = vec![
        0x30, 0x81, 0x87, // Sequence
            0x02, 0x01, 0x00, // Integer
            0x30, 0x13, // Sequence
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // P256
            0x04, 0x6d, // Octet String
                0x30, 0x6b, // Sequence
                    0x02, 0x01, 0x01, // Integer
                    0x04, 0x20, // Octet String
      ];
    pkcs8.extend_from_slice(secret_key); // append secret key as octet string
    pkcs8.push(0xa1); // First element
    let len = (public_key.len() + 4 - 1) as u8;
    pkcs8.push(len); // Length of the following bit string
    pkcs8.push(0x03); // Bit string
    pkcs8.push(len - 2); // Length
    pkcs8.push(0x00); // Unused bits
    pkcs8.extend_from_slice(public_key); // Public key bytes

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
#[cfg(test)]
fn build_signature_structure(payload: &[u8], alg: CoseSignatureType) -> Result<Vec<u8>, CoseError> {
    let mut sig_structure: Vec<CborType> = Vec::new();
    sig_structure.push(CborType::String("Signature".to_string()));
    // TODO #15: Add the protected body header here.
    sig_structure.push(CborType::Bytes(vec![]));

    // Encode values into the protected_sig_header, which is a byte array
    // encoding a map.
    if alg != CoseSignatureType::ES256 {
        return Err(CoseError::UnkownSignatureScheme);
    }
    let mut header_map: BTreeMap<CborType, CborType> = BTreeMap::new();
    header_map.insert(CborType::Integer(1), CborType::SignedInteger(-7));
    let header_map = CborType::Map(header_map).serialize();
    sig_structure.push(CborType::Bytes(header_map));

    // We don't hande external_aad.
    sig_structure.push(CborType::Bytes(vec![]));

    sig_structure.push(CborType::Bytes(payload.to_vec()));

    let sig_structure = CborType::Array(sig_structure);
    Ok(sig_structure.serialize())
}

#[cfg(test)]
fn build_p256_spki(key: &[u8]) -> Vec<u8> {
    let mut spki = vec![
        0x30, 0x59, // Sequence
            0x30, 0x13, //Sequence
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // P256
            0x03, 0x42, // Bit string
                0x00 // Unused bits
    ];
    spki.extend_from_slice(key); // Public key bytes
    spki
}

/// The key has to be an uncrompressed curve point on the point specified in alg.
#[cfg(test)]
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
    let pkcs8 = build_p256_pkcs8(public_key, secret_key);

    // The protected signature header contains
    //  * the signature algorithm
    //  * TODO #15: the DER encoded EE certificate
    let payload = build_signature_structure(payload, alg)?;

    let signature = nss::sign(nss_alg, &pkcs8, &payload);
    if !signature.is_ok() {
        return Err(CoseError::SigningFailed);
    }
    let signature = signature.unwrap();

    let mut cose_signature: Vec<CborType> = Vec::new();
    // TODO #15: add intermediate certificates to the protected header.
    cose_signature.push(CborType::Bytes(vec![]));

    // No body headers
    cose_signature.push(CborType::Map(BTreeMap::new()));

    // The payload is empty
    // TODO: it should be nil; depends on PR #22
    cose_signature.push(CborType::Bytes(vec![]));

    // Build the signature item.
    let mut signature_item: Vec<CborType> = Vec::new();

    // Protected signature header
    let mut header_map: BTreeMap<CborType, CborType> = BTreeMap::new();

    header_map.insert(CborType::Integer(1), CborType::SignedInteger(-7));
    let header_map = CborType::Map(header_map).serialize();
    signature_item.push(CborType::Bytes(header_map));

    // Unprotected signature header
    let mut header_map: BTreeMap<CborType, CborType> = BTreeMap::new();
    // TODO #15: Get certificates in here.
    header_map.insert(
        CborType::Integer(4),
        CborType::Bytes(build_p256_spki(public_key)),
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