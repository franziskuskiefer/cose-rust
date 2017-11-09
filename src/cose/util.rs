use cbor::CborType;
use cose::SignatureAlgorithm;
use std::collections::BTreeMap;
use cose::Signature;

/// Converts a `SignatureAlgorithm` to its corresponding `CborType`.
/// See RFC 8152 section 8.1 and RFC 8230 section 5.1.
pub fn signature_type_to_cbor_value(signature_type: &SignatureAlgorithm) -> CborType {
    CborType::SignedInteger(match signature_type {
        &SignatureAlgorithm::ES256 => -7,
        &SignatureAlgorithm::ES384 => -35,
        &SignatureAlgorithm::PS256 => -37,
    })
}

pub fn build_protected_sig_header(ee_cert: &[u8], alg: &SignatureAlgorithm) -> CborType {
    // Protected signature header
    let mut header_map: BTreeMap<CborType, CborType> = BTreeMap::new();

    // Signature type.
    let signature_type_value = signature_type_to_cbor_value(alg);
    header_map.insert(CborType::Integer(1), signature_type_value);

    // Signer certificate.
    header_map.insert(CborType::Integer(4), CborType::Bytes(ee_cert.to_vec()));

    let header_map = CborType::Map(header_map).serialize();
    CborType::Bytes(header_map)
}

pub fn build_protected_header(cert_chain: &[&[u8]]) -> CborType {
    let mut cert_array: Vec<CborType> = Vec::new();
    for cert in cert_chain {
        cert_array.push(CborType::Bytes(cert.to_vec()));
    }
    let mut protected_body_header: BTreeMap<CborType, CborType> = BTreeMap::new();
    protected_body_header.insert(CborType::Integer(4), CborType::Array(cert_array));
    let protected_body_header = CborType::Map(protected_body_header).serialize();

    CborType::Bytes(protected_body_header)
}

// Sig_structure is a CBOR array:
//
// Sig_structure = [
//   context : "Signature" / "Signature1" / "CounterSignature",
//   body_protected : empty_or_serialized_map,
//   ? sign_protected : empty_or_serialized_map,
//   external_aad : bstr,
//   payload : bstr
// ]
//
// In this case, the context is "Signature". There is no external_aad, so this defaults to a
// zero-length bstr.
pub fn get_sig_struct_bytes(
    protected_body_header_serialized: CborType,
    protected_signature_header_serialized: CborType,
    payload: &[u8],
) -> Vec<u8> {
    let mut sig_structure_array: Vec<CborType> = Vec::new();

    sig_structure_array.push(CborType::String(String::from("Signature")));
    sig_structure_array.push(protected_body_header_serialized);
    sig_structure_array.push(protected_signature_header_serialized);
    sig_structure_array.push(CborType::Bytes(Vec::new()));
    sig_structure_array.push(CborType::Bytes(payload.to_vec()));

    return CborType::Array(sig_structure_array).serialize();
}

pub fn build_sig_struct(ee_cert: &[u8], alg: &SignatureAlgorithm, sig_bytes: &Vec<u8>) -> CborType {
    // Build the signature item.
    let mut signature_item: Vec<CborType> = Vec::new();

    // Protected signature header
    signature_item.push(build_protected_sig_header(ee_cert, alg));

    // The unprotected signature header is empty.
    let empty_map: BTreeMap<CborType, CborType> = BTreeMap::new();
    signature_item.push(CborType::Map(empty_map));

    // And finally the signature bytes.
    signature_item.push(CborType::Bytes(sig_bytes.clone()));
    CborType::Array(signature_item)
}

// 98(
//  [
//    / protected / h'..', / {
//          \ kid \ 4:'..' \ Array of DER encoded intermediate certificates  \
//      } / ,
//    / unprotected / {},
//    / payload / nil, / The payload is the contents of the manifest file /
//    / signatures / [
//      [
//        / protected / h'a2012604..' / {
//            \ alg \ 1:-7, \ ECDSA with SHA-256 \
//            \ kid \ 4:'..' \ DER encoded signing certificate \
//          } / ,
//        / unprotected / {},
//        / signature / h'e2ae..'
//      ],
//      [
//        / protected / h'a201382404..' / {
//            \ alg \ 1:-37, \ RSASSA-PSS with SHA-256 \
//            \ kid \ 4:'..' \ DER encoded signing certificate \
//          } / ,
//        / unprotected / {},
//        / signature / h'00a2..'
//      ]
//    ]
//  ]
pub fn build_cose_signature(cert_chain: &[&[u8]], signature_vec: &Vec<Signature>) -> Vec<u8> {
    // Building the COSE signature content.
    let mut cose_signature: Vec<CborType> = Vec::new();

    // add cert chain as protected header
    cose_signature.push(build_protected_header(cert_chain));

    // Empty map (unprotected header)
    let empty_map: BTreeMap<CborType, CborType> = BTreeMap::new();
    cose_signature.push(CborType::Map(empty_map));

    // No payload (nil).
    cose_signature.push(CborType::Null);

    // Create signature items.
    let mut signatures: Vec<CborType> = Vec::new();
    for signature in signature_vec {
        let signature_item = build_sig_struct(
            signature.parameter.certificate,
            &signature.parameter.algorithm,
            &signature.signature_bytes,
        );
        signatures.push(signature_item);
    }

    // Pack the signature item and add everything to the cose signature object.
    cose_signature.push(CborType::Array(signatures));

    // A COSE signature is a tagged array (98).
    let signature_struct = CborType::Tag(98, Box::new(CborType::Array(cose_signature).clone()));

    return signature_struct.serialize();
}
