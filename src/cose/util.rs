use cbor::CborType;
use std::collections::BTreeMap;

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
pub fn build_sig_struct(
    cose_sign_array: &CborType,
    protected_signature_header_serialized: &CborType,
    payload: &[u8],
) -> Vec<CborType> {
    let mut sig_structure_array: Vec<CborType> = Vec::new();

    sig_structure_array.push(CborType::String(String::from("Signature")));
    sig_structure_array.push(cose_sign_array.clone());
    sig_structure_array.push(protected_signature_header_serialized.clone());
    sig_structure_array.push(CborType::Bytes(Vec::new()));
    sig_structure_array.push(CborType::Bytes(payload.to_owned()));

    return sig_structure_array;
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
pub fn build_cose_signature(cert_chain: &[&[u8]], ee_cert: &[u8], sig_bytes: &[u8]) -> Vec<u8> {
    // Building the COSE signature content.
    let mut cose_signature: Vec<CborType> = Vec::new();

    // Empty map.
    let empty_map: BTreeMap<CborType, CborType> = BTreeMap::new();

    // add cert chain as protected header
    let mut cert_array: Vec<CborType> = Vec::new();
    for cert in cert_chain {
        cert_array.push(CborType::Bytes(cert.to_vec()));
    }
    let mut protected_body_header: BTreeMap<CborType, CborType> = BTreeMap::new();
    protected_body_header.insert(CborType::Integer(4), CborType::Array(cert_array));
    let protected_body_header = CborType::Map(protected_body_header).serialize();
    cose_signature.push(CborType::Bytes(protected_body_header));

    // Empty map (unprotected header)
    cose_signature.push(CborType::Map(empty_map.clone()));

    // No content (nil).
    cose_signature.push(CborType::Null);

    // TODO #15: Handle multiple signatures

    // Build the signature item.
    let mut signature_item: Vec<CborType> = Vec::new();

    // Protected signature header
    let mut header_map: BTreeMap<CborType, CborType> = BTreeMap::new();

    // Signature type.
    // TODO #23: don't hard code signature type.
    header_map.insert(CborType::Integer(1), CborType::SignedInteger(-7));

    // Signer certificate.
    header_map.insert(CborType::Integer(4), CborType::Bytes(ee_cert.to_vec()));

    let header_map = CborType::Map(header_map).serialize();
    signature_item.push(CborType::Bytes(header_map));

    // The unprotected signature header is empty.
    signature_item.push(CborType::Map(empty_map.clone()));

    // And finally the signature bytes.
    signature_item.push(CborType::Bytes(sig_bytes.to_vec()));
    let signature_item = CborType::Array(signature_item);

    // Pack the signature item and add everything to the cose signature object.
    let signatures = vec![signature_item];
    cose_signature.push(CborType::Array(signatures));

    // A COSE signature is a tagged array (98).
    let signature_struct = CborType::Tag(98, Box::new(CborType::Array(cose_signature).clone()));

    return signature_struct.serialize();
}
