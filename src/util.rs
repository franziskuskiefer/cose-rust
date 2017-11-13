use cbor::CborType;

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
