use cbor::decoder::*;

#[derive(Debug)]
pub enum CoseType {
    COSESign = 98,
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum CoseSignatureType {
    ES256,
    ES384,
    ES512,
}

#[derive(Debug)]
pub struct CoseSignature {
    pub signature_type: CoseSignatureType,
    pub signature: Vec<u8>,
    pub signer_cert: Vec<u8>,
    pub certs: Vec<u8>,
    pub to_verify: Vec<u8>,
}

macro_rules! unpack {
   ($to:tt, $var:ident) => (
        match $var {
            &CBORType::$to(ref cose_object) => {
                cose_object
            }
            // XXX: This needs handling!
            _ => return Err("This is not a valid COSE signature object X."),
        };
    )
}

/// COSE_Sign = [
///     Headers,
///     payload : bstr / nil,
///     signatures : [+ COSE_Signature]
/// ]
///
/// Headers = (
///     protected : empty_or_serialized_map,
///     unprotected : header_map
/// )
///
/// This syntax is a little unintuitive. Taken together, the two previous definitions essentially
/// mean:
///
/// COSE_Sign = [
///     protected : empty_or_serialized_map,
///     unprotected : header_map
///     payload : bstr / nil,
///     signatures : [+ COSE_Signature]
/// ]
///
/// (COSE_Sign is an array. The first element is an empty or serialized map (in our case, it is
/// never expected to be empty). The second element is a map (it is expected to be empty. The third
/// element is a bstr or nil (it is expected to be nil). The fourth element is an array of
/// COSE_Signature.)
///
/// COSE_Signature =  [
///     Headers,
///     signature : bstr
/// ]
///
/// but again, unpacking this:
///
/// COSE_Signature =  [
///     protected : empty_or_serialized_map,
///     unprotected : header_map
///     signature : bstr
/// ]

pub fn decode_signature(bytes: Vec<u8>, payload: &[u8]) -> Result<Vec<CoseSignature>, &'static str> {
    // This has to be a COSE_Sign object, which is a tagged array.
    let tagged_cose_sign = decode(bytes)?;
    let cose_sign_array = match tagged_cose_sign {
        CBORType::Tag(tag, cose_sign) => {
            if tag != CoseType::COSESign as u64 {
                return Err("This is not a COSE_Sign object 0");
            }
            match *cose_sign {
                CBORType::Array(values) => values,
                _ => return Err("This is not a COSE_Sign object 1"),
            }
        },
        _ => return Err("This is not a COSE_Sign object 2"),
    };
    if cose_sign_array.len() != 4 {
        return Err("This is not a valid COSE signature object 3.");
    }
    let signatures = &cose_sign_array[3];
    let signatures = unpack!(Array, signatures);

    // Take the first signature.
    if signatures.len() < 1 {
        return Err("This is not a valid COSE Signature. Couldn't find a signature object.");
    }
    let cose_signature = &signatures[0];
    let cose_signature = unpack!(Array, cose_signature);
    if cose_signature.len() != 3 {
        return Err("This is not a valid COSE Signature. Too short.");
    }
    let protected_signature_header_bytes = &cose_signature[0];
    let protected_signature_header_bytes = unpack!(Bytes, protected_signature_header_bytes).clone();

    // Parse the protected signature header.
    let protected_signature_header = decode(protected_signature_header_bytes.clone())?;
    // This isn't quite right due to order... (it's a map)
    let signature_algorithm = match protected_signature_header {
        CBORType::Map(values) => {
            if values.len() < 1 {
                return Err("This is not a valid COSE signature object. Protected header is empty.");
            }
            values[0].clone()
        },
        _ => return Err("Invalid COSE signature object: protected header is not a map."),
    };
    match signature_algorithm.key {
        CBORType::Integer(val) => {
            if val != 1 {
                return Err("Invalid COSE signature: expected alg header key (1).");
            }
        },
        _ => return Err("Invalid COSE signature: header key is not an integer."),
    };
    match signature_algorithm.value{
        CBORType::SignedInteger(val) => {
            if val != -7 {
                return Err("Invalid COSE signature: expected ES256 (-7).");
            }
        },
        _ => return Err("Invalid COSE signature: alg value is not a signed integer."),
    };
    let signature_algorithm = CoseSignatureType::ES256;

    // Read the key ID from the unprotected header.
    let unprotected_signature_header = &cose_signature[1];
    let key_id = match unprotected_signature_header {
        &CBORType::Map(ref value) => {
            if value.len() < 1 {
                return Err("Invalid COSE signature: unprotected header is empty.");
            }
            value[0].clone()
        },
        _ => return Err("Invalid COSE signature: unprotected header is not a map."),
    };
    match key_id.key {
        CBORType::Integer(val) => {
            if val != 4 {
                return Err("Invalid COSE signature: expected kid header key (4).");
            }
        },
        _ => return Err("Invalid COSE signature: header key is not an integer."),
    };
    let key_id_bytes = &key_id.value.clone();
    let key_id = unpack!(Bytes, key_id_bytes);

    // Read the signature bytes.
    let signature_bytes = &cose_signature[2];
    let signature_bytes = unpack!(Bytes, signature_bytes).clone();
    let mut bytes_to_verify:Vec<u8> = Vec::new();
    // XXX: Use encoder for this.
    bytes_to_verify.push(0x69);
    bytes_to_verify.extend_from_slice(b"Signature");
    // XXX: Add protected body header when present.
    bytes_to_verify.push(0x40);
    if protected_signature_header_bytes.len() > 23 {
        // XXX: fix this.
        return Err("Sorry, this is not implemented for protected headers that are longer than 23.");
    }
    let tmp:u8 = ((2 << 5) as u8) + protected_signature_header_bytes.len() as u8;
    bytes_to_verify.push(tmp);
    bytes_to_verify.append(&mut protected_signature_header_bytes.clone());
    bytes_to_verify.push(0x40);
    if payload.len() > 23 {
        // XXX: fix this.
        return Err("Sorry, this is not implemented for payloads that are longer than 23.");
    }
    let tmp:u8 = ((2 << 5) as u8) + payload.len() as u8;
    bytes_to_verify.push(tmp);
    bytes_to_verify.extend_from_slice(payload);
    // Add CBOR array stuff.
    bytes_to_verify.insert(0, 0x85);

    let signature = CoseSignature {
        signature_type: signature_algorithm,
        signature: signature_bytes,
        signer_cert: key_id.clone(),
        certs: Vec::new(),
        to_verify: bytes_to_verify,
    };
    let mut result = Vec::new();
    result.push(signature);
    Ok(result)
}
