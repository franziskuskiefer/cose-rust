pub use cbor::decoder::*;
use std::io::{Cursor};

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
}

#[derive(Debug)]
pub struct CoseSignatures {
    pub values: Vec<CoseSignature>,
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

pub fn decode_signature(bytes: Vec<u8>) -> Result<CoseSignatures, &'static str> {
    let mut decoder_cursor = DecoderCursor {
        cursor: Cursor::new(bytes),
        decoded: CBORObject { values: Vec::new() },
    };
    let mut result = CoseSignatures { values: Vec::new() };
    decode_item(&mut decoder_cursor).unwrap();
    // This has to be as COSE_Sign object.
    if decoder_cursor.decoded.values.len() != 1 {
        return Err("This is not a COSE_Sign object 0");
    }
    let val = decoder_cursor.decoded.values[0].clone();
    match val {
        CBORType::Tag(val) => {
            if val != CoseType::COSESign as u64 {
                return Err("This is not a COSE_Sign object 1");
            }
        }
        _ => return Err("This is not a COSE_Sign object 2"),
    }

    // Now we know we have a COSE_Sign object.
    // The remaining data item has to be an array.
    decode_item(&mut decoder_cursor).unwrap();
    if decoder_cursor.decoded.values.len() < 2 {
        return Err("This is not a valid COSE signature object 0.");
    }
    let tmp = &decoder_cursor.decoded.values[1];
    let cose_object = unpack!(Array, tmp);
    println!(">>>> cose_object: {:?}", cose_object[0]);
    if cose_object.len() < 4 {
        return Err("This is not a valid COSE signature object 2.");
    }
    let tmp = &cose_object[3];
    let signature_items = unpack!(Array, tmp);
    println!(">>>> signature_item {:?}", signature_items);

    // Take the first signature.
    if signature_items.len() < 1 {
        return Err("This is not a valid COSE Signature. Couldn't find a signature object.");
    }
    let tmp = &signature_items[0];
    let signature_item = unpack!(Array, tmp);
    if signature_item.len() < 3 {
        return Err("This is not a valid COSE Signature. Too short.");
    }
    let tmp = &signature_item[0];
    let protected_signature_header = unpack!(Bytes, tmp).clone();
    println!(">>>> protected_signature_header {:?}", protected_signature_header);

    // Parse the protected signature header.
    let mut header_cursor = DecoderCursor {
        cursor: Cursor::new(protected_signature_header),
        decoded: CBORObject { values: Vec::new() },
    };
    decode_item(&mut header_cursor).unwrap();
    println!(">>>> protected_signature_header {:?}", header_cursor.decoded.values);
    if header_cursor.decoded.values.len() < 1 {
        return Err("This is not a valid COSE signature object. Protected header is empty.");
    }

    // Read the signature algorithm from the protected header.
    let tmp = &header_cursor.decoded.values[0];
    let signature_algorithm = unpack!(Map, tmp);
    if signature_algorithm.len() < 1 ||
       signature_algorithm[0].key != CBORType::Integer(1) { // XXX: algorithm
        return Err("This is not a valid COSE signature object. No algorithm given.");
    }
    if signature_algorithm[0].value != CBORType::SignedInteger(-7) { // XXX: ES256
        return Err("This is not a valid COSE signature object. Can't handle the algorithm.");
    }
    let signature_algorithm = CoseSignatureType::ES256;

    // Read the key ID from the unprotected header.
    let tmp = &signature_item[1];
    let key_id = unpack!(Map, tmp).clone();
    if key_id.len() < 1 ||
       key_id[0].key != CBORType::Integer(4) { // XXX: kid
        return Err("This is not a valid COSE signature object. No key ID given.");
    }
    // XXX: This has to be a byte string in our scenario.
    // XXX: Not used yet.
    let key_id = key_id[0].value.clone();

    // Read the signature bytes.
    let tmp = &signature_item[2];
    let signature_bytes = unpack!(Bytes, tmp).clone();

    let signature = CoseSignature {
        signature_type: signature_algorithm,
        signature: signature_bytes,
        signer_cert: Vec::new(),
        certs: Vec::new(),
    };
    result.values.push(signature);
    Ok(result)
}