use cbor::decoder::*;
use cbor::CborType;
use cose::CoseError;
use cose::util::get_sig_struct_bytes;

const COSE_SIGN_TAG: u64 = 98;

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
        match *$var {
            CborType::$to(ref cbor_object) => {
                cbor_object
            }
            _ => return Err(CoseError::UnexpectedType),
        };
    )
}

fn get_map_value(map: &CborType, key: &CborType) -> Result<CborType, CoseError> {
    match *map {
        CborType::Map(ref values) => {
            match values.get(key) {
                Some(x) => Ok(x.clone()),
                _ => Err(CoseError::MissingHeader),
            }
        }
        _ => Err(CoseError::UnexpectedType),
    }
}

/// `COSE_Sign` = [
///     Headers,
///     payload : bstr / nil,
///     signatures : [+ `COSE_Signature`]
/// ]
///
/// Headers = (
///     protected : `empty_or_serialized_map`,
///     unprotected : `header_map`
/// )
///
/// This syntax is a little unintuitive. Taken together, the two previous definitions essentially
/// mean:
///
/// `COSE_Sign` = [
///     protected : `empty_or_serialized_map`,
///     unprotected : `header_map`
///     payload : bstr / nil,
///     signatures : [+ `COSE_Signature`]
/// ]
///
/// (`COSE_Sign` is an array. The first element is an empty or serialized map (in our case, it is
/// never expected to be empty). The second element is a map (it is expected to be empty. The third
/// element is a bstr or nil (it is expected to be nil). The fourth element is an array of
/// `COSE_Signature`.)
///
/// `COSE_Signature` =  [
///     Headers,
///     signature : bstr
/// ]
///
/// but again, unpacking this:
///
/// `COSE_Signature` =  [
///     protected : `empty_or_serialized_map`,
///     unprotected : `header_map`
///     signature : bstr
/// ]
pub fn decode_signature(bytes: Vec<u8>, payload: &[u8]) -> Result<Vec<CoseSignature>, CoseError> {
    // This has to be a COSE_Sign object, which is a tagged array.
    let tagged_cose_sign = match decode(bytes) {
        Err(_) => return Err(CoseError::DecodingFailure),
        Ok(value) => value,
    };
    let cose_sign_array = match tagged_cose_sign {
        CborType::Tag(tag, cose_sign) => {
            if tag != COSE_SIGN_TAG {
                return Err(CoseError::UnexpectedTag);
            }
            match *cose_sign {
                CborType::Array(values) => values,
                _ => return Err(CoseError::UnexpectedType),
            }
        }
        _ => return Err(CoseError::UnexpectedType),
    };
    if cose_sign_array.len() != 4 {
        return Err(CoseError::MalformedInput);
    }
    let signatures = &cose_sign_array[3];
    let signatures = unpack!(Array, signatures);

    // Take the first signature.
    // TODO #15: support more than 1 signature.
    if signatures.len() < 1 {
        return Err(CoseError::MalformedInput);
    }
    let cose_signature = &signatures[0];
    let cose_signature = unpack!(Array, cose_signature);
    if cose_signature.len() != 3 {
        return Err(CoseError::MalformedInput);
    }
    let protected_signature_header_serialized = &cose_signature[0];
    let protected_signature_header_bytes = unpack!(Bytes, protected_signature_header_serialized)
        .clone();

    // Parse the protected signature header.
    let protected_signature_header = match decode(protected_signature_header_bytes.clone()) {
        Err(_) => return Err(CoseError::DecodingFailure),
        Ok(value) => value,
    };
    let signature_algorithm = get_map_value(&protected_signature_header, &CborType::Integer(1))?;
    match signature_algorithm {
        CborType::SignedInteger(val) => {
            if val != -7 {
                return Err(CoseError::UnexpectedHeaderValue);
            }
        }
        _ => return Err(CoseError::UnexpectedType),
    };
    // TODO #??: don't hard code signature algorithm. Unify algorithm defs.
    let signature_algorithm = CoseSignatureType::ES256;

    let ee_cert = &get_map_value(&protected_signature_header, &CborType::Integer(4))?;
    let ee_cert = unpack!(Bytes, ee_cert).clone();

    // Build signature structure to verify.
    let signature_bytes = &cose_signature[2];
    let signature_bytes = unpack!(Bytes, signature_bytes).clone();
    let sig_structure_bytes = get_sig_struct_bytes(
        cose_sign_array[0].clone(), // Protected body header.
        protected_signature_header_serialized.clone(),
        payload,
    );

    let signature = CoseSignature {
        signature_type: signature_algorithm,
        signature: signature_bytes,
        signer_cert: ee_cert,
        certs: Vec::new(),
        to_verify: sig_structure_bytes,
    };
    let mut result = Vec::new();
    result.push(signature);
    Ok(result)
}
