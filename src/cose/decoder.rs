use cbor::decoder::*;
use cbor::CborType;
use cose::CoseError;
use cose::util::get_sig_struct_bytes;
use cose::SignatureAlgorithm;

const COSE_SIGN_TAG: u64 = 98;

#[derive(Debug)]
pub struct CoseSignature {
    pub signature_type: SignatureAlgorithm,
    pub signature: Vec<u8>,
    pub signer_cert: Vec<u8>,
    pub certs: Vec<Vec<u8>>,
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
fn decode_signature_struct(
    cose_signature: &CborType,
    payload: &[u8],
    protected_body_head: CborType,
) -> Result<CoseSignature, CoseError> {
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
    let signature_algorithm = match signature_algorithm {
        CborType::SignedInteger(val) => {
            match val {
                -7 => SignatureAlgorithm::ES256,
                -37 => SignatureAlgorithm::PS256,
                _ => return Err(CoseError::UnexpectedHeaderValue),
            }
        }
        _ => return Err(CoseError::UnexpectedType),
    };

    let ee_cert = &get_map_value(&protected_signature_header, &CborType::Integer(4))?;
    let ee_cert = unpack!(Bytes, ee_cert).clone();

    // Build signature structure to verify.
    let signature_bytes = &cose_signature[2];
    let signature_bytes = unpack!(Bytes, signature_bytes).clone();
    let sig_structure_bytes = get_sig_struct_bytes(
        protected_body_head.clone(),
        protected_signature_header_serialized.clone(),
        payload,
    );

    // Read intermediate certificates from protected_body_head.
    let protected_body_head = &protected_body_head;
    let protected_body_head = unpack!(Bytes, protected_body_head);
    let protected_body_head_map = match decode(protected_body_head.to_vec()) {
        Ok(value) => value,
        Err(_) => return Err(CoseError::DecodingFailure),
    };
    let intermediate_certs_array = &get_map_value(&protected_body_head_map, &CborType::Integer(4))?;
    let intermediate_certs = unpack!(Array, intermediate_certs_array);
    let mut certs: Vec<Vec<u8>> = Vec::new();
    for cert in intermediate_certs {
        let cert = unpack!(Bytes, cert);
        certs.push(cert.clone());
    }

    Ok(CoseSignature {
        signature_type: signature_algorithm,
        signature: signature_bytes,
        signer_cert: ee_cert,
        certs: certs,
        to_verify: sig_structure_bytes,
    })
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
/// See `decode_signature_struct` for description of `COSE_Signature`.
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

    // Decode COSE_Signatures.
    // There has to be at least one signature to make this a valid COSE signature.
    if signatures.len() < 1 {
        return Err(CoseError::MalformedInput);
    }
    let mut result = Vec::new();
    for cose_signature in signatures {
        // cose_sign_array holds the protected body header.
        let signature =
            decode_signature_struct(cose_signature, payload, cose_sign_array[0].clone())?;
        result.push(signature);
    }

    Ok(result)
}
