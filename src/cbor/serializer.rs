use std::collections::BTreeMap;
use cbor::cbor::{CborType, CborError};

/// Given a vector of bytes to append to, a tag to use, and an unsigned value to encode, uses the
/// CBOR unsigned integer encoding to represent the given value.
fn common_encode_unsigned(output: &mut Vec<u8>, tag: u8, value: u64) {
    assert!(tag < 8);
    let shifted_tag = tag << 5;
    match value {
        0 ... 23 => {
            output.push(shifted_tag | (value as u8));
        },
        24 ... 255 => {
            output.push(shifted_tag | 24);
            output.push(value as u8);
        },
        256 ... 65535 => {
            output.push(shifted_tag | 25);
            output.push((value >> 8) as u8);
            output.push((value & 255) as u8);
        },
        65536 ... 4294967295 => {
            output.push(shifted_tag | 26);
            output.push((value >> 24) as u8);
            output.push(((value >> 16) & 255) as u8);
            output.push(((value >> 8) & 255) as u8);
            output.push((value & 255) as u8);
        },
        _ => {
            output.push(shifted_tag | 27);
            output.push((value >> 56) as u8);
            output.push(((value >> 48) & 255) as u8);
            output.push(((value >> 40) & 255) as u8);
            output.push(((value >> 32) & 255) as u8);
            output.push(((value >> 24) & 255) as u8);
            output.push(((value >> 16) & 255) as u8);
            output.push(((value >> 8) & 255) as u8);
            output.push((value & 255) as u8);
        }
    };
}

/// The major type is 0. For values 0 through 23, the 5 bits of additional information is just the
/// value of the unsigned number. For values representable in one byte, the additional information
/// has the value 24. If two bytes are necessary, the value is 25. If four bytes are necessary, the
/// value is 26. If 8 bytes are necessary, the value is 27. The following bytes are the value of the
/// unsigned number in as many bytes were indicated in network byte order (big endian).
fn encode_unsigned(output: &mut Vec<u8>, unsigned: u64) -> Result<(), CborError> {
    common_encode_unsigned(output, 0, unsigned);
    return Ok(());
}

/// The major type is 1. The encoding is the same as for positive (i.e. unsigned) integers, except
/// the value encoded is -1 minus the value of the negative number.
fn encode_negative(output: &mut Vec<u8>, negative: i64) -> Result<(), CborError> {
    assert!(negative < 0);
    let value_to_encode: u64 = (-1 - negative) as u64;
    common_encode_unsigned(output, 1, value_to_encode);
    return Ok(());
}

/// The major type is 2. The length of the data is encoded as with positive integers, followed by
/// the actual data.
fn encode_bytes(output: &mut Vec<u8>, bstr: &[u8]) -> Result<(), CborError> {
    common_encode_unsigned(output, 2, bstr.len() as u64);
    for byte in bstr {
        output.push(*byte);
    }
    return Ok(());
}

/// The major type is 3. The length is as with bstr. The UTF-8-encoded bytes of the string follow.
fn encode_string(output: &mut Vec<u8>, tstr: &String) -> Result<(), CborError> {
    let utf8_bytes = tstr.as_bytes();
    common_encode_unsigned(output, 3, utf8_bytes.len() as u64);
    for byte in utf8_bytes {
        output.push(*byte);
    }
    return Ok(());
}

/// The major type is 4. The number of items is encoded as with positive integers. Then follows the
/// encodings of the items themselves.
fn encode_array(output: &mut Vec<u8>, array: &[CborType]) -> Result<(), CborError> {
    common_encode_unsigned(output, 4, array.len() as u64);
    for element in array {
        let element_encoded = element.serialize();
        for byte in element_encoded {
            output.push(byte);
        }
    }
    return Ok(());
}

/// The major type is 5. The number of pairs is encoded as with positive integers. Then follows the
/// encodings of each key, value pair. In Canonical CBOR, the keys must be sorted lowest value to
/// highest.
fn encode_map(output: &mut Vec<u8>, map: &BTreeMap<CborType, CborType>) -> Result<(), CborError> {
    common_encode_unsigned(output, 5, map.len() as u64);
    for (key, value) in map {
        match key {
            // This implementation only supports integers and signed integers as
            // keys in a map. If anything else is, empty the output and return.
            &CborType::SignedInteger(_) => (),
            &CborType::Integer(_) => (),
            _ => {
                output.clear();
                return Err(CborError::InvalidMapKey);
            },
        }
        let key_encoded = key.serialize();
        for byte in key_encoded {
            output.push(byte);
        }
        let value_encoded = value.serialize();
        for byte in value_encoded {
            output.push(byte);
        }
    }
    return Ok(());
}

impl CborType {
    /// Serialize a Cbor object.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        let rv = match self {
            &CborType::Integer(ref unsigned) => encode_unsigned(&mut bytes, *unsigned),
            &CborType::SignedInteger(ref negative) => encode_negative(&mut bytes, *negative),
            &CborType::Bytes(ref bstr) => encode_bytes(&mut bytes, &bstr),
            &CborType::String(ref tstr) => encode_string(&mut bytes, &tstr),
            &CborType::Array(ref arr) => encode_array(&mut bytes, &arr),
            &CborType::Map(ref map) => encode_map(&mut bytes, &map),
            // TODO: Do we need to handle tag?
            _ => return Vec::new(),
        };
        match rv {
            Err(_) => Vec::new(),
            Ok(_) => bytes,
        }
    }
}
