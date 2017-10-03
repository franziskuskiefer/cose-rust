use cbor::cbor::{CBORType, CBORMap};

// pub enum CborType<'a> {
//     UInt(u64),
//     NInt(i64),
//     BStr(&'a [u8]),
//     TStr(&'a String),
//     Arr(&'a [CborType<'a>]),
//     Map(&'a BTreeMap<i64, CborType<'a>>), // TODO: find out what key value range we really have to support
// }

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
fn encode_unsigned(output: &mut Vec<u8>, unsigned: u64) {
    common_encode_unsigned(output, 0, unsigned);
}

/// The major type is 1. The encoding is the same as for positive (i.e. unsigned) integers, except
/// the value encoded is -1 minus the value of the negative number.
fn encode_negative(output: &mut Vec<u8>, negative: i64) {
    assert!(negative < 0);
    let value_to_encode: u64 = (-1 - negative) as u64;
    common_encode_unsigned(output, 1, value_to_encode);
}

/// The major type is 2. The length of the data is encoded as with positive integers, followed by
/// the actual data.
fn encode_bstr(output: &mut Vec<u8>, bstr: &[u8]) {
    common_encode_unsigned(output, 2, bstr.len() as u64);
    for byte in bstr {
        output.push(*byte);
    }
}

/// The major type is 3. The length is as with bstr. The UTF-8-encoded bytes of the string follow.
fn encode_tstr(output: &mut Vec<u8>, tstr: &String) {
    let utf8_bytes = tstr.as_bytes();
    common_encode_unsigned(output, 3, utf8_bytes.len() as u64);
    for byte in utf8_bytes {
        output.push(*byte);
    }
}

/// The major type is 4. The number of items is encoded as with positive integers. Then follows the
/// encodings of the items themselves.
fn encode_array(output: &mut Vec<u8>, array: &[CBORType]) {
    common_encode_unsigned(output, 4, array.len() as u64);
    for element in array {
        let element_encoded = element.serialize();
        for byte in element_encoded {
            output.push(byte);
        }
    }
}

/// The major type is 5. The number of pairs is encoded as with positive integers. Then follows the
/// encodings of each key, value pair. In Canonical CBOR, the keys must be sorted lowest value to
/// highest.
fn encode_map(output: &mut Vec<u8>, map: &Vec<CBORMap>) {
    common_encode_unsigned(output, 5, map.len() as u64);
    for item in map {
        let key_encoded = item.key.serialize();
        for byte in key_encoded {
            output.push(byte);
        }
        let value_encoded = item.value.serialize();
        for byte in value_encoded {
            output.push(byte);
        }
    }
}

impl CBORType {
    /// Sort a Cbor object.
    /// XXX: For now only sorting maps with (signed) integer keys.
    pub fn sort(&mut self) {
        match self {
            &mut CBORType::Map(ref mut map) => map.sort(),
            _ => (),
        }
    }

    /// Serialize a Cbor object.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        match self {
            &CBORType::Integer(ref unsigned) => encode_unsigned(&mut bytes, *unsigned),
            &CBORType::SignedInteger(ref negative) => encode_negative(&mut bytes, *negative),
            &CBORType::Bytes(ref bstr) => encode_bstr(&mut bytes, &bstr),
            &CBORType::String(ref tstr) => encode_tstr(&mut bytes, &tstr),
            &CBORType::Array(ref arr) => encode_array(&mut bytes, &arr),
            &CBORType::Map(ref map) => encode_map(&mut bytes, &map),
            // TODO: Do we need to handle tag?
            _ => return Vec::new(),
        };
        bytes
    }
}
