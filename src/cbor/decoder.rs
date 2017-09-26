use std::io::{Cursor, Read, Seek, SeekFrom};
use std::string::String;

/// Struct holding a cursor and additional information for decoding.
#[derive(Debug)]
struct DecoderCursor {
    cursor: Cursor<Vec<u8>>,
    indefinite: Vec<bool>,
    decoded: CBORObject,
}

/// Convert num bytes to a u64
fn read_int_from_bytes(bytes: &mut Cursor<Vec<u8>>, num: usize) -> Result<u64, &'static str> {
    let mut x: Vec<u8> = vec![0; num];
    if bytes.read(&mut x).unwrap() != num {
        return Err("Couldn't read all bytes");
    }
    println!("read_int_from_bytes pos: {:?}", bytes.position());
    let mut result: u64 = 0;
    for i in (0..num).rev() {
        result += (x[num - 1 - i] as u64) << (i * 8);
    }
    Ok(result)
}

/// Read an integer and return it as u64.
fn read_int(decoder_cursor: &mut DecoderCursor) -> Result<u64, &'static str> {
    let mut bytes = &mut decoder_cursor.cursor;
    let first_value = bytes.get_ref()[bytes.position() as usize] & 0x1F;
    bytes.seek(SeekFrom::Current(1)).unwrap();
    // XXX: this really has to be rewritten.
    if first_value == 31 {
        decoder_cursor.indefinite.push(true);
    } else {
        decoder_cursor.indefinite.push(false);
    }
    match first_value {
        24 => {
            // Manually advance cursor.
            let result = bytes.get_ref()[bytes.position() as usize] as u64;
            bytes.seek(SeekFrom::Current(1)).unwrap();
            Ok(result)
        }
        25 => return Ok(read_int_from_bytes(&mut bytes, 2).unwrap()),
        26 => return Ok(read_int_from_bytes(&mut bytes, 4).unwrap()),
        27 => return Ok(read_int_from_bytes(&mut bytes, 8).unwrap()),
        28...30 => return Err("Not well formed"),
        31 => Ok(31),
        _ => return Ok(first_value as u64),
    }
}

#[derive(Debug)]
pub enum CoseMapKey {
    Integer(u64),
    SignedInteger(i64),
    String(String),
}

#[derive(Debug)]
pub struct CoseMap {
    key: CoseMapKey,
    value: CBORType,
}

#[derive(Debug)]
pub enum CBORType {
    Integer(u64),
    SignedInteger(i64),
    Tag(u64),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<CBORType>),
    Map(Vec<CoseMap>),
}

impl PartialEq for CBORType {
    fn eq(&self, other: &CBORType) -> bool {
        let a = self;
        let b = other;
        match (a, b) {
            (&CBORType::Integer(a), &CBORType::Integer(b)) => return a == b,
            (&CBORType::Tag(a), &CBORType::Tag(b)) => return a == b,
            (&CBORType::SignedInteger(a), &CBORType::SignedInteger(b)) => return a == b,
            // XXX: implement the rest.
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct CBORObject {
    pub values: Vec<CBORType>,
}

impl PartialEq for CBORObject {
    fn eq(&self, other: &CBORObject) -> bool {
        if self.values.len() != other.values.len() {
            return false;
        }
        self.values.eq(&other.values)
    }
}

/// Decodes the next item in DecoderCursor.
fn decode_item(decoder_cursor: &mut DecoderCursor) -> Result<(), &'static str> {
    let major_type = decoder_cursor.cursor.get_ref()[decoder_cursor.cursor.position() as usize] >>
        5;
    match major_type {
        0 => {
            let int = read_int(decoder_cursor).unwrap();
            decoder_cursor.decoded.values.push(CBORType::Integer(int));
            Ok(())
        }
        6 => {
            let tag = read_int(decoder_cursor).unwrap();
            decoder_cursor.decoded.values.push(CBORType::Tag(tag));
            Ok(())
        }
        _ => return Err("malformed first byte"),
    }
}

/// Read the CBOR structure in bytes and return it as a COSE object.
#[allow(dead_code)]
pub fn decode(bytes: Vec<u8>) -> Result<CBORObject, &'static str> {
    let mut decoder_cursor = DecoderCursor {
        cursor: Cursor::new(bytes),
        indefinite: Vec::new(),
        decoded: CBORObject { values: Vec::new() },
    };
    decode_item(&mut decoder_cursor).unwrap();
    Ok(decoder_cursor.decoded)
}

// COSE verification
// XXX: move out of here.

#[derive(Debug)]
pub enum CoseType {
    COSESign = 98,
}

#[derive(Debug)]
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

pub fn decode_signature(bytes: Vec<u8>) -> Result<CoseSignatures, &'static str> {
    let mut decoder_cursor = DecoderCursor {
        cursor: Cursor::new(bytes),
        indefinite: Vec::new(),
        decoded: CBORObject { values: Vec::new() },
    };
    // let signature = CoseSignature {
    //     signature_type: CoseSignatureType::ES256, // default value
    //     signature: Vec::new(),
    //     signer_cert: Vec::new(),
    //     certs: Vec::new(),
    // };
    let mut result = CoseSignatures {
        values: Vec::new(),
    };
    decode_item(&mut decoder_cursor).unwrap();
    // This has to be as COSE_Sign object.
    if decoder_cursor.decoded.values.len() != 1 {
        return Err("This is not a COSE_Sign object");
    }
    let val = &decoder_cursor.decoded.values[0];
    match val {
        &CBORType::Tag(val) => {
            if val != CoseType::COSESign as u64 {
                return Err("This is not a COSE_Sign object");
            }
        },
        _ => return Err("This is not a COSE_Sign object"),
    }

    // Now we know we have a COSE_Sign object.
    // The remaining data item has to be an array.
    Ok(result)
}
