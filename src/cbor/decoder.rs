use std::io::{Cursor, Read, Seek, SeekFrom};
use std::string::String;

/// Struct holding a cursor and additional information for decoding.
#[derive(Debug)]
struct DecoderCursor {
    cursor: Cursor<Vec<u8>>,
    indefinite: Vec<bool>,
    decoded: CoseObject,
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
    value: CoseType
}

#[derive(Debug)]
pub enum CoseType {
    Integer(u64),
    SignedInteger(i64),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<CoseType>),
    Map(Vec<CoseMap>)
}

impl PartialEq for CoseType {
    fn eq(&self, other: &CoseType) -> bool {
        let a = self;
        let b = other;
        match (a, b) {
            (&CoseType::Integer(a), &CoseType::Integer(b)) => return a == b,
            (&CoseType::SignedInteger(a), &CoseType::SignedInteger(b)) => return a == b,
            // XXX: implement the rest.
            _ => false
        }
    }
}

#[derive(Debug)]
pub struct CoseObject {
    pub values: Vec<CoseType>
}

impl PartialEq for CoseObject {
    fn eq(&self, other: &CoseObject) -> bool {
        if self.values.len() != other.values.len() {
            return false;
        }
        self.values.eq(&other.values)
    }
}


fn decode_item(decoder_cursor: &mut DecoderCursor) -> Result<(), &'static str> {
    let major_type = decoder_cursor.cursor.get_ref()[decoder_cursor.cursor.position() as usize] >> 5;
    match major_type {
        0 => {
            let int = read_int(decoder_cursor).unwrap();
            decoder_cursor.decoded.values.push(CoseType::Integer(int));
            Ok(())
        },
        _ => return Err("malformed first byte"),
    }
}

/// Read the CBOR structure in bytes and return it as a COSE object.
#[allow(dead_code)]
pub fn decode(bytes: Vec<u8>) -> Result<CoseObject, &'static str> {
    let mut decoder_cursor = DecoderCursor {
        cursor: Cursor::new(bytes),
        indefinite: Vec::new(),
        decoded: CoseObject {values: Vec::new()},
    };
    decode_item(&mut decoder_cursor).unwrap();
    Ok(decoder_cursor.decoded)
}