use std::io::{Cursor, Read, Seek, SeekFrom};
use std::string::String;

/// Struct holding a cursor and additional information for decoding.
#[derive(Debug)]
struct DecoderCursor {
    cursor: Cursor<Vec<u8>>,
    indefinite: Vec<bool>,
    decoded: CBORObject,
}

impl DecoderCursor {
    /// Convert num bytes to a u64
    fn read_int_from_bytes(&mut self, num: usize) -> Result<u64, &'static str> {
        let mut bytes = &mut self.cursor;
        let mut x: Vec<u8> = vec![0; num];
        if bytes.read(&mut x).unwrap() != num {
            return Err("Couldn't read all bytes");
        }
        let mut result: u64 = 0;
        for i in (0..num).rev() {
            result += (x[num - 1 - i] as u64) << (i * 8);
        }
        Ok(result)
    }

    /// Read an integer and return it as u64.
    fn read_int(&mut self) -> Result<u64, &'static str> {
        let pos = self.cursor.position() as usize;
        let first_value = self.cursor.get_ref()[pos] & 0x1F;
        self.cursor.seek(SeekFrom::Current(1)).unwrap();
        let mut val: u64 = 0;
        match first_value {
            24 => {
                // Manually advance cursor.
                let pos = self.cursor.position() as usize;
                val = self.cursor.get_ref()[pos] as u64;
                self.cursor.seek(SeekFrom::Current(1)).unwrap();
            }
            25 => val = self.read_int_from_bytes(2).unwrap(),
            26 => val = self.read_int_from_bytes(4).unwrap(),
            27 => val = self.read_int_from_bytes(8).unwrap(),
            28...31 => return Err("Not well formed and indefinite len isn't supported"),
            _ => val = first_value as u64,
        }
        Ok(val)
    }

    /// Read an integer and add it to the decoded values.
    fn parse_int(&mut self, tag: bool) -> Result<(), &'static str> {
        let val = self.read_int().unwrap();
        if tag {
            self.decoded.values.push(CBORType::Tag(val));
        } else {
            self.decoded.values.push(CBORType::Integer(val));
        }
        Ok(())
    }

    fn read_signed_int(&mut self) -> Result<CBORType, &'static str> {
        let uint = self.read_int().unwrap();
        if uint > i64::max_value() as u64 {
            return Err("Signed integer doesn't fit in a i64 (too large)");
        }
        let result: i64 = -1 - uint as i64;
        Ok(CBORType::SignedInteger(result))
    }

    /// Read an integer and add it to the decoded values.
    fn parse_signed_int(&mut self) -> Result<(), &'static str> {
        let val = self.read_signed_int().unwrap();
        self.decoded.values.push(val);
        Ok(())
    }

    /// Read an array of data items and return it.
    fn read_array(&mut self) -> Result<CBORType, &'static str> {
        // Create a new array.
        let mut array: Vec<CBORType> = Vec::new();
        // Read the length of the array.
        let num_items = self.read_int().unwrap();
        println!("num_items: {:?}", num_items);
        // Decode each of the num_items data items.
        for item_num in 0..num_items {
            println!("inner\n{:?}", array);
            array.push(self.decode_item().unwrap());
        }
        println!("outer\n{:?}", array);
        Ok(CBORType::Array(array))
    }

    /// Read an array of data items.
    fn parse_array(&mut self) -> Result<(), &'static str> {
        let array = self.read_array().unwrap();
        self.decoded.values.push(array);
        Ok(())
    }

    /// Read a byte string and return it as hex string.
    fn read_byte_string(&mut self) -> Result<CBORType, &'static str> {
        let length = self.read_int().unwrap();
        if length > usize::max_value() as u64 {
            return Err("Byte array is too large to allocate.");
        }
        let length = length as usize;
        let mut byte_string: Vec<u8> = Vec::with_capacity(length);
        // XXX: rewrite without unsafe.
        unsafe {
            byte_string.set_len(length);
        }
        if self.cursor.read(&mut byte_string).unwrap() != length {
            return Err("Couldn't read enough data for this byte string");
        }
        Ok(CBORType::Bytes(byte_string))
    }

    /// Read a byte string and return it as hex string.
    fn parse_byte_string(&mut self) -> Result<(), &'static str> {
        let bytes = self.read_byte_string().unwrap();
        self.decoded.values.push(bytes);
        Ok(())
    }

    /// Decodes the next item in DecoderCursor.
    fn decode_item(&mut self) -> Result<CBORType, &'static str> {
        let pos = self.cursor.position() as usize;
        let major_type = self.cursor.get_ref()[pos] >> 5;
        match major_type {
            0 => return Ok(CBORType::Integer(self.read_int().unwrap())),
            1 => return Ok(self.read_signed_int().unwrap()),
            2 => return Ok(self.read_byte_string().unwrap()),
            4 => return Ok(self.read_array().unwrap()),
            6 => return Ok(CBORType::Tag(self.read_int().unwrap())),
            _ => return Err("Malformed first byte"),
        }
    }
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
pub enum CoseMapKey {
    Integer(u64),
    SignedInteger(i64),
    String(String),
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
pub struct CoseMap {
    key: CoseMapKey,
    value: CBORType,
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
pub enum CBORType {
    Integer(u64),
    SignedInteger(i64),
    Tag(u64),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<CBORType>),
    Map(Vec<CoseMap>),
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
        0 => decoder_cursor.parse_int(false),
        1 => decoder_cursor.parse_signed_int(),
        2 => decoder_cursor.parse_byte_string(),
        4 => decoder_cursor.parse_array(),
        6 => decoder_cursor.parse_int(true),
        _ => return Err("Malformed first byte"),
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
    let mut result = CoseSignatures { values: Vec::new() };
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
        }
        _ => return Err("This is not a COSE_Sign object"),
    }

    // Now we know we have a COSE_Sign object.
    // The remaining data item has to be an array.
    Ok(result)
}
