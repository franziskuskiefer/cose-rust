use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, SeekFrom};
use cbor::cbor::{CborType};

/// Struct holding a cursor and additional information for decoding.
#[derive(Debug)]
pub struct DecoderCursor {
    pub cursor: Cursor<Vec<u8>>,
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
        let val: u64 = match first_value {
            0...23 => first_value as u64,
            24 => {
                // Manually advance cursor.
                let pos = self.cursor.position() as usize;
                let tmp = self.cursor.get_ref()[pos] as u64;
                self.cursor.seek(SeekFrom::Current(1)).unwrap();
                tmp
            }
            25 => self.read_int_from_bytes(2).unwrap(),
            26 => self.read_int_from_bytes(4).unwrap(),
            27 => self.read_int_from_bytes(8).unwrap(),
            _ => return Err("Not well formed and indefinite len isn't supported"),
        };
        Ok(val)
    }

    fn read_signed_int(&mut self) -> Result<CborType, &'static str> {
        let uint = self.read_int().unwrap();
        if uint > i64::max_value() as u64 {
            return Err("Signed integer doesn't fit in a i64 (too large)");
        }
        let result: i64 = -1 - uint as i64;
        Ok(CborType::SignedInteger(result))
    }

    /// Read an array of data items and return it.
    fn read_array(&mut self) -> Result<CborType, &'static str> {
        // Create a new array.
        let mut array: Vec<CborType> = Vec::new();
        // Read the length of the array.
        let num_items = self.read_int().unwrap();
        // Decode each of the num_items data items.
        for _ in 0..num_items {
            array.push(self.decode_item().unwrap());
        }
        Ok(CborType::Array(array))
    }

    /// Read a byte string and return it as hex string.
    fn read_byte_string(&mut self) -> Result<CborType, &'static str> {
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
        Ok(CborType::Bytes(byte_string))
    }

    /// Read a map.
    fn read_map(&mut self) -> Result<CborType, &'static str> {
        // XXX: check for duplicate keys.
        let num_items = self.read_int().unwrap();
        // Create a new array.
        let mut map: BTreeMap<CborType, CborType> = BTreeMap::new();
        // Decode each of the num_items (key, data item) pairs.
        for _ in 0..num_items {
            let key_val = self.decode_item().unwrap();
            let item_value = self.decode_item().unwrap();
            map.insert(key_val, item_value);
        }
        Ok(CborType::Map(map))
    }

    /// Decodes the next item in DecoderCursor.
    pub fn decode_item(&mut self) -> Result<CborType, &'static str> {
        let pos = self.cursor.position() as usize;
        let major_type = self.cursor.get_ref()[pos] >> 5;
        match major_type {
            0 => return Ok(CborType::Integer(self.read_int().unwrap())),
            1 => return Ok(self.read_signed_int().unwrap()),
            2 => return Ok(self.read_byte_string().unwrap()),
            4 => return Ok(self.read_array().unwrap()),
            5 => return Ok(self.read_map().unwrap()),
            6 => return Ok(CborType::Tag(self.read_int().unwrap(),
                                         Box::new(self.decode_item().unwrap()))),
            _ => return Err("Malformed first byte"),
        }
    }
}

/// Read the CBOR structure in bytes and return it as a CBOR object.
pub fn decode(bytes: Vec<u8>) -> Result<CborType, &'static str> {
    let mut decoder_cursor = DecoderCursor {
        cursor: Cursor::new(bytes),
    };
    decoder_cursor.decode_item()
    // TODO: check cursor at end?
}
