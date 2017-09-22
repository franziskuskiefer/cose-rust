use std::io::{Cursor, Read, Seek, SeekFrom};
use std::string::String;

/// Struct holding a cursor and additional information for decoding.
#[derive(Debug)]
struct DecoderCursor {
    cursor: Cursor<Vec<u8>>,
    indefinite: Vec<bool>,
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

/// Read a signed integer and return it as i64.
fn read_signed_int(decoder_cursor: &mut DecoderCursor) -> Result<i64, &'static str> {
    let uint = read_int(decoder_cursor).unwrap();
    if uint > i64::max_value() as u64 {
        return Err("Signed integer doesn't fit in a i64 (too large)");
    }
    let result: i64 = -1 - uint as i64;
    Ok(result)
}

/// Read a byte string and return it as hex string.
fn read_byte_string(decoder_cursor: &mut DecoderCursor) -> Result<Vec<u8>, &'static str> {
    let length = read_int(decoder_cursor).unwrap();
    if length > usize::max_value() as u64 {
        return Err("Byte array is too large to allocate.");
    }
    let length = length as usize;
    let mut byte_string: Vec<u8> = Vec::with_capacity(length);
    unsafe {
        byte_string.set_len(length);
    } // with_capacity doesn't set the size :(
    let mut bytes = &mut decoder_cursor.cursor;
    if bytes.read(&mut byte_string).unwrap() != length {
        return Err("Couldn't read enough data for this byte string");
    }
    Ok(byte_string)
}

/// Read a UTF-8 string.
fn read_utf8_string(decoder_cursor: &mut DecoderCursor) -> Result<String, &'static str> {
    let byte_string = read_byte_string(decoder_cursor).unwrap();
    Ok(String::from_utf8(byte_string).unwrap())
}

/// Read an array of data items.
fn read_array(decoder_cursor: &mut DecoderCursor) -> Result<String, &'static str> {
    let num_items = read_int(decoder_cursor).unwrap();
    let mut result = "[".to_string();
    println!(" >>> LALALA 1");
    if decoder_cursor.indefinite.len() > 0 &&
        decoder_cursor.indefinite[decoder_cursor.indefinite.len() - 1]
    {
        println!(" >>> LALALA 2");
        // In this case num_items is irrelevant.
        // We read until we find the break item (0xFF).
        let mut item = decode_item(decoder_cursor).unwrap();
        while item != "break" {
            println!(" >>> LALALA 3");
            result += &item;
            result += &", ".to_string();
            item = decode_item(decoder_cursor).unwrap();
        }
        let mut result_len = result.len();
        if result_len > 2 {
            result_len -= 2;
        }
        println!(" >>> LALALA 4");
        result.truncate(result_len);
        decoder_cursor.indefinite.pop();
    } else {
        decoder_cursor.indefinite.push(false);
        // Decode each of the num_items data items.
        for item_num in 0..num_items {
            result += &decode_item(decoder_cursor).unwrap();
            if item_num < num_items - 1 {
                result += &", ".to_string();
            }
        }
    }
    result += &"]".to_string();
    Ok(result)
}

/// Read a map.
fn read_map(decoder_cursor: &mut DecoderCursor) -> Result<String, &'static str> {
    let num_items = read_int(decoder_cursor).unwrap();
    let mut result = "{".to_string();
    // Decode each of the num_items (key, data item) pairs.
    for item_num in 0..num_items {
        result += &decode_item(decoder_cursor).unwrap(); // key
        result += &": ".to_string();
        result += &decode_item(decoder_cursor).unwrap(); // value
        if item_num < num_items - 1 {
            result += &", ".to_string();
        }
    }
    result += &"}".to_string();
    Ok(result)
}

fn to_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join("")
}

/// This doesn't actually decode floating points (yet).
/// But we need it for the break item.
fn decode_seven(decoder_cursor: &mut DecoderCursor) -> Result<String, &'static str> {
    let mut bytes = &mut decoder_cursor.cursor;
    if bytes.get_ref()[bytes.position() as usize] == 0xFF {
        // Advance cursor manually beyond the break item.
        bytes.seek(SeekFrom::Current(1)).unwrap();
        return Ok("break".to_string());
    }
    Err("Not implemented (floating point)")
}

fn decode_item(decoder_cursor: &mut DecoderCursor) -> Result<String, &'static str> {
    let major_type = decoder_cursor.cursor.get_ref()[decoder_cursor.cursor.position() as usize] >>
        5;
    match major_type {
        0 => return Ok(read_int(decoder_cursor).unwrap().to_string()),
        1 => return Ok(read_signed_int(decoder_cursor).unwrap().to_string()),
        2 => return Ok(to_hex_string(&read_byte_string(decoder_cursor).unwrap())),
        3 => return read_utf8_string(decoder_cursor),
        4 => return read_array(decoder_cursor),
        5 => return read_map(decoder_cursor),
        6 => return Err("semantic tags are not implemented"),
        7 => return decode_seven(decoder_cursor),
        _ => return Err("malformed first byte"),
    }
}

/// Read the CBOR structure in bytes and return it as a string.
#[allow(dead_code)]
pub fn decode_element(bytes: Vec<u8>) -> Result<String, &'static str> {
    let mut decoder_cursor = DecoderCursor {
        cursor: Cursor::new(bytes),
        indefinite: Vec::new(),
    };
    decode_item(&mut decoder_cursor)
}
