use std::io::{Cursor, Read, Seek, SeekFrom};
use std::string::String;

/// Convert num bytes to a u64
fn read_int_from_bytes(bytes: &mut Cursor<&Vec<u8>>, num: usize) -> Result<u64, &'static str> {
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
fn read_int(bytes: &mut Cursor<&Vec<u8>>) -> Result<u64, &'static str> {
    let first_value = bytes.get_ref()[bytes.position() as usize] & 0x1F;
    bytes.seek(SeekFrom::Current(1)).unwrap();
    match first_value {
        24 => {
            // Manually advance cursor.
            let result = bytes.get_ref()[bytes.position() as usize] as u64;
            bytes.seek(SeekFrom::Current(1)).unwrap();
            Ok(result)
        }
        25 => return Ok(read_int_from_bytes(bytes, 2).unwrap()),
        26 => return Ok(read_int_from_bytes(bytes, 4).unwrap()),
        27 => return Ok(read_int_from_bytes(bytes, 8).unwrap()),
        28...31 => return Err("Not well formed"),
        _ => return Ok(first_value as u64),
    }
}

/// Read a signed integer and return it as i64.
fn read_signed_int(bytes: &mut Cursor<&Vec<u8>>) -> Result<i64, &'static str> {
    let uint = read_int(bytes).unwrap();
    if uint > i64::max_value() as u64 {
        return Err("Signed integer doesn't fit in a i64 (too large)");
    }
    let result: i64 = -1 - uint as i64;
    Ok(result)
}

/// Read a byte string and return it as hex string.
fn read_byte_string(bytes: &mut Cursor<&Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    let length = read_int(bytes).unwrap();
    if length > usize::max_value() as u64 {
        return Err("Byte array is too large to allocate.");
    }
    let length = length as usize;
    let mut byte_string: Vec<u8> = Vec::with_capacity(length);
    unsafe {
        byte_string.set_len(length);
    } // with_capacity doesn't set the size :(
    if bytes.read(&mut byte_string).unwrap() != length {
        return Err("Couldn't read enough data for this byte string");
    }
    Ok(byte_string)
}

/// Read a UTF-8 string.
fn read_utf8_string(bytes: &mut Cursor<&Vec<u8>>) -> Result<String, &'static str> {
    let byte_string = read_byte_string(bytes).unwrap();
    Ok(String::from_utf8(byte_string).unwrap())
}

/// Read an array of data items.
fn read_array(bytes: &mut Cursor<&Vec<u8>>) -> Result<String, &'static str> {
    let num_items = read_int(bytes).unwrap();
    let mut result = "[".to_string();
    // Decode each of the num_items data items.
    for item_num in 0..num_items {
        result += &decode_item(bytes).unwrap();
        if item_num < num_items - 1 {
            result += &", ".to_string();
        }
    }
    result += &"]".to_string();
    Ok(result)
}

/// Read a map.
fn read_map(bytes: &mut Cursor<&Vec<u8>>) -> Result<String, &'static str> {
    let num_items = read_int(bytes).unwrap();
    let mut result = "{".to_string();
    // Decode each of the num_items (key, data item) pairs.
    for item_num in 0..num_items {
        result += &decode_item(bytes).unwrap(); // key
        result += &": ".to_string();
        result += &decode_item(bytes).unwrap(); // value
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

fn decode_item(bytes: &mut Cursor<&Vec<u8>>) -> Result<String, &'static str> {
    let major_type = bytes.get_ref()[bytes.position() as usize] >> 5;
    match major_type {
        0 => return Ok(read_int(bytes).unwrap().to_string()),
        1 => return Ok(read_signed_int(bytes).unwrap().to_string()),
        2 => return Ok(to_hex_string(&read_byte_string(bytes).unwrap())),
        3 => return read_utf8_string(bytes),
        4 => return read_array(bytes),
        5 => return read_map(bytes),
        6 => return Err("semantic tags are not implemented"),
        7 => return Err("major type 7 is not implemented"),
        _ => return Err("malformed first byte"),
    }
}

/// Read the CBOR structure in bytes and return it as a string.
pub fn decode_element(bytes: &Vec<u8>) -> Result<String, &'static str> {
    let mut byte_cursor = Cursor::new(bytes);
    decode_item(&mut byte_cursor)
}
