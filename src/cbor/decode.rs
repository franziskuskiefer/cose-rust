use std::io::{Cursor, Read, Seek, SeekFrom};

/// Convert num bytes to a u64
fn read_int_from_bytes(bytes: &mut Cursor<&Vec<u8>>, num: usize) -> Result<u64, &'static str> {
    let mut x: Vec<u8> = vec![0; num];
    if bytes.read(&mut x).unwrap() != num {
        return Err("Couldn't read four bytes");
    }
    let mut result: u64 = 0;
    for i in (0..num).rev() {
        result += (x[num - 1 - i] as u64) << (i * 8);
    }
    Ok(result)
}

/// Read an integer and return it as u64.
fn read_int(bytes: &Vec<u8>) -> Result<u64, &'static str> {
    let first_value = bytes[0] & 0x1F;
    let mut byte_cursor = Cursor::new(bytes);
    byte_cursor.seek(SeekFrom::Start(1)).unwrap();
    match first_value {
        24 => return Ok(bytes[1] as u64),
        25 => return Ok(read_int_from_bytes(&mut byte_cursor, 2).unwrap()),
        26 => return Ok(read_int_from_bytes(&mut byte_cursor, 4).unwrap()),
        27 => return Ok(read_int_from_bytes(&mut byte_cursor, 8).unwrap()),
        28...31 => return Err("Not well formed"),
        _ => return Ok(first_value as u64),
    }
}

#[allow(unused_variables)]
fn read_signed_int(bytes: &Vec<u8>) -> Result<i64, &'static str> {
    let uint = read_int(bytes).unwrap();
    if uint > i64::max_value() as u64 {
        return Err("Signed integer doesn't fit in a i64 (too large)");
    }
    let result: i64 = -1 - uint as i64;
    Ok(result)
}

#[allow(unused_variables)]
fn read_byte_string(bytes: &Vec<u8>) -> Result<String, &'static str> {
    Err("not implemented")
}

#[allow(unused_variables)]
fn read_utf8_string(bytes: &Vec<u8>) -> Result<String, &'static str> {
    Err("not implemented")
}

#[allow(unused_variables)]
fn read_array(bytes: &Vec<u8>) -> Result<String, &'static str> {
    Err("not implemented")
}

#[allow(unused_variables)]
fn read_map(bytes: &Vec<u8>) -> Result<String, &'static str> {
    Err("not implemented")
}

/// Read the CBOR structure in bytes and return it as a string.
pub fn decode_element(bytes: &Vec<u8>) -> Result<String, &'static str> {
    let major_type = bytes[0] >> 5;
    match major_type {
        0 => return Ok(read_int(&bytes).unwrap().to_string()),
        1 => return Ok(read_signed_int(&bytes).unwrap().to_string()),
        2 => return read_byte_string(&bytes),
        3 => return read_utf8_string(&bytes),
        4 => return read_array(&bytes),
        5 => return read_map(&bytes),
        6 => return Err("semantic tags are not implemented"),
        7 => return Err("major type 7 is not implemented"),
        _ => return Err("malformed first byte"),
    }
}
