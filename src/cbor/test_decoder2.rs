use cbor::decoder::*;

// First test all the basic types
#[allow(dead_code)]
fn test_decoder(bytes: Vec<u8>, expected: CoseObject) {
    assert_eq!(decode(bytes).unwrap(), expected);
}

#[allow(dead_code)]
fn test_integer(bytes: Vec<u8>, expected: u64) {
    let decoded = decode(bytes).unwrap();
    for val in decoded.values {
        match val {
            CoseType::Integer(val) => assert_eq!(val, expected),
            _ => assert_eq!(1, 0)
        }
    }
}

fn test_integer_all(bytes: Vec<u8>, expected_value: u64) {
    let expected = CoseObject{values: vec![CoseType::Integer(expected_value)]};
    test_decoder(bytes.clone(), expected);
    test_integer(bytes, expected_value);
}

#[test]
fn test_integer_objects() {
    let bytes: Vec<u8> = vec![0x00];
    test_integer_all(bytes, 0);

    let bytes = vec![0x01];
    test_integer_all(bytes, 1);

    let bytes = vec![0x0A];
    test_integer_all(bytes, 10);

    let bytes = vec![0x17];
    test_integer_all(bytes, 23);

    let bytes = vec![0x18, 0x18];
    test_integer_all(bytes, 24);

    let bytes = vec![0x18, 0x19];
    test_integer_all(bytes, 25);

    let bytes = vec![0x18, 0x64];
    test_integer_all(bytes, 100);

    let bytes = vec![0x19, 0x03, 0xe8];
    test_integer_all(bytes, 1000);

    let bytes = vec![0x1a, 0x00, 0x0f, 0x42, 0x40];
    test_integer_all(bytes, 1000000);

    let bytes = vec![0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00];
    test_integer_all(bytes, 1000000000000);

    let bytes = vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    test_integer_all(bytes, 18446744073709551615);
}
