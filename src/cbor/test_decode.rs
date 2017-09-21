use cbor::decode::*;

// First test all the basic types

fn test_decoder(bytes: &Vec<u8>, expected: &'static str) {
    assert_eq!(decode_element(bytes).unwrap(), expected);
}

#[test]
fn test_integer() {
    let bytes: Vec<u8> = vec![0x00];
    test_decoder(&bytes, "0");

    let bytes = vec![0x01];
    test_decoder(&bytes, "1");

    let bytes = vec![0x0A];
    test_decoder(&bytes, "10");

    let bytes = vec![0x17];
    test_decoder(&bytes, "23");

    let bytes = vec![0x18, 0x18];
    test_decoder(&bytes, "24");

    let bytes = vec![0x18, 0x19];
    test_decoder(&bytes, "25");

    let bytes = vec![0x18, 0x64];
    test_decoder(&bytes, "100");

    let bytes = vec![0x19, 0x03, 0xe8];
    test_decoder(&bytes, "1000");

    let bytes = vec![0x1a, 0x00, 0x0f, 0x42, 0x40];
    test_decoder(&bytes, "1000000");

    let bytes = vec![0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00];
    test_decoder(&bytes, "1000000000000");

    let bytes = vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    test_decoder(&bytes, "18446744073709551615");
}

#[test]
fn test_signed_integer() {
    let bytes: Vec<u8> = vec![0x20];
    test_decoder(&bytes, "-1");

    let bytes = vec![0x29];
    test_decoder(&bytes, "-10");

    let bytes = vec![0x38, 0x63];
    test_decoder(&bytes, "-100");

    let bytes = vec![0x39, 0x03, 0xe7];
    test_decoder(&bytes, "-1000");

    let bytes = vec![0x39, 0x27, 0x0F];
    test_decoder(&bytes, "-10000");

    let bytes = vec![0x3A, 0x00, 0x01, 0x86, 0x9F];
    test_decoder(&bytes, "-100000");

    let bytes = vec![0x3B, 0x00, 0x00, 0x00, 0xE8, 0xD4, 0xA5, 0x0F, 0xFF];
    test_decoder(&bytes, "-1000000000000");
}

#[test]
#[should_panic]
fn test_signed_integer_errors() {
    let bytes: Vec<u8> = vec![0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                              0xff];
    test_decoder(&bytes, "-18446744073709551616");

    let bytes: Vec<u8> = vec![0xc3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00];
    test_decoder(&bytes, "-18446744073709551617");
}

#[test]
fn test_tagging() {
    // XXX: What to do with this?
    // let bytes = vec![0xc2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    // test_decoder(&bytes, "18446744073709551616");
}
