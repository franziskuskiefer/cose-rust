#[cfg(test)]
use cbor::cbor::{CBORType, CBORMap};

#[test]
fn test_nint() {
    struct Testcase {
        value: i64,
        expected: Vec<u8>,
    }
    let testcases: Vec<Testcase> = vec![
        Testcase { value: -1, expected: vec![0x20], },
        Testcase { value: -10, expected: vec![0x29], },
        Testcase { value: -100, expected: vec![0x38, 0x63], },
        Testcase { value: -1000, expected: vec![0x39, 0x03, 0xe7], },
        Testcase { value: -1000000, expected: vec![0x3a, 0x00, 0x0f, 0x42, 0x3f], },
        Testcase { value: -4611686018427387903,
                   expected: vec![0x3b, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe] },
    ];
    for testcase in testcases {
        let cbor = CBORType::SignedInteger(testcase.value);
        assert_eq!(testcase.expected, cbor.serialize());
    }
}

#[test]
fn test_bstr() {
    struct Testcase {
        value: Vec<u8>,
        expected: Vec<u8>,
    }
    let testcases: Vec<Testcase> = vec![
        Testcase { value: vec![], expected: vec![0x40] },
        Testcase { value: vec![0x01, 0x02, 0x03, 0x04],
                   expected: vec![0x44, 0x01, 0x02, 0x03, 0x04] },
        Testcase { value: vec![0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf,
                               0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf,
                               0xaf, 0xaf, 0xaf],
                   expected: vec![0x58, 0x19, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf,
                                  0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf,
                                  0xaf, 0xaf, 0xaf, 0xaf, 0xaf] },

    ];
    for testcase in testcases {
        let cbor = CBORType::Bytes(testcase.value);
        assert_eq!(testcase.expected, cbor.serialize());
    }
}

#[test]
fn test_tstr() {
    struct Testcase {
        value: String,
        expected: Vec<u8>,
    }
    let testcases: Vec<Testcase> = vec![
        Testcase { value: String::new(), expected: vec![0x60] },
        Testcase { value: String::from("a"), expected: vec![0x61, 0x61] },
        Testcase { value: String::from("IETF"), expected: vec![0x64, 0x49, 0x45, 0x54, 0x46] },
        Testcase { value: String::from("\"\\"), expected: vec![0x62, 0x22, 0x5c] },
        Testcase { value: String::from("水"), expected: vec![0x63, 0xe6, 0xb0, 0xb4] },
    ];
    for testcase in testcases {
        let cbor = CBORType::String(testcase.value);
        assert_eq!(testcase.expected, cbor.serialize());
    }
}

#[test]
fn test_arr() {
    struct Testcase {
        value: Vec<CBORType>,
        expected: Vec<u8>,
    }
    let nested_arr_1 = vec![CBORType::Integer(2), CBORType::Integer(3)];
    let nested_arr_2 = vec![CBORType::Integer(4), CBORType::Integer(5)];
    let testcases: Vec<Testcase> = vec![
        Testcase { value: vec![], expected: vec![0x80] },
        Testcase { value: vec![CBORType::Integer(1), CBORType::Integer(2), CBORType::Integer(3)],
                   expected: vec![0x83, 0x01, 0x02, 0x03] },
        Testcase { value: vec![CBORType::Integer(1),
                               CBORType::Array(nested_arr_1),
                               CBORType::Array(nested_arr_2)],
                   expected: vec![0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05] },
        Testcase { value: vec![CBORType::Integer(1), CBORType::Integer(2), CBORType::Integer(3),
                               CBORType::Integer(4), CBORType::Integer(5), CBORType::Integer(6),
                               CBORType::Integer(7), CBORType::Integer(8), CBORType::Integer(9),
                               CBORType::Integer(10), CBORType::Integer(11), CBORType::Integer(12),
                               CBORType::Integer(13), CBORType::Integer(14), CBORType::Integer(15),
                               CBORType::Integer(16), CBORType::Integer(17), CBORType::Integer(18),
                               CBORType::Integer(19), CBORType::Integer(20), CBORType::Integer(21),
                               CBORType::Integer(22), CBORType::Integer(23), CBORType::Integer(24),
                               CBORType::Integer(25)],
                   expected: vec![0x98, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                                  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                                  0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19] },
    ];
    for testcase in testcases {
        let cbor = CBORType::Array(testcase.value);
        assert_eq!(testcase.expected, cbor.serialize());
    }
}

#[test]
fn test_map() {
    let empty_map = CBORType::Map(vec![]);
    assert_eq!(vec![0xa0], empty_map.serialize());

    let mut positive_map =
        CBORType::Map(vec![
            CBORMap{key: CBORType::Integer(20), value: CBORType::Integer(10)},
            CBORMap{key: CBORType::Integer(10), value: CBORType::Integer(20)},
            CBORMap{key: CBORType::Integer(15), value: CBORType::Integer(15)}]);
    positive_map.sort();
    assert_eq!(vec![0xa3, 0x0a, 0x14, 0x0f, 0x0f, 0x14, 0x0a],
               positive_map.serialize());

    let mut negative_map =
        CBORType::Map(vec![
            CBORMap{key: CBORType::SignedInteger(-4), value: CBORType::Integer(10)},
            CBORMap{key: CBORType::SignedInteger(-1), value: CBORType::Integer(20)},
            CBORMap{key: CBORType::SignedInteger(-5), value: CBORType::Integer(15)},
            CBORMap{key: CBORType::SignedInteger(-6), value: CBORType::Integer(10)}]);
    negative_map.sort();
    assert_eq!(vec![0xa4, 0x25, 0x0a, 0x24, 0x0f, 0x23, 0x0a, 0x20, 0x14],
               negative_map.serialize());

    // let mut mixed_map: BTreeMap<i64, CBORType> = BTreeMap::new();
    // mixed_map.insert(0, CBORType::Integer(10));
    // mixed_map.insert(-10, CBORType::Integer(20));
    // mixed_map.insert(15, CBORType::Integer(15));
    let mut mixed_map =
        CBORType::Map(vec![
            CBORMap{key: CBORType::Integer(0), value: CBORType::Integer(10)},
            CBORMap{key: CBORType::SignedInteger(-10), value: CBORType::Integer(20)},
            CBORMap{key: CBORType::Integer(15), value: CBORType::Integer(10)}]);
    mixed_map.sort();
    assert_eq!(vec![0xa3, 0x29, 0x14, 0x00, 0x0a, 0x0f, 0x0f],
               mixed_map.serialize());
}

#[test]
fn test_integer() {
    struct Testcase {
        value: u64,
        expected: Vec<u8>,
    }
    let testcases: Vec<Testcase> = vec![
        Testcase { value: 0, expected: vec![0] },
        Testcase { value: 1, expected: vec![1] },
        Testcase { value: 10, expected: vec![0x0a] },
        Testcase { value: 23, expected: vec![0x17] },
        Testcase { value: 24, expected: vec![0x18, 0x18] },
        Testcase { value: 25, expected: vec![0x18, 0x19] },
        Testcase { value: 100, expected: vec![0x18, 0x64] },
        Testcase { value: 1000, expected: vec![0x19, 0x03, 0xe8] },
        Testcase { value: 1000000, expected: vec![0x1a, 0x00, 0x0f, 0x42, 0x40] },
        Testcase { value: 1000000000000,
                   expected: vec![0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00] },
        Testcase { value: 18446744073709551615,
                   expected: vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] },
    ];
    for testcase in testcases {
        let cbor = CBORType::Integer(testcase.value);
        assert_eq!(testcase.expected, cbor.serialize());
    }
}
