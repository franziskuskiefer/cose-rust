
#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(PartialOrd)]
#[derive(Eq)]
#[derive(Ord)]
pub struct CBORMap {
    pub key: CBORType,
    pub value: CBORType,
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(PartialOrd)]
#[derive(Eq)]
#[derive(Ord)]
pub enum CBORType {
    Integer(u64),
    SignedInteger(i64),
    Tag(u64, Box<CBORType>),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<CBORType>),
    Map(Vec<CBORMap>),
}

macro_rules! unpack {
   ($to:tt, $var:ident) => (
        match $var {
            &CBORType::$to(ref cbor_object) => {
                cbor_object
            }
            // XXX: This needs handling!
            _ => return Err("Error unpacking a CBORType."),
        };
    )
}
