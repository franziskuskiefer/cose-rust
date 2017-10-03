use std::collections::BTreeMap;
use std::cmp::Ordering;

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(PartialOrd)]
#[derive(Eq)]
pub enum CBORType {
    Integer(u64),
    SignedInteger(i64),
    Tag(u64, Box<CBORType>),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<CBORType>),
    Map(BTreeMap<CBORType, CBORType>),
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

impl Ord for CBORType {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (&CBORType::Integer(x), &CBORType::Integer(y)) => {
                if x < y {
                    return Ordering::Less;
                } else if x == y {
                    return Ordering::Equal;
                } else {
                    return Ordering::Greater;
                }
            }
            (&CBORType::SignedInteger(x), &CBORType::SignedInteger(y)) => {
                if x < y {
                    return Ordering::Less;
                } else if x == y {
                    return Ordering::Equal;
                } else {
                    return Ordering::Greater;
                }
            }
            (&CBORType::Integer(_), &CBORType::SignedInteger(_)) => {
                return Ordering::Greater;
            }
            (&CBORType::SignedInteger(_), &CBORType::Integer(_)) => {
                return Ordering::Less;
            }
            // TODO: implement to support something else than integer keys in maps.
            _ => return Ordering::Equal,
        }
    }
}
