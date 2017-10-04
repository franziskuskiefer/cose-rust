use std::collections::BTreeMap;
use std::cmp::Ordering;

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(PartialOrd)]
#[derive(Eq)]
pub enum CborType {
    Integer(u64),
    SignedInteger(i64),
    Tag(u64, Box<CborType>),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<CborType>),
    Map(BTreeMap<CborType, CborType>),
}

macro_rules! unpack {
   ($to:tt, $var:ident) => (
        match $var {
            &CborType::$to(ref cbor_object) => {
                cbor_object
            }
            // XXX: This needs handling!
            _ => return Err("Error unpacking a CborType."),
        };
    )
}

impl Ord for CborType {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (&CborType::Integer(x), &CborType::Integer(y)) => {
                x.cmp(&y)
            }
            (&CborType::SignedInteger(x), &CborType::SignedInteger(y)) => {
                x.cmp(&y)
            }
            (&CborType::Integer(_), &CborType::SignedInteger(_)) => {
                return Ordering::Greater;
            }
            (&CborType::SignedInteger(_), &CborType::Integer(_)) => {
                return Ordering::Less;
            }
            // TODO: implement to support something else than integer keys in maps.
            _ => return Ordering::Equal,
        }
    }
}
