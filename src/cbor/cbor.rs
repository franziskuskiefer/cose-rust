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

#[derive(Debug)]
pub enum CborError {
    CborParsingFailed,
    CborEncodingFailed,
    InvalidCborObject,
    InvalidMapKey,
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
    /// Sorting for maps: RFC 7049 Section 3.9
    ///
    /// The keys in every map must be sorted lowest value to highest.
    ///  *  If two keys have different lengths, the shorter one sorts
    ///     earlier;
    ///
    ///  *  If two keys have the same length, the one with the lower value
    ///     in (byte-wise) lexical order sorts earlier.
    fn cmp(&self, other: &Self) -> Ordering {
        let self_bytes = self.serialize();
        let other_bytes = other.serialize();
        if self_bytes.len() == other_bytes.len() {
            return self_bytes.cmp(&other_bytes);
        }
        self_bytes.len().cmp(&other_bytes.len())
    }
}
