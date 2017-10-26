use std::slice;
use std::mem;
use std::ptr;
use std::os::raw;

/// An enum identifying supported signature algorithms. Currently only ECDSA with SHA256 (ES256) and
/// RSASSA-PSS with SHA-256 (PS256) are supported. Note that with PS256, the salt length is defined
/// to be 32 bytes.
#[derive(Debug)]
pub enum SignatureAlgorithm {
    ES256,
    PS256,
}

type SECItemType = raw::c_uint; // TODO: actually an enum - is this the right size?
const SI_BUFFER: SECItemType = 0; // called siBuffer in NSS

#[repr(C)]
struct SECItem {
    typ: SECItemType,
    data: *const u8, // ugh it's not really const...
    len: raw::c_uint,
}

impl SECItem {
    fn maybe_new(data: &[u8]) -> Result<SECItem, NSSError> {
        if data.len() > u32::max_value() as usize {
            return Err(NSSError::InputTooLarge);
        }
        Ok(SECItem {
            typ: SI_BUFFER,
            data: data.as_ptr(),
            len: data.len() as u32,
        })
    }
}

#[repr(C)]
struct CkRsaPkcsPssParams {
    // Called CK_RSA_PKCS_PSS_PARAMS in NSS
    hash_alg: CkMechanismType, // Called hashAlg in NSS
    mgf: CkRsaPkcsMgfType,
    s_len: raw::c_ulong, // Called sLen in NSS
}

impl CkRsaPkcsPssParams {
    fn new() -> CkRsaPkcsPssParams {
        CkRsaPkcsPssParams {
            hash_alg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            s_len: 32,
        }
    }
}

// TODO: link to NSS source where these are defined
type SECOidTag = raw::c_uint; // TODO: actually an enum - is this the right size?
const SEC_OID_SHA256: SECOidTag = 191;

type CkMechanismType = raw::c_ulong; // called CK_MECHANISM_TYPE in NSS
const CKM_ECDSA: CkMechanismType = 0x00001041;
const CKM_RSA_PKCS_PSS: CkMechanismType = 0x0000000D;
const CKM_SHA256: CkMechanismType = 0x00000250;

type CkRsaPkcsMgfType = raw::c_ulong; // called CK_RSA_PKCS_MGF_TYPE in NSS
const CKG_MGF1_SHA256: CkRsaPkcsMgfType = 0x00000002;

type SECStatus = raw::c_int; // TODO: enum - right size?
const SEC_SUCCESS: SECStatus = 0; // Called SECSuccess in NSS
const SEC_FAILURE: SECStatus = -1; // Called SECFailure in NSS

enum CERTSubjectPublicKeyInfo {}

enum SECKEYPublicKey {}
enum SECKEYPrivateKey {}
enum PK11SlotInfo {}

const SHA256_LENGTH: usize = 32;

// TODO: ugh this will probably have a platform-specific name...
#[link(name = "nss3")]
extern "C" {
    fn PK11_HashBuf(
        hashAlg: SECOidTag,
        out: *mut u8,
        data_in: *const u8, // called "in" in NSS
        len: raw::c_int,
    ) -> SECStatus;
    fn PK11_VerifyWithMechanism(
        key: *const SECKEYPublicKey,
        mechanism: CkMechanismType,
        param: *const SECItem,
        sig: *const SECItem,
        hash: *const SECItem,
        wincx: *const raw::c_void,
    ) -> SECStatus;

    fn SECKEY_DecodeDERSubjectPublicKeyInfo(
        spkider: *const SECItem,
    ) -> *const CERTSubjectPublicKeyInfo;
    fn SECKEY_DestroySubjectPublicKeyInfo(spki: *const CERTSubjectPublicKeyInfo);

    fn SECKEY_ExtractPublicKey(spki: *const CERTSubjectPublicKeyInfo) -> *const SECKEYPublicKey;
    fn SECKEY_DestroyPublicKey(pubk: *const SECKEYPublicKey);

    fn PK11_ImportDERPrivateKeyInfoAndReturnKey(
        slot: *mut PK11SlotInfo,
        derPKI: *const SECItem,
        nickname: *const SECItem,
        publicValue: *const SECItem,
        isPerm: bool,
        isPrivate: bool,
        keyUsage: u32,
        privk: *mut *mut SECKEYPrivateKey,
        wincx: *const u8,
    ) -> SECStatus;
    fn PK11_GetInternalSlot() -> *mut PK11SlotInfo;
    fn PK11_SignatureLen(key: *const SECKEYPrivateKey) -> usize;
    fn PK11_SignWithMechanism(
        key: *const SECKEYPrivateKey,
        mech: CkMechanismType,
        param: *const SECItem,
        sig: *mut SECItem,
        hash: *const SECItem,
    ) -> SECStatus;
}

/// An error type describing errors that may be encountered during verification.
#[derive(Debug)]
pub enum NSSError {
    DecodingSPKIFailed,
    DecodingPKCS8Failed,
    InputTooLarge,
    LibraryFailure,
    SignatureVerificationFailed,
    SigningFailed,
    Unimplemented,
}

// XXX: make this work with other hashe algos.
fn hash(payload: &[u8]) -> Result<Vec<u8>, NSSError> {
    if payload.len() > raw::c_int::max_value() as usize {
        return Err(NSSError::InputTooLarge);
    }
    let mut hash_buf = vec![0; SHA256_LENGTH];
    let len: raw::c_int = payload.len() as raw::c_int;
    let hash_result =
        unsafe { PK11_HashBuf(SEC_OID_SHA256, hash_buf.as_mut_ptr(), payload.as_ptr(), len) };
    if hash_result != SEC_SUCCESS {
        return Err(NSSError::LibraryFailure);
    }
    Ok(hash_buf)
}

/// Main entrypoint for verification. Given a signature algorithm, the bytes of a subject public key
/// info, a payload, and a signature over the payload, returns a result based on the outcome of
/// decoding the subject public key info and running the signature verification algorithm on the
/// signed data.
pub fn verify_signature(
    signature_algorithm: SignatureAlgorithm,
    spki: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), NSSError> {
    let hash_buf = hash(payload).unwrap();
    let hash_item = SECItem::maybe_new(hash_buf.as_slice())?;

    let spki_item = SECItem::maybe_new(spki)?;
    // TODO: helper/macro for pattern of "call unsafe function, check null, defer unsafe release"?
    let spki_handle = unsafe { SECKEY_DecodeDERSubjectPublicKeyInfo(&spki_item) };
    if spki_handle.is_null() {
        return Err(NSSError::DecodingSPKIFailed);
    }
    defer!(unsafe {
        SECKEY_DestroySubjectPublicKeyInfo(spki_handle);
    });
    let key = unsafe { SECKEY_ExtractPublicKey(spki_handle) };
    if key.is_null() {
        // TODO: double-check that this can only fail if the library fails
        return Err(NSSError::LibraryFailure);
    }
    defer!(unsafe {
        SECKEY_DestroyPublicKey(key);
    });
    let signature_item = SECItem::maybe_new(signature)?;
    let mechanism = match signature_algorithm {
        SignatureAlgorithm::ES256 => CKM_ECDSA,
        SignatureAlgorithm::PS256 => CKM_RSA_PKCS_PSS,
    };
    let rsa_pss_params = CkRsaPkcsPssParams::new();
    // This isn't entirely NSS' fault, but it mostly is.
    let rsa_pss_params_ptr: *const CkRsaPkcsPssParams = &rsa_pss_params;
    let rsa_pss_params_ptr: *const u8 = rsa_pss_params_ptr as *const u8;
    let rsa_pss_params_bytes =
        unsafe { slice::from_raw_parts(rsa_pss_params_ptr, mem::size_of::<CkRsaPkcsPssParams>()) };
    let rsa_pss_params_secitem = SECItem::maybe_new(rsa_pss_params_bytes)?;
    let params_item: *const SECItem = match signature_algorithm {
        SignatureAlgorithm::ES256 => ptr::null(),
        SignatureAlgorithm::PS256 => &rsa_pss_params_secitem,
    };
    let null_cx_ptr: *const raw::c_void = ptr::null();
    let result = unsafe {
        PK11_VerifyWithMechanism(
            key,
            mechanism,
            params_item,
            &signature_item,
            &hash_item,
            null_cx_ptr,
        )
    };
    match result {
        SEC_SUCCESS => Ok(()),
        SEC_FAILURE => Err(NSSError::SignatureVerificationFailed),
        _ => Err(NSSError::LibraryFailure),
    }
}

pub fn sign(
    signature_algorithm: SignatureAlgorithm,
    pk8: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, NSSError> {
    match signature_algorithm {
        SignatureAlgorithm::ES256 => {}
        SignatureAlgorithm::PS256 => return Err(NSSError::Unimplemented),
    };
    let slot = unsafe { PK11_GetInternalSlot() };
    if slot.is_null() {
        println!("Couldn't get the internal NSS slot.");
        return Err(NSSError::LibraryFailure);
    }
    let pkcs8item = SECItem::maybe_new(pk8)?;
    let mut key: *mut SECKEYPrivateKey = ptr::null_mut();
    let ku_all = 0xFF;
    let rv = unsafe {
        PK11_ImportDERPrivateKeyInfoAndReturnKey(
            slot,
            &pkcs8item,
            ptr::null(),
            ptr::null(),
            false,
            false,
            ku_all,
            &mut key,
            ptr::null(),
        )
    };
    if rv != SEC_SUCCESS || key.is_null() {
        println!("Decoding the PKCS8 failed.");
        return Err(NSSError::DecodingPKCS8Failed);
    }
    let hash_buf = hash(payload).unwrap();
    let hash_item = SECItem::maybe_new(hash_buf.as_slice())?;
    let signature_len = unsafe { PK11_SignatureLen(key) };
    let mut signature: Vec<u8> = Vec::with_capacity(signature_len);
    // XXX: rewrite without unsafe.
    unsafe {
        signature.set_len(signature_len);
    }
    let mut signature_item = SECItem::maybe_new(signature.as_slice())?;
    let rv = unsafe {
        PK11_SignWithMechanism(key, CKM_ECDSA, ptr::null(), &mut signature_item, &hash_item)
    };

    if rv != SEC_SUCCESS || signature_item.len != signature_len as u32 {
        println!("Signing failed.");
        return Err(NSSError::SigningFailed);
    }
    Ok(signature)
}
