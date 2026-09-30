//! `crypto/x509/x_x509.c` — the `X509` object and its `X509_CINF`, transcribed as far as 10.8's
//! object core reaches. Phase 10.8, completed by 10.12.
//!
//! `crypto/x509/x_x509.c` is 310 lines. **The object core lands**: the `X509_CINF` and `X509`
//! structures with the authority's own layout, both `ASN1_ITEM` descriptors and the `x509_cb`
//! callback that maintains the extension cache, the `IMPLEMENT_ASN1_*` lifecycles (`X509_CINF_*`,
//! `X509_new`/`_new_ex`/`_free`/`_dup`, `d2i_X509`/`i2d_X509`), the library-context helpers
//! (`ossl_x509_set0_libctx`, `X509_set_ex_data`/`X509_get_ex_data`) and the three signature and
//! `distinguishing_id` readers.
//!
//! **10.12 adds the `X509_AUX` layer** (`:177-279`): `d2i_X509_AUX`, the file-local
//! `i2d_x509_aux_internal` and `i2d_X509_AUX`, now that `X509_CERT_AUX` is landed
//! (`src/x509/x_x509a.rs`), together with the `X509_CERT_AUX_free(ret->aux)` call in each of
//! `x509_cb`'s `ASN1_OP_D2I_PRE` and `ASN1_OP_FREE_POST` arms. 10.8 withheld all of these behind
//! the unlanded item; the item is the only blocker and it is gone, so the whole file is
//! transcribed.
//!
//! **One thing is still withheld**: the **extension-cache frees** in `x509_cb`'s
//! `ASN1_OP_D2I_PRE` and `ASN1_OP_FREE_POST` arms:
//!   `AUTHORITY_KEYID_free`, `CRL_DIST_POINTS_free`, `ossl_policy_cache_free`,
//!   `GENERAL_NAMES_free`, `NAME_CONSTRAINTS_free`, `IPAddressFamily_free` and
//!   `ASIdentifiers_free`. Every one is defined in a `v3_*`/`pcy_*` unit that is not landed, and
//!   the fields they would release are only ever written by `ossl_x509v3_cache_extensions`
//!   (`crypto/x509/x509_v3.c`), which is not landed either — so on every object this crate can
//!   build the pointers are NULL and each omitted call is a no-op. The omissions are marked at
//!   each site rather than hidden behind a helper.
//!
//! `ASN1_OP_D2I_PRE` has no Rust spelling as a fall-through, so its body and `ASN1_OP_NEW_POST`'s
//! are the one file-local [`x509_new_post`], which is what the authority's `/* fall through */`
//! means.
//!
//! ## The layout, and why it is measured rather than read
//!
//! `struct x509_cinf_st` and `struct x509_st` are declared in `include/crypto/x509.h`. Every
//! offset after `siginf` depends on the two `long`s, the four `uint32_t` flags, the twenty-byte
//! `sha1_hash` and the `CRYPTO_EX_DATA` block between them, and a `reference` count the item layer
//! reads through `ref_offset`. `courts/layout/measure-x509.c` asks the authority's own compiler
//! for the numbers the asserts below carry.
//!
//! ## No raise, and the court
//!
//! `crypto/x509/x_x509.c` raises nothing, so it is deliberately **not** an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`. Its evidence is `RT-STORE`'s 10.8 arms: a
//! certificate decoded from the authority's own DER re-encodes to the same bytes, `X509_dup`
//! agrees member for member, and `X509_up_ref`/`X509_free` move the count.
//!
//! SPDX-License-Identifier: Apache-2.0

// The structures below carry the authority's own member names (`serialNumber`, `issuerUID`, ...)
// so that a reader can line them up with `include/crypto/x509.h` without a translation table.
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BIT_STRING_it, ASN1_INTEGER_it};
use crate::asn1::layout::*;
use crate::asn1::new::{ASN1_item_new, ASN1_item_new_ex};
use crate::asn1::string::ASN1_OCTET_STRING_free;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::asn1::x_val::{X509Val, X509_VAL_it};
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data, CryptoExData,
    CRYPTO_EX_INDEX_X509,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};
use crate::runtime::obj::{Asn1Object, OBJ_obj2nid};
use crate::runtime::thread::CryptoRwlock;
use crate::x509::x509_set::X509SigInfo;
use crate::x509::x_exten::X509_EXTENSION_it;
use crate::x509::x_name::{X509Name, X509_NAME_it};
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_it};
use crate::x509::x_x509a::{d2i_X509_CERT_AUX, i2d_X509_CERT_AUX, X509CertAux, X509_CERT_AUX_free};

/// The `OPENSSL_FILE` strings for this unit's `OPENSSL_free`/`OPENSSL_strdup` expansions and the
/// lines they expand at.
const FILE: &core::ffi::CStr = c"crypto/x509/x_x509.c";
/// `ossl_x509_set0_libctx`'s `OPENSSL_free(x->propq)` (`:144`).
const LINE_FREE_PROPQ: c_int = 144;
/// `ossl_x509_set0_libctx`'s `OPENSSL_strdup(propq)` (`:147`).
const LINE_STRDUP_PROPQ: c_int = 147;
/// `x509_cb`'s `OPENSSL_free(ret->propq)` (`:98`).
const LINE_FREE_PROPQ_FREE_POST: c_int = 98;
/// `i2d_X509_AUX`'s `OPENSSL_malloc(length)` (`:268`).
const LINE_MALLOC_AUX: c_int = 268;
/// `i2d_X509_AUX`'s error-path `OPENSSL_free(*pp)` (`:275`).
const LINE_FREE_AUX: c_int = 275;

/// `struct x509_cinf_st` — `X509_CINF`, from `include/crypto/x509.h:160-172`.
///
/// `TBSCertificate`'s fields, with `validity` embedded as an [`X509Val`] pair and the trailing
/// [`Asn1Encoding`] that the item's `ASN1_AFLG_ENCODING` keeps the received bytes in.
#[repr(C)]
pub struct X509Cinf {
    /// `ASN1_INTEGER *version` — `[ 0 ]`, default v1, so nullable.
    pub(crate) version: *mut Asn1String,
    /// `ASN1_INTEGER serialNumber` — embedded.
    pub(crate) serialNumber: Asn1String,
    /// `X509_ALGOR signature` — embedded, the TBS signature algorithm.
    pub(crate) signature: X509Algor,
    /// `X509_NAME *issuer` — mandatory.
    pub(crate) issuer: *mut X509Name,
    /// `X509_VAL validity` — embedded.
    pub(crate) validity: X509Val,
    /// `X509_NAME *subject` — mandatory.
    pub(crate) subject: *mut X509Name,
    /// `X509_PUBKEY *key` — mandatory.
    pub(crate) key: *mut X509Pubkey,
    /// `ASN1_BIT_STRING *issuerUID` — `[ 1 ]` optional in v2.
    pub(crate) issuerUID: *mut Asn1String,
    /// `ASN1_BIT_STRING *subjectUID` — `[ 2 ]` optional in v2.
    pub(crate) subjectUID: *mut Asn1String,
    /// `STACK_OF(X509_EXTENSION) *extensions` — `[ 3 ]` optional in v3.
    pub(crate) extensions: *mut crate::runtime::stack::OpenSslStack,
    /// `ASN1_ENCODING enc` — the received encoding, kept by `ASN1_AFLG_ENCODING`.
    pub(crate) enc: Asn1Encoding,
}

const _: () = {
    assert!(core::mem::size_of::<X509Cinf>() == 136);
    assert!(core::mem::offset_of!(X509Cinf, version) == 0);
    assert!(core::mem::offset_of!(X509Cinf, serialNumber) == 8);
    assert!(core::mem::offset_of!(X509Cinf, signature) == 32);
    assert!(core::mem::offset_of!(X509Cinf, issuer) == 48);
    assert!(core::mem::offset_of!(X509Cinf, validity) == 56);
    assert!(core::mem::offset_of!(X509Cinf, subject) == 72);
    assert!(core::mem::offset_of!(X509Cinf, key) == 80);
    assert!(core::mem::offset_of!(X509Cinf, issuerUID) == 88);
    assert!(core::mem::offset_of!(X509Cinf, subjectUID) == 96);
    assert!(core::mem::offset_of!(X509Cinf, extensions) == 104);
    assert!(core::mem::offset_of!(X509Cinf, enc) == 112);
};

/// `struct x509_st` — `X509`, from `include/crypto/x509.h:174-208`.
///
/// The certificate body, the outer signature algorithm and bit string, the signature-info cache,
/// the reference count and lock the item layer reads through `ref_offset`/`ref_lock`, and the
/// extension cache the `x509_cb` maintans. The cache members' own types (`AUTHORITY_KEYID`,
/// `X509_POLICY_CACHE`, `DIST_POINT`, `GENERAL_NAME`, `NAME_CONSTRAINTS`, `IPAddressFamily`,
/// `ASIdentifiers`, `X509_CERT_AUX`) are Phase 11's and are modelled as `*mut c_void`; every one
/// is a pointer, so the layout is exact.
#[repr(C)]
pub struct X509 {
    /// `X509_CINF cert_info` — the signed body, embedded.
    pub(crate) cert_info: X509Cinf,
    /// `X509_ALGOR sig_alg` — the outer signature algorithm, embedded.
    pub(crate) sig_alg: X509Algor,
    /// `ASN1_BIT_STRING signature` — the outer signature, embedded.
    pub(crate) signature: Asn1String,
    /// `X509_SIG_INFO siginf` — the cached signature strength, read by `X509_get_signature_info`.
    pub(crate) siginf: X509SigInfo,
    /// `CRYPTO_REF_COUNT references` — the count `X509_up_ref`/`X509_free` move.
    pub(crate) references: c_int,
    /// `CRYPTO_EX_DATA ex_data` — the application extension block.
    pub(crate) ex_data: CryptoExData,
    /// `long ex_pathlen` — cached path length, or -1.
    pub(crate) ex_pathlen: c_long,
    /// `long ex_pcpathlen` — cached policy-constraints path length, or -1.
    pub(crate) ex_pcpathlen: c_long,
    /// `uint32_t ex_flags` — the `EXFLAG_*` word.
    pub(crate) ex_flags: c_uint,
    /// `uint32_t ex_kusage` — cached key usage.
    pub(crate) ex_kusage: c_uint,
    /// `uint32_t ex_xkusage` — cached extended key usage.
    pub(crate) ex_xkusage: c_uint,
    /// `uint32_t ex_nscert` — cached Netscape certificate type.
    pub(crate) ex_nscert: c_uint,
    /// `ASN1_OCTET_STRING *skid` — cached subject key identifier.
    pub(crate) skid: *mut Asn1String,
    /// `AUTHORITY_KEYID *akid` — cached authority key identifier (type withheld).
    pub(crate) akid: *mut c_void,
    /// `X509_POLICY_CACHE *policy_cache` — cached policy tree (type withheld).
    pub(crate) policy_cache: *mut c_void,
    /// `STACK_OF(DIST_POINT) *crldp` — cached CRL distribution points (type withheld).
    pub(crate) crldp: *mut c_void,
    /// `STACK_OF(GENERAL_NAME) *altname` — cached subject alt names (type withheld).
    pub(crate) altname: *mut c_void,
    /// `NAME_CONSTRAINTS *nc` — cached name constraints (type withheld).
    pub(crate) nc: *mut c_void,
    /// `STACK_OF(IPAddressFamily) *rfc3779_addr` — cached RFC 3779 address blocks (type withheld).
    pub(crate) rfc3779_addr: *mut c_void,
    /// `struct ASIdentifiers_st *rfc3779_asid` — cached RFC 3779 AS identifiers (type withheld).
    pub(crate) rfc3779_asid: *mut c_void,
    /// `unsigned char sha1_hash[SHA_DIGEST_LENGTH]` — the certificate's SHA-1 fingerprint.
    pub(crate) sha1_hash: [c_uchar; 20],
    /// `X509_CERT_AUX *aux` — the trust/alias/reject suffix (type withheld).
    pub(crate) aux: *mut c_void,
    /// `CRYPTO_RWLOCK *lock` — the lock guarding the extension cache.
    pub(crate) lock: *mut CryptoRwlock,
    /// `volatile int ex_cached` — non-zero once the cache is built.
    pub(crate) ex_cached: c_int,
    /// `ASN1_OCTET_STRING *distinguishing_id` — the authentication id, or NULL.
    pub(crate) distinguishing_id: *mut Asn1String,
    /// `OSSL_LIB_CTX *libctx` — the object's library context.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — the object's property query, owned.
    pub(crate) propq: *mut c_char,
}

const _: () = {
    assert!(core::mem::size_of::<X509>() == 384);
    assert!(core::mem::offset_of!(X509, cert_info) == 0);
    assert!(core::mem::offset_of!(X509, sig_alg) == 136);
    assert!(core::mem::offset_of!(X509, signature) == 152);
    assert!(core::mem::offset_of!(X509, siginf) == 176);
    assert!(core::mem::offset_of!(X509, references) == 192);
    assert!(core::mem::offset_of!(X509, ex_data) == 200);
    assert!(core::mem::offset_of!(X509, ex_pathlen) == 216);
    assert!(core::mem::offset_of!(X509, ex_pcpathlen) == 224);
    assert!(core::mem::offset_of!(X509, ex_flags) == 232);
    assert!(core::mem::offset_of!(X509, ex_kusage) == 236);
    assert!(core::mem::offset_of!(X509, ex_xkusage) == 240);
    assert!(core::mem::offset_of!(X509, ex_nscert) == 244);
    assert!(core::mem::offset_of!(X509, skid) == 248);
    assert!(core::mem::offset_of!(X509, akid) == 256);
    assert!(core::mem::offset_of!(X509, policy_cache) == 264);
    assert!(core::mem::offset_of!(X509, crldp) == 272);
    assert!(core::mem::offset_of!(X509, altname) == 280);
    assert!(core::mem::offset_of!(X509, nc) == 288);
    assert!(core::mem::offset_of!(X509, rfc3779_addr) == 296);
    assert!(core::mem::offset_of!(X509, rfc3779_asid) == 304);
    assert!(core::mem::offset_of!(X509, sha1_hash) == 312);
    assert!(core::mem::offset_of!(X509, aux) == 336);
    assert!(core::mem::offset_of!(X509, lock) == 344);
    assert!(core::mem::offset_of!(X509, ex_cached) == 352);
    assert!(core::mem::offset_of!(X509, distinguishing_id) == 360);
    assert!(core::mem::offset_of!(X509, libctx) == 368);
    assert!(core::mem::offset_of!(X509, propq) == 376);
};

// ---------------------------------------------------------------------------------------------
// The `X509_CINF` item — `ASN1_SEQUENCE_enc(X509_CINF, enc, 0)` (`:18-29`)
// ---------------------------------------------------------------------------------------------

/// `X509_CINF`'s `ASN1_AUX` — `ASN1_SEQUENCE_enc(X509_CINF, enc, 0)`: `ASN1_AFLG_ENCODING`,
/// `enc_offset = offsetof(X509_CINF, enc)`, and no callback.
struct SyncAux(Asn1Aux);

// SAFETY: a `static` compiled from constants (a null `app_data`, integer offsets, no function
// pointers), written once by the loader, with no interior mutability reachable through a shared
// reference.
unsafe impl Sync for SyncAux {}

/// The `ASN1_AUX` block named above.
static X509_CINF_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: ASN1_AFLG_ENCODING,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: None,
    enc_offset: 112,
    asn1_const_cb: None,
});

/// `X509_CINF_seq_tt` — `ASN1_SEQUENCE_enc(X509_CINF, enc, 0)` (`crypto/x509/x_x509.c:18-29`):
/// `ASN1_EXP_OPT(version)`, `ASN1_EMBED(serialNumber)`, `ASN1_EMBED(signature)`,
/// `ASN1_SIMPLE(issuer)`, `ASN1_EMBED(validity)`, `ASN1_SIMPLE(subject)`, `ASN1_SIMPLE(key)`,
/// `ASN1_IMP_OPT(issuerUID, 1)`, `ASN1_IMP_OPT(subjectUID, 2)` and
/// `ASN1_EXP_SEQUENCE_OF_OPT(extensions, 3)`.
static X509_CINF_TT: [Asn1Template; 10] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 8,
        field_name: c"serialNumber".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 32,
        field_name: c"signature".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 48,
        field_name: c"issuer".as_ptr(),
        item: X509_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 56,
        field_name: c"validity".as_ptr(),
        item: X509_VAL_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 72,
        field_name: c"subject".as_ptr(),
        item: X509_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 80,
        field_name: c"key".as_ptr(),
        item: X509_PUBKEY_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 88,
        field_name: c"issuerUID".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 96,
        field_name: c"subjectUID".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: 104,
        field_name: c"extensions".as_ptr(),
        item: X509_EXTENSION_it as *mut c_void,
    },
];

/// `X509_CINF_it`'s descriptor — `ASN1_SEQUENCE_END_enc(X509_CINF, X509_CINF)` at
/// `crypto/x509/x_x509.c:29`.
static X509_CINF_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_CINF_TT.as_ptr(),
    tcount: 10,
    funcs: (&X509_CINF_AUX.0) as *const Asn1Aux as *const c_void,
    size: core::mem::size_of::<X509Cinf>() as c_long,
    sname: c"X509_CINF".as_ptr(),
};

/// `const ASN1_ITEM *X509_CINF_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END_enc(X509_CINF, X509_CINF)`.
#[no_mangle]
pub extern "C" fn X509_CINF_it() -> *const Asn1Item {
    &X509_CINF_ITEM
}

/// `X509_CINF *X509_CINF_new(void)` — `crypto/x509/x_x509.c:31`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_CINF)`.
#[no_mangle]
pub extern "C" fn X509_CINF_new() -> *mut X509Cinf {
    // SAFETY: `X509_CINF_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_CINF_it()).cast::<X509Cinf>() }
}

/// `void X509_CINF_free(X509_CINF *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_CINF_free(a: *mut X509Cinf) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_CINF_it()) }
}

/// `X509_CINF *d2i_X509_CINF(X509_CINF **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_CINF(
    a: *mut *mut X509Cinf,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Cinf {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_CINF_it()).cast::<X509Cinf>() }
}

/// `int i2d_X509_CINF(const X509_CINF *a, unsigned char **out)` — the same macro's encoder, which
/// `i2d_re_X509_tbs` and `x509_cmp` use.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_CINF(a: *const X509Cinf, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_CINF_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `x509_cb` callback and its helper — `crypto/x509/x_x509.c:36-124`
// ---------------------------------------------------------------------------------------------

/// The `ASN1_OP_NEW_POST` body, which `ASN1_OP_D2I_PRE` falls through to. Zeroes the extension
/// cache and the flag words, sets the sentinel path lengths, and creates the `ex_data` block.
///
/// # Safety
/// `ret` is a live `X509`.
unsafe fn x509_new_post(ret: *mut X509) -> c_int {
    // SAFETY: `ret` is live per the contract.
    unsafe {
        (*ret).ex_cached = 0;
        (*ret).ex_kusage = 0;
        (*ret).ex_xkusage = 0;
        (*ret).ex_nscert = 0;
        (*ret).ex_flags = 0;
        (*ret).ex_pathlen = -1;
        (*ret).ex_pcpathlen = -1;
        (*ret).skid = ptr::null_mut();
        (*ret).akid = ptr::null_mut();
        (*ret).policy_cache = ptr::null_mut();
        (*ret).altname = ptr::null_mut();
        (*ret).nc = ptr::null_mut();
        (*ret).rfc3779_addr = ptr::null_mut();
        (*ret).rfc3779_asid = ptr::null_mut();
        (*ret).distinguishing_id = ptr::null_mut();
        (*ret).aux = ptr::null_mut();
        (*ret).crldp = ptr::null_mut();
        if CRYPTO_new_ex_data(
            CRYPTO_EX_INDEX_X509,
            ret.cast::<c_void>(),
            &raw mut (*ret).ex_data,
        ) == 0
        {
            return 0;
        }
    }
    1
}

/// `static int x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/x509/x_x509.c:36-124`.
///
/// # Safety
/// The item layer's own callback contract.
unsafe extern "C" fn x509_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    it: *const Asn1Item,
    exarg: *mut c_void,
) -> c_int {
    let _ = it;
    // SAFETY: `pval` points at a live `X509` for every operation.
    let ret = unsafe { (*pval).cast::<X509>() };

    match operation {
        ASN1_OP_D2I_PRE => {
            // SAFETY: `ret` is live. The cache releases the authority performs here for
            // `akid`/`crldp`/`policy_cache`/`altname`/`nc`/`rfc3779_addr`/`rfc3779_asid` are
            // withheld: each names a `v3_*`/`pcy_*` free whose unit is not landed, and every one is
            // only ever written by `ossl_x509v3_cache_extensions` (`x509_v3.c`, also not landed),
            // so on every object this crate can build the pointers are NULL. The `aux` free and the
            // two string frees are landed.
            unsafe {
                CRYPTO_free_ex_data(
                    CRYPTO_EX_INDEX_X509,
                    ret.cast::<c_void>(),
                    &raw mut (*ret).ex_data,
                );
                X509_CERT_AUX_free((*ret).aux.cast());
                ASN1_OCTET_STRING_free((*ret).skid);
                ASN1_OCTET_STRING_free((*ret).distinguishing_id);
            }
            // The authority's `/* fall through */`.
            // SAFETY: `ret` is live.
            unsafe { return x509_new_post(ret) };
        }
        ASN1_OP_NEW_POST => {
            // SAFETY: `ret` is live.
            return unsafe { x509_new_post(ret) };
        }
        ASN1_OP_FREE_POST => {
            // SAFETY: `ret` is live. The six withheld cache frees are the same ones the
            // `ASN1_OP_D2I_PRE` arm withholds, for the same reason; `aux` and the two strings land.
            unsafe {
                CRYPTO_free_ex_data(
                    CRYPTO_EX_INDEX_X509,
                    ret.cast::<c_void>(),
                    &raw mut (*ret).ex_data,
                );
                X509_CERT_AUX_free((*ret).aux.cast());
                ASN1_OCTET_STRING_free((*ret).skid);
                ASN1_OCTET_STRING_free((*ret).distinguishing_id);
                CRYPTO_free(
                    (*ret).propq.cast(),
                    FILE.as_ptr(),
                    LINE_FREE_PROPQ_FREE_POST,
                );
            }
        }
        ASN1_OP_DUP_POST => {
            // SAFETY: `exarg` is the source `X509` for this operation.
            let old = exarg.cast::<X509>();
            // SAFETY: `ret` and `old` are live.
            if unsafe { ossl_x509_set0_libctx(ret, (*old).libctx, (*old).propq) } == 0 {
                return 0;
            }
        }
        ASN1_OP_GET0_LIBCTX => {
            // SAFETY: `exarg` is a `OSSL_LIB_CTX **` out-slot.
            unsafe { *(exarg.cast::<*mut c_void>()) = (*ret).libctx };
        }
        ASN1_OP_GET0_PROPQ => {
            // SAFETY: `exarg` is a `const char **` out-slot.
            unsafe { *(exarg.cast::<*const c_char>()) = (*ret).propq };
        }
        _ => {}
    }
    1
}

/// `X509`'s `ASN1_AUX` — `ASN1_SEQUENCE_ref(X509, x509_cb)` (`:126`): `ASN1_AFLG_REFCOUNT`,
/// `ref_offset = offsetof(X509, references)`, `ref_lock = offsetof(X509, lock)`, `x509_cb`.
struct SyncAuxRefcount(Asn1Aux);

// SAFETY: as [`X509_CINF_AUX`], plus one function pointer; the block is written once by the loader
// and its fields are never mutated through the shared reference the item's `funcs` slot takes.
unsafe impl Sync for SyncAuxRefcount {}

/// The `ASN1_AUX` block named above.
static X509_AUX: SyncAuxRefcount = SyncAuxRefcount(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: ASN1_AFLG_REFCOUNT,
    ref_offset: 192,
    ref_lock: 344,
    asn1_cb: Some(x509_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `X509_seq_tt` — `ASN1_SEQUENCE_ref(X509, x509_cb)` (`:126-130`):
/// `ASN1_EMBED(X509, cert_info, X509_CINF)`, `ASN1_EMBED(X509, sig_alg, X509_ALGOR)` and
/// `ASN1_EMBED(X509, signature, ASN1_BIT_STRING)`.
static X509_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"cert_info".as_ptr(),
        item: X509_CINF_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 136,
        field_name: c"sig_alg".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 152,
        field_name: c"signature".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `X509_it`'s descriptor — `ASN1_SEQUENCE_END_ref(X509, X509)` at `crypto/x509/x_x509.c:130`.
static X509_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_TT.as_ptr(),
    tcount: 3,
    funcs: (&X509_AUX.0) as *const Asn1Aux as *const c_void,
    size: core::mem::size_of::<X509>() as c_long,
    sname: c"X509".as_ptr(),
};

/// `const ASN1_ITEM *X509_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END_ref(X509, X509)`.
#[no_mangle]
pub extern "C" fn X509_it() -> *const Asn1Item {
    &X509_ITEM
}

/// `X509 *X509_new(void)` — `crypto/x509/x_x509.c:132`, from `IMPLEMENT_ASN1_FUNCTIONS(X509)`.
#[no_mangle]
pub extern "C" fn X509_new() -> *mut X509 {
    // SAFETY: `X509_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_it()).cast::<X509>() }
}

/// `void X509_free(X509 *a)` — the same macro's free half. The reference count `X509_it`'s
/// `ASN1_AFLG_REFCOUNT` maintains is decremented by the item layer, so this releases `a` only when
/// it reaches zero.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_free(a: *mut X509) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_it()) }
}

/// `X509 *X509_dup(const X509 *a)` — `IMPLEMENT_ASN1_DUP_FUNCTION(X509)` (`:133`).
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_dup(a: *const X509) -> *mut X509 {
    // SAFETY: `a` is NULL or live per the contract; `X509_it()` is a static item.
    unsafe { ASN1_item_dup(X509_it(), a.cast()).cast::<X509>() }
}

/// `X509 *d2i_X509(X509 **a, const unsigned char **in, long len)` — `crypto/x509/x_x509.c:132`'s
/// generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509(
    a: *mut *mut X509,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509 {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_it()).cast::<X509>() }
}

/// `int i2d_X509(const X509 *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509(a: *const X509, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_it()) }
}

/// `X509 *d2i_X509_AUX(X509 **a, const unsigned char **pp, long length)` —
/// `crypto/x509/x_x509.c:184-212`.
///
/// Decodes the certificate, then, if bytes remain, decodes the `X509_CERT_AUX` suffix into
/// `ret->aux`. `freeret` records whether this call created the slot, so the error path frees the
/// certificate only when it did.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `pp` points at a readable cursor; `length` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_AUX(
    a: *mut *mut X509,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut X509 {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        let mut q = *pp;
        let freeret = a.is_null() || (*a).is_null();
        let ret = d2i_X509(a, &raw mut q, length);
        if ret.is_null() {
            return ptr::null_mut();
        }
        let consumed = (q as isize - *pp as isize) as c_long;
        let remaining = length - consumed;
        if remaining > 0 {
            let auxslot = &raw mut (*ret).aux as *mut *mut X509CertAux;
            if d2i_X509_CERT_AUX(auxslot, &raw mut q, remaining).is_null() {
                if freeret {
                    X509_free(ret);
                    if !a.is_null() {
                        *a = ptr::null_mut();
                    }
                }
                return ptr::null_mut();
            }
        }
        *pp = q;
        ret
    }
}

/// `static int i2d_x509_aux_internal(const X509 *a, unsigned char **pp)` —
/// `crypto/x509/x_x509.c:220-243`.
///
/// Encodes the certificate followed by its AUX suffix, or answers the combined length for a NULL
/// `pp`. On an AUX failure the cursor is restored to `start`, which is the authority's own hygiene
/// note about not compounding a lower layer's error-path perturbation.
///
/// # Safety
///
/// `a` is NULL or live; `pp` is NULL or a writable cursor.
unsafe fn i2d_x509_aux_internal(a: *const X509, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        let start = if pp.is_null() { ptr::null_mut() } else { *pp };
        let length = i2d_X509(a, pp);
        if length <= 0 || a.is_null() {
            return length;
        }
        let tmplen = i2d_X509_CERT_AUX((*a).aux.cast::<X509CertAux>(), pp);
        if tmplen < 0 {
            if !start.is_null() {
                *pp = start;
            }
            return tmplen;
        }
        length + tmplen
    }
}

/// `int i2d_X509_AUX(const X509 *a, unsigned char **pp)` — `crypto/x509/x_x509.c:254-279`.
///
/// With a caller-supplied buffer this is [`i2d_x509_aux_internal`]; with `pp` non-NULL and `*pp`
/// NULL it allocates the combined buffer and keeps `*pp` at the allocated pointer while the two
/// encoders advance a local cursor.
///
/// # Safety
///
/// `a` is NULL or live; `pp` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_AUX(a: *const X509, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        if pp.is_null() || !(*pp).is_null() {
            return i2d_x509_aux_internal(a, pp);
        }
        let length = i2d_x509_aux_internal(a, ptr::null_mut());
        if length <= 0 {
            return length;
        }
        let buf = CRYPTO_malloc(length as usize, FILE.as_ptr(), LINE_MALLOC_AUX).cast::<c_uchar>();
        *pp = buf;
        let mut tmp = buf;
        if tmp.is_null() {
            return -1;
        }
        let length = i2d_x509_aux_internal(a, &raw mut tmp);
        if length <= 0 {
            CRYPTO_free((*pp).cast(), FILE.as_ptr(), LINE_FREE_AUX);
            *pp = ptr::null_mut();
        }
        length
    }
}

/// `X509 *X509_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/x509/x_x509.c:155-165`.
///
/// # Safety
///
/// `libctx` is NULL or a live context and `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_new_ex(libctx: *mut c_void, propq: *const c_char) -> *mut X509 {
    // SAFETY: `X509_it()` is a static item; the libctx/propq are the caller's contract.
    let cert = unsafe { ASN1_item_new_ex(X509_it(), libctx, propq).cast::<X509>() };
    // SAFETY: `cert` is NULL or a fresh object.
    if unsafe { ossl_x509_set0_libctx(cert, libctx, propq) } == 0 {
        // SAFETY: `cert` is NULL or a fresh object this call owns.
        unsafe { X509_free(cert) };
        return ptr::null_mut();
    }
    cert
}

/// `int ossl_x509_set0_libctx(X509 *x, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/x509/x_x509.c:140-153`.
///
/// # Safety
///
/// `x` is NULL or a live `X509`; `libctx` is NULL or a live context and `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509_set0_libctx(
    x: *mut X509,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if !x.is_null() {
        // SAFETY: `x` is live per the contract.
        unsafe {
            (*x).libctx = libctx;
            CRYPTO_free((*x).propq.cast(), FILE.as_ptr(), LINE_FREE_PROPQ);
            (*x).propq = ptr::null_mut();
            if !propq.is_null() {
                (*x).propq = CRYPTO_strdup(propq, FILE.as_ptr(), LINE_STRDUP_PROPQ);
                if (*x).propq.is_null() {
                    return 0;
                }
            }
        }
    }
    1
}

/// `int X509_set_ex_data(X509 *r, int idx, void *arg)` — `crypto/x509/x_x509.c:167-170`.
///
/// # Safety
///
/// `r` is live; `arg` is the caller's value.
#[no_mangle]
pub unsafe extern "C" fn X509_set_ex_data(r: *mut X509, idx: c_int, arg: *mut c_void) -> c_int {
    // SAFETY: `r` is live and `ex_data` is its own block.
    unsafe { CRYPTO_set_ex_data(&raw mut (*r).ex_data, idx, arg) }
}

/// `void *X509_get_ex_data(const X509 *r, int idx)` — `crypto/x509/x_x509.c:172-175`.
///
/// # Safety
///
/// `r` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_get_ex_data(r: *const X509, idx: c_int) -> *mut c_void {
    // SAFETY: `r` is live and `ex_data` is its own block.
    unsafe { CRYPTO_get_ex_data(&raw const (*r).ex_data, idx) }
}

/// `int i2d_re_X509_tbs(X509 *x, unsigned char **pp)` — `crypto/x509/x_x509.c:281-285`.
///
/// Marks the cached TBS encoding stale before re-encoding it, which is what makes a signature
/// computed over a re-encoded TBS differ from the received one.
///
/// # Safety
///
/// `x` is live; `pp` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_re_X509_tbs(x: *mut X509, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: `x` is live and `cert_info.enc.modified` is its own field.
    unsafe {
        (*x).cert_info.enc.modified = 1;
        i2d_X509_CINF(&raw const (*x).cert_info, pp)
    }
}

/// `void X509_get0_signature(const ASN1_BIT_STRING **psig, const X509_ALGOR **palg,
/// const X509 *x)` — `crypto/x509/x_x509.c:287-294`.
///
/// # Safety
///
/// `x` is live; each out-pointer is NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_signature(
    psig: *mut *const Asn1String,
    palg: *mut *const X509Algor,
    x: *const X509,
) {
    // SAFETY: `x` is live and its two members are its own.
    unsafe {
        if !psig.is_null() {
            *psig = &raw const (*x).signature;
        }
        if !palg.is_null() {
            *palg = &raw const (*x).sig_alg;
        }
    }
}

/// `int X509_get_signature_nid(const X509 *x)` — `crypto/x509/x_x509.c:296-299`.
///
/// # Safety
///
/// `x` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_get_signature_nid(x: *const X509) -> c_int {
    // SAFETY: `x` is live and its `sig_alg.algorithm` is its own.
    unsafe { OBJ_obj2nid((*x).sig_alg.algorithm as *const Asn1Object) }
}

/// `void X509_set0_distinguishing_id(X509 *x, ASN1_OCTET_STRING *d_id)` —
/// `crypto/x509/x_x509.c:301-305`.
///
/// # Safety
///
/// `x` is live; `d_id` is NULL or owned by the caller and handed over.
#[no_mangle]
pub unsafe extern "C" fn X509_set0_distinguishing_id(x: *mut X509, d_id: *mut Asn1String) {
    // SAFETY: `x` is live and `distinguishing_id` is its own field.
    unsafe {
        ASN1_OCTET_STRING_free((*x).distinguishing_id);
        (*x).distinguishing_id = d_id;
    }
}

/// `ASN1_OCTET_STRING *X509_get0_distinguishing_id(X509 *x)` — `crypto/x509/x_x509.c:307-310`.
///
/// # Safety
///
/// `x` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_distinguishing_id(x: *mut X509) -> *mut Asn1String {
    // SAFETY: `x` is live.
    unsafe { (*x).distinguishing_id }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blank certificate has the authority's layout: the sentinel path lengths, a one-valued
    /// reference count and a NULL cache.
    #[test]
    fn a_blank_certificate_has_the_authoritys_defaults() {
        // SAFETY: `x` is a live object this test owns.
        unsafe {
            let x = X509_new();
            assert!(!x.is_null());
            assert_eq!((*x).references, 1);
            assert_eq!((*x).ex_pathlen, -1);
            assert_eq!((*x).ex_pcpathlen, -1);
            assert!((*x).skid.is_null());
            assert!((*x).aux.is_null());
            // The mandatory `X509_CINF` columns are allocated by the item layer's own `new`.
            assert!(!(*x).cert_info.issuer.is_null());
            assert!(!(*x).cert_info.subject.is_null());
            assert!(!(*x).cert_info.key.is_null());
            X509_free(x);
        }
    }
}
