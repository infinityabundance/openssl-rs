//! `crypto/rsa/rsa_asn1.c` — the two `RSAPublicKey`/`RSAPrivateKey` templates and the
//! `RSA_PSS_PARAMS`/`RSA_OAEP_PARAMS` templates, Phase 8.4.
//!
//! ## The whole unit, and the measurement that said which half was this stratum's first
//!
//! `crypto/rsa/rsa_asn1.c` is one hundred and twenty-seven lines and defines four items. Two of
//! them are the plain key codecs — `RSAPublicKey` (`n`, `e`) and `RSAPrivateKey` (the version
//! word, `n`, `e`, `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp` and the optional multi-prime
//! `prime_infos`) — with the `RSA_PRIME_INFO` item they nest, and the two dups over them. D341 had
//! measured the plain-key half as landable on its own (its closure is `RSA_new`/`RSA_free`,
//! `ossl_rsa_multip_calc_product` and the Phase 5 item machinery), and D345 landed it.
//!
//! The other two items are `RSA_PSS_PARAMS` and `RSA_OAEP_PARAMS`, whose templates carry
//! `X509_ALGOR` fields and whose free callbacks call `X509_ALGOR_free`. They were withheld with
//! that reason until **D348**, because `X509_ALGOR` had no crate module and the crate's
//! `X509Algor` was `_private: [u8; 0]`. D348 lands `crypto/asn1/x_algor.c` whole as
//! [`crate::asn1::x_algor`], which is the item and the destructor these two templates name, so the
//! withheld half joins the module here and `rsa_asn1.c` becomes whole.
//!
//! ## The templates the brief's blocker named, and the one flag they carry
//!
//! Both items are `ASN1_SEQUENCE_cb` forms over four (PSS) and three (OAEP) `ASN1_EXP_OPT`
//! fields, so each field is an **explicit** `[n]` wrapper: `ASN1_TFLG_EXPLICIT |
//! ASN1_TFLG_OPTIONAL`, which is `ASN1_TFLG_EXPTAG | ASN1_TFLG_CONTEXT | ASN1_TFLG_OPTIONAL`. The
//! context bit matters — the encoder takes the wrapper's class from it — and is written out rather
//! than reduced to `ASN1_TFLG_EXPTAG | ASN1_TFLG_OPTIONAL`, so the emitted `a0`/`a1`/`a2`/`a3`
//! tags are the authority's. `rsa_pss_cb` and `rsa_oaep_cb` are `FREE_PRE` hooks that release the
//! `maskHash` field, which the template does not encode; they answer 1 and not the `2` the two key
//! callbacks answer, because they do not take over the free.
//!
//! The seven exports `IMPLEMENT_ASN1_FUNCTIONS`/`_DUP_FUNCTION` generate over them
//! (`RSA_PSS_PARAMS_new`/`_free`/`_dup`/`_it`/`d2i_`/`i2d_` and the five `RSA_OAEP_PARAMS_*`
//! equivalents, which have no dup) are the names the Phase 8 ledger carried as open; D348 is what
//! moves them.
//!
//! ## The callback, and the one operation the plain templates do not share
//!
//! `rsa_cb` (`rsa_asn1.c:28-48`) handles `NEW_PRE`/`FREE_PRE` as `dsa_cb` and `dh_cb` do, and adds
//! `ASN1_OP_D2I_POST`: a decoded object whose `version` is `RSA_ASN1_VERSION_MULTI` has its
//! multi-prime CRT product computed by [`ossl_rsa_multip_calc_product`], and a failure there fails
//! the decode. The **`RSAPublicKey`** item carries the same callback but no `prime_infos` template,
//! so its `D2I_POST` reads a version that is never `MULTI` and returns 1.
//!
//! ## The court: `RT-RSA`
//!
//! `RT-RSA`'s new arms build a two-prime key, encode and decode it through both templates and both
//! dups, and observe the round trip by re-reading the components and comparing them by value;
//! **no modulus, exponent, prime or private component is printed** — every observation is a return
//! code, a decoded length, a presence predicate or an equality the probe computes itself. D348 adds
//! the PSS/OAEP half to the same court: a `RSA_PSS_PARAMS` is built from constants, `i2d_`'d and its
//! DER printed in full (it is a public constant, not a secret), `d2i_`'d back and compared, and both
//! `RSA_PSS_PARAMS_dup` and the OAEP templates are driven the same way.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::x_algor::{X509_ALGOR_free, X509_ALGOR_it};
use crate::asn1::x_bignum::{BIGNUM_it, CBIGNUM_it};
use crate::asn1::x_int64::INT32_it;
use crate::rsa::mp::ossl_rsa_multip_calc_product;
use crate::rsa::object::{RSA_free, RSA_new, RSA_ASN1_VERSION_MULTI};
use crate::rsa::{Rsa, RsaOaepParams, RsaPrimeInfo, RsaPssParams};

/// `sizeof(RSA)` — the `size` every item the `ASN1_SEQUENCE_END_cb(RSA, name)` form spells carries,
/// because the non-static macro stringifies `#tname` for `sname` but takes `sizeof(stname)`.
const RSA_SIZE: c_long = core::mem::size_of::<Rsa>() as c_long;

/// `sizeof(RSA_PRIME_INFO)` — `rsa_local.h:19-25`'s five pointers, measured at 40 by the object
/// test in [`crate::rsa`].
const PRIME_INFO_SIZE: c_long = core::mem::size_of::<RsaPrimeInfo>() as c_long;

/// The offsets the templates below name, asserted rather than typed twice. A wrong offset is a
/// decode into the wrong member, and for a structure of nine same-typed pointers a swap of two
/// fields is invisible to a round trip that compares the whole set rather than each name.
const OFFSET_VERSION: c_ulong = offset_of!(Rsa, version) as c_ulong;
const OFFSET_N: c_ulong = offset_of!(Rsa, n) as c_ulong;
const OFFSET_E: c_ulong = offset_of!(Rsa, e) as c_ulong;
const OFFSET_D: c_ulong = offset_of!(Rsa, d) as c_ulong;
const OFFSET_P: c_ulong = offset_of!(Rsa, p) as c_ulong;
const OFFSET_Q: c_ulong = offset_of!(Rsa, q) as c_ulong;
const OFFSET_DMP1: c_ulong = offset_of!(Rsa, dmp1) as c_ulong;
const OFFSET_DMQ1: c_ulong = offset_of!(Rsa, dmq1) as c_ulong;
const OFFSET_IQMP: c_ulong = offset_of!(Rsa, iqmp) as c_ulong;
const OFFSET_PRIME_INFOS: c_ulong = offset_of!(Rsa, prime_infos) as c_ulong;

const _: () = {
    assert!(RSA_SIZE == 216);
    assert!(PRIME_INFO_SIZE == 40);
    assert!(OFFSET_VERSION == 16);
    assert!(OFFSET_N == 40);
    assert!(OFFSET_E == 48);
    assert!(OFFSET_D == 56);
    assert!(OFFSET_P == 64);
    assert!(OFFSET_Q == 72);
    assert!(OFFSET_DMP1 == 80);
    assert!(OFFSET_DMQ1 == 88);
    assert!(OFFSET_IQMP == 96);
    assert!(OFFSET_PRIME_INFOS == 136);
};

/// `int rsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/rsa/rsa_asn1.c:28-48`.
///
/// # Safety
///
/// The item machinery's own contract: `pval` points at the value slot for this item.
unsafe extern "C" fn rsa_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_NEW_PRE {
        // SAFETY: `pval` is the value slot per the caller's contract.
        let fresh = unsafe { RSA_new() }.cast::<c_void>();
        // SAFETY: as above.
        unsafe { *pval = fresh };
        if !fresh.is_null() {
            return 2;
        }
        return 0;
    } else if operation == ASN1_OP_FREE_PRE {
        // SAFETY: `pval` is the value slot and holds a value this stratum built.
        unsafe {
            RSA_free((*pval).cast::<Rsa>());
            *pval = ptr::null_mut();
        }
        return 2;
    } else if operation == ASN1_OP_D2I_POST {
        // SAFETY: `pval` holds the object the decoder just built.
        let rsa = unsafe { (*pval).cast::<Rsa>() };
        // SAFETY: `rsa` is live.
        if unsafe { (*rsa).version } != RSA_ASN1_VERSION_MULTI {
            // not a multi-prime key, skip
            return 1;
        }
        // SAFETY: `rsa` is live.
        return if unsafe { ossl_rsa_multip_calc_product(rsa) } == 1 {
            2
        } else {
            0
        };
    }
    1
}

/// The `ASN1_AUX` both key items share. Wrapped for the same reason [`crate::dsa::asn1`] and
/// [`crate::dh::asn1`] wrap theirs: [`Asn1Aux`] holds raw pointers and so is not `Sync` by itself.
#[repr(transparent)]
struct SyncAux(Asn1Aux);

// SAFETY: built from constants — a null `app_data`, integer offsets, a `None` const-callback and
// one function pointer — written once by the loader, and with no interior mutability reachable
// through a shared reference. The machinery reads only `asn1_cb` out of it.
unsafe impl Sync for SyncAux {}

/// `static const ASN1_AUX RSAPrivateKey_aux = { NULL, 0, 0, 0, rsa_cb, 0, NULL }`, shared with
/// `RSAPublicKey`, which the authority gives its own copy of the same constant.
static RSA_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(rsa_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `RSA_PRIME_INFO_seq_tt` — `ASN1_SEQUENCE(RSA_PRIME_INFO) = { ASN1_SIMPLE(RSA_PRIME_INFO, r,`
/// `CBIGNUM), ASN1_SIMPLE(RSA_PRIME_INFO, d, CBIGNUM), ASN1_SIMPLE(RSA_PRIME_INFO, t, CBIGNUM) }`.
///
/// The structure has five members; the two the template does not name (`pp` and `m`) are the
/// runtime bookkeeping `ossl_rsa_multip_calc_product` fills, not encoded fields.
static RAPRIMEINFO_SEQ_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: offset_of!(RsaPrimeInfo, r) as c_ulong,
        field_name: c"r".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: offset_of!(RsaPrimeInfo, d) as c_ulong,
        field_name: c"d".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: offset_of!(RsaPrimeInfo, t) as c_ulong,
        field_name: c"t".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
];

/// The `RSA_PRIME_INFO` item accessor — `ASN1_SEQUENCE_END(RSA_PRIME_INFO)`'s non-static item. It
/// is declared in the **internal** `rsa_local.h:27` and not the installed `rsa.h`, so it is not an
/// export and is private here.
fn rsaprimeinfo_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: RAPRIMEINFO_SEQ_TT.as_ptr(),
        tcount: 3,
        funcs: ptr::null(),
        size: PRIME_INFO_SIZE,
        sname: c"RSA_PRIME_INFO".as_ptr(),
    };
    &IT
}

/// `RSAPrivateKey_seq_tt` — `ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = { ... }`.
static RSAPRIVATEKEY_SEQ_TT: [Asn1Template; 10] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: OFFSET_VERSION,
        field_name: c"version".as_ptr(),
        item: INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_N,
        field_name: c"n".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_E,
        field_name: c"e".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_D,
        field_name: c"d".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_P,
        field_name: c"p".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_Q,
        field_name: c"q".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_DMP1,
        field_name: c"dmp1".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_DMQ1,
        field_name: c"dmq1".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_IQMP,
        field_name: c"iqmp".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL | ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: OFFSET_PRIME_INFOS,
        field_name: c"prime_infos".as_ptr(),
        item: rsaprimeinfo_it as *mut c_void,
    },
];

/// `const ASN1_ITEM *RSAPrivateKey_it(void)` — `include/openssl/rsa.h:320`, defined by
/// `ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)` at `crypto/rsa/rsa_asn1.c:68`.
#[no_mangle]
pub extern "C" fn RSAPrivateKey_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: RSAPRIVATEKEY_SEQ_TT.as_ptr(),
        tcount: 10,
        funcs: ptr::addr_of!(RSA_AUX.0).cast(),
        size: RSA_SIZE,
        sname: c"RSAPrivateKey".as_ptr(),
    };
    &IT
}

/// `RSAPublicKey_seq_tt` — `ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = { ASN1_SIMPLE(RSA, n, BIGNUM),`
/// `ASN1_SIMPLE(RSA, e, BIGNUM) }`.
static RSAPUBLICKEY_SEQ_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_N,
        field_name: c"n".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_E,
        field_name: c"e".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
];

/// `const ASN1_ITEM *RSAPublicKey_it(void)` — `include/openssl/rsa.h:318`, defined by
/// `ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)` at `crypto/rsa/rsa_asn1.c:73`.
#[no_mangle]
pub extern "C" fn RSAPublicKey_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: RSAPUBLICKEY_SEQ_TT.as_ptr(),
        tcount: 2,
        funcs: ptr::addr_of!(RSA_AUX.0).cast(),
        size: RSA_SIZE,
        sname: c"RSAPublicKey".as_ptr(),
    };
    &IT
}

/// `RSA *d2i_RSAPublicKey(RSA **a, const unsigned char **in, long len)` —
/// `crypto/rsa/rsa_asn1.c:117`, from
/// `IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(RSA, RSAPublicKey, RSAPublicKey)`.
///
/// # Safety
///
/// `a` is null or a writable slot; `in` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSAPublicKey(
    a: *mut *mut Rsa,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Rsa {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, RSAPublicKey_it()).cast::<Rsa>() }
}

/// `int i2d_RSAPublicKey(const RSA *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is null or a live key; `out` is null or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSAPublicKey(a: *const Rsa, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, RSAPublicKey_it()) }
}

/// `RSA *d2i_RSAPrivateKey(RSA **a, const unsigned char **in, long len)` — `:115`.
///
/// # Safety
///
/// As [`d2i_RSAPublicKey`].
#[no_mangle]
pub unsafe extern "C" fn d2i_RSAPrivateKey(
    a: *mut *mut Rsa,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Rsa {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, RSAPrivateKey_it()).cast::<Rsa>() }
}

/// `int i2d_RSAPrivateKey(const RSA *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// As [`i2d_RSAPublicKey`].
#[no_mangle]
pub unsafe extern "C" fn i2d_RSAPrivateKey(a: *const Rsa, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, RSAPrivateKey_it()) }
}

/// `RSA *RSAPublicKey_dup(const RSA *rsa)` — `crypto/rsa/rsa_asn1.c:119-122`.
///
/// # Safety
///
/// `rsa` is null or a live key.
#[no_mangle]
pub unsafe extern "C" fn RSAPublicKey_dup(rsa: *const Rsa) -> *mut Rsa {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_dup(RSAPublicKey_it(), rsa.cast::<c_void>()).cast::<Rsa>() }
}

/// `RSA *RSAPrivateKey_dup(const RSA *rsa)` — `crypto/rsa/rsa_asn1.c:124-127`.
///
/// # Safety
///
/// `rsa` is null or a live key.
#[no_mangle]
pub unsafe extern "C" fn RSAPrivateKey_dup(rsa: *const Rsa) -> *mut Rsa {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_dup(RSAPrivateKey_it(), rsa.cast::<c_void>()).cast::<Rsa>() }
}

// ---------------------------------------------------------------------------------------------
// The PSS and OAEP parameter templates — `crypto/rsa/rsa_asn1.c:75-113` (D348)
// ---------------------------------------------------------------------------------------------

/// The offsets the two templates below name, asserted rather than typed twice. `maskHash` is last
/// and is **not** encoded: it is the field the two `FREE_PRE` callbacks release.
const OFFSET_PSS_HASH_ALGORITHM: c_ulong = offset_of!(RsaPssParams, hash_algorithm) as c_ulong;
const OFFSET_PSS_MASK_GEN_ALGORITHM: c_ulong =
    offset_of!(RsaPssParams, mask_gen_algorithm) as c_ulong;
const OFFSET_PSS_SALT_LENGTH: c_ulong = offset_of!(RsaPssParams, salt_length) as c_ulong;
const OFFSET_PSS_TRAILER_FIELD: c_ulong = offset_of!(RsaPssParams, trailer_field) as c_ulong;
const OFFSET_OAEP_HASH_FUNC: c_ulong = offset_of!(RsaOaepParams, hash_func) as c_ulong;
const OFFSET_OAEP_MASK_GEN_FUNC: c_ulong = offset_of!(RsaOaepParams, mask_gen_func) as c_ulong;
const OFFSET_OAEP_P_SOURCE_FUNC: c_ulong = offset_of!(RsaOaepParams, p_source_func) as c_ulong;

const _: () = {
    assert!(core::mem::size_of::<RsaPssParams>() == 40);
    assert!(core::mem::size_of::<RsaOaepParams>() == 32);
    assert!(OFFSET_PSS_HASH_ALGORITHM == 0);
    assert!(OFFSET_PSS_MASK_GEN_ALGORITHM == 8);
    assert!(OFFSET_PSS_SALT_LENGTH == 16);
    assert!(OFFSET_PSS_TRAILER_FIELD == 24);
    assert!(OFFSET_OAEP_HASH_FUNC == 0);
    assert!(OFFSET_OAEP_MASK_GEN_FUNC == 8);
    assert!(OFFSET_OAEP_P_SOURCE_FUNC == 16);
};

/// `int rsa_pss_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/rsa/rsa_asn1.c:76-84`.
///
/// One operation and one answer: a `FREE_PRE` releases the decoded `maskHash`, which no template
/// field owns, and the callback answers 1 (not the `2` `rsa_cb` answers) so the item layer keeps
/// freeing the templated fields itself.
///
/// # Safety
///
/// The item machinery's own contract: `pval` points at the value slot for this item.
unsafe extern "C" fn rsa_pss_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_FREE_PRE {
        // SAFETY: `pval` is the value slot and holds a value this stratum built.
        let pss = unsafe { (*pval).cast::<RsaPssParams>() };
        // SAFETY: `pss` is live and `mask_hash` is NULL or this object's own identifier.
        unsafe { X509_ALGOR_free((*pss).mask_hash) };
    }
    1
}

/// `int rsa_oaep_cb(...)` — `crypto/rsa/rsa_asn1.c:97-105`, the OAEP twin of [`rsa_pss_cb`].
///
/// # Safety
///
/// As [`rsa_pss_cb`].
unsafe extern "C" fn rsa_oaep_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_FREE_PRE {
        // SAFETY: `pval` is the value slot and holds a value this stratum built.
        let oaep = unsafe { (*pval).cast::<RsaOaepParams>() };
        // SAFETY: `oaep` is live and `mask_hash` is NULL or this object's own identifier.
        unsafe { X509_ALGOR_free((*oaep).mask_hash) };
    }
    1
}

/// The `ASN1_AUX` the two PSS callbacks share, wrapped for the reason [`SyncAux`] is.
static RSA_PSS_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(rsa_pss_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// The `ASN1_AUX` the OAEP callback carries.
static RSA_OAEP_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(rsa_oaep_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `RSA_PSS_PARAMS_seq_tt` — `ASN1_SEQUENCE_cb(RSA_PSS_PARAMS, rsa_pss_cb)` at
/// `crypto/rsa/rsa_asn1.c:86-91`: four `ASN1_EXP_OPT` fields, `[0]` through `[3]`.
///
/// The flags are `ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL` — the authority's own expansion of
/// `ASN1_EXP_OPT` — so the wrapper's class is context-specific.
static RSA_PSS_PARAMS_SEQ_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: OFFSET_PSS_HASH_ALGORITHM,
        field_name: c"hashAlgorithm".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: OFFSET_PSS_MASK_GEN_ALGORITHM,
        field_name: c"maskGenAlgorithm".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: OFFSET_PSS_SALT_LENGTH,
        field_name: c"saltLength".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: OFFSET_PSS_TRAILER_FIELD,
        field_name: c"trailerField".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `RSA_OAEP_PARAMS_seq_tt` — `ASN1_SEQUENCE_cb(RSA_OAEP_PARAMS, rsa_oaep_cb)` at
/// `crypto/rsa/rsa_asn1.c:107-111`: three `ASN1_EXP_OPT` fields, `[0]` through `[2]`.
static RSA_OAEP_PARAMS_SEQ_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: OFFSET_OAEP_HASH_FUNC,
        field_name: c"hashFunc".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: OFFSET_OAEP_MASK_GEN_FUNC,
        field_name: c"maskGenFunc".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: OFFSET_OAEP_P_SOURCE_FUNC,
        field_name: c"pSourceFunc".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
];

/// `const ASN1_ITEM *RSA_PSS_PARAMS_it(void)` — `include/openssl/rsa.h:334`, defined by
/// `ASN1_SEQUENCE_END_cb(RSA_PSS_PARAMS, RSA_PSS_PARAMS)` at `crypto/rsa/rsa_asn1.c:91`.
#[no_mangle]
pub extern "C" fn RSA_PSS_PARAMS_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: RSA_PSS_PARAMS_SEQ_TT.as_ptr(),
        tcount: 4,
        funcs: ptr::addr_of!(RSA_PSS_AUX.0).cast(),
        size: core::mem::size_of::<RsaPssParams>() as c_long,
        sname: c"RSA_PSS_PARAMS".as_ptr(),
    };
    &IT
}

/// `const ASN1_ITEM *RSA_OAEP_PARAMS_it(void)` — `include/openssl/rsa.h:345`, defined by
/// `ASN1_SEQUENCE_END_cb(RSA_OAEP_PARAMS, RSA_OAEP_PARAMS)` at `crypto/rsa/rsa_asn1.c:111`.
#[no_mangle]
pub extern "C" fn RSA_OAEP_PARAMS_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: RSA_OAEP_PARAMS_SEQ_TT.as_ptr(),
        tcount: 3,
        funcs: ptr::addr_of!(RSA_OAEP_AUX.0).cast(),
        size: core::mem::size_of::<RsaOaepParams>() as c_long,
        sname: c"RSA_OAEP_PARAMS".as_ptr(),
    };
    &IT
}

/// `RSA_PSS_PARAMS *RSA_PSS_PARAMS_new(void)` — `crypto/rsa/rsa_asn1.c:93`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(RSA_PSS_PARAMS)`.
#[no_mangle]
pub extern "C" fn RSA_PSS_PARAMS_new() -> *mut RsaPssParams {
    // SAFETY: `RSA_PSS_PARAMS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(RSA_PSS_PARAMS_it()).cast::<RsaPssParams>() }
}

/// `void RSA_PSS_PARAMS_free(RSA_PSS_PARAMS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn RSA_PSS_PARAMS_free(a: *mut RsaPssParams) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), RSA_PSS_PARAMS_it()) }
}

/// `RSA_PSS_PARAMS *RSA_PSS_PARAMS_dup(const RSA_PSS_PARAMS *a)` — `crypto/rsa/rsa_asn1.c:94`, from
/// `IMPLEMENT_ASN1_DUP_FUNCTION(RSA_PSS_PARAMS)`.
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn RSA_PSS_PARAMS_dup(a: *const RsaPssParams) -> *mut RsaPssParams {
    // SAFETY: `a` is NULL or live per the contract; `RSA_PSS_PARAMS_it()` is a static item.
    unsafe { ASN1_item_dup(RSA_PSS_PARAMS_it(), a.cast::<c_void>()).cast::<RsaPssParams>() }
}

/// `RSA_PSS_PARAMS *d2i_RSA_PSS_PARAMS(RSA_PSS_PARAMS **a, const unsigned char **in, long len)` —
/// `crypto/rsa/rsa_asn1.c:93`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSA_PSS_PARAMS(
    a: *mut *mut RsaPssParams,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut RsaPssParams {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, RSA_PSS_PARAMS_it()).cast::<RsaPssParams>() }
}

/// `int i2d_RSA_PSS_PARAMS(const RSA_PSS_PARAMS *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSA_PSS_PARAMS(
    a: *const RsaPssParams,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, RSA_PSS_PARAMS_it()) }
}

/// `RSA_OAEP_PARAMS *RSA_OAEP_PARAMS_new(void)` — `crypto/rsa/rsa_asn1.c:113`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(RSA_OAEP_PARAMS)`.
#[no_mangle]
pub extern "C" fn RSA_OAEP_PARAMS_new() -> *mut RsaOaepParams {
    // SAFETY: `RSA_OAEP_PARAMS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(RSA_OAEP_PARAMS_it()).cast::<RsaOaepParams>() }
}

/// `void RSA_OAEP_PARAMS_free(RSA_OAEP_PARAMS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn RSA_OAEP_PARAMS_free(a: *mut RsaOaepParams) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), RSA_OAEP_PARAMS_it()) }
}

/// `RSA_OAEP_PARAMS *d2i_RSA_OAEP_PARAMS(RSA_OAEP_PARAMS **a, const unsigned char **in,
/// long len)` — `crypto/rsa/rsa_asn1.c:113`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSA_OAEP_PARAMS(
    a: *mut *mut RsaOaepParams,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut RsaOaepParams {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, RSA_OAEP_PARAMS_it()).cast::<RsaOaepParams>() }
}

/// `int i2d_RSA_OAEP_PARAMS(const RSA_OAEP_PARAMS *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSA_OAEP_PARAMS(
    a: *const RsaOaepParams,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, RSA_OAEP_PARAMS_it()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::arith::BN_cmp;
    use crate::bn::bignum::{BN_new, BN_set_word};
    use crate::rsa::object::{
        RSA_get0_factors, RSA_get0_key, RSA_set0_crt_params, RSA_set0_factors, RSA_set0_key,
    };
    use crate::runtime::mem::CRYPTO_free;

    /// A structurally valid two-prime key: `n = 61 * 53`, `e = 17`, `d = 2753`, with the CRT
    /// parameters. The templates do not validate the numbers, so this rounds trips every field
    /// without a generation.
    ///
    /// # Safety
    ///
    /// The answer is owned by the caller and released with [`RSA_free`].
    unsafe fn small_rsa() -> *mut Rsa {
        // SAFETY: the constructors and setters are the crate's own.
        unsafe {
            let k = RSA_new();
            let (n, e, d) = (BN_new(), BN_new(), BN_new());
            let (p, q) = (BN_new(), BN_new());
            let (dmp1, dmq1, iqmp) = (BN_new(), BN_new(), BN_new());
            assert_eq!(BN_set_word(n, 3233), 1);
            assert_eq!(BN_set_word(e, 17), 1);
            assert_eq!(BN_set_word(d, 2753), 1);
            assert_eq!(BN_set_word(p, 61), 1);
            assert_eq!(BN_set_word(q, 53), 1);
            assert_eq!(BN_set_word(dmp1, 53), 1);
            assert_eq!(BN_set_word(dmq1, 49), 1);
            assert_eq!(BN_set_word(iqmp, 38), 1);
            assert_eq!(RSA_set0_key(k, n, e, d), 1);
            assert_eq!(RSA_set0_factors(k, p, q), 1);
            assert_eq!(RSA_set0_crt_params(k, dmp1, dmq1, iqmp), 1);
            k
        }
    }

    /// `RSAPublicKey` carries `n` and `e` and nothing else, and `i2d`/`d2i` are an inverse pair.
    #[test]
    fn the_public_template_round_trips_without_the_private_half() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let k = small_rsa();
            let n = i2d_RSAPublicKey(k, ptr::null_mut());
            assert!(n > 0);
            let mut der: *mut c_uchar = ptr::null_mut();
            assert_eq!(i2d_RSAPublicKey(k, &mut der), n);
            let mut cp: *const c_uchar = der;
            let back = d2i_RSAPublicKey(ptr::null_mut(), &mut cp, c_long::from(n));
            assert!(!back.is_null());
            assert_eq!(cp, der.add(n as usize));

            let (mut bn, mut be, mut bd) = (ptr::null(), ptr::null(), ptr::null());
            RSA_get0_key(back, &mut bn, &mut be, &mut bd);
            assert!(!bn.is_null() && !be.is_null());
            assert_eq!(BN_cmp(bn, (*k).n), 0);
            assert_eq!(BN_cmp(be, (*k).e), 0);
            assert!(bd.is_null(), "the public template has no private exponent");

            RSA_free(back);
            CRYPTO_free(der.cast(), ptr::null(), 0);
            RSA_free(k);
        }
    }

    /// `RSAPrivateKey` carries all nine components plus the version word, and both dups are the
    /// encode-then-decode of their templates.
    #[test]
    fn the_private_template_and_both_dups_round_trip() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let k = small_rsa();
            let n = i2d_RSAPrivateKey(k, ptr::null_mut());
            assert!(n > 0);
            let mut der: *mut c_uchar = ptr::null_mut();
            assert_eq!(i2d_RSAPrivateKey(k, &mut der), n);
            let mut cp: *const c_uchar = der;
            let back = d2i_RSAPrivateKey(ptr::null_mut(), &mut cp, c_long::from(n));
            assert!(!back.is_null());
            let (mut bn, mut be, mut bd) = (ptr::null(), ptr::null(), ptr::null());
            let (mut bp, mut bq) = (ptr::null(), ptr::null());
            RSA_get0_key(back, &mut bn, &mut be, &mut bd);
            RSA_get0_factors(back, &mut bp, &mut bq);
            assert_eq!(BN_cmp(bn, (*k).n), 0);
            assert_eq!(BN_cmp(be, (*k).e), 0);
            assert_eq!(BN_cmp(bd, (*k).d), 0);
            assert_eq!(BN_cmp(bp, (*k).p), 0);
            assert_eq!(BN_cmp(bq, (*k).q), 0);
            RSA_free(back);

            let pd = RSAPublicKey_dup(k);
            assert!(!pd.is_null());
            assert_eq!(BN_cmp((*pd).n, (*k).n), 0);
            assert_eq!(BN_cmp((*pd).e, (*k).e), 0);
            RSA_free(pd);

            let prd = RSAPrivateKey_dup(k);
            assert!(!prd.is_null());
            assert_eq!(BN_cmp((*prd).d, (*k).d), 0);
            assert_eq!(BN_cmp((*prd).p, (*k).p), 0);
            assert_eq!(BN_cmp((*prd).q, (*k).q), 0);
            RSA_free(prd);

            CRYPTO_free(der.cast(), ptr::null(), 0);
            RSA_free(k);
        }
    }

    /// An object with no components cannot be encoded — the Phase 5 item layer answers -1 — and a
    /// negative length refuses before anything is read.
    #[test]
    fn the_refusals_are_the_item_layers() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let empty = RSA_new();
            assert_eq!(i2d_RSAPrivateKey(empty, ptr::null_mut()), -1);
            let mut cp: *const c_uchar = ptr::null();
            assert!(d2i_RSAPublicKey(ptr::null_mut(), &mut cp, -1).is_null());
            RSA_free(empty);
        }
    }

    #[test]
    fn the_item_accessors_are_stable() {
        assert_eq!(RSAPublicKey_it(), RSAPublicKey_it());
        assert_eq!(RSAPrivateKey_it(), RSAPrivateKey_it());
        assert_ne!(RSAPublicKey_it(), RSAPrivateKey_it());
        assert_eq!(RSA_PSS_PARAMS_it(), RSA_PSS_PARAMS_it());
        assert_eq!(RSA_OAEP_PARAMS_it(), RSA_OAEP_PARAMS_it());
    }

    /// The two PSS/OAEP templates round-trip through the item layer, and the fields are the
    /// explicit `[n]` wrappers the authority emits.
    #[test]
    fn the_pss_and_oaep_templates_round_trip() {
        use crate::asn1::prim::ASN1_INTEGER_set;
        use crate::asn1::string::ASN1_INTEGER_new;
        use crate::asn1::x_algor::{X509_ALGOR_new, X509_ALGOR_set0};
        use crate::runtime::obj::OBJ_nid2obj;

        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let pss = RSA_PSS_PARAMS_new();
            assert!(!pss.is_null());
            let salt = ASN1_INTEGER_new();
            assert_eq!(ASN1_INTEGER_set(salt, 32), 1);
            (*pss).salt_length = salt;
            let hash = X509_ALGOR_new();
            assert_eq!(
                X509_ALGOR_set0(
                    hash,
                    OBJ_nid2obj(672 /* NID_sha256 */),
                    V_ASN1_NULL,
                    ptr::null_mut()
                ),
                1
            );
            (*pss).hash_algorithm = hash;

            let n = i2d_RSA_PSS_PARAMS(pss, ptr::null_mut());
            assert!(n > 0);
            let mut der: *mut c_uchar = ptr::null_mut();
            assert_eq!(i2d_RSA_PSS_PARAMS(pss, &mut der), n);
            assert_eq!(*der, 0x30, "the parameters are a SEQUENCE");
            assert_eq!(*der.add(2), 0xa0, "hashAlgorithm is an explicit [0]");

            let mut cp: *const c_uchar = der;
            let back = d2i_RSA_PSS_PARAMS(ptr::null_mut(), &mut cp, c_long::from(n));
            assert!(!back.is_null());
            assert_eq!(cp, der.add(n as usize));
            // The decode is the inverse: re-encoding the decoded object answers the same bytes.
            let n2 = i2d_RSA_PSS_PARAMS(back, ptr::null_mut());
            assert_eq!(n2, n);
            let mut der2: *mut c_uchar = ptr::null_mut();
            assert_eq!(i2d_RSA_PSS_PARAMS(back, &mut der2), n);
            assert_eq!(
                core::slice::from_raw_parts(der, n as usize),
                core::slice::from_raw_parts(der2, n as usize)
            );

            // `_dup` is a fresh, equal object.
            let dup = RSA_PSS_PARAMS_dup(back);
            assert!(!dup.is_null());
            assert_ne!((*dup).salt_length, (*back).salt_length);
            let n3 = i2d_RSA_PSS_PARAMS(dup, ptr::null_mut());
            assert_eq!(n3, n);

            CRYPTO_free(der.cast(), ptr::null(), 0);
            CRYPTO_free(der2.cast(), ptr::null(), 0);
            RSA_PSS_PARAMS_free(dup);
            RSA_PSS_PARAMS_free(back);
            RSA_PSS_PARAMS_free(pss);

            // The OAEP item is a three-field template with the same free hook.
            let oaep = RSA_OAEP_PARAMS_new();
            assert!(!oaep.is_null());
            let n4 = i2d_RSA_OAEP_PARAMS(oaep, ptr::null_mut());
            assert_eq!(n4, 2, "an empty RSA_OAEP_PARAMS is a two-byte SEQUENCE");
            let mut oder: *mut c_uchar = ptr::null_mut();
            assert_eq!(i2d_RSA_OAEP_PARAMS(oaep, &mut oder), n4);
            let mut op: *const c_uchar = oder;
            let oback = d2i_RSA_OAEP_PARAMS(ptr::null_mut(), &mut op, c_long::from(n4));
            assert!(!oback.is_null());
            assert_eq!(op, oder.add(2));
            CRYPTO_free(oder.cast(), ptr::null(), 0);
            RSA_OAEP_PARAMS_free(oback);
            RSA_OAEP_PARAMS_free(oaep);
        }
    }

    /// The three offsets and the two sizes the templates are built from, asserted here as well as
    /// in the `const` block so a layout change is a test failure and not only a compile error.
    #[test]
    fn the_offsets_are_the_measured_layout() {
        assert_eq!(RSA_SIZE, 216);
        assert_eq!(PRIME_INFO_SIZE, 40);
        assert_eq!(OFFSET_VERSION, 16);
        assert_eq!(OFFSET_N, 40);
        assert_eq!(OFFSET_PRIME_INFOS, 136);
    }
}
