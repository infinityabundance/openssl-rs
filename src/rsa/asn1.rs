//! `crypto/rsa/rsa_asn1.c`'s plain-key half — the two `RSAPublicKey`/`RSAPrivateKey` templates and
//! their dups, Phase 8.4.
//!
//! ## A partial unit, and the measurement that says which half is this stratum's
//!
//! `crypto/rsa/rsa_asn1.c` is one hundred and twenty-seven lines and defines four items. Two of
//! them are the plain key codecs — `RSAPublicKey` (`n`, `e`) and `RSAPrivateKey` (the version
//! word, `n`, `e`, `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp` and the optional multi-prime
//! `prime_infos`) — with the `RSA_PRIME_INFO` item they nest, and the two dups over them. The
//! other two are `RSA_PSS_PARAMS` and `RSA_OAEP_PARAMS`, whose templates carry `X509_ALGOR`
//! fields and whose callbacks call `X509_ALGOR_free`; those are Phase 11's, because `X509_ALGOR`
//! is declared in `x509.h` and the crate's `X509Algor` is `_private: [u8; 0]`.
//!
//! So this is the [`crate::ec::asn1`] shape: the unit transcribed as far as this stratum reaches,
//! with the remainder withheld and named. `docs/DECISIONS.md` D341 had already measured the
//! plain-key half as landable — its closure is `RSA_new`/`RSA_free`, `ossl_rsa_multip_calc_product`
//! and the Phase 5 item machinery, with `X509_ALGOR_free` reached **only** by the two PSS/OAEP
//! templates — and D345 lands it.
//!
//! ## Why the two withheld items are *not* recorded as divergences, and the measurement that says so
//!
//! Giving `crypto/rsa/rsa_asn1.c` a crate module makes the prerequisite gate's direction B inspect
//! every identifier the unit's bodies reference. The two withheld templates are `RSA_PSS_PARAMS`
//! and `RSA_OAEP_PARAMS`, whose seven export names (`_new`, `_free`, `_it`, `_dup`) are produced by
//! `IMPLEMENT_ASN1_FUNCTIONS`/`IMPLEMENT_ASN1_DUP_FUNCTION` rather than written out, so the
//! lexical scan never sees them and the gate never owes them — the same reason
//! [`crate::ec::asn1`]'s row gives for the two `_free` members of `X9_62_PENTANOMIAL` and
//! `X9_62_CHARACTERISTIC_TWO`. A divergence row may **not** be added for them: the gate's own
//! direction D rejects a row covering a name it did not observe. The `X509_ALGOR_*` identifiers the
//! two PSS/OAEP callbacks reach *are* skipped, because their defining unit has no crate module,
//! which is direction B's own guard. The omission is therefore recorded here and in
//! `docs/DECISIONS.md` D345 rather than in the gate's tables, because the gate measures names and
//! the missing thing is a template.
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
//! code, a decoded length, a presence predicate or an equality the probe computes itself.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::*;
use crate::asn1::x_bignum::{BIGNUM_it, CBIGNUM_it};
use crate::asn1::x_int64::INT32_it;
use crate::rsa::mp::ossl_rsa_multip_calc_product;
use crate::rsa::object::{RSA_free, RSA_new, RSA_ASN1_VERSION_MULTI};
use crate::rsa::Rsa;
use crate::rsa::RsaPrimeInfo;

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
