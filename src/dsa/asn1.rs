//! `crypto/dsa/dsa_asn1.c` — the three `dsa.h` DER templates and `DSAparams_dup`, Phase 8.6.
//!
//! The unit is seventy-two lines, it is **whole** (D327's rule), and it defines five exports and
//! no internals beyond one `static` callback: `d2i_DSAPrivateKey`/`i2d_DSAPrivateKey`,
//! `d2i_DSAPublicKey`/`i2d_DSAPublicKey`, `d2i_DSAparams`/`i2d_DSAparams` and `DSAparams_dup`.
//! The three `_it` items are `static` in the authority (`static_ASN1_SEQUENCE_END_cb`) and are
//! private here for the same reason: `dsa.h` declares the encode entry points with
//! `DECLARE_ASN1_ENCODE_FUNCTIONS_only`, which names no item accessor at all, so nothing outside
//! this file can reach them.
//!
//! ## Why this unit lands here rather than with 8.8's method objects
//!
//! `docs/PHASE-8-SUBPHASES.md`'s 8.6 row groups `dsa_asn1.c` with `dsa_ameth.c`/`dsa_prn.c` as
//! "8.8's ASN.1 method machinery", and the session brief repeated that grouping. The authority
//! is the other way: the *ledger* assigns all seven of these names to `src/dsa/mod.rs` (8.6's
//! module), `docs/PHASE-8-AMETH-INTEGRATION-PLAN.md` §6 names `d2i_DSAPublicKey` as one of the
//! three callees `d2i_PublicKey` (8.8's) waits on and assigns it to 8.6, and D341 measured this
//! file's lexical closure as **"no non-Phase-8 reference at all"** — every callee is Phase 5's
//! `ASN1_item_*` machinery or this stratum's own `DSA_new`/`DSA_free`. Nothing it reaches is
//! Phase 11's, because nothing here reads an `X509_PUBKEY`/`X509_ALGOR`/`PKCS8_PRIV_KEY_INFO`;
//! that is what the *ameth* callbacks do, and they are a different file. D345 records the
//! correction.
//!
//! ## The callback, and the three items that share it
//!
//! `ASN1_SEQUENCE_cb(name, dsa_cb)` gives each item an `ASN1_AUX` whose `asn1_cb` is `dsa_cb`,
//! and `dsa_cb` (`dsa_asn1.c:25-39`) does exactly two things: on `ASN1_OP_NEW_PRE` it answers a
//! fresh [`DSA_new`] and returns `2` ("handled"), and on `ASN1_OP_FREE_PRE` it runs [`DSA_free`],
//! nulls the slot, and returns `2`. Every other operation returns `1`. That is what makes a
//! decoded object a **real** [`Dsa`] — with a method table, a lock and a reference count — rather
//! than `item.size` zeroed bytes, and it is why the item's `size` (which the authority's
//! `static_ASN1_SEQUENCE_END_cb(DSA, name)` sets to `sizeof(DSA)` for all three) is transcribed
//! even though the callback bypasses the default allocation on the paths that matter.
//!
//! The authority declares one `name##_aux` per item; this crate builds **one** shared `DSA_AUX`,
//! because the three are the same constant and the address of an `ASN1_AUX` is reachable from no
//! caller — the machinery reads `asn1_cb` out of it and nothing else.
//!
//! ## The templates, and the one offset that is a lie if it is wrong
//!
//! Each template is the authority's field list read against the crate's own measured layout
//! ([`crate::dsa::Dsa`], whose offsets `courts/layout/measure-dsa.c` fixes): `version` at 4 is an
//! `ASN1_TFLG_EMBED` of `INT32`, and `params.p`/`params.q`/`params.g`, `pub_key` and `priv_key`
//! are `ASN1_SIMPLE` pointers. The offsets are `core::mem::offset_of!` rather than typed numbers,
//! and the `assert!` block below makes a layout change a compile error rather than a decode into
//! the wrong member.
//!
//! ## The court: `RT-DSA`
//!
//! `RT-DSA`'s new arms build a parameter set, encode it with `i2d_DSAparams`, decode it again with
//! `d2i_DSAparams`, and observe the round trip by re-reading the three parameters and comparing
//! them by value. `DSAparams_dup` is driven the same way, as is the private-key template through
//! `DSA_set0_key`, and **no arm prints a key, a private scalar or a signature component** —
//! the observations are return codes, decoded lengths and equalities the probe computes itself.
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
use crate::dsa::object::{DSA_free, DSA_new};
use crate::dsa::Dsa;

/// `#tname` as the authority's `static_ASN1_SEQUENCE_END_cb(DSA, name)` stringifies it — the
/// **structure** name, not the item's, because the static form of the macro spells `#stname`.
/// The string reaches a caller only as the `Type=<sname>` data of a failed operation's error.
const DSA_SNAME: *const core::ffi::c_char = c"DSA".as_ptr();

/// `sizeof(DSA)` — the `size` every one of the three items carries, from
/// `static_ASN1_SEQUENCE_END_cb(DSA, name)`'s `sizeof(stname)`.
const DSA_SIZE: c_long = core::mem::size_of::<Dsa>() as c_long;

/// The offsets the three template arrays below name, asserted rather than typed twice. A wrong
/// offset is a decode into the wrong member, which no round trip on a structure whose fields are
/// all pointers would catch.
const OFFSET_VERSION: c_ulong = offset_of!(Dsa, version) as c_ulong;
const OFFSET_P: c_ulong =
    (offset_of!(Dsa, params) + offset_of!(crate::ffc::FfcParams, p)) as c_ulong;
const OFFSET_Q: c_ulong =
    (offset_of!(Dsa, params) + offset_of!(crate::ffc::FfcParams, q)) as c_ulong;
const OFFSET_G: c_ulong =
    (offset_of!(Dsa, params) + offset_of!(crate::ffc::FfcParams, g)) as c_ulong;
const OFFSET_PUB: c_ulong = offset_of!(Dsa, pub_key) as c_ulong;
const OFFSET_PRIV: c_ulong = offset_of!(Dsa, priv_key) as c_ulong;

const _: () = {
    assert!(DSA_SIZE == 200);
    assert!(OFFSET_VERSION == 4);
    assert!(OFFSET_P == 8);
    assert!(OFFSET_Q == 16);
    assert!(OFFSET_G == 24);
    assert!(OFFSET_PUB == 104);
    assert!(OFFSET_PRIV == 112);
};

/// `int dsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/dsa/dsa_asn1.c:25-39`.
///
/// Returns `2` on the two operations it handles, which is the "the callback did the work" answer
/// the machinery distinguishes from `1` ("carry on") and `0` ("failed").
///
/// # Safety
///
/// The item machinery's own contract: `pval` points at the value slot for this item.
unsafe extern "C" fn dsa_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_NEW_PRE {
        // SAFETY: `pval` is the value slot per the caller's contract.
        let fresh = unsafe { DSA_new() }.cast::<c_void>();
        // SAFETY: as above.
        unsafe { *pval = fresh };
        if !fresh.is_null() {
            return 2;
        }
        return 0;
    } else if operation == ASN1_OP_FREE_PRE {
        // SAFETY: `pval` is the value slot and holds a value this stratum built.
        unsafe {
            DSA_free((*pval).cast::<Dsa>());
            *pval = ptr::null_mut();
        }
        return 2;
    }
    1
}

/// The `ASN1_AUX` the three items share. Wrapped because [`Asn1Aux`] holds raw pointers and so
/// is not `Sync` on its own; the wrapper's `unsafe impl` below is the same claim
/// [`crate::asn1::layout`] makes for [`Asn1Item`] and [`Asn1Template`].
#[repr(transparent)]
struct SyncAux(Asn1Aux);

// SAFETY: this value is built from constants — a null `app_data`, integer offsets, a `None`
// const-callback and one function pointer — is written once by the loader and never again, and
// exposes no interior mutability through a shared reference. The machinery only ever reads
// `asn1_cb` out of it.
unsafe impl Sync for SyncAux {}

/// `static const ASN1_AUX DSAPrivateKey_aux = { NULL, 0, 0, 0, dsa_cb, 0, NULL }` — the same
/// initialiser `ASN1_SEQUENCE_cb(DSAparams, dsa_cb)` and `ASN1_SEQUENCE_cb(DSAPublicKey, dsa_cb)`
/// each spell again. One shared constant for the three, as the module note records.
static DSA_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(dsa_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `DSAPrivateKey_seq_tt` — `ASN1_SEQUENCE_cb(DSAPrivateKey, dsa_cb) = { ... }`.
static DSAPRIVATEKEY_SEQ_TT: [Asn1Template; 6] = [
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
        offset: OFFSET_P,
        field_name: c"params.p".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_Q,
        field_name: c"params.q".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_G,
        field_name: c"params.g".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_PUB,
        field_name: c"pub_key".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_PRIV,
        field_name: c"priv_key".as_ptr(),
        item: CBIGNUM_it as *mut c_void,
    },
];

/// The `DSAPrivateKey` item accessor — `ASN1_SEQUENCE_END_cb`'s `static_ASN1_ITEM_start`, private
/// in the authority and here.
fn dsaprivatekey_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: DSAPRIVATEKEY_SEQ_TT.as_ptr(),
        tcount: 6,
        funcs: ptr::addr_of!(DSA_AUX.0).cast(),
        size: DSA_SIZE,
        sname: DSA_SNAME,
    };
    &IT
}

/// `DSAparams_seq_tt` — `ASN1_SEQUENCE_cb(DSAparams, dsa_cb) = { ... }`.
static DSAPARAMS_SEQ_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_P,
        field_name: c"params.p".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_Q,
        field_name: c"params.q".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_G,
        field_name: c"params.g".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
];

/// The `DSAparams` item accessor — private, as above.
fn dsaparams_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: DSAPARAMS_SEQ_TT.as_ptr(),
        tcount: 3,
        funcs: ptr::addr_of!(DSA_AUX.0).cast(),
        size: DSA_SIZE,
        sname: DSA_SNAME,
    };
    &IT
}

/// `DSAPublicKey_seq_tt` — `ASN1_SEQUENCE_cb(DSAPublicKey, dsa_cb) = { ... }`.
static DSAPUBLICKEY_SEQ_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_PUB,
        field_name: c"pub_key".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_P,
        field_name: c"params.p".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_Q,
        field_name: c"params.q".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_G,
        field_name: c"params.g".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
];

/// The `DSAPublicKey` item accessor — private, as above.
fn dsapublickey_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: DSAPUBLICKEY_SEQ_TT.as_ptr(),
        tcount: 4,
        funcs: ptr::addr_of!(DSA_AUX.0).cast(),
        size: DSA_SIZE,
        sname: DSA_SNAME,
    };
    &IT
}

/// `DSA *d2i_DSAPrivateKey(DSA **a, const unsigned char **in, long len)` —
/// `crypto/dsa/dsa_asn1.c:50`, from `IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(DSA, DSAPrivateKey,
/// DSAPrivateKey)`.
///
/// # Safety
///
/// `a` is null or a writable slot; `in` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_DSAPrivateKey(
    a: *mut *mut Dsa,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Dsa {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, dsaprivatekey_it()).cast::<Dsa>() }
}

/// `int i2d_DSAPrivateKey(const DSA *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is null or a live key; `out` is null or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_DSAPrivateKey(a: *const Dsa, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, dsaprivatekey_it()) }
}

/// `DSA *d2i_DSAPublicKey(DSA **a, const unsigned char **in, long len)` — `:67`.
///
/// # Safety
///
/// As [`d2i_DSAPrivateKey`].
#[no_mangle]
pub unsafe extern "C" fn d2i_DSAPublicKey(
    a: *mut *mut Dsa,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Dsa {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, dsapublickey_it()).cast::<Dsa>() }
}

/// `int i2d_DSAPublicKey(const DSA *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// As [`i2d_DSAPrivateKey`].
#[no_mangle]
pub unsafe extern "C" fn i2d_DSAPublicKey(a: *const Dsa, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, dsapublickey_it()) }
}

/// `DSA *d2i_DSAparams(DSA **a, const unsigned char **in, long len)` — `:58`.
///
/// # Safety
///
/// As [`d2i_DSAPrivateKey`].
#[no_mangle]
pub unsafe extern "C" fn d2i_DSAparams(
    a: *mut *mut Dsa,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Dsa {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, dsaparams_it()).cast::<Dsa>() }
}

/// `int i2d_DSAparams(const DSA *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// As [`i2d_DSAPrivateKey`].
#[no_mangle]
pub unsafe extern "C" fn i2d_DSAparams(a: *const Dsa, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, dsaparams_it()) }
}

/// `DSA *DSAparams_dup(const DSA *dsa)` — `crypto/dsa/dsa_asn1.c:69-72`.
///
/// The authority's whole body is `ASN1_item_dup(ASN1_ITEM_rptr(DSAparams), dsa)`, and this is
/// that call. Because the duplicate is an encode-then-decode, the `DSAparams` template's `dsa_cb`
/// makes the answer a real key object rather than a byte copy.
///
/// # Safety
///
/// `dsa` is null or a live key.
#[no_mangle]
pub unsafe extern "C" fn DSAparams_dup(dsa: *const Dsa) -> *mut Dsa {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_dup(dsaparams_it(), dsa.cast::<c_void>()).cast::<Dsa>() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    use crate::bn::arith::BN_cmp;
    use crate::bn::bignum::BN_set_word;
    use crate::dsa::object::{DSA_get0_key, DSA_get0_pqg, DSA_set0_key, DSA_set0_pqg};
    use crate::runtime::mem::CRYPTO_free;

    /// A structurally valid `DSA`: `p = 23`, `q = 11`, `g = 2`, `y = 4`, `x = 2`. The templates do
    /// not validate the numbers, so this rounds trip every field without a generation.
    ///
    /// # Safety
    ///
    /// The answer is owned by the caller and released with [`DSA_free`].
    unsafe fn small_dsa() -> *mut Dsa {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let d = DSA_new();
            let p = crate::bn::bignum::BN_new();
            let q = crate::bn::bignum::BN_new();
            let g = crate::bn::bignum::BN_new();
            assert_eq!(BN_set_word(p, 23), 1);
            assert_eq!(BN_set_word(q, 11), 1);
            assert_eq!(BN_set_word(g, 2), 1);
            assert_eq!(DSA_set0_pqg(d, p, q, g), 1);
            let y = crate::bn::bignum::BN_new();
            let x = crate::bn::bignum::BN_new();
            assert_eq!(BN_set_word(y, 4), 1);
            assert_eq!(BN_set_word(x, 2), 1);
            assert_eq!(DSA_set0_key(d, y, x), 1);
            d
        }
    }

    /// Encode a key with the given `i2d` and read it back, asserting the parameter triple always
    /// survives and the key pair survives exactly as the template carries it — `DSAparams` has
    /// neither half, `DSAPublicKey` the public only, `DSAPrivateKey` both.
    ///
    /// # Safety
    ///
    /// `d` is a live key.
    unsafe fn round_trip(
        d: *mut Dsa,
        encode: unsafe extern "C" fn(*const Dsa, *mut *mut c_uchar) -> c_int,
        decode: unsafe extern "C" fn(*mut *mut Dsa, *mut *const c_uchar, c_long) -> *mut Dsa,
        has_pub: bool,
        has_priv: bool,
    ) -> c_long {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let n = encode(d, ptr::null_mut());
            assert!(n > 0);
            let mut der: *mut c_uchar = ptr::null_mut();
            assert_eq!(encode(d, &mut der), n);
            assert!(!der.is_null());

            let mut cp: *const c_uchar = der;
            let back = decode(ptr::null_mut(), &mut cp, c_long::from(n));
            assert!(!back.is_null());
            assert_eq!(
                cp,
                der.add(n as usize),
                "the decode consumes the whole encoding"
            );

            let mut op = ptr::null();
            let mut oq = ptr::null();
            let mut og = ptr::null();
            let mut bp = ptr::null();
            let mut bq = ptr::null();
            let mut bg = ptr::null();
            DSA_get0_pqg(d, &mut op, &mut oq, &mut og);
            DSA_get0_pqg(back, &mut bp, &mut bq, &mut bg);
            assert_eq!(BN_cmp(bp, op), 0);
            assert_eq!(BN_cmp(bq, oq), 0);
            assert_eq!(BN_cmp(bg, og), 0);

            let mut oy = ptr::null();
            let mut ox = ptr::null();
            let mut by = ptr::null();
            let mut bx = ptr::null();
            DSA_get0_key(d, &mut oy, &mut ox);
            DSA_get0_key(back, &mut by, &mut bx);
            if has_pub {
                assert!(!by.is_null() && BN_cmp(by, oy) == 0);
            } else {
                assert!(by.is_null());
            }
            if has_priv {
                assert!(!bx.is_null() && BN_cmp(bx, ox) == 0);
            } else {
                assert!(bx.is_null());
            }

            DSA_free(back);
            CRYPTO_free(der.cast(), ptr::null(), 0);
            c_long::from(n)
        }
    }

    /// The three templates are an inverse pair each, and `DSAparams_dup` is the decode of the
    /// `DSAparams` encoding.
    #[test]
    fn every_template_round_trips() {
        // SAFETY: `d` is this test's own live object and every callee is the crate's own.
        unsafe {
            let d = small_dsa();
            round_trip(d, i2d_DSAparams, d2i_DSAparams, false, false);
            round_trip(d, i2d_DSAPublicKey, d2i_DSAPublicKey, true, false);
            round_trip(d, i2d_DSAPrivateKey, d2i_DSAPrivateKey, true, true);

            let dup = DSAparams_dup(d);
            assert!(!dup.is_null());
            let (mut p, mut q, mut g) = (ptr::null(), ptr::null(), ptr::null());
            let (mut p2, mut q2, mut g2) = (ptr::null(), ptr::null(), ptr::null());
            DSA_get0_pqg(d, &mut p, &mut q, &mut g);
            DSA_get0_pqg(dup, &mut p2, &mut q2, &mut g2);
            assert_eq!(BN_cmp(p, p2), 0);
            assert_eq!(BN_cmp(q, q2), 0);
            assert_eq!(BN_cmp(g, g2), 0);
            // The duplicate carries the parameters template only, so it has no key.
            let (mut y, mut x) = (ptr::null(), ptr::null());
            DSA_get0_key(dup, &mut y, &mut x);
            assert!(y.is_null() && x.is_null());

            DSA_free(dup);
            DSA_free(d);
        }
    }

    /// A negative length refutes before anything is read, and an object with no parameters cannot
    /// be encoded.
    #[test]
    fn the_refusals_are_the_authoritys() {
        // SAFETY: `empty` is this test's own live object and every callee is the crate's own.
        unsafe {
            let empty = DSA_new();
            assert_eq!(i2d_DSAparams(empty, ptr::null_mut()), -1);
            let mut cp: *const c_uchar = ptr::null();
            assert!(d2i_DSAparams(ptr::null_mut(), &mut cp, -1).is_null());
            DSA_free(empty);
        }
    }
}
