//! `crypto/dh/dh_asn1.c` — the `DHparams`/`DHxparams` DER templates, Phase 8.5.
//!
//! The unit is one hundred and sixty-seven lines and it lands **whole** (D327's rule): one
//! `static` callback, four template items of which one is exported (`DHparams_it`) and three are
//! private, the two `DHparams` encode entry points, and the X9.42 pair whose body translates
//! between the two private structures `int_dhvparams`/`int_dhx942_dh` and a real [`Dh`] object.
//!
//! ## Why this unit lands here rather than with 8.8's method objects
//!
//! `docs/PHASE-8-SUBPHASES.md`'s 8.5 row and the session brief both group `dh_asn1.c` with
//! `dh_ameth.c`/`dh_prn.c` as "8.8's ASN.1 machinery". The authority is the other way, and three
//! of its own files say so: D341 measured this unit's lexical closure as needing **only Phase 5**
//! (the `ASN1_item_*` machinery, already landed); `docs/PHASE-8-AMETH-INTEGRATION-PLAN.md` §6
//! assigns the plain `DHparams` template to 8.5's module; and `src/ffc/params.rs`'s four
//! `#[allow(dead_code)]` comments each name `crypto/dh/dh_asn1.c` as their intended reader.
//! Nothing here reads an `X509_PUBKEY`/`X509_ALGOR`/`PKCS8_PRIV_KEY_INFO`; that is what the
//! *ameth* callbacks do. D345 records the correction.
//!
//! ## `DHparams`'s callback does three things, not two
//!
//! `dh_cb` (`dh_asn1.c:25-46`) handles `NEW_PRE` and `FREE_PRE` exactly as `dsa_cb` does, and then
//! adds `ASN1_OP_D2I_POST`: a freshly decoded object has its `DH_FLAG_TYPE_*` bits cleared, gets
//! `DH_FLAG_TYPE_DH` set, has its named group cached by [`ossl_dh_cache_named_group`], and its
//! `dirty_cnt` bumped. The X9.42 path does **not** go through `dh_cb` — it decodes the private
//! `int_dhx942_dh` structure and sets `DH_FLAG_TYPE_DHX` itself — which is why `d2i_DHxparams` is
//! a hand-written function rather than a third `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
//!
//! ## The two private structures, and the one authority value this crate must supply
//!
//! `int_dhvparams` is `{ ASN1_BIT_STRING *seed; BIGNUM *counter; }` and `int_dhx942_dh` is
//! `{ BIGNUM *p, *q, *g, *j; int_dhvparams *vparams; }` (`dh_asn1.c:61-72`). Their items are
//! built from the crate's own [`Asn1String`] and [`BigNum`] pointers, and `int_dhx942_dh`'s
//! `vparams` template names the `DHvparams` item through the item-expression indirection the
//! crate's `call_item_exp` resolves.
//!
//! **One value the authority reads uninitialised, recorded rather than copied.** `i2d_DHxparams`
//! declares a stack `ASN1_BIT_STRING seed` and assigns only `seed.data`, `seed.length` and
//! `seed.flags` (`:140`, `:149`, `:152`) — `seed.type` is never written, so the authority hands
//! the encoder an indeterminate `type`. The encoder does not read it (the BIT STRING tag comes
//! from the template's item, not the value), so the field is unobservable; this transcription
//! zero-initialises it and records the difference here rather than inventing a value the
//! authority does not set. This is the same class of finding D344 recorded for
//! `EVP_PKEY_CTX_get_ecdh_cofactor_mode`'s uninitialised `int mode`.
//!
//! ## The court: `RT-DH`
//!
//! `RT-DH`'s new arms encode a parameter set with `i2d_DHparams`, decode it again, and observe the
//! round trip by re-reading `p`/`g` and comparing them by value; `DHparams_it` and the X9.42 pair
//! are driven the same way with a seed and counter the probe chooses. **No arm prints a private
//! key or a shared secret** — the observations are return codes, decoded lengths and equalities
//! the probe computes itself.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_BIT_STRING_it;
use crate::asn1::layout::*;
use crate::asn1::string::ASN1_STRING_free;
use crate::asn1::x_bignum::BIGNUM_it;
use crate::asn1::x_int64::ZINT32_it;
use crate::bn::bignum::{BN_free, BN_get_word, BN_new, BN_set_word, BigNum};
use crate::dh::group_params::ossl_dh_cache_named_group;
use crate::dh::object::{DH_clear_flags, DH_free, DH_new, DH_set0_pqg, DH_set_flags};
use crate::dh::Dh;
use crate::ffc::params::{
    ossl_ffc_params_get0_pqg, ossl_ffc_params_get_validate_params, ossl_ffc_params_set0_j,
    ossl_ffc_params_set_validate_params,
};
use crate::ffc::FfcParams;
use crate::runtime::mem::CRYPTO_free;

/// `DH_FLAG_TYPE_MASK` — `include/openssl/dh.h:110`. The word `DH_FLAG_TYPE_DH`/`_DHX` live in,
/// and the mask `dh_cb` clears on every decoded object.
const DH_FLAG_TYPE_MASK: c_int = 0xF000;
/// `DH_FLAG_TYPE_DH` — `include/openssl/dh.h:111`. The zero word: a PKCS#3 parameter set.
const DH_FLAG_TYPE_DH: c_int = 0x0000;
/// `DH_FLAG_TYPE_DHX` — `include/openssl/dh.h:112`. X9.42, which `d2i_DHxparams` sets itself.
const DH_FLAG_TYPE_DHX: c_int = 0x1000;

/// `ASN1_STRING_FLAG_BITS_LEFT` — `include/openssl/asn1.h`. In the low three bits of an
/// `ASN1_STRING`'s `flags`, and the value `i2d_DHxparams` gives the seed it encodes.
const ASN1_STRING_FLAG_BITS_LEFT: c_long = 0x08;

/// The authority's `#tname` for the `DHparams` item — `ASN1_SEQUENCE_END_cb(DH, DHparams)` is the
/// **non-static** form, so it spells `#tname` ("DHparams") rather than `#stname`.
const DHPARAMS_SNAME: *const c_char = c"DHparams".as_ptr();
/// `static_ASN1_SEQUENCE_END_name(int_dhvparams, DHvparams)`'s `#stname`.
const DHVPARAMS_SNAME: *const c_char = c"int_dhvparams".as_ptr();
/// `static_ASN1_SEQUENCE_END_name(int_dhx942_dh, DHxparams)`'s `#stname`.
const DHXPARAMS_SNAME: *const c_char = c"int_dhx942_dh".as_ptr();

/// The translation unit the X9.42 pair's one allocation and two releases are attributed to, with
/// the admitted build record's `../../src/openssl-3.6.4/` prefix.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/dh/dh_asn1.c".as_ptr();

/// `sizeof(DH)` — the `DHparams` item's `size`, from `ASN1_SEQUENCE_END_cb(DH, DHparams)`.
const DH_SIZE: c_long = core::mem::size_of::<Dh>() as c_long;

/// The two offsets the `DHparams` template names, asserted rather than typed twice.
const OFFSET_P: c_ulong = (offset_of!(Dh, params) + offset_of!(FfcParams, p)) as c_ulong;
const OFFSET_G: c_ulong = (offset_of!(Dh, params) + offset_of!(FfcParams, g)) as c_ulong;
const OFFSET_LENGTH: c_ulong = offset_of!(Dh, length) as c_ulong;

/// `int_dhvparams` — `crypto/dh/dh_asn1.c:61-64`.
#[repr(C)]
struct IntDhvparams {
    /// `ASN1_BIT_STRING *seed`.
    seed: *mut Asn1String,
    /// `BIGNUM *counter`.
    counter: *mut BigNum,
}

/// `int_dhx942_dh` — `crypto/dh/dh_asn1.c:66-72`.
#[repr(C)]
struct IntDhx942Dh {
    /// `BIGNUM *p`.
    p: *mut BigNum,
    /// `BIGNUM *q`.
    q: *mut BigNum,
    /// `BIGNUM *g`.
    g: *mut BigNum,
    /// `BIGNUM *j`.
    j: *mut BigNum,
    /// `int_dhvparams *vparams`.
    vparams: *mut IntDhvparams,
}

const _: () = {
    assert!(DH_SIZE == 208);
    assert!(OFFSET_P == 8);
    assert!(OFFSET_G == 24);
    assert!(OFFSET_LENGTH == 104);
    assert!(core::mem::size_of::<IntDhvparams>() == 16);
    assert!(core::mem::size_of::<IntDhx942Dh>() == 40);
    assert!(offset_of!(IntDhvparams, seed) == 0);
    assert!(offset_of!(IntDhvparams, counter) == 8);
    assert!(offset_of!(IntDhx942Dh, p) == 0);
    assert!(offset_of!(IntDhx942Dh, q) == 8);
    assert!(offset_of!(IntDhx942Dh, g) == 16);
    assert!(offset_of!(IntDhx942Dh, j) == 24);
    assert!(offset_of!(IntDhx942Dh, vparams) == 32);
};

/// `int dh_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/dh/dh_asn1.c:25-46`.
///
/// # Safety
///
/// The item machinery's own contract: `pval` points at the value slot for this item.
unsafe extern "C" fn dh_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_NEW_PRE {
        // SAFETY: `pval` is the value slot per the caller's contract.
        let fresh = unsafe { DH_new() }.cast::<c_void>();
        // SAFETY: as above.
        unsafe { *pval = fresh };
        if !fresh.is_null() {
            return 2;
        }
        return 0;
    } else if operation == ASN1_OP_FREE_PRE {
        // SAFETY: `pval` is the value slot and holds a value this stratum built.
        unsafe {
            DH_free((*pval).cast::<Dh>());
            *pval = ptr::null_mut();
        }
        return 2;
    } else if operation == ASN1_OP_D2I_POST {
        // SAFETY: `pval` holds the object the decoder just built.
        unsafe {
            let dh = (*pval).cast::<Dh>();
            DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
            DH_set_flags(dh, DH_FLAG_TYPE_DH);
            ossl_dh_cache_named_group(dh);
            (*dh).dirty_cnt += 1;
        }
    }
    1
}

/// The `DHparams` item's `ASN1_AUX`. Wrapped for the same reason [`crate::dsa::asn1`] wraps its
/// own: [`Asn1Aux`] holds raw pointers and so is not `Sync` by itself.
#[repr(transparent)]
struct SyncAux(Asn1Aux);

// SAFETY: built from constants (a null `app_data`, integer offsets, a `None` const-callback and
// one function pointer), written once by the loader, and with no interior mutability reachable
// through a shared reference. The machinery reads only `asn1_cb` out of it.
unsafe impl Sync for SyncAux {}

/// `static const ASN1_AUX DHparams_aux = { NULL, 0, 0, 0, dh_cb, 0, NULL }` —
/// `ASN1_SEQUENCE_cb(DHparams, dh_cb)`.
static DHPARAMS_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(dh_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `DHparams_seq_tt` — `ASN1_SEQUENCE_cb(DHparams, dh_cb) = { ASN1_SIMPLE(DH, params.p, BIGNUM),`
/// `ASN1_SIMPLE(DH, params.g, BIGNUM), ASN1_OPT_EMBED(DH, length, ZINT32) }`.
static DHPARAMS_SEQ_TT: [Asn1Template; 3] = [
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
        offset: OFFSET_G,
        field_name: c"params.g".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 0,
        offset: OFFSET_LENGTH,
        field_name: c"length".as_ptr(),
        item: ZINT32_it as *mut c_void,
    },
];

/// `const ASN1_ITEM *DHparams_it(void)` — `include/openssl/dh.h:144`'s `DECLARE_ASN1_ITEM(DHparams)`,
/// defined by `ASN1_SEQUENCE_END_cb(DH, DHparams)` at `crypto/dh/dh_asn1.c:52`.
///
/// The one item in this unit with external linkage in the authority, and therefore an export.
#[no_mangle]
pub extern "C" fn DHparams_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: DHPARAMS_SEQ_TT.as_ptr(),
        tcount: 3,
        funcs: ptr::addr_of!(DHPARAMS_AUX.0).cast(),
        size: DH_SIZE,
        sname: DHPARAMS_SNAME,
    };
    &IT
}

/// `DHvparams_seq_tt` — `ASN1_SEQUENCE(DHvparams) = { ASN1_SIMPLE(int_dhvparams, seed,`
/// `ASN1_BIT_STRING), ASN1_SIMPLE(int_dhvparams, counter, BIGNUM) }`.
static DHVPARAMS_SEQ_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: offset_of!(IntDhvparams, seed) as c_ulong,
        field_name: c"seed".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: offset_of!(IntDhvparams, counter) as c_ulong,
        field_name: c"counter".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
];

/// The `DHvparams` item accessor — `static_ASN1_SEQUENCE_END_name(int_dhvparams, DHvparams)`'s
/// static, private here.
fn dhvparams_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: DHVPARAMS_SEQ_TT.as_ptr(),
        tcount: 2,
        funcs: ptr::null(),
        size: core::mem::size_of::<IntDhvparams>() as c_long,
        sname: DHVPARAMS_SNAME,
    };
    &IT
}

/// `DHxparams_seq_tt` — `ASN1_SEQUENCE(DHxparams) = { ASN1_SIMPLE(int_dhx942_dh, p, BIGNUM),`
/// `ASN1_SIMPLE(int_dhx942_dh, g, BIGNUM), ASN1_SIMPLE(int_dhx942_dh, q, BIGNUM),`
/// `ASN1_OPT(int_dhx942_dh, j, BIGNUM), ASN1_OPT(int_dhx942_dh, vparams, DHvparams) }`.
///
/// Note the encoding order — `p, g, q` — is the authority's and is **not** the structure's field
/// order (`p, q, g`); the template list is what decides the wire, and this is its order.
static DHXPARAMS_SEQ_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: offset_of!(IntDhx942Dh, p) as c_ulong,
        field_name: c"p".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: offset_of!(IntDhx942Dh, g) as c_ulong,
        field_name: c"g".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: offset_of!(IntDhx942Dh, q) as c_ulong,
        field_name: c"q".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: offset_of!(IntDhx942Dh, j) as c_ulong,
        field_name: c"j".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: offset_of!(IntDhx942Dh, vparams) as c_ulong,
        field_name: c"vparams".as_ptr(),
        item: dhvparams_it as *mut c_void,
    },
];

/// The `DHxparams` item accessor — private, as above.
fn dhxparams_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: DHXPARAMS_SEQ_TT.as_ptr(),
        tcount: 5,
        funcs: ptr::null(),
        size: core::mem::size_of::<IntDhx942Dh>() as c_long,
        sname: DHXPARAMS_SNAME,
    };
    &IT
}

/// `DH *d2i_DHparams(DH **a, const unsigned char **in, long len)` — `crypto/dh/dh_asn1.c:54`,
/// from `IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(DH, DHparams, DHparams)`.
///
/// # Safety
///
/// `a` is null or a writable slot; `in` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_DHparams(
    a: *mut *mut Dh,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Dh {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, DHparams_it()).cast::<Dh>() }
}

/// `int i2d_DHparams(const DH *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is null or a live key; `out` is null or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_DHparams(a: *const Dh, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, DHparams_it()) }
}

/// `int_dhx942_dh *d2i_int_dhx(int_dhx942_dh **a, const unsigned char **pp, long length)` —
/// `crypto/dh/dh_asn1.c:88`, from `IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(int_dhx942_dh, DHxparams,
/// int_dhx)`.
///
/// Internal in the authority and private here: only [`d2i_DHxparams`] calls it.
///
/// # Safety
///
/// As [`d2i_DHparams`], over the private structure.
unsafe fn d2i_int_dhx(
    a: *mut *mut IntDhx942Dh,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut IntDhx942Dh {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), pp, length, dhxparams_it()).cast::<IntDhx942Dh>() }
}

/// `int i2d_int_dhx(const int_dhx942_dh *a, unsigned char **pp)` — `:89`, the same macro's encoder.
///
/// # Safety
///
/// `a` is null or a live private structure; `pp` is null or a writable cursor.
unsafe fn i2d_int_dhx(a: *const IntDhx942Dh, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), pp, dhxparams_it()) }
}

/// `DH *d2i_DHxparams(DH **a, const unsigned char **pp, long length)` —
/// `crypto/dh/dh_asn1.c:93-133`.
///
/// Decodes the private X9.42 structure and **translates it immediately** into a real [`Dh`]: the
/// three parameters go to `DH_set0_pqg`, `j` to `ossl_ffc_params_set0_j`, and, when the optional
/// validation block is present, the seed and counter to `ossl_ffc_params_set_validate_params`
/// before the private structure is released. `a`, when non-NULL, has its old value freed and
/// takes the new object — the same in-place convention the encoder macro uses.
///
/// # Safety
///
/// `a` is null or a writable slot; `pp` points at a readable cursor; `length` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_DHxparams(
    a: *mut *mut Dh,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut Dh {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let dh = DH_new();
        if dh.is_null() {
            return ptr::null_mut();
        }

        let dhx = d2i_int_dhx(ptr::null_mut(), pp, length);
        if dhx.is_null() {
            DH_free(dh);
            return ptr::null_mut();
        }

        if !a.is_null() {
            DH_free(*a);
            *a = dh;
        }

        let params = &mut (*dh).params;
        DH_set0_pqg(dh, (*dhx).p, (*dhx).q, (*dhx).g);
        ossl_ffc_params_set0_j(params, (*dhx).j);

        if !(*dhx).vparams.is_null() {
            // The counter has a maximum value of `4 * numbits(p) - 1`.
            let counter = BN_get_word((*(*dhx).vparams).counter) as c_int;
            ossl_ffc_params_set_validate_params(
                params,
                (*(*(*dhx).vparams).seed).data,
                (*(*(*dhx).vparams).seed).length as usize,
                counter,
            );
            ASN1_STRING_free((*(*dhx).vparams).seed);
            BN_free((*(*dhx).vparams).counter);
            CRYPTO_free((*dhx).vparams.cast(), FILE, 125);
            (*dhx).vparams = ptr::null_mut();
        }

        CRYPTO_free(dhx.cast(), FILE, 129);
        DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
        DH_set_flags(dh, DH_FLAG_TYPE_DHX);
        dh
    }
}

/// `int i2d_DHxparams(const DH *dh, unsigned char **pp)` — `crypto/dh/dh_asn1.c:135-167`.
///
/// Builds the private structure from the object's parameters and encodes it. The validation block
/// is emitted only when the counter is set and the seed is non-empty; the `err:` label releases
/// the counter `BN_new` may have allocated even when `BN_set_word` failed.
///
/// # Safety
///
/// `dh` is a live key; `pp` is null or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_DHxparams(dh: *const Dh, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret = 0;
        let mut dhx: IntDhx942Dh = core::mem::zeroed();
        let mut dhv = IntDhvparams {
            seed: ptr::null_mut(),
            counter: ptr::null_mut(),
        };
        // The authority's stack `ASN1_BIT_STRING seed`, whose `type` it never writes; see the
        // module note. The encoder reads only `data`, `length` and `flags`.
        let mut seed = Asn1String {
            length: 0,
            type_: 0,
            data: ptr::null_mut(),
            flags: 0,
        };
        let mut seedlen = 0usize;
        let params = &(*dh).params;
        let mut counter: c_int = 0;

        ossl_ffc_params_get0_pqg(params, &mut dhx.p, &mut dhx.q, &mut dhx.g);
        dhx.j = params.j;
        ossl_ffc_params_get_validate_params(params, &mut seed.data, &mut seedlen, &mut counter);
        seed.length = seedlen as c_int;

        if counter != -1 && !seed.data.is_null() && seed.length > 0 {
            seed.flags = ASN1_STRING_FLAG_BITS_LEFT;
            dhv.seed = &mut seed;
            dhv.counter = BN_new();
            if dhv.counter.is_null() {
                return 0;
            }
            if BN_set_word(dhv.counter, counter as c_ulong) == 0 {
                // goto err
                BN_free(dhv.counter);
                return ret;
            }
            dhx.vparams = &mut dhv;
        } else {
            dhx.vparams = ptr::null_mut();
        }

        ret = i2d_int_dhx(&dhx, pp);

        // err:
        BN_free(dhv.counter);
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    use crate::bn::arith::BN_cmp;
    use crate::dh::group_params::DH_new_by_nid;
    use crate::dh::object::DH_get0_pqg;
    use crate::runtime::obj::NID_ffdhe2048;

    /// A named group costs no generation: `DH_new_by_nid` installs `p`, `q` and `g` from the
    /// landed `dh_named_groups[]` table, which is what every arm below round-trips.
    ///
    /// # Safety
    ///
    /// The answer is owned by the caller and released with [`DH_free`].
    unsafe fn ffdhe2048() -> *mut Dh {
        // SAFETY: the constructor is the crate's own.
        let d = unsafe { DH_new_by_nid(NID_ffdhe2048) };
        assert!(!d.is_null());
        d
    }

    /// `DHparams_it` is an item accessor: two calls answer the same address, as the authority's
    /// function-local `static` does.
    #[test]
    fn the_item_accessor_is_stable() {
        assert!(!DHparams_it().is_null());
        assert_eq!(DHparams_it(), DHparams_it());
    }

    /// The `DHparams` template carries `p` and `g` and no `q`; the `DHxparams` template carries
    /// all three. Both are inverse pairs.
    #[test]
    fn both_templates_round_trip() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let d = ffdhe2048();

            // DHparams: p and g.
            let n = i2d_DHparams(d, ptr::null_mut());
            assert!(n > 0);
            let mut der: *mut c_uchar = ptr::null_mut();
            assert_eq!(i2d_DHparams(d, &mut der), n);
            let mut cp: *const c_uchar = der;
            let back = d2i_DHparams(ptr::null_mut(), &mut cp, c_long::from(n));
            assert!(!back.is_null());
            let (mut sp, mut sq, mut sg) = (ptr::null(), ptr::null(), ptr::null());
            let (mut bp, mut bq, mut bg) = (ptr::null(), ptr::null(), ptr::null());
            DH_get0_pqg(d, &mut sp, &mut sq, &mut sg);
            DH_get0_pqg(back, &mut bp, &mut bq, &mut bg);
            assert_eq!(BN_cmp(bp, sp), 0);
            assert_eq!(BN_cmp(bg, sg), 0);
            // **The template carries no `q`, but the decoded object has one.** `dh_cb`'s
            // `ASN1_OP_D2I_POST` runs `ossl_dh_cache_named_group`, which finds the FFDHE-2048 row
            // by `p` and fills the object's `q` from it — so the `DHparams` decode is not the
            // template's three fields alone, and `q` compares with the source's.
            assert!(!bq.is_null());
            assert_eq!(BN_cmp(bq, sq), 0);
            DH_free(back);
            CRYPTO_free(der.cast(), ptr::null(), 0);

            // DHxparams: p, q and g.
            let mut der: *mut c_uchar = ptr::null_mut();
            let n = i2d_DHxparams(d, &mut der);
            assert!(n > 0);
            let mut cp: *const c_uchar = der;
            let back = d2i_DHxparams(ptr::null_mut(), &mut cp, c_long::from(n));
            assert!(!back.is_null());
            let (mut bp, mut bq, mut bg) = (ptr::null(), ptr::null(), ptr::null());
            DH_get0_pqg(back, &mut bp, &mut bq, &mut bg);
            assert_eq!(BN_cmp(bp, sp), 0);
            assert_eq!(BN_cmp(bq, sq), 0);
            assert_eq!(BN_cmp(bg, sg), 0);
            DH_free(back);
            CRYPTO_free(der.cast(), ptr::null(), 0);

            DH_free(d);
        }
    }

    /// A negative length refuses before anything is read.
    #[test]
    fn a_negative_length_refuses() {
        // SAFETY: the buffer is this test's own and the callee is the crate's own.
        unsafe {
            let buf = [0x30u8];
            let mut cp: *const c_uchar = buf.as_ptr();
            assert!(d2i_DHparams(ptr::null_mut(), &mut cp, -1).is_null());
        }
    }
}
