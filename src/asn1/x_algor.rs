//! `crypto/asn1/x_algor.c` — the `AlgorithmIdentifier` family, transcribed whole.
//!
//! This is the authority's own `X509_ALGOR` translation unit: the `ASN1_SEQUENCE(X509_ALGOR)`
//! template and the `X509_ALGORS` `SEQUENCE OF` template, the six `DECLARE_ASN1_*`-generated
//! export groups over them, and the nine hand-written functions the file adds. It is **Phase
//! 8.8's root**: every callee it reaches was already in the crate, so it is the one unit of the
//! 8.8 closure that could be transcribed whole without waiting on another stratum, and it is what
//! the `RSA_PSS_PARAMS`/`RSA_OAEP_PARAMS` templates of `crypto/rsa/rsa_asn1.c` need (D348).
//!
//! ## The `X509_ALGOR` type, and the two declarations this replaces
//!
//! The authority declares `struct X509_algor_st` in `include/openssl/x509.h` as two fields,
//! `ASN1_OBJECT *algorithm` then `ASN1_TYPE *parameter`. The crate had two declarations of the
//! name before this unit: a real two-field `X509Algor` in `src/evp/cipher_ctx.rs` and an opaque
//! `_private: [u8; 0]` placeholder in `src/evp/pkey_asn1.rs`. The authority's layout matches the
//! former, so that is the one definition kept — moved here, into the module whose authority file
//! defines its item — and both old sites now `pub use` it. No third struct exists.
//!
//! ## What the item layer generates, and where each name lands
//!
//! `ASN1_SEQUENCE(X509_ALGOR)` with `ASN1_SEQUENCE_END(X509_ALGOR)` gives the `X509_ALGOR_it`
//! accessor; `IMPLEMENT_ASN1_FUNCTIONS(X509_ALGOR)` adds `_new`, `_free`, `d2i_` and `i2d_`;
//! `IMPLEMENT_ASN1_DUP_FUNCTION(X509_ALGOR)` adds `_dup`. `ASN1_ITEM_TEMPLATE(X509_ALGORS)` with
//! `ASN1_ITEM_TEMPLATE_END(X509_ALGORS)` gives the `X509_ALGORS_it` accessor, and
//! `IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(X509_ALGORS, X509_ALGORS, X509_ALGORS)` adds the
//! `d2i_`/`i2d_` pair. The `X509_ALGORS` value is a `STACK_OF(X509_ALGOR)`, so its two codecs
//! speak in [`OpenSslStack`] terms.
//!
//! ## The one raise, and the one macro that is not called by name
//!
//! `ossl_x509_algor_get_md` raises `ASN1_R_UNKNOWN_DIGEST` at `x_algor.c:165` when a fetched
//! digest is absent; the coordinate is generated into [`crate::runtime::err_sites`] because this
//! file now joins that generator's covered set. The line calls `EVP_get_digestbyobj`, which is a
//! **macro** in `include/openssl/evp.h` (`#define EVP_get_digestbyobj(a)
//! EVP_get_digestbynid(OBJ_obj2nid(a))`, itself `EVP_get_digestbyname(OBJ_nid2sn(...))`), so the
//! transcription writes the expansion and reaches only landed names. That is what keeps this
//! unit's own missing-callee set empty.
//!
//! **That lookup is a recorded deferral, not this unit's defect.** `EVP_get_digestbyname`
//! answers NULL for every built-in digest name on the candidate because the legacy `OBJ_NAME`
//! database is empty — `src/runtime/init.rs`'s `add_all_legacy_methods` is a no-op and
//! `src/context/namemap.rs` records the legacy pre-population as **Phase 13's** (D343, D344). So
//! the non-NULL-OID path of [`ossl_x509_algor_get_md`] is incomparable and is observed by neither
//! the court nor a unit test; the SHA1 default (a direct static) and the identifier's OID are what
//! are checked, and D348 records the coordinate. None of the five internals is an export, so
//! `court_coverage.py` does not require them to be courted.
//!
//! ## The court
//!
//! `RT-ASN1-TEMPLATE` carries the arms: it is the phase-5 probe that already drives
//! `ASN1_item_*` through a caller-built descriptor, and `X509_ALGOR` is the first *installed*
//! item it drives. The arms are round trips, item-name/size checks, `set0`/`get0`/`cmp`/`copy`
//! return codes and the one drained raise — no address and no random value is printed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::a_type::{
    ASN1_TYPE_cmp, ASN1_TYPE_free, ASN1_TYPE_new, ASN1_TYPE_set, ASN1_TYPE_set1,
    ASN1_TYPE_unpack_sequence,
};
use crate::asn1::asn_pack::ASN1_item_pack;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_ANY_it, ASN1_OBJECT_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::ASN1_STRING_free;
use crate::evp::digest::{EVP_MD_get_type, EVP_MD_is_a, EvpMd};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::legacy_sha::EVP_sha1;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{
    Asn1Object, NID_mgf1, OBJ_cmp, OBJ_dup, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::stack::OpenSslStack;

/// `EVP_MD_FLAG_DIGALGID_ABSENT` — `include/openssl/evp.h`. The digest-algorithm identifier's
/// parameter is omitted for a digest carrying this bit and is an explicit `NULL` otherwise, which
/// is the whole of what [`X509_ALGOR_set_md`] decides.
const EVP_MD_FLAG_DIGALGID_ABSENT: c_ulong = 0x0008;

/// `struct X509_algor_st` — `X509_ALGOR`, from `include/openssl/x509.h`.
///
/// The authority's two fields in order. This is the **one** definition of the name in the crate;
/// `src/evp/cipher_ctx.rs` and `src/evp/pkey_asn1.rs` re-export it rather than declaring their
/// own (D348). The item layer reads the offsets below, so a swap would be a decode into the wrong
/// member and is asserted rather than typed twice.
#[repr(C)]
pub struct X509Algor {
    /// `ASN1_OBJECT *algorithm` — the algorithm OID, read by `get0`/`cmp`/`mgf1_decode`.
    pub algorithm: *mut Asn1Object,
    /// `ASN1_TYPE *parameter` — the algorithm parameters, `ASN1_ANY` and optional.
    pub parameter: *mut Asn1Type,
}

const _: () = {
    assert!(core::mem::size_of::<X509Algor>() == 16);
    assert!(core::mem::offset_of!(X509Algor, algorithm) == 0);
    assert!(core::mem::offset_of!(X509Algor, parameter) == 8);
};

/// `X509_ALGOR_seq_tt` — `crypto/asn1/x_algor.c:18-21`'s `ASN1_SEQUENCE(X509_ALGOR)`:
/// `ASN1_SIMPLE(X509_ALGOR, algorithm, ASN1_OBJECT)` and `ASN1_OPT(X509_ALGOR, parameter,
/// ASN1_ANY)`.
static X509_ALGOR_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"algorithm".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"parameter".as_ptr(),
        item: ASN1_ANY_it as *mut c_void,
    },
];

/// `X509_ALGOR_it`'s descriptor — `ASN1_SEQUENCE_END(X509_ALGOR)` at `crypto/asn1/x_algor.c:21`.
static X509_ALGOR_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_ALGOR_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Algor>() as c_long,
    sname: c"X509_ALGOR".as_ptr(),
};

/// `const ASN1_ITEM *X509_ALGOR_it(void)` — `include/openssl/x509.h:517`, from
/// `ASN1_SEQUENCE_END(X509_ALGOR)`.
#[no_mangle]
pub extern "C" fn X509_ALGOR_it() -> *const Asn1Item {
    &X509_ALGOR_ITEM
}

/// `X509_ALGORS_item_tt` — `crypto/asn1/x_algor.c:23`'s
/// `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, algorithms, X509_ALGOR)`.
///
/// Written out rather than built from [`crate::asn1::items`]'s `template_item!`, which uses one
/// token for both the field name and the item name; here they differ (`algorithms` versus
/// `X509_ALGORS`), and the field name is what a `SEQUENCE OF` template carries.
static X509_ALGORS_ITEM_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"algorithms".as_ptr(),
    item: X509_ALGOR_it as *mut c_void,
};

/// `X509_ALGORS_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(X509_ALGORS)` at
/// `crypto/asn1/x_algor.c:24`: a `PRIMITIVE` item whose single template is a `SEQUENCE OF`, with
/// `utype` `-1` and `tcount` 0.
static X509_ALGORS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &X509_ALGORS_ITEM_TT,
    tcount: 0,
    funcs: ptr::null_mut(),
    size: 0,
    sname: c"X509_ALGORS".as_ptr(),
};

/// `const ASN1_ITEM *X509_ALGORS_it(void)` — `include/openssl/x509.h:517`, from
/// `ASN1_ITEM_TEMPLATE_END(X509_ALGORS)`.
#[no_mangle]
pub extern "C" fn X509_ALGORS_it() -> *const Asn1Item {
    &X509_ALGORS_ITEM
}

/// `X509_ALGOR *X509_ALGOR_new(void)` — `crypto/asn1/x_algor.c:26`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_ALGOR)`.
#[no_mangle]
pub extern "C" fn X509_ALGOR_new() -> *mut X509Algor {
    // SAFETY: `X509_ALGOR_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_ALGOR_it()).cast::<X509Algor>() }
}

/// `void X509_ALGOR_free(X509_ALGOR *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_ALGOR_free(a: *mut X509Algor) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), X509_ALGOR_it()) }
}

/// `X509_ALGOR *X509_ALGOR_dup(const X509_ALGOR *a)` — `crypto/asn1/x_algor.c:28`, from
/// `IMPLEMENT_ASN1_DUP_FUNCTION(X509_ALGOR)`: the encode-then-decode of its own template, so a
/// fresh object with fresh nested values.
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_ALGOR_dup(a: *const X509Algor) -> *mut X509Algor {
    // SAFETY: `a` is NULL or live per the contract; `X509_ALGOR_it()` is a static item.
    unsafe { ASN1_item_dup(X509_ALGOR_it(), a.cast::<c_void>()).cast::<X509Algor>() }
}

/// `X509_ALGOR *d2i_X509_ALGOR(X509_ALGOR **a, const unsigned char **in, long len)` —
/// `crypto/asn1/x_algor.c:26`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_ALGOR(
    a: *mut *mut X509Algor,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Algor {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_ALGOR_it()).cast::<X509Algor>() }
}

/// `int i2d_X509_ALGOR(const X509_ALGOR *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_ALGOR(a: *const X509Algor, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_ALGOR_it()) }
}

/// `X509_ALGORS *d2i_X509_ALGORS(X509_ALGORS **a, const unsigned char **in, long len)` —
/// `crypto/asn1/x_algor.c:27`'s generated decoder. `X509_ALGORS` is `STACK_OF(X509_ALGOR)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot holding NULL or a live stack; `in_` points at a readable cursor;
/// `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_ALGORS(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_ALGORS_it()).cast::<OpenSslStack>() }
}

/// `int i2d_X509_ALGORS(const X509_ALGORS *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live stack of `X509_ALGOR`; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_ALGORS(a: *const OpenSslStack, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_ALGORS_it()) }
}

/// `int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype, void *pval)` —
/// `crypto/asn1/x_algor.c:30-50`.
///
/// Takes ownership of `aobj` and, when `ptype` is neither `V_ASN1_UNDEF` nor `V_ASN1_EOC`, of
/// `pval` through the fresh parameter. The parameter is allocated only when `ptype` is a real
/// type *and* the field is currently NULL, so a repeated `set0` reuses the parameter and simply
/// overwrites its value.
///
/// # Safety
///
/// `alg` is NULL or a live object. A non-NULL `pval` must be a value `ASN1_TYPE_set` may adopt for
/// `ptype`.
#[no_mangle]
pub unsafe extern "C" fn X509_ALGOR_set0(
    alg: *mut X509Algor,
    aobj: *mut Asn1Object,
    ptype: c_int,
    pval: *mut c_void,
) -> c_int {
    if alg.is_null() {
        return 0;
    }

    // SAFETY: `alg` is live per the check above.
    if ptype != V_ASN1_UNDEF && unsafe { (*alg).parameter }.is_null() {
        // SAFETY: `ASN1_TYPE_new` answers a fresh value or NULL.
        let fresh = ASN1_TYPE_new();
        if fresh.is_null() {
            return 0;
        }
        // SAFETY: `alg` is live and the field is writable.
        unsafe { (*alg).parameter = fresh };
    }

    // SAFETY: `alg` is live; the old OID is this object's own and `aobj` is the caller's to give.
    unsafe {
        ASN1_OBJECT_free((*alg).algorithm);
        (*alg).algorithm = aobj;
    }

    if ptype == V_ASN1_EOC {
        return 1;
    }
    if ptype == V_ASN1_UNDEF {
        // SAFETY: `alg` is live; the parameter is this object's own.
        unsafe {
            ASN1_TYPE_free((*alg).parameter);
            (*alg).parameter = ptr::null_mut();
        }
    } else {
        // SAFETY: `alg` is live and its parameter is non-NULL on this arm.
        unsafe { ASN1_TYPE_set((*alg).parameter, ptype, pval) };
    }
    1
}

/// `X509_ALGOR *ossl_X509_ALGOR_from_nid(int nid, int ptype, void *pval)` —
/// `crypto/asn1/x_algor.c:52-69`. Internal (`include/crypto/asn1.h`), so `pub(crate)`.
///
/// The `OBJ_nid2obj` object is **not** freed on the failure path: it is the shared static entry the
/// object database hands out, which is what the authority's own comment records.
///
/// A reader outside this file exists already: [`ossl_x509_algor_md_to_mgf1`] builds the MGF1
/// identifier with it, and `crypto/rsa/rsa_pss.c` reaches the same shape through this crate's
/// `rsa` stratum.
///
/// # Safety
///
/// `pval` is NULL or a value `X509_ALGOR_set0` may adopt for `ptype`.
#[allow(dead_code)]
// read by the RSA PSS/OAEP units (`rsa_ameth.c`, `rsa_backend.c`) and `p5_pbev2.c`, none of which is transcribed yet (D348)
#[allow(non_snake_case)] // the authority's own symbol name
pub(crate) unsafe fn ossl_X509_ALGOR_from_nid(
    nid: c_int,
    ptype: c_int,
    pval: *mut c_void,
) -> *mut X509Algor {
    // SAFETY: `OBJ_nid2obj` answers a shared static object or NULL.
    let algo = OBJ_nid2obj(nid);
    if algo.is_null() {
        return ptr::null_mut();
    }
    let alg = X509_ALGOR_new();
    if alg.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `alg` is live and `algo` is the caller's to give.
    if unsafe { X509_ALGOR_set0(alg, algo, ptype, pval) } != 0 {
        return alg;
    }
    // SAFETY: `set0` failed after taking neither; prevent the free from releasing `algo`.
    unsafe { (*alg).algorithm = ptr::null_mut() };
    // SAFETY: `alg` is this call's own object.
    unsafe { X509_ALGOR_free(alg) };
    ptr::null_mut()
}

/// `void X509_ALGOR_get0(const ASN1_OBJECT **paobj, int *pptype, const void **ppval, const
/// X509_ALGOR *algor)` — `crypto/asn1/x_algor.c:71-85`.
///
/// The authority's early `return` inside the `pptype` arm is load-bearing: when the parameter is
/// absent, `pptype` is set to `V_ASN1_UNDEF` and `ppval` is **not** written, so a caller's slot is
/// left as it was. Transcribed as the same early return rather than merged into one `if`.
///
/// # Safety
///
/// `algor` is a live object; each output pointer is NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn X509_ALGOR_get0(
    paobj: *mut *const Asn1Object,
    pptype: *mut c_int,
    ppval: *mut *const c_void,
    algor: *const X509Algor,
) {
    if !paobj.is_null() {
        // SAFETY: `algor` is live and `paobj` is the caller's writable slot.
        unsafe { *paobj = (*algor).algorithm as *const Asn1Object };
    }
    if !pptype.is_null() {
        // SAFETY: `algor` is live.
        if unsafe { (*algor).parameter }.is_null() {
            // SAFETY: `pptype` is non-NULL per the check.
            unsafe { *pptype = V_ASN1_UNDEF };
            return;
        }
        // SAFETY: `algor` and its parameter are live.
        unsafe { *pptype = (*(*algor).parameter).type_ };
        if !ppval.is_null() {
            // SAFETY: `algor` and its parameter are live; `ppval` is the caller's slot.
            unsafe { *ppval = (*(*algor).parameter).value.ptr };
        }
    }
}

/// `void X509_ALGOR_set_md(X509_ALGOR *alg, const EVP_MD *md)` — `crypto/asn1/x_algor.c:88-94`.
///
/// A digest with `EVP_MD_FLAG_DIGALGID_ABSENT` gets an absent parameter (`V_ASN1_UNDEF`) and every
/// other digest an explicit `NULL`; the returned status of the inner `set0` is discarded, which is
/// why the authority's cast is `(void)`.
///
/// # Safety
///
/// `alg` is a live object; `md` is a live digest.
#[no_mangle]
pub unsafe extern "C" fn X509_ALGOR_set_md(alg: *mut X509Algor, md: *const EvpMd) {
    // SAFETY: `md` is live per the contract.
    let type_ = if unsafe { (*md).flags } & EVP_MD_FLAG_DIGALGID_ABSENT != 0 {
        V_ASN1_UNDEF
    } else {
        V_ASN1_NULL
    };
    // SAFETY: `OBJ_nid2obj` answers a shared static; `set0` adopts it and `alg` is live.
    unsafe {
        X509_ALGOR_set0(
            alg,
            OBJ_nid2obj(EVP_MD_get_type(md)),
            type_,
            ptr::null_mut(),
        );
    }
}

/// `int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b)` — `crypto/asn1/x_algor.c:96-105`.
///
/// Two absent parameters are equal without calling `ASN1_TYPE_cmp`, which the authority guards
/// because its comparison dereferences both sides.
///
/// # Safety
///
/// `a` and `b` are live objects.
#[no_mangle]
pub unsafe extern "C" fn X509_ALGOR_cmp(a: *const X509Algor, b: *const X509Algor) -> c_int {
    // SAFETY: `a` and `b` are live per the contract.
    let rv = unsafe { OBJ_cmp((*a).algorithm, (*b).algorithm) };
    if rv != 0 {
        return rv;
    }
    // SAFETY: `a` and `b` are live.
    if unsafe { (*a).parameter }.is_null() && unsafe { (*b).parameter }.is_null() {
        return 0;
    }
    // SAFETY: `a` and `b` are live; at least one parameter is non-NULL, which is what
    // `ASN1_TYPE_cmp` requires.
    unsafe { ASN1_TYPE_cmp((*a).parameter, (*b).parameter) }
}

/// `int X509_ALGOR_copy(X509_ALGOR *dest, const X509_ALGOR *src)` —
/// `crypto/asn1/x_algor.c:107-139`.
///
/// A deep copy, and the free-then-duplicate order is the authority's: `dest`'s old OID and
/// parameter are released first, then `algorithm` is `OBJ_dup`'d and `parameter` is a fresh
/// `ASN1_TYPE` filled with `ASN1_TYPE_set1`. Every failure leaves `dest` partly rebuilt rather
/// than restored, which is what the authority does and why this is a copy *into* a caller's object
/// rather than a constructor.
///
/// # Safety
///
/// `dest` is a live writable object; `src` is a live object. They must not be the same object.
#[no_mangle]
pub unsafe extern "C" fn X509_ALGOR_copy(dest: *mut X509Algor, src: *const X509Algor) -> c_int {
    if src.is_null() || dest.is_null() {
        return 0;
    }

    // SAFETY: `dest` is live.
    if !unsafe { (*dest).algorithm }.is_null() {
        // SAFETY: `dest`'s OID is its own.
        unsafe { ASN1_OBJECT_free((*dest).algorithm) };
    }
    // SAFETY: `dest` is live.
    unsafe { (*dest).algorithm = ptr::null_mut() };

    // SAFETY: `dest` is live.
    if !unsafe { (*dest).parameter }.is_null() {
        // SAFETY: `dest`'s parameter is its own.
        unsafe { ASN1_TYPE_free((*dest).parameter) };
    }
    // SAFETY: `dest` is live.
    unsafe { (*dest).parameter = ptr::null_mut() };

    // SAFETY: `src` is live.
    if !unsafe { (*src).algorithm }.is_null() {
        // SAFETY: `OBJ_dup` answers a fresh object or NULL; `dest` is writable.
        let dup = unsafe { OBJ_dup((*src).algorithm) };
        if dup.is_null() {
            return 0;
        }
        // SAFETY: `dest` is writable.
        unsafe { (*dest).algorithm = dup };
    }

    // SAFETY: `src` is live.
    if !unsafe { (*src).parameter }.is_null() {
        // SAFETY: `ASN1_TYPE_new` answers a fresh value or NULL.
        let fresh = ASN1_TYPE_new();
        if fresh.is_null() {
            return 0;
        }
        // SAFETY: `dest` is writable.
        unsafe { (*dest).parameter = fresh };

        // `ASN1_TYPE_set1` copies the value, which is what the authority's comment means by "set
        // does copy as a side effect".
        // SAFETY: `dest`'s parameter is fresh and `src`'s is live.
        if unsafe {
            ASN1_TYPE_set1(
                (*dest).parameter,
                (*(*src).parameter).type_,
                (*(*src).parameter).value.ptr,
            )
        } == 0
        {
            return 0;
        }
    }

    1
}

/// `int ossl_x509_algor_new_from_md(X509_ALGOR **palg, const EVP_MD *md)` —
/// `crypto/asn1/x_algor.c:142-154`. Internal.
///
/// The default digest is SHA1 and needs no object: a NULL `md` or one named `SHA1` answers success
/// leaving `*palg` untouched. Otherwise a fresh identifier is built and stored.
///
/// # Safety
///
/// `palg` is a writable slot. `md` is NULL or a live digest.
#[allow(dead_code)]
// read by `crypto/rsa/rsa_ameth.c:508,514` and `crypto/cms/cms_rsa.c:155`, neither transcribed yet (D348)
#[allow(non_snake_case)] // the authority's own symbol name
pub(crate) unsafe fn ossl_x509_algor_new_from_md(
    palg: *mut *mut X509Algor,
    md: *const EvpMd,
) -> c_int {
    if md.is_null() {
        return 1;
    }
    // SAFETY: `md` is live per the check above.
    if unsafe { EVP_MD_is_a(md, c"SHA1".as_ptr()) } != 0 {
        return 1;
    }
    let alg = X509_ALGOR_new();
    if alg.is_null() {
        return 0;
    }
    // SAFETY: `alg` is live and `md` is the caller's.
    unsafe { X509_ALGOR_set_md(alg, md) };
    // SAFETY: `palg` is the caller's writable slot.
    unsafe { *palg = alg };
    1
}

/// `const EVP_MD *ossl_x509_algor_get_md(X509_ALGOR *alg)` — `crypto/asn1/x_algor.c:157-167`.
/// Internal.
///
/// A NULL identifier is the default SHA1. Otherwise the OID is resolved through
/// `EVP_get_digestbyobj`, which `include/openssl/evp.h` defines as
/// `EVP_get_digestbyname(OBJ_nid2sn(OBJ_obj2nid(a)))`; an unresolved object raises
/// `ASN1_R_UNKNOWN_DIGEST` at `x_algor.c:165` and answers NULL.
///
/// # Safety
///
/// `alg` is NULL or a live object.
#[allow(dead_code)]
// read by `crypto/rsa/rsa_backend.c:634,637` and `crypto/cms/cms_rsa.c`, neither transcribed yet (D348)
#[allow(non_snake_case)] // the authority's own symbol name
pub(crate) unsafe fn ossl_x509_algor_get_md(alg: *mut X509Algor) -> *const EvpMd {
    if alg.is_null() {
        return EVP_sha1();
    }
    // SAFETY: `alg` is live.
    let nid = unsafe { OBJ_obj2nid((*alg).algorithm) };
    // SAFETY: `OBJ_nid2sn` answers a static string or NULL and `EVP_get_digestbyname` is the
    // global lookup the macro expands to.
    let md = unsafe { EVP_get_digestbyname(OBJ_nid2sn(nid)) };
    if md.is_null() {
        // SAFETY: a compile-time-constant site, generated from `x_algor.c:165`.
        unsafe { raise_site(&err_sites::X_ALGOR_165) };
    }
    md
}

/// `X509_ALGOR *ossl_x509_algor_mgf1_decode(X509_ALGOR *alg)` — `crypto/asn1/x_algor.c:169-175`.
/// Internal.
///
/// Only an MGF1 identifier has a decodable parameter, and the decode is the item layer's own
/// `ASN1_TYPE_unpack_sequence` over a private `X509_ALGOR` item.
///
/// # Safety
///
/// `alg` is a live object.
#[allow(dead_code)]
// read by `crypto/rsa/rsa_backend.c:545,574`, `rsa_ameth.c:256` and `cms_rsa.c:30`, none transcribed yet (D348)
#[allow(non_snake_case)] // the authority's own symbol name
pub(crate) unsafe fn ossl_x509_algor_mgf1_decode(alg: *mut X509Algor) -> *mut X509Algor {
    // SAFETY: `alg` is live per the contract.
    if unsafe { OBJ_obj2nid((*alg).algorithm) } != NID_mgf1 {
        return ptr::null_mut();
    }
    // SAFETY: `alg` is live and its parameter is a live `ASN1_TYPE`.
    unsafe { ASN1_TYPE_unpack_sequence(X509_ALGOR_it(), (*alg).parameter).cast::<X509Algor>() }
}

/// `int ossl_x509_algor_md_to_mgf1(X509_ALGOR **palg, const EVP_MD *mgf1md)` —
/// `crypto/asn1/x_algor.c:178-199`. Internal.
///
/// The MGF1 identifier embeds a whole `AlgorithmIdentifier` inside its parameter, so the digest's
/// own identifier is packed with `ASN1_item_pack` and handed to `ossl_X509_ALGOR_from_nid` as a
/// `V_ASN1_SEQUENCE` value. `*palg` is zeroed first, so a SHA1 default and every failure answer a
/// NULL slot; the success of the whole function is `*palg != NULL`.
///
/// # Safety
///
/// `palg` is a writable slot. `mgf1md` is NULL or a live digest.
#[allow(dead_code)]
// read by `crypto/rsa/rsa_ameth.c:512` and `crypto/cms/cms_rsa.c:157`, neither transcribed yet (D348)
#[allow(non_snake_case)] // the authority's own symbol name
pub(crate) unsafe fn ossl_x509_algor_md_to_mgf1(
    palg: *mut *mut X509Algor,
    mgf1md: *const EvpMd,
) -> c_int {
    let mut algtmp: *mut X509Algor = ptr::null_mut();
    let mut stmp: *mut Asn1String = ptr::null_mut();

    // SAFETY: `palg` is the caller's writable slot.
    unsafe { *palg = ptr::null_mut() };
    if mgf1md.is_null() {
        return 1;
    }
    // SAFETY: `mgf1md` is live per the check above.
    if unsafe { EVP_MD_is_a(mgf1md, c"SHA1".as_ptr()) } != 0 {
        return 1;
    }
    // SAFETY: `algtmp` is this frame's slot and `mgf1md` is live.
    if unsafe { ossl_x509_algor_new_from_md(&mut algtmp, mgf1md) } == 0 {
        // SAFETY: `stmp` is still NULL and `algtmp` is NULL or this call's temporary.
        unsafe {
            ASN1_STRING_free(stmp);
            X509_ALGOR_free(algtmp);
        }
        return 0;
    }
    // SAFETY: `algtmp` is live and `stmp` is this frame's slot.
    if unsafe { ASN1_item_pack(algtmp.cast::<c_void>(), X509_ALGOR_it(), &mut stmp) }.is_null() {
        // SAFETY: `stmp` is NULL on this arm and `algtmp` is live.
        unsafe {
            ASN1_STRING_free(stmp);
            X509_ALGOR_free(algtmp);
        }
        return 0;
    }
    // SAFETY: `NID_mgf1` is a shared static object; `stmp` is the packed string, adopted by the
    // identifier on success.
    let built = unsafe { ossl_X509_ALGOR_from_nid(NID_mgf1, V_ASN1_SEQUENCE, stmp.cast()) };
    // SAFETY: `palg` is the caller's writable slot.
    unsafe { *palg = built };
    if built.is_null() {
        // SAFETY: `stmp` is this call's packed string and `algtmp` is live; `from_nid` freed only
        // its own half-built object, not the caller's string.
        unsafe {
            ASN1_STRING_free(stmp);
            X509_ALGOR_free(algtmp);
        }
        return 0;
    }
    // Ownership of `stmp` moved into `built`; the authority's `stmp = NULL` before `err:`.
    // SAFETY: `algtmp` is live; `built` is not freed here.
    unsafe { X509_ALGOR_free(algtmp) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mem::CRYPTO_free;
    use crate::runtime::obj::{OBJ_nid2obj, OBJ_obj2nid};

    /// `set0` builds an identifier whose OID is the caller's and whose parameter is an explicit
    /// `NULL`, and `i2d`/`d2i` are an inverse pair over it.
    #[test]
    fn the_item_round_trips_and_decodes_to_the_same_oid() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let alg = X509_ALGOR_new();
            assert!(!alg.is_null());
            // SAFETY: `OBJ_nid2obj` answers a shared static object.
            let oid = OBJ_nid2obj(64 /* NID_sha1 */);
            assert_eq!(X509_ALGOR_set0(alg, oid, V_ASN1_NULL, ptr::null_mut()), 1);

            let n = i2d_X509_ALGOR(alg, ptr::null_mut());
            assert!(n > 0);
            let mut der: *mut c_uchar = ptr::null_mut();
            assert_eq!(i2d_X509_ALGOR(alg, &mut der), n);
            assert_eq!(*der, 0x30, "the identifier is a SEQUENCE");

            let mut cp: *const c_uchar = der;
            let back = d2i_X509_ALGOR(ptr::null_mut(), &mut cp, c_long::from(n));
            assert!(!back.is_null());
            assert_eq!(cp, der.add(n as usize));
            assert_eq!(X509_ALGOR_cmp(alg, back), 0);
            assert_eq!(OBJ_obj2nid((*back).algorithm), 64);

            // `get0` reports the type and leaves the value slot NULL for an `ASN1_NULL`.
            let mut got_type = -99;
            let sentinel_slot: u8 = 0;
            let sentinel = core::ptr::addr_of!(sentinel_slot).cast::<c_void>();
            let mut got_val: *const c_void = sentinel;
            X509_ALGOR_get0(ptr::null_mut(), &mut got_type, &mut got_val, back);
            assert_eq!(got_type, V_ASN1_NULL);

            X509_ALGOR_free(back);
            CRYPTO_free(der.cast(), ptr::null(), 0);
            X509_ALGOR_free(alg);
        }
    }

    /// An identifier with no parameter reports `V_ASN1_UNDEF` and does not write the caller's
    /// value slot — the authority's early return.
    #[test]
    fn an_absent_parameter_reports_undef_and_leaves_the_value_slot_alone() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let alg = X509_ALGOR_new();
            assert_eq!(
                X509_ALGOR_set0(alg, OBJ_nid2obj(64), V_ASN1_UNDEF, ptr::null_mut()),
                1
            );
            let mut got_type = -99;
            let sentinel_slot: u8 = 0;
            let sentinel = core::ptr::addr_of!(sentinel_slot).cast::<c_void>();
            let mut got_val: *const c_void = sentinel;
            X509_ALGOR_get0(ptr::null_mut(), &mut got_type, &mut got_val, alg);
            assert_eq!(got_type, V_ASN1_UNDEF);
            assert_eq!(got_val, sentinel, "ppval is not written on the absent arm");
            X509_ALGOR_free(alg);
        }
    }

    /// `copy` is a deep copy, an MGF1 identifier built through `ASN1_item_pack` decodes back to the
    /// digest it embeds, and `new_from_md`'s NULL/default arms answer without allocating.
    /// `copy` is a deep copy, an MGF1 identifier built through `ASN1_item_pack` decodes back to an
    /// identifier carrying the embedded OID, and `new_from_md`'s NULL/default arms answer without
    /// allocating.
    ///
    /// The decoded digest's *method* is deliberately not asserted: `ossl_x509_algor_get_md` resolves
    /// a non-NULL OID through `EVP_get_digestbyname`, which this crate answers NULL for every
    /// built-in name because the legacy `OBJ_NAME` database is Phase 13's (D343, D344). Only the
    /// SHA1 default — a direct static, no lookup — is observable here, and the identifier's OID is
    /// what the rest of the test checks.
    #[test]
    fn copy_and_mgf1_round_trip() {
        use crate::asn1::asn_pack::ASN1_item_pack;
        use crate::asn1::x_algor::{X509_ALGOR_new, X509_ALGOR_set0};
        use crate::evp::legacy_sha::EVP_sha1;
        use crate::runtime::obj::OBJ_nid2obj;

        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let src = X509_ALGOR_new();
            assert_eq!(
                X509_ALGOR_set0(src, OBJ_nid2obj(64), V_ASN1_NULL, ptr::null_mut()),
                1
            );
            let dst = X509_ALGOR_new();
            assert_eq!(X509_ALGOR_copy(dst, src), 1);
            assert_eq!(X509_ALGOR_cmp(src, dst), 0);
            // `OBJ_dup` answers the shared static entry for a static object, so the two pointers
            // may be equal; what the copy guarantees is an independent *value*.
            assert!(!(*dst).algorithm.is_null());

            // Build the MGF1 identifier the way the authority's `md_to_mgf1` does: pack a SHA-256
            // identifier and store the sequence under `NID_mgf1`, then decode it back.
            let inner_src = X509_ALGOR_new();
            assert_eq!(
                X509_ALGOR_set0(inner_src, OBJ_nid2obj(672), V_ASN1_NULL, ptr::null_mut()),
                1
            );
            let mut stmp: *mut Asn1String = ptr::null_mut();
            assert!(!ASN1_item_pack(inner_src.cast(), X509_ALGOR_it(), &mut stmp).is_null());
            let mgf1 = ossl_X509_ALGOR_from_nid(NID_mgf1, V_ASN1_SEQUENCE, stmp.cast());
            assert!(!mgf1.is_null());
            assert_eq!(OBJ_obj2nid((*mgf1).algorithm), NID_mgf1);
            let inner = ossl_x509_algor_mgf1_decode(mgf1);
            assert!(!inner.is_null());
            assert_eq!(OBJ_obj2nid((*inner).algorithm), 672);

            // `get_md`'s NULL default is SHA1, a direct static; `new_from_md`'s NULL and SHA1 arms
            // answer success without touching the caller's slot.
            assert_eq!(ossl_x509_algor_get_md(ptr::null_mut()), EVP_sha1());
            let mut alg: *mut X509Algor = ptr::null_mut();
            assert_eq!(ossl_x509_algor_new_from_md(&mut alg, ptr::null()), 1);
            assert!(alg.is_null());
            assert_eq!(ossl_x509_algor_new_from_md(&mut alg, EVP_sha1()), 1);
            assert!(alg.is_null());

            X509_ALGOR_free(inner);
            X509_ALGOR_free(mgf1);
            X509_ALGOR_free(inner_src);
            X509_ALGOR_free(dst);
            X509_ALGOR_free(src);
        }
    }

    /// The item accessors answer stable, distinct addresses, and the `X509_ALGORS` descriptor is a
    /// `SEQUENCE OF` over the `X509_ALGOR` item.
    #[test]
    fn the_item_accessors_are_stable() {
        assert_eq!(X509_ALGOR_it(), X509_ALGOR_it());
        assert_eq!(X509_ALGORS_it(), X509_ALGORS_it());
        assert_ne!(
            X509_ALGOR_it() as *const _ as usize,
            X509_ALGORS_it() as *const _ as usize
        );
        // SAFETY: `X509_ALGORS_it()` answers a static item this crate owns.
        unsafe {
            let it = &*X509_ALGORS_it();
            assert_eq!(it.itype, ASN1_ITYPE_PRIMITIVE);
            assert_eq!(it.utype, V_ASN1_UNDEF as c_long);
            assert_eq!(it.tcount, 0);
            assert!(!it.templates.is_null());
        }
    }
}
