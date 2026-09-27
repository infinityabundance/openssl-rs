//! `crypto/asn1/p5_pbe.c` — `PBEPARAM` and the PKCS#5 v1.5 PBE algorithm identifier builder.
//! Phase 11's unit, landed early so Phase 10 can close (D443's pull-forward).
//!
//! The authority file is 112 lines. It declares the `PBEPARAM` structure
//! (`salt`/`iter`), generates its `_it`/`_new`/`_free`/`d2i_`/`i2d_` names with
//! `IMPLEMENT_ASN1_FUNCTIONS`, and builds an `X509_ALGOR` for a PKCS#5 v1.5 PBE scheme.
//!
//! **Why this lands with Phase 10 and not with Phase 11.** The atlas assigns all 548
//! `x509.h` exports to Phase 11 (`forensics/atlas/symbol-ownership.json`) and Phase 11 is
//! `not-started`. `PKCS5_pbe_set_ex` here and `PKCS5_pbe2_set_iv_ex` in
//! [`crate::asn1::p5_pbev2`] are the *only* unlanded names in `PKCS8_encrypt_ex`'s closure
//! (`crypto/pkcs12/p12_p8e.c:30`, `:44`), and `PKCS8_encrypt` is the only unlanded name in
//! `encode_key2any.c`'s closure and in 10.2/10.3's shrouded-key and `p7encdata` spellings.
//! So this is the same stratum-ordering pull-forward D442 did for `PKCS7`, one stratum
//! further along: the symbols read `implemented` with `owning_phase: 11` while Phase 11
//! stays `not-started`, and no Phase 11 evidence row is created.
//!
//! ## The item
//!
//! `ASN1_SEQUENCE(PBEPARAM)` is two `ASN1_SIMPLE` columns, so the item is a plain
//! `SEQUENCE` over [`Pbeparam`] with `ASN1_OCTET_STRING_it`/`ASN1_INTEGER_it`. The
//! private descriptor `src/evp/p5_crpt.rs` still carries for the same authority item
//! (it needed the *type* and not the accessors) is left untouched by this slice.
//!
//! ## The raises
//!
//! Four sites, and each is the authority's: the two `ERR_R_ASN1_LIB` for a failed
//! `PBEPARAM_new`/`ASN1_INTEGER_set`/`ASN1_item_pack`, and `ERR_R_X509_LIB` for a failed
//! `X509_ALGOR_new` in the `_set_ex` façade. The `saltlen < 0` and allocation-failure arms
//! raise nothing, exactly as the authority leaves them.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::asn_pack::ASN1_item_pack;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::string::ASN1_STRING_set0;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_free, X509_ALGOR_new, X509_ALGOR_set0};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::OBJ_nid2obj;

/// `PKCS5_DEFAULT_ITER` — `include/openssl/evp.h:45`.
const PKCS5_DEFAULT_ITER: c_int = 2048;

/// `PKCS5_DEFAULT_PBE1_SALT_LEN` — `include/crypto/evp.h:26`, which is `PKCS5_SALT_LEN`.
const PKCS5_DEFAULT_PBE1_SALT_LEN: c_int = 8;

/// `struct PBEPARAM_st` — `include/openssl/x509.h:261-264`. The item's two columns in
/// order: the salt octets and the iteration count (`ASN1_INTEGER` is an `ASN1_STRING`).
#[repr(C)]
pub struct Pbeparam {
    /// `ASN1_OCTET_STRING *salt` — at offset 0.
    pub(crate) salt: *mut Asn1String,
    /// `ASN1_INTEGER *iter` — at offset 8.
    pub(crate) iter: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<Pbeparam>() == 16);
    assert!(core::mem::offset_of!(Pbeparam, salt) == 0);
    assert!(core::mem::offset_of!(Pbeparam, iter) == 8);
};

/// `PBEPARAM_seq_tt` — `crypto/asn1/p5_pbe.c:19-22`'s `ASN1_SEQUENCE(PBEPARAM)`:
/// `ASN1_SIMPLE(PBEPARAM, salt, ASN1_OCTET_STRING)` and
/// `ASN1_SIMPLE(PBEPARAM, iter, ASN1_INTEGER)`.
static PBEPARAM_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"salt".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"iter".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `PBEPARAM_it`'s descriptor — `ASN1_SEQUENCE_END(PBEPARAM)` at `crypto/asn1/p5_pbe.c:22`.
pub(crate) static PBEPARAM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PBEPARAM_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pbeparam>() as c_long,
    sname: c"PBEPARAM".as_ptr(),
};

/// `const ASN1_ITEM *PBEPARAM_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END(PBEPARAM)`.
#[no_mangle]
pub extern "C" fn PBEPARAM_it() -> *const Asn1Item {
    &PBEPARAM_ITEM
}

/// `PBEPARAM *PBEPARAM_new(void)` — `crypto/asn1/p5_pbe.c:24`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PBEPARAM)`.
#[no_mangle]
pub extern "C" fn PBEPARAM_new() -> *mut Pbeparam {
    // SAFETY: `PBEPARAM_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PBEPARAM_it()).cast::<Pbeparam>() }
}

/// `void PBEPARAM_free(PBEPARAM *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PBEPARAM_free(a: *mut Pbeparam) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PBEPARAM_it()) }
}

/// `PBEPARAM *d2i_PBEPARAM(PBEPARAM **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes it.
#[no_mangle]
pub unsafe extern "C" fn d2i_PBEPARAM(
    a: *mut *mut Pbeparam,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pbeparam {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PBEPARAM_it()).cast::<Pbeparam>() }
}

/// `int i2d_PBEPARAM(const PBEPARAM *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PBEPARAM(a: *const Pbeparam, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer.
    unsafe { ASN1_item_i2d(a.cast(), out, PBEPARAM_it()) }
}

/// `int PKCS5_pbe_set0_algor_ex(X509_ALGOR *algor, int alg, int iter,
/// const unsigned char *salt, int saltlen, OSSL_LIB_CTX *ctx)` —
/// `crypto/asn1/p5_pbe.c:28-80`.
///
/// Builds a fresh `PBEPARAM` over the caller's salt (or a drawn one), packs it into an
/// octet string and installs it as the algorithm's `V_ASN1_SEQUENCE` parameter. The
/// `iter <= 0` arm means `PKCS5_DEFAULT_ITER`; `saltlen == 0` means
/// `PKCS5_DEFAULT_PBE1_SALT_LEN`; a negative `saltlen` refuses without raising.
///
/// # Safety
/// `algor` is a live `X509_ALGOR`; `salt` is NULL or `saltlen` readable bytes; `ctx` is the
/// `RAND` lookup's library context.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe_set0_algor_ex(
    algor: *mut X509Algor,
    alg: c_int,
    iter: c_int,
    salt: *const c_uchar,
    saltlen: c_int,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: no preconditions.
    let pbe = PBEPARAM_new();
    if pbe.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_PBE_39) };
        return 0;
    }
    // SAFETY: `pbe` is a fresh value whose `iter`/`salt` slots the item layer allocated.
    unsafe {
        let iter = if iter <= 0 { PKCS5_DEFAULT_ITER } else { iter };
        if ASN1_INTEGER_set((*pbe).iter, c_long::from(iter)) == 0 {
            raise_site(&err_sites::P5_PBE_45);
            PBEPARAM_free(pbe);
            return 0;
        }

        let saltlen = if saltlen == 0 {
            PKCS5_DEFAULT_PBE1_SALT_LEN
        } else if saltlen < 0 {
            PBEPARAM_free(pbe);
            return 0;
        } else {
            saltlen
        };

        let sstr = CRYPTO_malloc(saltlen as usize, FILE.as_ptr(), 53).cast::<c_uchar>();
        if sstr.is_null() {
            PBEPARAM_free(pbe);
            return 0;
        }
        if !salt.is_null() {
            ptr::copy_nonoverlapping(salt, sstr, saltlen as usize);
        } else if RAND_bytes_ex(ctx, sstr, saltlen as usize, 0) <= 0 {
            CRYPTO_free(sstr.cast::<c_void>(), FILE.as_ptr(), 59);
            PBEPARAM_free(pbe);
            return 0;
        }

        ASN1_STRING_set0((*pbe).salt, sstr.cast::<c_void>(), saltlen);

        let mut pbe_str: *mut Asn1String = ptr::null_mut();
        if ASN1_item_pack(pbe.cast::<c_void>(), PBEPARAM_it(), &mut pbe_str).is_null() {
            raise_site(&err_sites::P5_PBE_65);
            // `sstr` was adopted by the salt string, so the free path frees the PBEPARAM,
            // which frees the octet string and its buffer.
            PBEPARAM_free(pbe);
            return 0;
        }
        PBEPARAM_free(pbe);

        if X509_ALGOR_set0(
            algor,
            OBJ_nid2obj(alg),
            V_ASN1_SEQUENCE,
            pbe_str.cast::<c_void>(),
        ) != 0
        {
            return 1;
        }
        // The authority's `err:` tail frees the packed string when `set0` refused it.
        crate::asn1::string::ASN1_STRING_free(pbe_str);
    }
    0
}

/// `int PKCS5_pbe_set0_algor(X509_ALGOR *algor, int alg, int iter,
/// const unsigned char *salt, int saltlen)` — `crypto/asn1/p5_pbe.c:82-86`.
///
/// # Safety
/// As [`PKCS5_pbe_set0_algor_ex`], without the context.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe_set0_algor(
    algor: *mut X509Algor,
    alg: c_int,
    iter: c_int,
    salt: *const c_uchar,
    saltlen: c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe { PKCS5_pbe_set0_algor_ex(algor, alg, iter, salt, saltlen, ptr::null_mut()) }
}

/// `X509_ALGOR *PKCS5_pbe_set_ex(int alg, int iter, const unsigned char *salt,
/// int saltlen, OSSL_LIB_CTX *ctx)` — `crypto/asn1/p5_pbe.c:90-106`.
///
/// # Safety
/// `salt` is NULL or `saltlen` readable bytes; `ctx` is the `RAND` lookup's context.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe_set_ex(
    alg: c_int,
    iter: c_int,
    salt: *const c_uchar,
    saltlen: c_int,
    ctx: *mut c_void,
) -> *mut X509Algor {
    // SAFETY: no preconditions.
    let ret = X509_ALGOR_new();
    if ret.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_PBE_97) };
        return ptr::null_mut();
    }

    // SAFETY: `ret` is live and the rest is forwarded.
    if unsafe { PKCS5_pbe_set0_algor_ex(ret, alg, iter, salt, saltlen, ctx) } != 0 {
        return ret;
    }

    // SAFETY: `ret` is this frame's own.
    unsafe { X509_ALGOR_free(ret) };
    ptr::null_mut()
}

/// `X509_ALGOR *PKCS5_pbe_set(int alg, int iter, const unsigned char *salt,
/// int saltlen)` — `crypto/asn1/p5_pbe.c:108-112`.
///
/// # Safety
/// `salt` is NULL or `saltlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe_set(
    alg: c_int,
    iter: c_int,
    salt: *const c_uchar,
    saltlen: c_int,
) -> *mut X509Algor {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe { PKCS5_pbe_set_ex(alg, iter, salt, saltlen, ptr::null_mut()) }
}

/// `crypto/asn1/p5_pbe.c` — the authority's `__FILE__` string, for the allocator's
/// bookkeeping.
const FILE: &core::ffi::CStr = c"crypto/asn1/p5_pbe.c";

#[cfg(test)]
mod tests {
    use super::*;

    /// The item is the authority's: `ASN1_ITYPE_SEQUENCE`, `V_ASN1_SEQUENCE`, two fields,
    /// no aux block, and the structure's own size.
    #[test]
    fn the_pbeparam_item_has_the_authority_shape() {
        assert_eq!(PBEPARAM_ITEM.itype, ASN1_ITYPE_SEQUENCE);
        assert_eq!(PBEPARAM_ITEM.utype, V_ASN1_SEQUENCE as c_long);
        assert_eq!(PBEPARAM_ITEM.tcount, 2);
        assert!(PBEPARAM_ITEM.funcs.is_null());
        assert_eq!(PBEPARAM_ITEM.size, 16);
        assert_eq!(&PBEPARAM_ITEM as *const Asn1Item, PBEPARAM_it());
    }
}
