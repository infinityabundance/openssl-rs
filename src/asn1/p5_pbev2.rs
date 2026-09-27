//! `crypto/asn1/p5_pbev2.c` — `PBE2PARAM`/`PBKDF2PARAM`/`PBMAC1PARAM` and the PKCS#5 v2.0
//! PBE algorithm identifier builders. Phase 11's unit, landed early so Phase 10 can close
//! (D443's pull-forward).
//!
//! The authority file is 279 lines. It declares the three structures, generates their
//! item accessors, and builds the `AlgorithmIdentifier`s for `PBES2` and `PBKDF2`:
//! [`PKCS5_pbe2_set_iv_ex`] (the encryption scheme plus its key-derivation function) and
//! [`PKCS5_pbkdf2_set_ex`] (the key-derivation function alone).
//!
//! **Why this lands with Phase 10 and not with Phase 11.** The atlas assigns all 548
//! `x509.h` exports to Phase 11 and Phase 11 is `not-started`.
//! [`PKCS5_pbe2_set_iv_ex`] and [`crate::asn1::p5_pbe::PKCS5_pbe_set_ex`] are the *only*
//! unlanded names in `PKCS8_encrypt_ex`'s closure, and `PKCS8_encrypt` is the only
//! unlanded name in `encode_key2any.c`'s closure; [`PKCS5_pbkdf2_set`] and the
//! `PBMAC1PARAM` group are the MAC setters' blocker. This is D442's `PKCS7` pull-forward
//! one stratum further along: the symbols read `implemented` with `owning_phase: 11`
//! while Phase 11 stays `not-started`, and no Phase 11 evidence row is created.
//!
//! ## The items
//!
//! `src/evp/p5_crpt2.rs` carries private `PBE2PARAM`/`PBKDF2PARAM` descriptors for these
//! same authority items because it needed the *types* and not the accessors; those are
//! left untouched by this slice, which publishes the exported accessors over identical
//! descriptors.
//!
//! ## The raises
//!
//! Every raise is the authority's: the `NID_undef` cipher, the allocation failures
//! (`ERR_R_ASN1_LIB`/`ERR_R_EVP_LIB`), the two parameter-setting failures
//! (`ASN1_R_ERROR_SETTING_CIPHER_PARAMS`, `ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER`), the
//! negative `saltlen` and the `RAND` failure. The `ERR_set_mark`/`ERR_pop_to_mark` pair
//! around the PRF preference probe is kept: the probe's own error is discarded, which is
//! what makes an unspecified PRF fall back to `hmacWithSHA256` rather than fail.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_new, ASN1_TYPE_pack_sequence};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_ANY_it, ASN1_INTEGER_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::string::{ASN1_INTEGER_new, ASN1_OCTET_STRING_new};
use crate::asn1::x_algor::{
    ossl_X509_ALGOR_from_nid, X509Algor, X509_ALGOR_free, X509_ALGOR_it, X509_ALGOR_new,
};
use crate::evp::cipher::{
    EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length, EVP_CIPHER_get_type, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_param_to_asn1,
    EVP_CipherInit_ex, EvpCipherCtx,
};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::err::{err_sites, raise_site, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::obj::{
    NID_hmacWithSHA1, NID_hmacWithSHA256, NID_id_pbkdf2, NID_pbes2, NID_rc2_cbc, NID_undef,
    OBJ_nid2obj,
};

/// `PKCS5_DEFAULT_ITER` — `include/openssl/evp.h:45`.
const PKCS5_DEFAULT_ITER: c_int = 2048;

/// `PKCS5_DEFAULT_PBE2_SALT_LEN` — `include/crypto/evp.h:27`.
const PKCS5_DEFAULT_PBE2_SALT_LEN: c_int = 16;

/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;

/// `EVP_CTRL_PBE_PRF_NID` — `include/openssl/evp.h:386`, the PRF-preference probe.
const EVP_CTRL_PBE_PRF_NID: c_int = 0x7;

/// `struct PBE2PARAM_st` — `include/openssl/x509.h:268-271`. Two algorithm identifiers.
#[repr(C)]
pub struct Pbe2Param {
    /// `X509_ALGOR *keyfunc` — the `PBKDF2` key-derivation function, at offset 0.
    pub(crate) keyfunc: *mut X509Algor,
    /// `X509_ALGOR *encryption` — the cipher, at offset 8.
    pub(crate) encryption: *mut X509Algor,
}

/// `struct PBKDF2PARAM_st` — `include/openssl/x509.h:273-279`. `salt` is `ASN1_ANY`
/// rather than an octet string, which is why a decoder checks its selector.
#[repr(C)]
pub struct Pbkdf2Param {
    /// `ASN1_TYPE *salt` — usually an octet string, at offset 0.
    pub(crate) salt: *mut Asn1Type,
    /// `ASN1_INTEGER *iter` — the iteration count, at offset 8.
    pub(crate) iter: *mut Asn1String,
    /// `ASN1_INTEGER *keylength` — optional, at offset 16.
    pub(crate) keylength: *mut Asn1String,
    /// `X509_ALGOR *prf` — optional, at offset 24.
    pub(crate) prf: *mut X509Algor,
}

/// `struct PBMAC1PARAM_st` — `include/openssl/x509.h:281-284`, the RFC 9879 MAC scheme's
/// parameter. Two algorithm identifiers, like [`Pbe2Param`].
#[repr(C)]
pub struct Pbmac1Param {
    /// `X509_ALGOR *keyDerivationFunc` — at offset 0.
    pub(crate) key_derivation_func: *mut X509Algor,
    /// `X509_ALGOR *messageAuthScheme` — at offset 8.
    pub(crate) message_auth_scheme: *mut X509Algor,
}

const _: () = {
    assert!(core::mem::size_of::<Pbe2Param>() == 16);
    assert!(core::mem::offset_of!(Pbe2Param, keyfunc) == 0);
    assert!(core::mem::offset_of!(Pbe2Param, encryption) == 8);
    assert!(core::mem::size_of::<Pbkdf2Param>() == 32);
    assert!(core::mem::offset_of!(Pbkdf2Param, salt) == 0);
    assert!(core::mem::offset_of!(Pbkdf2Param, iter) == 8);
    assert!(core::mem::offset_of!(Pbkdf2Param, keylength) == 16);
    assert!(core::mem::offset_of!(Pbkdf2Param, prf) == 24);
    assert!(core::mem::size_of::<Pbmac1Param>() == 16);
    assert!(core::mem::offset_of!(Pbmac1Param, key_derivation_func) == 0);
    assert!(core::mem::offset_of!(Pbmac1Param, message_auth_scheme) == 8);
};

/// `PBE2PARAM_seq_tt` — `crypto/asn1/p5_pbev2.c:22-25`.
static PBE2PARAM_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"keyfunc".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"encryption".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
];

/// `PBKDF2PARAM_seq_tt` — `crypto/asn1/p5_pbev2.c:29-34`.
static PBKDF2PARAM_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"salt".as_ptr(),
        item: ASN1_ANY_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"iter".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"keylength".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"prf".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
];

/// `PBMAC1PARAM_seq_tt` — `crypto/asn1/p5_pbev2.c:38-41`.
static PBMAC1PARAM_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"keyDerivationFunc".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"messageAuthScheme".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
];

/// `PBE2PARAM_it`'s descriptor — `ASN1_SEQUENCE_END(PBE2PARAM)` at `crypto/asn1/p5_pbev2.c:25`.
pub(crate) static PBE2PARAM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PBE2PARAM_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pbe2Param>() as c_long,
    sname: c"PBE2PARAM".as_ptr(),
};

/// `PBKDF2PARAM_it`'s descriptor — `ASN1_SEQUENCE_END(PBKDF2PARAM)` at `:34`.
pub(crate) static PBKDF2PARAM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PBKDF2PARAM_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pbkdf2Param>() as c_long,
    sname: c"PBKDF2PARAM".as_ptr(),
};

/// `PBMAC1PARAM_it`'s descriptor — `ASN1_SEQUENCE_END(PBMAC1PARAM)` at `:41`.
pub(crate) static PBMAC1PARAM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PBMAC1PARAM_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pbmac1Param>() as c_long,
    sname: c"PBMAC1PARAM".as_ptr(),
};

/// `const ASN1_ITEM *PBE2PARAM_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END(PBE2PARAM)`.
#[no_mangle]
pub extern "C" fn PBE2PARAM_it() -> *const Asn1Item {
    &PBE2PARAM_ITEM
}

/// `const ASN1_ITEM *PBKDF2PARAM_it(void)` — `include/openssl/x509.h`.
#[no_mangle]
pub extern "C" fn PBKDF2PARAM_it() -> *const Asn1Item {
    &PBKDF2PARAM_ITEM
}

/// `const ASN1_ITEM *PBMAC1PARAM_it(void)` — `include/openssl/x509.h`.
#[no_mangle]
pub extern "C" fn PBMAC1PARAM_it() -> *const Asn1Item {
    &PBMAC1PARAM_ITEM
}

/// `PBE2PARAM *PBE2PARAM_new(void)` — `crypto/asn1/p5_pbev2.c:27`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PBE2PARAM)`.
#[no_mangle]
pub extern "C" fn PBE2PARAM_new() -> *mut Pbe2Param {
    // SAFETY: `PBE2PARAM_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PBE2PARAM_it()).cast::<Pbe2Param>() }
}

/// `void PBE2PARAM_free(PBE2PARAM *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PBE2PARAM_free(a: *mut Pbe2Param) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PBE2PARAM_it()) }
}

/// `PBE2PARAM *d2i_PBE2PARAM(PBE2PARAM **a, const unsigned char **in, long len)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes it.
#[no_mangle]
pub unsafe extern "C" fn d2i_PBE2PARAM(
    a: *mut *mut Pbe2Param,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pbe2Param {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PBE2PARAM_it()).cast::<Pbe2Param>() }
}

/// `int i2d_PBE2PARAM(const PBE2PARAM *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PBE2PARAM(a: *const Pbe2Param, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer.
    unsafe { ASN1_item_i2d(a.cast(), out, PBE2PARAM_it()) }
}

/// `PBKDF2PARAM *PBKDF2PARAM_new(void)` — `crypto/asn1/p5_pbev2.c:36`.
#[no_mangle]
pub extern "C" fn PBKDF2PARAM_new() -> *mut Pbkdf2Param {
    // SAFETY: `PBKDF2PARAM_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PBKDF2PARAM_it()).cast::<Pbkdf2Param>() }
}

/// `void PBKDF2PARAM_free(PBKDF2PARAM *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PBKDF2PARAM_free(a: *mut Pbkdf2Param) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PBKDF2PARAM_it()) }
}

/// `PBKDF2PARAM *d2i_PBKDF2PARAM(PBKDF2PARAM **a, const unsigned char **in, long len)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes it.
#[no_mangle]
pub unsafe extern "C" fn d2i_PBKDF2PARAM(
    a: *mut *mut Pbkdf2Param,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pbkdf2Param {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PBKDF2PARAM_it()).cast::<Pbkdf2Param>() }
}

/// `int i2d_PBKDF2PARAM(const PBKDF2PARAM *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PBKDF2PARAM(a: *const Pbkdf2Param, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer.
    unsafe { ASN1_item_i2d(a.cast(), out, PBKDF2PARAM_it()) }
}

/// `PBMAC1PARAM *PBMAC1PARAM_new(void)` — `crypto/asn1/p5_pbev2.c:43`.
#[no_mangle]
pub extern "C" fn PBMAC1PARAM_new() -> *mut Pbmac1Param {
    // SAFETY: `PBMAC1PARAM_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PBMAC1PARAM_it()).cast::<Pbmac1Param>() }
}

/// `void PBMAC1PARAM_free(PBMAC1PARAM *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PBMAC1PARAM_free(a: *mut Pbmac1Param) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PBMAC1PARAM_it()) }
}

/// `PBMAC1PARAM *d2i_PBMAC1PARAM(PBMAC1PARAM **a, const unsigned char **in, long len)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes it.
#[no_mangle]
pub unsafe extern "C" fn d2i_PBMAC1PARAM(
    a: *mut *mut Pbmac1Param,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pbmac1Param {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PBMAC1PARAM_it()).cast::<Pbmac1Param>() }
}

/// `int i2d_PBMAC1PARAM(const PBMAC1PARAM *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PBMAC1PARAM(a: *const Pbmac1Param, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer.
    unsafe { ASN1_item_i2d(a.cast(), out, PBMAC1PARAM_it()) }
}

/// `X509_ALGOR *PKCS5_pbe2_set_iv_ex(const EVP_CIPHER *cipher, int iter,
/// unsigned char *salt, int saltlen, unsigned char *aiv, int prf_nid,
/// OSSL_LIB_CTX *libctx)` — `crypto/asn1/p5_pbev2.c:51-163`.
///
/// Builds a `PBES2` `AlgorithmIdentifier`: the cipher's identifier and IV as
/// `encryption`, and a fresh `PBKDF2` identifier as `keyfunc`. An unspecified `prf_nid`
/// (`-1`) takes the cipher's own preference when it has one and `hmacWithSHA256`
/// otherwise; the probe's error is deliberately discarded.
///
/// # Safety
/// `cipher` is a live cipher; `salt`/`aiv` are NULL or `saltlen`/IV-length readable bytes;
/// `libctx` is the `RAND` lookup's context.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe2_set_iv_ex(
    cipher: *const EvpCipher,
    iter: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    aiv: *mut c_uchar,
    prf_nid: c_int,
    libctx: *mut c_void,
) -> *mut X509Algor {
    let scheme: *mut X509Algor;
    let mut ret: *mut X509Algor = ptr::null_mut();
    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    let mut iv = [0 as c_uchar; EVP_MAX_IV_LENGTH];
    let mut pbe2: *mut Pbe2Param = ptr::null_mut();

    // SAFETY: `cipher` is live per the contract.
    let alg_nid = unsafe { EVP_CIPHER_get_type(cipher) };
    if alg_nid == NID_undef {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_PBEV2_64) };
        // SAFETY: the arguments are NULL or live per the contract.
        return unsafe { pbe2_err(ctx, pbe2, ret) };
    }

    // SAFETY: no preconditions.
    pbe2 = PBE2PARAM_new();
    if pbe2.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_PBEV2_69) };
        // SAFETY: the arguments are NULL or live per the contract.
        return unsafe { pbe2_err(ctx, pbe2, ret) };
    }

    // SAFETY: `pbe2` is a fresh value whose two algorithm slots the item layer allocated.
    unsafe {
        scheme = (*pbe2).encryption;
        (*scheme).algorithm = OBJ_nid2obj(alg_nid);
        (*scheme).parameter = ASN1_TYPE_new();
        if (*scheme).parameter.is_null() {
            raise_site(&err_sites::P5_PBEV2_77);
            return pbe2_err(ctx, pbe2, ret);
        }

        let ivlen = EVP_CIPHER_get_iv_length(cipher);
        if ivlen > 0 {
            if !aiv.is_null() {
                ptr::copy_nonoverlapping(aiv, iv.as_mut_ptr(), ivlen as usize);
            } else if RAND_bytes_ex(libctx, iv.as_mut_ptr(), ivlen as usize, 0) <= 0 {
                return pbe2_err(ctx, pbe2, ret);
            }
        }

        ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            raise_site(&err_sites::P5_PBEV2_92);
            return pbe2_err(ctx, pbe2, ret);
        }

        // The dummy init only sets up the IV and the PRF.
        if EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), iv.as_ptr(), 0) == 0 {
            return pbe2_err(ctx, pbe2, ret);
        }
        if EVP_CIPHER_param_to_asn1(ctx, (*scheme).parameter) <= 0 {
            raise_site(&err_sites::P5_PBEV2_100);
            return pbe2_err(ctx, pbe2, ret);
        }

        let mut prf_nid = prf_nid;
        let _ = ERR_set_mark();
        if prf_nid == -1
            && EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_PBE_PRF_NID,
                0,
                (&mut prf_nid as *mut c_int).cast::<c_void>(),
            ) <= 0
        {
            prf_nid = NID_hmacWithSHA256;
        }
        let _ = ERR_pop_to_mark();
        EVP_CIPHER_CTX_free(ctx);
        ctx = ptr::null_mut();

        let keylen = if alg_nid == NID_rc2_cbc {
            EVP_CIPHER_get_key_length(cipher)
        } else {
            -1
        };

        X509_ALGOR_free((*pbe2).keyfunc);
        (*pbe2).keyfunc = PKCS5_pbkdf2_set_ex(iter, salt, saltlen, prf_nid, keylen, libctx);
        if (*pbe2).keyfunc.is_null() {
            raise_site(&err_sites::P5_PBEV2_130);
            return pbe2_err(ctx, pbe2, ret);
        }

        ret = X509_ALGOR_new();
        if ret.is_null() {
            raise_site(&err_sites::P5_PBEV2_137);
            return pbe2_err(ctx, pbe2, ret);
        }

        (*ret).algorithm = OBJ_nid2obj(NID_pbes2);

        if ASN1_TYPE_pack_sequence(PBE2PARAM_it(), pbe2.cast::<c_void>(), &mut (*ret).parameter)
            .is_null()
        {
            raise_site(&err_sites::P5_PBEV2_147);
            return pbe2_err(ctx, pbe2, ret);
        }

        PBE2PARAM_free(pbe2);
    }
    ret
}

/// The authority's `err:` tail: release the cipher context, the `PBE2PARAM` (which owns
/// `scheme`) and the answer, and return NULL.
///
/// # Safety
/// Each pointer is NULL or live and owned by the caller.
unsafe fn pbe2_err(
    ctx: *mut EvpCipherCtx,
    pbe2: *mut Pbe2Param,
    ret: *mut X509Algor,
) -> *mut X509Algor {
    // SAFETY: both are NULL or live per the contract.
    unsafe {
        EVP_CIPHER_CTX_free(ctx);
        PBE2PARAM_free(pbe2);
        X509_ALGOR_free(ret);
    }
    ptr::null_mut()
}

/// `X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter,
/// unsigned char *salt, int saltlen, unsigned char *aiv, int prf_nid)` —
/// `crypto/asn1/p5_pbev2.c:165-171`.
///
/// # Safety
/// As [`PKCS5_pbe2_set_iv_ex`], without the context.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe2_set_iv(
    cipher: *const EvpCipher,
    iter: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    aiv: *mut c_uchar,
    prf_nid: c_int,
) -> *mut X509Algor {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe { PKCS5_pbe2_set_iv_ex(cipher, iter, salt, saltlen, aiv, prf_nid, ptr::null_mut()) }
}

/// `X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter, unsigned char *salt,
/// int saltlen)` — `crypto/asn1/p5_pbev2.c:173-178`.
///
/// # Safety
/// `cipher` is live; `salt` is NULL or `saltlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe2_set(
    cipher: *const EvpCipher,
    iter: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
) -> *mut X509Algor {
    // SAFETY: the arguments are forwarded under this function's contract; the IV is drawn.
    unsafe {
        PKCS5_pbe2_set_iv_ex(
            cipher,
            iter,
            salt,
            saltlen,
            ptr::null_mut(),
            -1,
            ptr::null_mut(),
        )
    }
}

/// `X509_ALGOR *PKCS5_pbkdf2_set_ex(int iter, unsigned char *salt, int saltlen,
/// int prf_nid, int keylen, OSSL_LIB_CTX *libctx)` — `crypto/asn1/p5_pbev2.c:180-273`.
///
/// Builds a `PBKDF2` `AlgorithmIdentifier`: an octet-string salt, the iteration count, an
/// optional key length and an optional PRF. A `prf_nid` of `0`/`hmacWithSHA1` leaves the
/// PRF column null, which is the authority's default-PRF spelling.
///
/// # Safety
/// `salt` is NULL or `saltlen` readable bytes; `libctx` is the `RAND` lookup's context.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbkdf2_set_ex(
    iter: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    prf_nid: c_int,
    keylen: c_int,
    libctx: *mut c_void,
) -> *mut X509Algor {
    let kdf: *mut Pbkdf2Param = PBKDF2PARAM_new();
    let mut keyfunc: *mut X509Algor = ptr::null_mut();

    if kdf.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_PBEV2_189) };
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let osalt = ASN1_OCTET_STRING_new();
    if osalt.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_PBEV2_193) };
        // SAFETY: `kdf` is this frame's own and `keyfunc` is null.
        return unsafe { pbkdf2_err(kdf, keyfunc) };
    }

    // SAFETY: `kdf` is fresh, so `salt` points at the `ASN1_ANY` the item layer allocated.
    unsafe {
        (*(*kdf).salt).value.ptr = osalt.cast::<c_void>();
        (*(*kdf).salt).type_ = V_ASN1_OCTET_STRING;

        if saltlen < 0 {
            raise_site(&err_sites::P5_PBEV2_201);
            return pbkdf2_err(kdf, keyfunc);
        }
        let saltlen = if saltlen == 0 {
            PKCS5_DEFAULT_PBE2_SALT_LEN
        } else {
            saltlen
        };
        // SAFETY: `osalt` is this frame's own string.
        (*osalt).data = CRYPTO_malloc(saltlen as usize, FILE.as_ptr(), 206).cast::<c_uchar>();
        if (*osalt).data.is_null() {
            return pbkdf2_err(kdf, keyfunc);
        }
        (*osalt).length = saltlen;

        if !salt.is_null() {
            ptr::copy_nonoverlapping(salt, (*osalt).data, saltlen as usize);
        } else if RAND_bytes_ex(libctx, (*osalt).data, saltlen as usize, 0) <= 0 {
            raise_site(&err_sites::P5_PBEV2_214);
            return pbkdf2_err(kdf, keyfunc);
        }

        let iter = if iter <= 0 { PKCS5_DEFAULT_ITER } else { iter };
        if ASN1_INTEGER_set((*kdf).iter, c_long::from(iter)) == 0 {
            raise_site(&err_sites::P5_PBEV2_222);
            return pbkdf2_err(kdf, keyfunc);
        }

        if keylen > 0 {
            (*kdf).keylength = ASN1_INTEGER_new();
            if (*kdf).keylength.is_null() {
                raise_site(&err_sites::P5_PBEV2_230);
                return pbkdf2_err(kdf, keyfunc);
            }
            if ASN1_INTEGER_set((*kdf).keylength, c_long::from(keylen)) == 0 {
                raise_site(&err_sites::P5_PBEV2_234);
                return pbkdf2_err(kdf, keyfunc);
            }
        }

        // The PRF column can stay null for the default `hmacWithSHA1`.
        if prf_nid > 0 && prf_nid != NID_hmacWithSHA1 {
            (*kdf).prf = ossl_X509_ALGOR_from_nid(prf_nid, V_ASN1_NULL, ptr::null_mut());
            if (*kdf).prf.is_null() {
                raise_site(&err_sites::P5_PBEV2_243);
                return pbkdf2_err(kdf, keyfunc);
            }
        }

        keyfunc = X509_ALGOR_new();
        if keyfunc.is_null() {
            raise_site(&err_sites::P5_PBEV2_252);
            return pbkdf2_err(kdf, keyfunc);
        }

        (*keyfunc).algorithm = OBJ_nid2obj(NID_id_pbkdf2);

        if ASN1_TYPE_pack_sequence(
            PBKDF2PARAM_it(),
            kdf.cast::<c_void>(),
            &mut (*keyfunc).parameter,
        )
        .is_null()
        {
            raise_site(&err_sites::P5_PBEV2_262);
            return pbkdf2_err(kdf, keyfunc);
        }

        PBKDF2PARAM_free(kdf);
    }
    keyfunc
}

/// The authority's `err:` tail of [`PKCS5_pbkdf2_set_ex`]: release the `PBKDF2PARAM`
/// (which owns the salt) and the answer.
///
/// # Safety
/// Each pointer is NULL or live and owned by the caller.
unsafe fn pbkdf2_err(kdf: *mut Pbkdf2Param, keyfunc: *mut X509Algor) -> *mut X509Algor {
    // SAFETY: both are NULL or live per the contract.
    unsafe {
        PBKDF2PARAM_free(kdf);
        X509_ALGOR_free(keyfunc);
    }
    ptr::null_mut()
}

/// `X509_ALGOR *PKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen,
/// int prf_nid, int keylen)` — `crypto/asn1/p5_pbev2.c:275-279`.
///
/// # Safety
/// `salt` is NULL or `saltlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbkdf2_set(
    iter: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    prf_nid: c_int,
    keylen: c_int,
) -> *mut X509Algor {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe { PKCS5_pbkdf2_set_ex(iter, salt, saltlen, prf_nid, keylen, ptr::null_mut()) }
}

/// `crypto/asn1/p5_pbev2.c` — the authority's `__FILE__` string, for the allocator's
/// bookkeeping.
const FILE: &core::ffi::CStr = c"crypto/asn1/p5_pbev2.c";

#[cfg(test)]
mod tests {
    use super::*;

    /// The three items have the authority's shape, and the private descriptors
    /// `src/evp/p5_crpt2.rs` used to carry now agree with the public ones.
    #[test]
    fn the_pbe2_item_family_has_the_authority_shape() {
        assert_eq!(PBE2PARAM_ITEM.itype, ASN1_ITYPE_SEQUENCE);
        assert_eq!(PBE2PARAM_ITEM.tcount, 2);
        assert_eq!(PBE2PARAM_ITEM.size, 16);
        assert_eq!(PBKDF2PARAM_ITEM.tcount, 4);
        assert_eq!(PBKDF2PARAM_ITEM.size, 32);
        assert_eq!(PBMAC1PARAM_ITEM.tcount, 2);
        assert_eq!(PBMAC1PARAM_ITEM.size, 16);
        assert_eq!(&PBE2PARAM_ITEM as *const Asn1Item, PBE2PARAM_it());
        assert_eq!(&PBKDF2PARAM_ITEM as *const Asn1Item, PBKDF2PARAM_it());
        assert_eq!(&PBMAC1PARAM_ITEM as *const Asn1Item, PBMAC1PARAM_it());
    }
}
