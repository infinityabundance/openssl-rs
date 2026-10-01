//! Phase 11.7 — `crypto/asn1/p5_scrypt.c`'s `x509.h` half: the `SCRYPT_PARAMS` item and
//! `PKCS5_pbe2_set_scrypt`.
//!
//! `crypto/asn1/p5_scrypt.c` is one authority translation unit split across two strata: its two
//! `PKCS5_v2_scrypt_keyivgen*` exports are declared in `evp.h` and are Phase 7's, transcribed in
//! `src/evp/p5_scrypt.rs`; `PKCS5_pbe2_set_scrypt` and the `SCRYPT_PARAMS_*`/`d2i_SCRYPT_PARAMS`
//! accessors are declared in `x509.h` and are Phase 11's, and they are what this module writes.
//!
//! ## A second `SCRYPT_PARAMS` descriptor, on purpose
//!
//! `src/evp/p5_scrypt.rs` decodes through a *private* `SCRYPT_PARAMS` descriptor because its keygen
//! body needs the type and not the accessors. This module publishes the exported accessors over a
//! descriptor of its own, with identical fields and `sname`, exactly as `src/asn1/p5_pbev2.rs`
//! records for the `PBE2PARAM` pair: the private one stays private and no symbol is defined twice.
//! The five template entries and the field offsets are asserted, not typed twice.
//!
//! ## `pkcs5_scrypt_set` is where the refusals live
//!
//! `PKCS5_pbe2_set_scrypt` is the PKCS#5 v2.0 builder: it validates the scrypt parameters by asking
//! the KDF (with no output buffer) whether they are acceptable, builds the cipher's identifier and
//! IV, and hangs a `SCRYPT_PARAMS` key-derivation function off it. Every allocation failure raises
//! `ERR_R_ASN1_LIB`, and the two parameter refusals raise `ASN1_R_INVALID_SCRYPT_PARAMETERS` and
//! `ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER`. `pkcs5_scrypt_set` is the helper that packs the
//! `SCRYPT_PARAMS` into the key function's parameter.
//!
//! ## `keylen` is only set for RC2
//!
//! The authority assigns `keylen` from the cipher's key length **only when the algorithm is
//! `NID_rc2_cbc`**; every other cipher leaves it zero, so no `keyLength` is encoded. That is not
//! tidiness: a `keyLength` column on a non-RC2 scheme would be a different `SCRYPT_PARAMS` and a
//! different DER document, so it is reproduced rather than generalised.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_new, ASN1_TYPE_pack_sequence};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::p5_pbev2::{PBE2PARAM_free, PBE2PARAM_it, PBE2PARAM_new, Pbe2Param};
use crate::asn1::prim::{ASN1_INTEGER_set_int64, ASN1_INTEGER_set_uint64};
use crate::asn1::string::{ASN1_INTEGER_new, ASN1_STRING_set};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_free, X509_ALGOR_new};
use crate::evp::cipher::{
    EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length, EVP_CIPHER_get_type, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_param_to_asn1, EVP_CipherInit_ex,
    EvpCipherCtx,
};
use crate::evp::pbe::EVP_PBE_scrypt;
use crate::rand::rand_lib::RAND_bytes;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{NID_id_scrypt, NID_pbes2, NID_rc2_cbc, NID_undef, OBJ_nid2obj};

/// `PKCS5_DEFAULT_PBE2_SALT_LEN` — `include/crypto/evp.h:27`, `16`. Declared here rather than
/// imported because `src/asn1/p5_pbev2.rs` keeps its copy private to that unit; the value is a
/// header constant, not an implementation detail.
const PKCS5_DEFAULT_PBE2_SALT_LEN: c_int = 16;

/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;

/// `SCRYPT_PARAMS` — `crypto/asn1/p5_scrypt.c:21-27`.
///
/// `#[repr(C)]` because the template reaches the fields by *offset*: the offsets below are asserted
/// against this declaration rather than assumed from it. The type is public because
/// [`SCRYPT_PARAMS_new`] and its two codecs are; the fields are the item layer's own.
#[repr(C)]
pub struct ScryptParams {
    /// `ASN1_SIMPLE(SCRYPT_PARAMS, salt, ASN1_OCTET_STRING)` — a pointer, at offset 0.
    salt: *mut Asn1String,
    /// `ASN1_SIMPLE(SCRYPT_PARAMS, costParameter, ASN1_INTEGER)` — at offset 8.
    cost_parameter: *mut Asn1String,
    /// `ASN1_SIMPLE(SCRYPT_PARAMS, blockSize, ASN1_INTEGER)` — at offset 16.
    block_size: *mut Asn1String,
    /// `ASN1_SIMPLE(SCRYPT_PARAMS, parallelizationParameter, ASN1_INTEGER)` — at offset 24.
    parallelization_parameter: *mut Asn1String,
    /// `ASN1_OPT(SCRYPT_PARAMS, keyLength, ASN1_INTEGER)` — at offset 32.
    key_length: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<ScryptParams>() == 40);
    assert!(core::mem::offset_of!(ScryptParams, salt) == 0);
    assert!(core::mem::offset_of!(ScryptParams, cost_parameter) == 8);
    assert!(core::mem::offset_of!(ScryptParams, block_size) == 16);
    assert!(core::mem::offset_of!(ScryptParams, parallelization_parameter) == 24);
    assert!(core::mem::offset_of!(ScryptParams, key_length) == 32);
};

/// `scrypt_params_seq_tt` — `crypto/asn1/p5_scrypt.c:21-27`'s five fields, the last optional.
static SCRYPT_PARAMS_TT: [Asn1Template; 5] = [
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
        field_name: c"costParameter".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"blockSize".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"parallelizationParameter".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 32,
        field_name: c"keyLength".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `SCRYPT_PARAMS_it`'s descriptor — `ASN1_SEQUENCE_END(SCRYPT_PARAMS)` at
/// `crypto/asn1/p5_scrypt.c:29`.
static SCRYPT_PARAMS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: SCRYPT_PARAMS_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<ScryptParams>() as c_long,
    sname: c"SCRYPT_PARAMS".as_ptr(),
};

/// `const ASN1_ITEM *SCRYPT_PARAMS_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END(SCRYPT_PARAMS)`.
#[no_mangle]
pub extern "C" fn SCRYPT_PARAMS_it() -> *const Asn1Item {
    &SCRYPT_PARAMS_ITEM
}

/// `SCRYPT_PARAMS *SCRYPT_PARAMS_new(void)` — `crypto/asn1/p5_scrypt.c:31`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(SCRYPT_PARAMS)`.
#[no_mangle]
pub extern "C" fn SCRYPT_PARAMS_new() -> *mut ScryptParams {
    // SAFETY: `SCRYPT_PARAMS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(SCRYPT_PARAMS_it()) }.cast::<ScryptParams>()
}

/// `void SCRYPT_PARAMS_free(SCRYPT_PARAMS *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn SCRYPT_PARAMS_free(a: *mut ScryptParams) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), SCRYPT_PARAMS_it()) }
}

/// `SCRYPT_PARAMS *d2i_SCRYPT_PARAMS(SCRYPT_PARAMS **a, const unsigned char **in, long len)` —
/// the macro's generated decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_SCRYPT_PARAMS(
    a: *mut *mut ScryptParams,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut ScryptParams {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, SCRYPT_PARAMS_it()).cast::<ScryptParams>() }
}

/// `int i2d_SCRYPT_PARAMS(const SCRYPT_PARAMS *a, unsigned char **out)` — the macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_SCRYPT_PARAMS(
    a: *const ScryptParams,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, SCRYPT_PARAMS_it()) }
}

/// `static X509_ALGOR *pkcs5_scrypt_set(const unsigned char *salt, int saltlen, size_t keylen,
/// uint64_t N, uint64_t r, uint64_t p)` — `crypto/asn1/p5_scrypt.c:158-237`.
///
/// Packs a `SCRYPT_PARAMS` into `id-scrypt`'s `AlgorithmIdentifier`: an optional salt (drawn when
/// absent), the three cost parameters and, only for a positive `keylen`, the optional key length.
///
/// # Safety
/// `salt` is NULL or `saltlen` readable bytes.
unsafe fn pkcs5_scrypt_set(
    salt: *const c_uchar,
    saltlen: c_int,
    keylen: usize,
    n: u64,
    r: u64,
    p: u64,
) -> *mut X509Algor {
    let mut keyfunc: *mut X509Algor = ptr::null_mut();
    // SAFETY: `SCRYPT_PARAMS_it()` is a static item the crate owns.
    let sparam = unsafe { ASN1_item_new(SCRYPT_PARAMS_it()) }.cast::<ScryptParams>();

    if sparam.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_166) };
        // SAFETY: `sparam` is NULL here and `keyfunc` is NULL.
        return unsafe { scrypt_err(sparam.cast(), keyfunc) };
    }

    let saltlen = if saltlen == 0 {
        PKCS5_DEFAULT_PBE2_SALT_LEN
    } else {
        saltlen
    };

    /* "This will either copy salt or grow the buffer." With a NULL `salt` the length still
     * allocates, and `saltlen` bytes are then drawn into it below. */
    // SAFETY: `sparam` is live and its `salt` is the item's own integer; `salt` is NULL or
    // `saltlen` readable bytes.
    if unsafe { ASN1_STRING_set((*sparam).salt, salt.cast::<c_void>(), saltlen) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_175) };
        // SAFETY: `sparam` is this frame's own and `keyfunc` is NULL.
        return unsafe { scrypt_err(sparam.cast(), keyfunc) };
    }

    // SAFETY: `salt` was NULL and `salt`'s string now owns at least `saltlen` writable bytes.
    if salt.is_null() && unsafe { RAND_bytes((*(*sparam).salt).data, saltlen) } <= 0 {
        // SAFETY: `sparam` is this frame's own and `keyfunc` is NULL.
        return unsafe { scrypt_err(sparam.cast(), keyfunc) };
    }

    // SAFETY: `sparam` is live and each integer is non-NULL after a fresh `ASN1_item_new`.
    if unsafe {
        ASN1_INTEGER_set_uint64((*sparam).cost_parameter, n) == 0
            || ASN1_INTEGER_set_uint64((*sparam).block_size, r) == 0
            || ASN1_INTEGER_set_uint64((*sparam).parallelization_parameter, p) == 0
    } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_193) };
        // SAFETY: `sparam` is this frame's own and `keyfunc` is NULL.
        return unsafe { scrypt_err(sparam.cast(), keyfunc) };
    }

    /* "If have a key len set it up." */
    if keylen > 0 {
        let key_length = ASN1_INTEGER_new();
        // SAFETY: `sparam` is live and its `key_length` slot is this frame's.
        unsafe { (*sparam).key_length = key_length };
        if key_length.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::P5_SCRYPT_202) };
            // SAFETY: `sparam` is this frame's own and `keyfunc` is NULL.
            return unsafe { scrypt_err(sparam.cast(), keyfunc) };
        }
        // SAFETY: `key_length` is live.
        if unsafe { ASN1_INTEGER_set_int64(key_length, keylen as i64) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::P5_SCRYPT_206) };
            // SAFETY: `sparam` is this frame's own and `keyfunc` is NULL.
            return unsafe { scrypt_err(sparam.cast(), keyfunc) };
        }
    }

    /* "Finally setup the keyfunc structure." */
    // SAFETY: no preconditions.
    keyfunc = X509_ALGOR_new();
    if keyfunc.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_215) };
        // SAFETY: `sparam` is this frame's own and `keyfunc` is NULL.
        return unsafe { scrypt_err(sparam.cast(), keyfunc) };
    }

    // SAFETY: `keyfunc` is a fresh identifier whose algorithm slot this frame writes.
    unsafe { (*keyfunc).algorithm = OBJ_nid2obj(NID_id_scrypt) };

    /* "Encode SCRYPT_PARAMS into parameter of pbe2." */
    // SAFETY: `sparam` and `keyfunc` are live; the item is this file's own static.
    if unsafe {
        ASN1_TYPE_pack_sequence(
            SCRYPT_PARAMS_it(),
            sparam.cast::<c_void>(),
            &mut (*keyfunc).parameter,
        )
    }
    .is_null()
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_226) };
        // SAFETY: `sparam` is this frame's own and `keyfunc` is live.
        return unsafe { scrypt_err(sparam.cast(), keyfunc) };
    }

    // SAFETY: `sparam` is this frame's own; the pack copied it into the parameter.
    unsafe { ASN1_item_free(sparam.cast::<c_void>(), SCRYPT_PARAMS_it()) };
    keyfunc
}

/// The authority's `err:` tail of [`pkcs5_scrypt_set`]: release the decode and the answer, answer
/// NULL.
///
/// # Safety
/// `sparam` is NULL or this frame's own decode; `keyfunc` is NULL or this frame's own identifier.
unsafe fn scrypt_err(sparam: *mut ScryptParams, keyfunc: *mut X509Algor) -> *mut X509Algor {
    // SAFETY: both are NULL or live per the contract.
    unsafe {
        ASN1_item_free(sparam.cast::<c_void>(), SCRYPT_PARAMS_it());
        X509_ALGOR_free(keyfunc);
    }
    ptr::null_mut()
}

/// The authority's `err:` tail of [`PKCS5_pbe2_set_scrypt`]: the `PBE2PARAM` (which owns `scheme`),
/// the answer and the cipher context.
///
/// # Safety
/// Each pointer is NULL or live and owned by the caller.
unsafe fn pbe2_err(
    ctx: *mut EvpCipherCtx,
    pbe2: *mut Pbe2Param,
    ret: *mut X509Algor,
) -> *mut X509Algor {
    // SAFETY: all three are NULL or live per the contract.
    unsafe {
        PBE2PARAM_free(pbe2);
        X509_ALGOR_free(ret);
        EVP_CIPHER_CTX_free(ctx);
    }
    ptr::null_mut()
}

/// `X509_ALGOR *PKCS5_pbe2_set_scrypt(const EVP_CIPHER *cipher, const unsigned char *salt,
/// int saltlen, unsigned char *aiv, uint64_t N, uint64_t r, uint64_t p)` —
/// `crypto/asn1/p5_scrypt.c:41-156`.
///
/// The PKCS#5 v2.0 `PBES2` identifier for a scrypt key-derivation function. The parameter check is
/// the authority's *probe*: `EVP_PBE_scrypt(NULL, 0, NULL, 0, N, r, p, 0, NULL, 0)` throws its key
/// away and is asked only whether the parameters are acceptable, so a court's scrypt sees two
/// derivations per successful call and one per refusal.
///
/// A NULL `aiv` draws the IV with `RAND_bytes`, so a deterministic caller must pass one.
///
/// # Safety
/// `cipher` is NULL or a live cipher; `salt` is NULL or `saltlen` readable bytes; `aiv` is NULL or
/// an IV-length readable buffer.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe2_set_scrypt(
    cipher: *const EvpCipher,
    salt: *const c_uchar,
    saltlen: c_int,
    aiv: *mut c_uchar,
    n: u64,
    r: u64,
    p: u64,
) -> *mut X509Algor {
    let mut ret: *mut X509Algor = ptr::null_mut();
    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    let mut iv = [0 as c_uchar; EVP_MAX_IV_LENGTH];
    let mut pbe2: *mut Pbe2Param = ptr::null_mut();

    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_54) };
        // SAFETY: all three are NULL here.
        return unsafe { pbe2_err(ctx, pbe2, ret) };
    }

    // SAFETY: the two NULLs are the authority's "probe the parameters" call, with no output buffer.
    if unsafe {
        EVP_PBE_scrypt(
            ptr::null(),
            0,
            ptr::null(),
            0,
            n,
            r,
            p,
            0,
            ptr::null_mut(),
            0,
        )
    } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_59) };
        // SAFETY: all three are NULL here.
        return unsafe { pbe2_err(ctx, pbe2, ret) };
    }

    // SAFETY: `cipher` is live per the check above.
    let alg_nid = unsafe { EVP_CIPHER_get_type(cipher) };
    if alg_nid == NID_undef {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_65) };
        // SAFETY: all three are NULL here.
        return unsafe { pbe2_err(ctx, pbe2, ret) };
    }

    // SAFETY: no preconditions.
    pbe2 = PBE2PARAM_new();
    if pbe2.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_SCRYPT_71) };
        // SAFETY: `ctx` and `ret` are NULL here.
        return unsafe { pbe2_err(ctx, pbe2, ret) };
    }

    /* "Setup the AlgorithmIdentifier for the encryption scheme." `scheme` is the embedded
     * `encryption` slot `PBE2PARAM_new` allocated; it is owned by `pbe2`. */
    // SAFETY: `pbe2` is a fresh value whose two algorithm slots the item layer allocated.
    unsafe {
        let scheme = (*pbe2).encryption;
        (*scheme).algorithm = OBJ_nid2obj(alg_nid);
        (*scheme).parameter = ASN1_TYPE_new();
        if (*scheme).parameter.is_null() {
            raise_site(&err_sites::P5_SCRYPT_81);
            return pbe2_err(ctx, pbe2, ret);
        }

        /* "Create random IV." A caller-supplied `aiv` keeps the output deterministic. */
        let ivlen = EVP_CIPHER_get_iv_length(cipher);
        if ivlen > 0 {
            if !aiv.is_null() {
                ptr::copy_nonoverlapping(aiv, iv.as_mut_ptr(), ivlen as usize);
            } else if RAND_bytes(iv.as_mut_ptr(), ivlen) <= 0 {
                return pbe2_err(ctx, pbe2, ret);
            }
        }

        ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            raise_site(&err_sites::P5_SCRYPT_96);
            return pbe2_err(ctx, pbe2, ret);
        }

        /* "Dummy cipherinit to just setup the IV." */
        if EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), iv.as_ptr(), 0) == 0 {
            return pbe2_err(ctx, pbe2, ret);
        }
        if EVP_CIPHER_param_to_asn1(ctx, (*scheme).parameter) <= 0 {
            raise_site(&err_sites::P5_SCRYPT_104);
            return pbe2_err(ctx, pbe2, ret);
        }
        EVP_CIPHER_CTX_free(ctx);
        ctx = ptr::null_mut();

        /* "If its RC2 then we'd better setup the key length." Every other cipher leaves this at
         * zero, so no `keyLength` is encoded. */
        let keylen = if alg_nid == NID_rc2_cbc {
            EVP_CIPHER_get_key_length(cipher) as usize
        } else {
            0
        };

        /* "Setup keyfunc." */
        X509_ALGOR_free((*pbe2).keyfunc);
        (*pbe2).keyfunc = pkcs5_scrypt_set(salt, saltlen, keylen, n, r, p);
        if (*pbe2).keyfunc.is_null() {
            raise_site(&err_sites::P5_SCRYPT_122);
            return pbe2_err(ctx, pbe2, ret);
        }

        /* "Now set up top level AlgorithmIdentifier." */
        ret = X509_ALGOR_new();
        if ret.is_null() {
            raise_site(&err_sites::P5_SCRYPT_130);
            return pbe2_err(ctx, pbe2, ret);
        }

        (*ret).algorithm = OBJ_nid2obj(NID_pbes2);

        /* "Encode PBE2PARAM into parameter." */
        if ASN1_TYPE_pack_sequence(PBE2PARAM_it(), pbe2.cast::<c_void>(), &mut (*ret).parameter)
            .is_null()
        {
            raise_site(&err_sites::P5_SCRYPT_141);
            return pbe2_err(ctx, pbe2, ret);
        }

        PBE2PARAM_free(pbe2);
    }
    ret
}
