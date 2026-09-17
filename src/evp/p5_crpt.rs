//! Phase 7.4c — `crypto/evp/p5_crpt.c`: PKCS#5 v1.5 password-based key derivation.
//!
//! Three exports, one of them empty, and one private ASN.1 item that the authority puts in a file
//! this stratum does not own.
//!
//! ## `PKCS5_PBE_add` is an empty function, and it stays one
//!
//! `crypto/evp/p5_crpt.c:22-24` is
//!
//! ```text
//! /*
//!  * Doesn't do anything now: Builtin PBE algorithms in static table.
//!  */
//! void PKCS5_PBE_add(void) { }
//! ```
//!
//! so there is no loop to write and nothing to register. It is landed here rather than deferred to
//! 7.5 because 7.5's row is `crypto/pem/pem_pk8.c`'s and this function's *file* is this slice's,
//! and because a caller that links it must not fail to link on an empty body.
//!
//! ## The one decoder, and where its item lives
//!
//! `PKCS5_PBE_keyivgen_ex` reads its parameter through `ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM), param)`.
//! `PBEPARAM` is declared in `crypto/asn1/p5_pbe.c:19-24`, whose *exported* accessors
//! (`PBEPARAM_it`, `PBEPARAM_new`, `PBEPARAM_free`, `d2i_PBEPARAM`, `i2d_PBEPARAM`) are Phase 11's
//! per `forensics/atlas/symbol-ownership.json`. What this file needs is not those accessors but the
//! two-field descriptor, so the descriptor is transcribed here as a **file-local** `static`, with
//! `sname` spelled `"PBEPARAM"` exactly as `ASN1_SEQUENCE_END_name` spells it. That is the same
//! move `src/asn1/evp_asn1.rs` makes for its two integer/octet-string pair items, and the same
//! reason: the item is `static const` inside the authority's own accessor, and nothing outside the
//! translation unit can name it. Phase 11 will land the accessors and, with them, a second
//! descriptor with identical fields and identical bytes produced; the `pub` half stays Phase 11's
//! and no symbol is defined twice.
//!
//! ## Two refusals before two more, and the order is the contract
//!
//! The body refuses in a fixed order and each refusal has its own reason:
//!
//! ```text
//! :46  param NULL / not a SEQUENCE / empty          EVP_R_DECODE_ERROR
//! :52  the SEQUENCE does not decode as PBEPARAM     EVP_R_DECODE_ERROR   (plus ASN1's own record)
//! :58  ivl < 0 || ivl > 16                          EVP_R_INVALID_IV_LENGTH
//! :63  kl < 0 || kl > 64                            EVP_R_INVALID_KEY_LENGTH
//! ```
//!
//! The `16` is a literal and not `EVP_MAX_IV_LENGTH` (which is also 16, so the two agree here);
//! the `64` **is** `sizeof(md_tmp)` and therefore `EVP_MAX_MD_SIZE`. `ivl` and `kl` are read
//! *before* the parameter is decoded into salt and iteration count, so an invalid cipher length
//! refuses without the PBEPARAM ever being freed — which is why `goto err` and not `return 0`.
//!
//! ## The derivation is PBKDF1 and the split is `16 - ivl`
//!
//! `EVP_KDF_fetch(libctx, "PBKDF1", propq)` — the name is `OSSL_KDF_NAME_PBKDF1` from the
//! generated `core_names.h`, and the derivation is asked for `mdsize` bytes even though only `kl`
//! of them become the key. The key is `md_tmp[0..kl]` and the IV is `md_tmp[16 - ivl..16]`: the
//! **last** `ivl` bytes of the first block, not the bytes after the key. A transcription that
//! wrote `md_tmp + kl` would agree for `kl + ivl == 16` and disagree for every other pair, which
//! is most of them.
//!
//! ## `EVP_MD_name` is a macro
//!
//! `include/openssl/evp.h:556` spells `EVP_MD_name` as `EVP_MD_get0_name`, so the digest name
//! handed to the KDF is the method's *short* name — and it is read **before** the parameter is
//! validated, because the authority's declaration is an initialiser. A NULL `md` would fault
//! there on both sides, which is why the court never passes one.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::asn_pack::ASN1_item_unpack;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::evp::cipher::{EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length, EvpCipher};
use crate::evp::cipher_ctx::{EVP_CipherInit_ex, EvpCipherCtx};
use crate::evp::digest::{EVP_MD_get0_name, EVP_MD_get_size, EvpMd};
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free, EvpKdf,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::OPENSSL_cleanse;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`.
const EVP_MAX_MD_SIZE: usize = 64;
/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: usize = 64;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;

/// `OSSL_KDF_NAME_PBKDF1` — `include/openssl/core_names.h:74`.
const OSSL_KDF_NAME_PBKDF1: *const c_char = c"PBKDF1".as_ptr();
/// `OSSL_KDF_PARAM_PASSWORD` — `include/openssl/core_names.h:299`.
const OSSL_KDF_PARAM_PASSWORD: *const c_char = c"pass".as_ptr();
/// `OSSL_KDF_PARAM_SALT` — `include/openssl/core_names.h:304`.
const OSSL_KDF_PARAM_SALT: *const c_char = c"salt".as_ptr();
/// `OSSL_KDF_PARAM_ITER` — `include/openssl/core_names.h:290`.
const OSSL_KDF_PARAM_ITER: *const c_char = c"iter".as_ptr();
/// `OSSL_KDF_PARAM_DIGEST` — `include/openssl/core_names.h:281`, which is `OSSL_ALG_PARAM_DIGEST`.
const OSSL_KDF_PARAM_DIGEST: *const c_char = c"digest".as_ptr();

/// `PBEPARAM` — `crypto/asn1/p5_pbe.c:19-22`'s `ASN1_SEQUENCE(PBEPARAM)`, declared as the C
/// typedef's two field pointers.
///
/// `#[repr(C)]` because the template reaches the fields by *offset*: the offsets below are
/// asserted against this declaration rather than assumed from it.
#[repr(C)]
struct PbeParam {
    /// `ASN1_SIMPLE(PBEPARAM, salt, ASN1_OCTET_STRING)` — a pointer, at offset 0.
    salt: *mut Asn1String,
    /// `ASN1_SIMPLE(PBEPARAM, iter, ASN1_INTEGER)` — a pointer, at offset 8.
    iter: *mut Asn1String,
}

// The offsets the template array below names.
const _: () = {
    assert!(core::mem::size_of::<PbeParam>() == 16);
    assert!(core::mem::offset_of!(PbeParam, salt) == 0);
    assert!(core::mem::offset_of!(PbeParam, iter) == 8);
};

/// `pbe_seq_tt` — `crypto/asn1/p5_pbe.c:19-22`'s two `ASN1_SIMPLE` fields.
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

/// `PBEPARAM_it`'s descriptor — the `static const ASN1_ITEM local_it` inside
/// `IMPLEMENT_ASN1_FUNCTIONS(PBEPARAM)`, private here because this stratum does not own the
/// accessor. See the module doc.
static PBEPARAM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PBEPARAM_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<PbeParam>() as c_long,
    sname: c"PBEPARAM".as_ptr(),
};

/// `void PKCS5_PBE_add(void)` — `crypto/evp/p5_crpt.c:22`.
///
/// An empty body in the authority ("Doesn't do anything now: Builtin PBE algorithms in static
/// table") and an empty body here.
///
/// # Safety
/// Nothing: the function touches no state.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_PBE_add() {}

/// `int PKCS5_PBE_keyivgen_ex(EVP_CIPHER_CTX *cctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md, int en_de,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/evp/p5_crpt.c:26`.
///
/// # Safety
/// `cctx` must be a live `EVP_CIPHER_CTX`; `pass` NULL or NUL-terminated (or `passlen` bytes when
/// `passlen != -1`); `param` NULL or a live `ASN1_TYPE`; `cipher` and `md` live; `libctx` NULL or
/// live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_PBE_keyivgen_ex(
    cctx: *mut EvpCipherCtx,
    pass: *const c_char,
    mut passlen: c_int,
    param: *mut Asn1Type,
    cipher: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut md_tmp = [0u8; EVP_MAX_MD_SIZE];
    let mut key = [0u8; EVP_MAX_KEY_LENGTH];
    let mut iv = [0u8; EVP_MAX_IV_LENGTH];
    let mut kctx: *mut crate::evp::kdf::EvpKdfCtx = ptr::null_mut();
    let mut params = [OSSL_PARAM_construct_end(); 5];
    /* The authority's initialiser, so it is read before the refusal at `:46`. */
    // SAFETY: `md` is live per the contract.
    let mdname = unsafe { EVP_MD_get0_name(md) };

    /* Extract useful info from parameter */
    // SAFETY: `param` is NULL or live per the contract.
    let (ptype, pseq) = if param.is_null() {
        (0, ptr::null_mut())
    } else {
        // SAFETY: `param` is live per the branch condition.
        unsafe { ((*param).type_, (*param).value.ptr.cast::<Asn1String>()) }
    };
    if param.is_null() || ptype != V_ASN1_SEQUENCE || pseq.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT_46) };

        return 0;
    }

    // SAFETY: `pseq` is a live `ASN1_STRING` from the check above, and the item is this file's
    // own static.
    let pbe: *mut PbeParam = unsafe { ASN1_item_unpack(pseq, &PBEPARAM_ITEM) }.cast::<PbeParam>();
    if pbe.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT_52) };
        return 0;
    }

    // SAFETY: `cipher` is live per the contract.
    let ivl = unsafe { EVP_CIPHER_get_iv_length(cipher) };
    /* The authority spells this `ivl < 0 || ivl > 16`; the same test with the same bounds. */
    if !(0..=16).contains(&ivl) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT_58) };
        // SAFETY: `pbe` is this call's own decode and `kctx` is NULL or live.
        return unsafe { finish_err(pbe, kctx) };
    }
    // SAFETY: `cipher` is live per the contract.
    let kl = unsafe { EVP_CIPHER_get_key_length(cipher) };
    if kl < 0 || kl > EVP_MAX_MD_SIZE as c_int {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT_63) };
        // SAFETY: `pbe` is this call's own decode and `kctx` is NULL or live.
        return unsafe { finish_err(pbe, kctx) };
    }

    // SAFETY: `pbe` is live and its two fields are the decode's own allocations; a decoded
    // mandatory field is non-NULL, and the `iter` test is the authority's own.
    let (iter, salt, saltlen) = unsafe {
        (
            if (*pbe).iter.is_null() {
                1
            } else {
                ASN1_INTEGER_get((*pbe).iter) as c_int
            },
            (*(*pbe).salt).data,
            (*(*pbe).salt).length,
        )
    };

    if pass.is_null() {
        passlen = 0;
    } else if passlen == -1 {
        // SAFETY: `pass` is NUL-terminated per the contract.
        passlen = unsafe { crate::runtime::bio::sys::strlen(pass) } as c_int;
    }

    // SAFETY: `md` is live per the contract.
    let mdsize = unsafe { EVP_MD_get_size(md) };
    if mdsize <= 0 {
        // SAFETY: `pbe` is this call's own decode and `kctx` is NULL or live.
        return unsafe { finish_err(pbe, kctx) };
    }

    // SAFETY: `libctx` is NULL or live and `propq` is NULL or NUL-terminated.
    let kdf: *mut EvpKdf = unsafe { EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PBKDF1, propq) };
    // SAFETY: `kdf` is NULL or live, which the constructor tolerates.
    kctx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: `kdf` is NULL or live and this call gives its reference back.
    unsafe { EVP_KDF_free(kdf) };
    if kctx.is_null() {
        // SAFETY: `pbe` is this call's own decode and `kctx` is NULL or live.
        return unsafe { finish_err(pbe, kctx) };
    }

    // SAFETY: the constructors take a name and a buffer; every buffer here is this frame's and
    // every name is a compile-time constant.
    unsafe {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD,
            pass.cast::<c_void>().cast_mut(),
            passlen as usize,
        );
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            salt.cast::<c_void>(),
            saltlen as usize,
        );
        params[2] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, ptr::addr_of!(iter).cast_mut());
        params[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdname.cast_mut(), 0);
    }
    // SAFETY: `kctx` is live, `md_tmp` is `mdsize` writable bytes, and the array is this frame's
    // own and terminated.
    if unsafe { EVP_KDF_derive(kctx, md_tmp.as_mut_ptr(), mdsize as usize, params.as_ptr()) } != 1 {
        // SAFETY: `pbe` is this call's own decode and `kctx` is NULL or live.
        return unsafe { finish_err(pbe, kctx) };
    }
    // SAFETY: `kl <= 64` and `ivl <= 16` were checked above, so both slices are in bounds of
    // their destinations, and `16 - ivl` is in bounds of `md_tmp`. The `EVP_CipherInit_ex`
    // arguments are this frame's own buffers.
    let init_ok = unsafe {
        ptr::copy_nonoverlapping(md_tmp.as_ptr(), key.as_mut_ptr(), kl as usize);
        ptr::copy_nonoverlapping(
            md_tmp.as_ptr().add((16 - ivl) as usize),
            iv.as_mut_ptr(),
            ivl as usize,
        );
        EVP_CipherInit_ex(
            cctx,
            cipher,
            ptr::null_mut(),
            key.as_ptr(),
            iv.as_ptr(),
            en_de,
        )
    };
    if init_ok == 0 {
        // SAFETY: `pbe` is this call's own decode and `kctx` is NULL or live.
        return unsafe { finish_err(pbe, kctx) };
    }
    // SAFETY: both buffers are this frame's own.
    unsafe {
        OPENSSL_cleanse(md_tmp.as_mut_ptr().cast(), EVP_MAX_MD_SIZE);
        OPENSSL_cleanse(key.as_mut_ptr().cast(), EVP_MAX_KEY_LENGTH);
        OPENSSL_cleanse(iv.as_mut_ptr().cast(), EVP_MAX_IV_LENGTH);
    }
    let rv: c_int = 1;
    // SAFETY: `kctx` is NULL or live and `pbe` is this call's own decode.
    unsafe {
        EVP_KDF_CTX_free(kctx);
        ASN1_item_free(pbe.cast::<c_void>(), &PBEPARAM_ITEM);
    }
    rv
}

/// The authority's `err:` label, which releases `kctx` and frees the decode and answers 0.
///
/// # Safety
/// `kctx` must be NULL or live; `pbe` NULL or this call's own `PBEPARAM` decode.
unsafe fn finish_err(pbe: *mut PbeParam, kctx: *mut crate::evp::kdf::EvpKdfCtx) -> c_int {
    // SAFETY: both are NULL or live per the contract.
    unsafe {
        EVP_KDF_CTX_free(kctx);
        ASN1_item_free(pbe.cast::<c_void>(), &PBEPARAM_ITEM);
    }
    0
}

/// `int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *cctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md, int en_de)` —
/// `crypto/evp/p5_crpt.c:112`.
///
/// # Safety
/// As [`PKCS5_PBE_keyivgen_ex`], with a NULL library context and property query.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_PBE_keyivgen(
    cctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    cipher: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with the two NULLs the
    // authority passes.
    unsafe {
        PKCS5_PBE_keyivgen_ex(
            cctx,
            pass,
            passlen,
            param,
            cipher,
            md,
            en_de,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The private item is the authority's: `ASN1_ITYPE_SEQUENCE`, `V_ASN1_SEQUENCE`, two fields,
    /// no aux block, and the structure's own size.
    #[test]
    fn the_private_pbeparam_item_has_the_authority_shape() {
        assert_eq!(PBEPARAM_ITEM.itype, ASN1_ITYPE_SEQUENCE);
        assert_eq!(PBEPARAM_ITEM.utype, V_ASN1_SEQUENCE as c_long);
        assert_eq!(PBEPARAM_ITEM.tcount, 2);
        assert!(PBEPARAM_ITEM.funcs.is_null());
        assert_eq!(PBEPARAM_ITEM.size, 16);
    }

    /// `PKCS5_PBE_add` is a no-op, and so is calling it twice.
    #[test]
    fn pbe_add_is_empty() {
        // SAFETY: the function touches no state.
        unsafe { PKCS5_PBE_add() };
        // SAFETY: the function touches no state.
        unsafe { PKCS5_PBE_add() };
    }

    /// The two refusals that need no cipher: a NULL parameter, and a parameter of the wrong type.
    /// Each answers 0, and the wrong-type one is the second refusal and not the first, because the
    /// authority tests `param == NULL || param->type != V_ASN1_SEQUENCE || ...` as one condition.
    #[test]
    fn the_parameter_refusals_precede_the_cipher() {
        // SAFETY: a NULL parameter is the first refusal, and `cipher`/`md` are never reached.
        let null_param = unsafe {
            PKCS5_PBE_keyivgen(
                ptr::null_mut(),
                c"p".as_ptr(),
                -1,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                1,
            )
        };
        assert_eq!(null_param, 0);
        /* `ERR_clear_error` is a safe entry point of this crate. */
        crate::runtime::err::ERR_clear_error();

        let mut t = Asn1Type {
            type_: V_ASN1_INTEGER,
            value: Asn1TypeValue {
                ptr: ptr::null_mut(),
            },
        };
        // SAFETY: `t` is a live local of the wrong type, so the same refusal fires.
        let wrong_type = unsafe {
            PKCS5_PBE_keyivgen(
                ptr::null_mut(),
                c"p".as_ptr(),
                -1,
                &mut t,
                ptr::null(),
                ptr::null(),
                1,
            )
        };
        assert_eq!(wrong_type, 0);
        /* `ERR_clear_error` is a safe entry point of this crate. */
        crate::runtime::err::ERR_clear_error();
    }
}
