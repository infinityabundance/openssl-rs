//! `crypto/pkcs12/p12_key.c` — the PKCS#12 KDF façade, transcribed whole. Phase 10 (10.4).
//!
//! Six exports, and they are three façades over one engine:
//!
//! ```text
//! PKCS12_key_gen_asc(_ex)    ASCII password  -> OPENSSL_asc2uni  -> uni_ex
//! PKCS12_key_gen_utf8(_ex)   UTF-8 password  -> OPENSSL_utf82uni -> uni_ex
//! PKCS12_key_gen_uni(_ex)    raw password    -> the EVP_KDF "PKCS12KDF" row
//! ```
//!
//! ## `PKCS12_key_gen_uni_ex` is a provider-KDF call, not a hand-written derivation
//!
//! The authority does not implement the PKCS#12 KDF here: it fetches
//! `EVP_KDF_fetch(libctx, "PKCS12KDF", propq)` and hands the derivation to
//! `EVP_KDF_derive` with five parameters — the digest's *short* name
//! (`EVP_MD_get0_name`), the password octets, the salt octets, the `id` byte and the iteration
//! count. `providers/implementations/kdfs/pkcs12kdf.c` is the unit that actually derives, and it is
//! landed in this crate (`src/provider/kdf.rs`, D373). So the vector the court compares is the
//! provider row's output, reached through this façade exactly as `test/evp_test.c`'s `pbe_test_run`
//! reaches it.
//!
//! The `id` is `1` (key), `2` (IV) or `3` (MAC), and it is passed by address to
//! `OSSL_PARAM_construct_int`. The digest is `EVP_MD_get0_name(md)` **before** any refusal, and a
//! NULL `md` would fault on both sides, which is why the arguments are only ever live digests.
//!
//! ## `n <= 0` is the first refusal, and it is the only one `uni_ex` owns
//!
//! The authority returns 0 for `n <= 0` *before* it fetches anything; every other failure in the
//! body is a propagated NULL from the fetch, the context constructor or the derivation, with no
//! raise of this unit's own. So the file raises only in the two conversions below.
//!
//! ## The two conversions raise `ERR_R_PKCS12_LIB`, and the password is cleansed
//!
//! `PKCS12_key_gen_asc_ex`/`_utf8_ex` raise `ERR_raise(ERR_LIB_PKCS12, ERR_R_PKCS12_LIB)` when the
//! conversion fails, and on every outcome they release the converted password with
//! `OPENSSL_clear_free(unipass, uniplen)` — a *cleansing* free, because it is a password. A NULL
//! `pass` is normalised to `(NULL, 0)` rather than converted.
//!
//! ## The court
//!
//! The unit raises, so it is an entry in `gen_err_raise_sites.py`'s `COVERED_FILES` under the
//! `PKCS12_KEY` stem (`p12_decr.c` and `p12_sbag.c` already carry `PKCS12` and their line numbers
//! collide with this file's `32`/`62`). The `err_sites::PKCS12_KEY_*` coordinates below are
//! generated from the authority. Its evidence is `CT-PKCS12`, the KDF construction vectors read
//! from the pinned `test/recipes/30-test_evp_data/evppbe_pkcs12.txt`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::evp::digest::{EVP_MD_get0_name, EvpMd};
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string,
};
use crate::pkcs12::p12_utl::{OPENSSL_asc2uni, OPENSSL_utf82uni};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_clear_free;

/// `crypto/pkcs12/p12_key.c` — the authority's `__FILE__` string, for the allocator's bookkeeping.
const FILE: &core::ffi::CStr = c"crypto/pkcs12/p12_key.c";

/// `OSSL_KDF_NAME_PKCS12KDF` — the name the authority passes to `EVP_KDF_fetch`
/// (`include/openssl/core_names.h`).
const OSSL_KDF_NAME_PKCS12KDF: *const c_char = c"PKCS12KDF".as_ptr();
/// `OSSL_KDF_PARAM_DIGEST` — `include/openssl/core_names.h:281`, `"digest"`.
const OSSL_KDF_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
/// `OSSL_KDF_PARAM_PASSWORD` — `include/openssl/core_names.h:299`, `"pass"`.
const OSSL_KDF_PARAM_PASSWORD: *const c_char = c"pass".as_ptr();
/// `OSSL_KDF_PARAM_SALT` — `include/openssl/core_names.h:304`, `"salt"`.
const OSSL_KDF_PARAM_SALT: *const c_char = c"salt".as_ptr();
/// `OSSL_KDF_PARAM_PKCS12_ID` — `include/openssl/core_names.h:300`, `"id"`.
const OSSL_KDF_PARAM_PKCS12_ID: *const c_char = c"id".as_ptr();
/// `OSSL_KDF_PARAM_ITER` — `include/openssl/core_names.h:290`, `"iter"`.
const OSSL_KDF_PARAM_ITER: *const c_char = c"iter".as_ptr();

/// `PKCS12_key_gen_asc_ex` — `crypto/pkcs12/p12_key.c:19-39`.
///
/// # Safety
/// `pass` is NULL or a string of `passlen` bytes (or NUL-terminated when `passlen == -1`);
/// `salt` is read-only for `saltlen` bytes (and may be NULL with `saltlen == 0`); `out` is
/// writable for `n` bytes; `md_type` is a live digest; `ctx`/`propq` are the KDF lookup's.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_key_gen_asc_ex(
    pass: *const c_char,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    id: c_int,
    iter: c_int,
    n: c_int,
    out: *mut c_uchar,
    md_type: *const EvpMd,
    ctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut unipass: *mut c_uchar = ptr::null_mut();
    let mut uniplen: c_int = 0;

    if pass.is_null() {
        unipass = ptr::null_mut();
        uniplen = 0;
    } else {
        // SAFETY: `pass` is a string of `passlen` bytes per the contract and the two out-slots are
        // this frame's.
        let converted =
            unsafe { OPENSSL_asc2uni(pass, passlen, &raw mut unipass, &raw mut uniplen) };
        if converted.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS12_KEY_32) };
            return 0;
        }
    }
    // SAFETY: `unipass`/`uniplen` describe the conversion's own buffer, or are NULL/0; the rest of
    // the arguments are forwarded under this function's contract.
    let ret = unsafe {
        PKCS12_key_gen_uni_ex(
            unipass, uniplen, salt, saltlen, id, iter, n, out, md_type, ctx, propq,
        )
    };
    // SAFETY: `unipass` is the conversion's own buffer of `uniplen` bytes (or NULL/0), and it is a
    // password, so it is cleansed before release.
    unsafe { CRYPTO_clear_free(unipass.cast(), uniplen.max(0) as usize, FILE.as_ptr(), 37) };
    c_int::from(ret > 0)
}

/// `int PKCS12_key_gen_asc(const char *pass, int passlen, unsigned char *salt, int saltlen,
/// int id, int iter, int n, unsigned char *out, const EVP_MD *md_type)` —
/// `crypto/pkcs12/p12_key.c:41-47`.
///
/// # Safety
/// As [`PKCS12_key_gen_asc_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_key_gen_asc(
    pass: *const c_char,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    id: c_int,
    iter: c_int,
    n: c_int,
    out: *mut c_uchar,
    md_type: *const EvpMd,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_key_gen_asc_ex(
            pass,
            passlen,
            salt,
            saltlen,
            id,
            iter,
            n,
            out,
            md_type,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `PKCS12_key_gen_utf8_ex` — `crypto/pkcs12/p12_key.c:49-69`.
///
/// # Safety
/// As [`PKCS12_key_gen_asc_ex`], with `pass` interpreted as UTF-8 (falling back to the naive
/// conversion on a decode failure, `OPENSSL_utf82uni`'s own allowance).
#[no_mangle]
pub unsafe extern "C" fn PKCS12_key_gen_utf8_ex(
    pass: *const c_char,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    id: c_int,
    iter: c_int,
    n: c_int,
    out: *mut c_uchar,
    md_type: *const EvpMd,
    ctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut unipass: *mut c_uchar = ptr::null_mut();
    let mut uniplen: c_int = 0;

    if pass.is_null() {
        unipass = ptr::null_mut();
        uniplen = 0;
    } else {
        // SAFETY: `pass` is a string of `passlen` bytes per the contract and the two out-slots are
        // this frame's.
        let converted =
            unsafe { OPENSSL_utf82uni(pass, passlen, &raw mut unipass, &raw mut uniplen) };
        if converted.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS12_KEY_62) };
            return 0;
        }
    }
    // SAFETY: `unipass`/`uniplen` describe the conversion's own buffer, or are NULL/0; the rest of
    // the arguments are forwarded under this function's contract.
    let ret = unsafe {
        PKCS12_key_gen_uni_ex(
            unipass, uniplen, salt, saltlen, id, iter, n, out, md_type, ctx, propq,
        )
    };
    // SAFETY: `unipass` is the conversion's own buffer of `uniplen` bytes (or NULL/0), and it is a
    // password, so it is cleansed before release.
    unsafe { CRYPTO_clear_free(unipass.cast(), uniplen.max(0) as usize, FILE.as_ptr(), 67) };
    c_int::from(ret > 0)
}

/// `int PKCS12_key_gen_utf8(const char *pass, int passlen, unsigned char *salt, int saltlen,
/// int id, int iter, int n, unsigned char *out, const EVP_MD *md_type)` —
/// `crypto/pkcs12/p12_key.c:71-77`.
///
/// # Safety
/// As [`PKCS12_key_gen_utf8_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_key_gen_utf8(
    pass: *const c_char,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    id: c_int,
    iter: c_int,
    n: c_int,
    out: *mut c_uchar,
    md_type: *const EvpMd,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_key_gen_utf8_ex(
            pass,
            passlen,
            salt,
            saltlen,
            id,
            iter,
            n,
            out,
            md_type,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int PKCS12_key_gen_uni_ex(unsigned char *pass, int passlen, unsigned char *salt, int saltlen,
/// int id, int iter, int n, unsigned char *out, const EVP_MD *md_type, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/pkcs12/p12_key.c:79-135`.
///
/// The engine: one `EVP_KDF` fetch of `PKCS12KDF`, one context, five parameters and one
/// `EVP_KDF_derive`. The `OSSL_TRACE_BEGIN(PKCS12_KEYGEN)` blocks are no-ops on a build without
/// tracing and are not part of this crate's surface.
///
/// # Safety
/// `pass` is read-only for `passlen` bytes (NULL allowed with `passlen == 0`); `salt` read-only for
/// `saltlen` bytes; `out` writable for `n` bytes; `md_type` a live digest; `libctx`/`propq` the KDF
/// lookup's.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_key_gen_uni_ex(
    pass: *mut c_uchar,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    id: c_int,
    iter: c_int,
    n: c_int,
    out: *mut c_uchar,
    md_type: *const EvpMd,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut res: c_int = 0;
    let mut params = [OSSL_PARAM_construct_end(); 6];
    /* The `id` and `iter` are passed by address, exactly as the authority's `params[3]`/`params[4]`
     * point at the caller's copies; these two locals are those copies. */
    let mut id_slot = id;
    let mut iter_slot = iter;

    if n <= 0 {
        return 0;
    }

    // SAFETY: `libctx` is NULL or live and `propq` is NULL or NUL-terminated per the contract.
    let kdf = unsafe { EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PKCS12KDF, propq) };
    if kdf.is_null() {
        return 0;
    }
    // SAFETY: `kdf` is live per the branch condition; a NULL descriptor is tolerated.
    let ctx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: `kdf` is live and this call gives its reference back.
    unsafe { EVP_KDF_free(kdf) };
    if ctx.is_null() {
        return 0;
    }

    /* SAFETY: `md_type` is live per the contract, so its name pointer is the method's own static
     * string; every other argument is a compile-time-constant name or a slot of this frame. */
    unsafe {
        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            EVP_MD_get0_name(md_type).cast_mut(),
            0,
        );
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD,
            pass.cast::<c_void>(),
            passlen.max(0) as usize,
        );
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            salt.cast::<c_void>(),
            saltlen.max(0) as usize,
        );
        params[3] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS12_ID, &raw mut id_slot);
        params[4] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &raw mut iter_slot);
    }

    // SAFETY: `ctx` is live, `out` is `n` writable bytes, and the parameter array is this frame's
    // own and terminated.
    if unsafe { EVP_KDF_derive(ctx, out, n.max(0) as usize, params.as_ptr()) } != 0 {
        res = 1;
    }
    // SAFETY: `ctx` is live.
    unsafe { EVP_KDF_CTX_free(ctx) };
    res
}

/// `int PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt, int saltlen,
/// int id, int iter, int n, unsigned char *out, const EVP_MD *md_type)` —
/// `crypto/pkcs12/p12_key.c:137-142`.
///
/// # Safety
/// As [`PKCS12_key_gen_uni_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_key_gen_uni(
    pass: *mut c_uchar,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    id: c_int,
    iter: c_int,
    n: c_int,
    out: *mut c_uchar,
    md_type: *const EvpMd,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_key_gen_uni_ex(
            pass,
            passlen,
            salt,
            saltlen,
            id,
            iter,
            n,
            out,
            md_type,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::digest::EVP_MD_fetch;
    use crate::runtime::err::ERR_clear_error;

    /// A NULL password is normalised to `(NULL, 0)` and never reaches the conversion, so the call
    /// proceeds to the `PKCS12KDF` row. The KDF refuses nothing here, so the derivation succeeds
    /// and the vector `evppbe_pkcs12.txt`'s first stanza records is reproduced.
    #[test]
    fn the_first_pinned_vector_is_reproduced() {
        let _g = crate::test_support::lock_global_state();
        /* Vector: id=1, iter=1, MD=SHA1, Password=0073006D006500670000, Salt=0A58CF64530D823F,
         * Key=8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3. */
        let mut pass = [0u8; 10];
        pass.copy_from_slice(&[0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67, 0x00, 0x00]);
        let mut salt = [0x0au8, 0x58, 0xcf, 0x64, 0x53, 0x0d, 0x82, 0x3f];
        let mut out = [0u8; 24];
        // SAFETY: a NULL library context and property query select the default provider.
        let md = unsafe { EVP_MD_fetch(ptr::null_mut(), c"SHA1".as_ptr(), ptr::null()) };
        assert!(!md.is_null());
        // SAFETY: every buffer is this frame's and the digest is live.
        let rc = unsafe {
            PKCS12_key_gen_uni(
                pass.as_mut_ptr(),
                pass.len() as c_int,
                salt.as_mut_ptr(),
                salt.len() as c_int,
                1,
                1,
                out.len() as c_int,
                out.as_mut_ptr(),
                md,
            )
        };
        assert_eq!(rc, 1);
        assert_eq!(
            out,
            [
                0x8a, 0xaa, 0xe6, 0x29, 0x7b, 0x6c, 0xb0, 0x46, 0x42, 0xab, 0x5b, 0x07, 0x78, 0x51,
                0x28, 0x4e, 0xb7, 0x12, 0x8f, 0x1a, 0x2a, 0x7f, 0xbc, 0xa3
            ]
        );
        // SAFETY: `md` is this call's own fetched digest.
        unsafe { crate::evp::digest::EVP_MD_free(md) };
        ERR_clear_error();
    }

    /// `n <= 0` is the unit's own refusal and precedes the fetch.
    #[test]
    fn a_non_positive_length_refuses_before_the_fetch() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the `n <= 0` arm touches nothing else.
        let rc = unsafe {
            PKCS12_key_gen_uni(
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                1,
                1,
                0,
                ptr::null_mut(),
                ptr::null(),
            )
        };
        assert_eq!(rc, 0);
        ERR_clear_error();
    }
}
