//! `crypto/srp/srp_lib.c` — the SRP arithmetic. Phase 12.8.
//!
//! The fourteen exports `srp.h` declares — the client- and server-side calculations
//! (`SRP_Calc_A`, `SRP_Calc_B`, `SRP_Calc_server_key`, `SRP_Calc_u`, `SRP_Calc_x`,
//! `SRP_Calc_client_key` and their `_ex` forms), the two verifiers
//! (`SRP_Verify_A_mod_N`, `SRP_Verify_B_mod_N`), and the RFC 5054 group table accessors
//! (`SRP_check_known_gN_param`, `SRP_get_default_gN`) — and the two statics they reach,
//! `srp_Calc_xy` and `srp_Calc_k`.
//!
//! The `knowngN[]` table is the authority's own seven rows in its own order. Its numbers are
//! [`crate::bn::bn_srp`]'s shared constants, so the rows are built once on first use and
//! never mutated — the contract a C `static` array has by construction.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]
// `#[no_mangle] pub extern "C" fn` is the ABI spelling of each export, but the enclosing
// `srp` module is `pub(crate)`, so `unreachable_pub` (a warn this crate promotes with
// `-D warnings`) would otherwise force the ABI part of the way down to `pub(crate)`. This is
// the allow `src/provider/base.rs` records for the same reason.
#![allow(unreachable_pub)]
// The authority's C initialisers (`tmp`, `S`, `cs`, `res`, ...) are dead on the paths that
// reach its `err:` label; the assignments are kept so the transcription reads as the source
// does.
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_uchar, c_void, CStr};
use core::ptr;
use std::sync::OnceLock;

use crate::bn::arith::{
    BN_add, BN_cmp, BN_mod_add, BN_mod_exp, BN_mod_mul, BN_mod_sub, BN_mul, BN_nnmod, BN_ucmp,
};
use crate::bn::bignum::{
    BN_bin2bn, BN_bn2bin, BN_bn2binpad, BN_clear_free, BN_free, BN_is_zero, BN_new, BN_num_bits,
    BN_set_flags, BN_with_flags, BigNum, BN_FLG_CONSTTIME,
};
use crate::bn::bn_srp::{
    ossl_bn_generator_19, ossl_bn_generator_2, ossl_bn_generator_5, ossl_bn_group_1024,
    ossl_bn_group_1536, ossl_bn_group_2048, ossl_bn_group_3072, ossl_bn_group_4096,
    ossl_bn_group_6144, ossl_bn_group_8192,
};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new, BN_CTX_new_ex, BnCtx};
use crate::evp::digest::{
    EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free, EvpMd,
};
use crate::runtime::bio::sys::{strcmp, strlen};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

use super::SrpGN;

/// The authority translation unit for this module.
pub(crate) const FILE: &CStr = c"crypto/srp/srp_lib.c";

/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h`'s 20-byte SHA-1 answer.
const SHA_DIGEST_LENGTH: c_int = 20;

/// `srp_Calc_xy`'s `OPENSSL_malloc_array(numN, 2)` — `crypto/srp/srp_lib.c:42`.
const LINE_MALLOC_TMP: c_int = 42;
/// `srp_Calc_xy`'s `OPENSSL_free(tmp)` — `crypto/srp/srp_lib.c:51`.
const LINE_FREE_TMP: c_int = 51;
/// `SRP_Calc_x_ex`'s `OPENSSL_malloc(BN_num_bytes(s))` — `crypto/srp/srp_lib.c:157`.
const LINE_MALLOC_CS: c_int = 157;
/// `SRP_Calc_x_ex`'s `OPENSSL_free(cs)` — `crypto/srp/srp_lib.c:184`.
const LINE_FREE_CS: c_int = 184;

/// The number of rows in `knowngN[]`, which is `OSSL_NELEM`'s answer for the authority's
/// initialiser — `crypto/srp/srp_lib.c:288-296`.
const KNOWN_GN_NUMBER: usize = 7;

/// `BN_num_bytes(a)` — `include/openssl/bn.h`'s macro `((BN_num_bits(a) + 7) / 8)`, written
/// as its body because a macro has no symbol.
///
/// # Safety
///
/// `a` must be NULL or a live `BIGNUM`.
unsafe fn bn_num_bytes(a: *const BigNum) -> c_int {
    // SAFETY: `a` is NULL or live per the caller's contract.
    (unsafe { BN_num_bits(a) } + 7) / 8
}

/// `calculate = SHA1(PAD(x) || PAD(y))` — `crypto/srp/srp_lib.c:26-53`.
///
/// # Safety
///
/// `x`, `y` and `N` must be NULL or live `BIGNUM`s; `libctx` NULL or a live library context;
/// `propq` NULL or NUL-terminated.
unsafe fn srp_Calc_xy(
    x: *const BigNum,
    y: *const BigNum,
    N: *const BigNum,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut BigNum {
    let mut digest = [0u8; SHA_DIGEST_LENGTH as usize];
    let mut res: *mut BigNum = ptr::null_mut();
    // SAFETY: the arguments are the caller's and are forwarded under this function's contract.
    let sha1: *mut EvpMd = unsafe { EVP_MD_fetch(libctx, c"SHA1".as_ptr(), propq) };
    if sha1.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `N` is NULL or live per the contract.
    let numN = unsafe { bn_num_bytes(N) };
    let mut tmp: *mut c_uchar = ptr::null_mut();
    'done: {
        // `x != N` is the authority's pointer comparison: a straddling `x` is already
        // reduced modulo `N`.
        if x != N
            // SAFETY: `x` and `N` are NULL or live per the contract.
            && unsafe { BN_ucmp(x, N) } >= 0
        {
            break 'done;
        }
        if y != N
            // SAFETY: `y` and `N` are NULL or live per the contract.
            && unsafe { BN_ucmp(y, N) } >= 0
        {
            break 'done;
        }
        // The allocation is `numN * 2` bytes, the authority's `OPENSSL_malloc_array`.
        tmp = CRYPTO_malloc((numN as usize) * 2, FILE.as_ptr(), LINE_MALLOC_TMP).cast::<c_uchar>();
        if tmp.is_null() {
            break 'done;
        }
        // SAFETY: `x`/`y` are NULL or live; `tmp` is a live buffer of `numN * 2` bytes; the
        // digest buffer is `SHA_DIGEST_LENGTH` bytes and `sha1` is the fetched method.
        let ok = unsafe {
            BN_bn2binpad(x, tmp, numN) >= 0
                && BN_bn2binpad(y, tmp.add(numN as usize), numN) >= 0
                && EVP_Digest(
                    tmp.cast(),
                    (numN as usize) * 2,
                    digest.as_mut_ptr(),
                    ptr::null_mut(),
                    sha1,
                    ptr::null_mut(),
                ) != 0
        };
        if !ok {
            break 'done;
        }
        // SAFETY: the digest buffer is live and `SHA_DIGEST_LENGTH` bytes long.
        res = unsafe { BN_bin2bn(digest.as_ptr(), SHA_DIGEST_LENGTH, ptr::null_mut()) };
    }
    // SAFETY: `sha1` came from `EVP_MD_fetch`; `tmp` from `CRYPTO_malloc` (or is NULL).
    unsafe {
        EVP_MD_free(sha1);
        CRYPTO_free(tmp.cast(), FILE.as_ptr(), LINE_FREE_TMP);
    }
    res
}

/// `k = SHA1(N | PAD(g))` — tls-srp RFC 5054. `crypto/srp/srp_lib.c:55-61`.
///
/// # Safety
///
/// As [`srp_Calc_xy`].
unsafe fn srp_Calc_k(
    N: *const BigNum,
    g: *const BigNum,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut BigNum {
    // SAFETY: forwarded under this function's contract.
    unsafe { srp_Calc_xy(N, g, N, libctx, propq) }
}

/// `BIGNUM *SRP_Calc_u_ex(const BIGNUM *A, const BIGNUM *B, const BIGNUM *N, OSSL_LIB_CTX
/// *libctx, const char *propq)` — `crypto/srp/srp_lib.c:63-68`.
///
/// # Safety
///
/// `A`, `B` and `N` must be NULL or live `BIGNUM`s; `libctx` NULL or a live library context;
/// `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_u_ex(
    A: *const BigNum,
    B: *const BigNum,
    N: *const BigNum,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut BigNum {
    // SAFETY: forwarded under this function's contract.
    unsafe { srp_Calc_xy(A, B, N, libctx, propq) }
}

/// `BIGNUM *SRP_Calc_u(const BIGNUM *A, const BIGNUM *B, const BIGNUM *N)` —
/// `crypto/srp/srp_lib.c:70-74`.
///
/// # Safety
///
/// `A`, `B` and `N` must be NULL or live `BIGNUM`s.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_u(
    A: *const BigNum,
    B: *const BigNum,
    N: *const BigNum,
) -> *mut BigNum {
    // SAFETY: forwarded under this function's contract.
    unsafe { srp_Calc_xy(A, B, N, ptr::null_mut(), ptr::null()) }
}

/// `BIGNUM *SRP_Calc_server_key(const BIGNUM *A, const BIGNUM *v, const BIGNUM *u, const
/// BIGNUM *b, const BIGNUM *N)` — `crypto/srp/srp_lib.c:76-104`.
///
/// # Safety
///
/// `A`, `v`, `u`, `b` and `N` must be NULL or live `BIGNUM`s.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_server_key(
    A: *const BigNum,
    v: *const BigNum,
    u: *const BigNum,
    b: *const BigNum,
    N: *const BigNum,
) -> *mut BigNum {
    if u.is_null() || A.is_null() || v.is_null() || b.is_null() || N.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: no arguments.
    let bn_ctx = unsafe { BN_CTX_new() };
    if bn_ctx.is_null() {
        return ptr::null_mut();
    }

    let mut tmp: *mut BigNum = ptr::null_mut();
    let mut S: *mut BigNum = ptr::null_mut();
    'done: {
        // SAFETY: no arguments.
        tmp = unsafe { BN_new() };
        if tmp.is_null() {
            break 'done;
        }

        // S = (A * v**u) ** b
        // SAFETY: all pointers are live; `tmp` is the output slot.
        if unsafe { BN_mod_exp(tmp, v, u, N, bn_ctx) } == 0 {
            break 'done;
        }
        // SAFETY: all pointers are live.
        if unsafe { BN_mod_mul(tmp, A, tmp, N, bn_ctx) } == 0 {
            break 'done;
        }

        // SAFETY: no arguments.
        S = unsafe { BN_new() };
        if !S.is_null()
            // SAFETY: all pointers are live.
            && unsafe { BN_mod_exp(S, tmp, b, N, bn_ctx) } == 0
        {
            // SAFETY: `S` is live.
            unsafe { BN_free(S) };
            S = ptr::null_mut();
        }
    }
    // SAFETY: `bn_ctx` is live or NULL; `tmp` is live or NULL.
    unsafe {
        BN_CTX_free(bn_ctx);
        BN_clear_free(tmp);
    }
    S
}

/// `BIGNUM *SRP_Calc_B_ex(const BIGNUM *b, const BIGNUM *N, const BIGNUM *g, const BIGNUM *v,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/srp/srp_lib.c:106-134`.
///
/// # Safety
///
/// `b`, `N`, `g` and `v` must be NULL or live `BIGNUM`s; `libctx` NULL or a live library
/// context; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_B_ex(
    b: *const BigNum,
    N: *const BigNum,
    g: *const BigNum,
    v: *const BigNum,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut BigNum {
    if b.is_null() || N.is_null() || g.is_null() || v.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: no arguments.
    let bn_ctx = unsafe { BN_CTX_new_ex(libctx) };
    if bn_ctx.is_null() {
        return ptr::null_mut();
    }

    let mut kv: *mut BigNum = ptr::null_mut();
    let mut gb: *mut BigNum = ptr::null_mut();
    let mut B: *mut BigNum = ptr::null_mut();
    let mut k: *mut BigNum = ptr::null_mut();
    'done: {
        // SAFETY: no arguments.
        unsafe {
            kv = BN_new();
            gb = BN_new();
            B = BN_new();
        }
        if kv.is_null() || gb.is_null() || B.is_null() {
            break 'done;
        }

        // B = g**b + k*v
        // SAFETY: all pointers are live.
        let mut ok = unsafe { BN_mod_exp(gb, g, b, N, bn_ctx) } != 0;
        if ok {
            // SAFETY: forwarded under this function's contract.
            k = unsafe { srp_Calc_k(N, g, libctx, propq) };
            ok = !k.is_null()
                // SAFETY: all pointers are live.
                && unsafe { BN_mod_mul(kv, v, k, N, bn_ctx) } != 0
                // SAFETY: all pointers are live.
                && unsafe { BN_mod_add(B, gb, kv, N, bn_ctx) } != 0;
        }
        if !ok {
            // SAFETY: `B` is live or NULL.
            unsafe { BN_free(B) };
            B = ptr::null_mut();
        }
    }
    // SAFETY: the temporaries are live or NULL.
    unsafe {
        BN_CTX_free(bn_ctx);
        BN_clear_free(kv);
        BN_clear_free(gb);
        BN_free(k);
    }
    B
}

/// `BIGNUM *SRP_Calc_B(const BIGNUM *b, const BIGNUM *N, const BIGNUM *g, const BIGNUM *v)` —
/// `crypto/srp/srp_lib.c:136-140`.
///
/// # Safety
///
/// `b`, `N`, `g` and `v` must be NULL or live `BIGNUM`s.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_B(
    b: *const BigNum,
    N: *const BigNum,
    g: *const BigNum,
    v: *const BigNum,
) -> *mut BigNum {
    // SAFETY: forwarded under this function's contract.
    unsafe { SRP_Calc_B_ex(b, N, g, v, ptr::null_mut(), ptr::null()) }
}

/// `BIGNUM *SRP_Calc_x_ex(const BIGNUM *s, const char *user, const char *pass, OSSL_LIB_CTX
/// *libctx, const char *propq)` — `crypto/srp/srp_lib.c:142-187`.
///
/// # Safety
///
/// `s` must be NULL or a live `BIGNUM`; `user` and `pass` NULL or NUL-terminated; `libctx`
/// NULL or a live library context; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_x_ex(
    s: *const BigNum,
    user: *const c_char,
    pass: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut BigNum {
    if s.is_null() || user.is_null() || pass.is_null() {
        return ptr::null_mut();
    }

    let mut dig = [0u8; SHA_DIGEST_LENGTH as usize];
    let mut cs: *mut c_uchar = ptr::null_mut();
    let mut res: *mut BigNum = ptr::null_mut();
    let mut sha1: *mut EvpMd = ptr::null_mut();

    // SAFETY: no arguments.
    let ctxt = EVP_MD_CTX_new();
    if ctxt.is_null() {
        return ptr::null_mut();
    }

    'done: {
        // SAFETY: `s` is NULL or live; the allocation is `BN_num_bytes(s)` bytes.
        cs = unsafe { CRYPTO_malloc(bn_num_bytes(s) as usize, FILE.as_ptr(), LINE_MALLOC_CS) }
            .cast::<c_uchar>();
        if cs.is_null() {
            break 'done;
        }

        // SAFETY: the arguments are forwarded under this function's contract.
        sha1 = unsafe { EVP_MD_fetch(libctx, c"SHA1".as_ptr(), propq) };
        if sha1.is_null() {
            break 'done;
        }

        // SAFETY: `user` and `pass` are NUL-terminated per the contract; `dig` is
        // `SHA_DIGEST_LENGTH` bytes; `ctxt` and `sha1` are live.
        let mut ok = unsafe {
            EVP_DigestInit_ex(ctxt, sha1, ptr::null_mut()) != 0
                && EVP_DigestUpdate(ctxt, user.cast(), strlen(user)) != 0
                && EVP_DigestUpdate(ctxt, c":".as_ptr().cast(), 1) != 0
                && EVP_DigestUpdate(ctxt, pass.cast(), strlen(pass)) != 0
                && EVP_DigestFinal_ex(ctxt, dig.as_mut_ptr(), ptr::null_mut()) != 0
                && EVP_DigestInit_ex(ctxt, sha1, ptr::null_mut()) != 0
        };
        if !ok {
            break 'done;
        }
        // SAFETY: `s` is live and `cs` is `BN_num_bytes(s)` bytes.
        ok = unsafe { BN_bn2bin(s, cs) } >= 0;
        if !ok {
            break 'done;
        }
        // SAFETY: `s` is live; `cs` holds `BN_num_bytes(s)` bytes.
        ok = unsafe { EVP_DigestUpdate(ctxt, cs.cast(), bn_num_bytes(s) as usize) } != 0;
        if ok {
            // SAFETY: `dig` is live and `SHA_DIGEST_LENGTH` bytes.
            ok = unsafe {
                EVP_DigestUpdate(ctxt, dig.as_ptr().cast(), dig.len()) != 0
                    && EVP_DigestFinal_ex(ctxt, dig.as_mut_ptr(), ptr::null_mut()) != 0
            };
        }
        if !ok {
            break 'done;
        }
        // SAFETY: `dig` is live and `SHA_DIGEST_LENGTH` bytes.
        res = unsafe { BN_bin2bn(dig.as_ptr(), SHA_DIGEST_LENGTH, ptr::null_mut()) };
    }

    // SAFETY: `sha1` came from `EVP_MD_fetch`; `cs` from `CRYPTO_malloc` (or NULL); `ctxt`
    // came from `EVP_MD_CTX_new`.
    unsafe {
        EVP_MD_free(sha1);
        CRYPTO_free(cs.cast(), FILE.as_ptr(), LINE_FREE_CS);
        EVP_MD_CTX_free(ctxt);
    }
    res
}

/// `BIGNUM *SRP_Calc_x(const BIGNUM *s, const char *user, const char *pass)` —
/// `crypto/srp/srp_lib.c:189-192`.
///
/// # Safety
///
/// `s` must be NULL or a live `BIGNUM`; `user` and `pass` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_x(
    s: *const BigNum,
    user: *const c_char,
    pass: *const c_char,
) -> *mut BigNum {
    // SAFETY: forwarded under this function's contract.
    unsafe { SRP_Calc_x_ex(s, user, pass, ptr::null_mut(), ptr::null()) }
}

/// `BIGNUM *SRP_Calc_A(const BIGNUM *a, const BIGNUM *N, const BIGNUM *g)` —
/// `crypto/srp/srp_lib.c:194-208`.
///
/// # Safety
///
/// `a`, `N` and `g` must be NULL or live `BIGNUM`s.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_A(
    a: *const BigNum,
    N: *const BigNum,
    g: *const BigNum,
) -> *mut BigNum {
    if a.is_null() || N.is_null() || g.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: no arguments.
    let bn_ctx: *mut BnCtx = unsafe { BN_CTX_new() };
    if bn_ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: no arguments.
    let mut A: *mut BigNum = unsafe { BN_new() };
    if !A.is_null()
        // SAFETY: all pointers are live.
        && unsafe { BN_mod_exp(A, g, a, N, bn_ctx) } == 0
    {
        // SAFETY: `A` is live.
        unsafe { BN_free(A) };
        A = ptr::null_mut();
    }
    // SAFETY: `bn_ctx` is live.
    unsafe { BN_CTX_free(bn_ctx) };
    A
}

/// `BIGNUM *SRP_Calc_client_key_ex(const BIGNUM *N, const BIGNUM *B, const BIGNUM *g, const
/// BIGNUM *x, const BIGNUM *a, const BIGNUM *u, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/srp/srp_lib.c:210-253`.
///
/// # Safety
///
/// `N`, `B`, `g`, `x`, `a` and `u` must be NULL or live `BIGNUM`s; `libctx` NULL or a live
/// library context; `propq` NULL or NUL-terminated.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub unsafe extern "C" fn SRP_Calc_client_key_ex(
    N: *const BigNum,
    B: *const BigNum,
    g: *const BigNum,
    x: *const BigNum,
    a: *const BigNum,
    u: *const BigNum,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut BigNum {
    if u.is_null() || B.is_null() || N.is_null() || g.is_null() || x.is_null() || a.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: no arguments.
    let bn_ctx = unsafe { BN_CTX_new_ex(libctx) };
    if bn_ctx.is_null() {
        return ptr::null_mut();
    }

    let mut tmp: *mut BigNum = ptr::null_mut();
    let mut tmp2: *mut BigNum = ptr::null_mut();
    let mut tmp3: *mut BigNum = ptr::null_mut();
    let mut k: *mut BigNum = ptr::null_mut();
    let mut K: *mut BigNum = ptr::null_mut();
    let mut xtmp: *mut BigNum = ptr::null_mut();
    'done: {
        // SAFETY: no arguments.
        unsafe {
            tmp = BN_new();
            tmp2 = BN_new();
            tmp3 = BN_new();
            xtmp = BN_new();
        }
        if tmp.is_null() || tmp2.is_null() || tmp3.is_null() || xtmp.is_null() {
            break 'done;
        }

        // SAFETY: `xtmp` and `x` are distinct live objects; `tmp` is live.
        unsafe {
            BN_with_flags(xtmp, x, BN_FLG_CONSTTIME);
            BN_set_flags(tmp, BN_FLG_CONSTTIME);
        }

        // SAFETY: all pointers are live.
        let mut ok = unsafe { BN_mod_exp(tmp, g, xtmp, N, bn_ctx) } != 0;
        if ok {
            // SAFETY: forwarded under this function's contract.
            k = unsafe { srp_Calc_k(N, g, libctx, propq) };
            ok = !k.is_null()
                // SAFETY: all pointers are live.
                && unsafe { BN_mod_mul(tmp2, tmp, k, N, bn_ctx) } != 0
                // SAFETY: all pointers are live.
                && unsafe { BN_mod_sub(tmp, B, tmp2, N, bn_ctx) } != 0
                // SAFETY: all pointers are live.
                && unsafe { BN_mul(tmp3, u, xtmp, bn_ctx) } != 0
                // SAFETY: all pointers are live.
                && unsafe { BN_add(tmp2, a, tmp3) } != 0;
        }
        if !ok {
            break 'done;
        }

        // SAFETY: no arguments.
        K = unsafe { BN_new() };
        if !K.is_null()
            // SAFETY: all pointers are live.
            && unsafe { BN_mod_exp(K, tmp, tmp2, N, bn_ctx) } == 0
        {
            // SAFETY: `K` is live.
            unsafe { BN_free(K) };
            K = ptr::null_mut();
        }
    }
    // SAFETY: the temporaries are live or NULL.
    unsafe {
        BN_CTX_free(bn_ctx);
        BN_free(xtmp);
        BN_clear_free(tmp);
        BN_clear_free(tmp2);
        BN_clear_free(tmp3);
        BN_free(k);
    }
    K
}

/// `BIGNUM *SRP_Calc_client_key(const BIGNUM *N, const BIGNUM *B, const BIGNUM *g, const
/// BIGNUM *x, const BIGNUM *a, const BIGNUM *u)` — `crypto/srp/srp_lib.c:255-259`.
///
/// # Safety
///
/// `N`, `B`, `g`, `x`, `a` and `u` must be NULL or live `BIGNUM`s.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_client_key(
    N: *const BigNum,
    B: *const BigNum,
    g: *const BigNum,
    x: *const BigNum,
    a: *const BigNum,
    u: *const BigNum,
) -> *mut BigNum {
    // SAFETY: forwarded under this function's contract.
    unsafe { SRP_Calc_client_key_ex(N, B, g, x, a, u, ptr::null_mut(), ptr::null()) }
}

/// `int SRP_Verify_B_mod_N(const BIGNUM *B, const BIGNUM *N)` — `crypto/srp/srp_lib.c:261-280`.
///
/// Checks whether `B % N` is non-zero.
///
/// # Safety
///
/// `B` and `N` must be NULL or live `BIGNUM`s.
#[no_mangle]
pub unsafe extern "C" fn SRP_Verify_B_mod_N(B: *const BigNum, N: *const BigNum) -> c_int {
    if B.is_null() || N.is_null() {
        return 0;
    }
    // SAFETY: no arguments.
    let bn_ctx = unsafe { BN_CTX_new() };
    if bn_ctx.is_null() {
        return 0;
    }

    let mut ret: c_int = 0;
    // SAFETY: no arguments.
    let r: *mut BigNum = unsafe { BN_new() };
    'done: {
        if r.is_null() {
            break 'done;
        }
        // SAFETY: all pointers are live.
        if unsafe { BN_nnmod(r, B, N, bn_ctx) } == 0 {
            break 'done;
        }
        // SAFETY: `r` is live.
        ret = c_int::from(unsafe { BN_is_zero(r) } == 0);
    }
    // SAFETY: `bn_ctx` and `r` are live or NULL.
    unsafe {
        BN_CTX_free(bn_ctx);
        BN_free(r);
    }
    ret
}

/// `int SRP_Verify_A_mod_N(const BIGNUM *A, const BIGNUM *N)` — `crypto/srp/srp_lib.c:282-286`.
///
/// # Safety
///
/// `A` and `N` must be NULL or live `BIGNUM`s.
#[no_mangle]
pub unsafe extern "C" fn SRP_Verify_A_mod_N(A: *const BigNum, N: *const BigNum) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { SRP_Verify_B_mod_N(A, N) }
}

/// The `knowngN[]` table, once built, behind the `Send`/`Sync` assertion a shared reference
/// needs.
///
/// `OnceLock` requires `T: Send + Sync`, and [`SrpGN`] holds raw pointers into another
/// module's constants. The invariant that makes the assertion true is the table's own: it is
/// written **once**, by `OnceLock`'s initialiser, before any reader can observe it, and never
/// mutated afterwards.
struct Table([SrpGN; KNOWN_GN_NUMBER]);

// SAFETY: nothing in a `SrpGN` is ever written after `OnceLock` publishes it; the three
// pointers are the addresses of process-lifetime constants and a string literal, so sending
// or sharing the table shares only immutable data.
unsafe impl Send for Table {}
// SAFETY: as the `Send` implementation above.
unsafe impl Sync for Table {}

/// `static SRP_gN knowngN[]` — `crypto/srp/srp_lib.c:288-296`.
///
/// Built once on first use, in the authority's own row order, which is descending group
/// width. The order is load-bearing for [`SRP_get_default_gN`] with a NULL `id`: the
/// authority's `return knowngN` answers the first row, the 8192-bit group.
fn knowngN() -> &'static [SrpGN; KNOWN_GN_NUMBER] {
    static TABLE: OnceLock<Table> = OnceLock::new();
    &TABLE
        .get_or_init(|| {
            // SAFETY: every accessor takes no pointers and answers the shared constant
            // behind its own authority symbol.
            let entries = unsafe {
                [
                    SrpGN {
                        id: c"8192".as_ptr().cast_mut(),
                        g: ossl_bn_generator_19(),
                        N: ossl_bn_group_8192(),
                    },
                    SrpGN {
                        id: c"6144".as_ptr().cast_mut(),
                        g: ossl_bn_generator_5(),
                        N: ossl_bn_group_6144(),
                    },
                    SrpGN {
                        id: c"4096".as_ptr().cast_mut(),
                        g: ossl_bn_generator_5(),
                        N: ossl_bn_group_4096(),
                    },
                    SrpGN {
                        id: c"3072".as_ptr().cast_mut(),
                        g: ossl_bn_generator_5(),
                        N: ossl_bn_group_3072(),
                    },
                    SrpGN {
                        id: c"2048".as_ptr().cast_mut(),
                        g: ossl_bn_generator_2(),
                        N: ossl_bn_group_2048(),
                    },
                    SrpGN {
                        id: c"1536".as_ptr().cast_mut(),
                        g: ossl_bn_generator_2(),
                        N: ossl_bn_group_1536(),
                    },
                    SrpGN {
                        id: c"1024".as_ptr().cast_mut(),
                        g: ossl_bn_generator_2(),
                        N: ossl_bn_group_1024(),
                    },
                ]
            };
            Table(entries)
        })
        .0
}

/// `char *SRP_check_known_gN_param(const BIGNUM *g, const BIGNUM *N)` —
/// `crypto/srp/srp_lib.c:304-315`.
///
/// Answers the matched row's id, a pointer into process-lifetime constant storage, or NULL.
///
/// # Safety
///
/// `g` and `N` must be NULL or live `BIGNUM`s.
#[no_mangle]
pub unsafe extern "C" fn SRP_check_known_gN_param(
    g: *const BigNum,
    N: *const BigNum,
) -> *mut c_char {
    if g.is_null() || N.is_null() {
        return ptr::null_mut();
    }
    for row in knowngN() {
        // SAFETY: every row's `g`/`N` are process-lifetime constants and `g`/`N` are live.
        if unsafe { BN_cmp(row.g, g) } == 0 && unsafe { BN_cmp(row.N, N) } == 0 {
            return row.id;
        }
    }
    ptr::null_mut()
}

/// `SRP_gN *SRP_get_default_gN(const char *id)` — `crypto/srp/srp_lib.c:317-328`.
///
/// With a NULL `id` the answer is the table base — the 8192-bit row; otherwise the matched
/// row, or NULL.
///
/// # Safety
///
/// `id` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SRP_get_default_gN(id: *const c_char) -> *mut SrpGN {
    let table = knowngN();
    if id.is_null() {
        return table.as_ptr().cast_mut();
    }
    for row in table {
        // SAFETY: every row's `id` is a process-lifetime string and `id` is NUL-terminated.
        if unsafe { strcmp(row.id, id) } == 0 {
            return (row as *const SrpGN).cast_mut();
        }
    }
    ptr::null_mut()
}
