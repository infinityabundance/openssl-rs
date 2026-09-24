//! `crypto/param_build_set.c` — the key-management helpers shared by a provider's `export()` and
//! `get_params()` methods, Phase 8.7.
//!
//! One hundred and twenty-nine lines and **seven internals**, each a two-way write: when a
//! `OSSL_PARAM_BLD` is supplied the value is pushed into the builder, otherwise it is looked up
//! by key in an `OSSL_PARAM[]` and set in place. A key that is in neither answers 1 (nothing to
//! do) rather than 0 (failure), which is the authority's own asymmetry and is why a caller that
//! asks for a parameter the peer does not carry gets a success.
//!
//! `crypto/param_build_set.c` is a **shared** unit: `crypto/ec/ec_backend.c` is the first caller
//! the crate reaches, and `crypto/ffc/ffc_backend.c`'s `ossl_ffc_params_todata` — D330's and
//! D331's recorded blocker — reaches the same four. The whole unit lands here rather than the
//! reachable subset, because a unit given a crate module makes every internal it defines
//! countable (D327's rule) and a partial transcription would be a finding rather than a smaller
//! landing. Its own callees — `OSSL_PARAM_BLD_push_*`, `OSSL_PARAM_locate`, `OSSL_PARAM_set_*`
//! and `OPENSSL_sk_num`/`OPENSSL_sk_value` — are all in the crate, so this module's closure is
//! empty.
//!
//! The one refusal is `ossl_param_build_set_bn_pad`'s `CRYPTO_R_TOO_SMALL_BUFFER`
//! (`param_build_set.c:82`), raised when the caller's fixed-width buffer is narrower than the
//! padding the request asks for. Its coordinate comes from the lexical scan like every other.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar};

use crate::bn::bignum::BigNum;
use crate::params::build::{
    OSSL_PARAM_BLD_push_BN, OSSL_PARAM_BLD_push_BN_pad, OSSL_PARAM_BLD_push_int,
    OSSL_PARAM_BLD_push_long, OSSL_PARAM_BLD_push_octet_string, OSSL_PARAM_BLD_push_utf8_string,
    OSSL_PARAM_BLD,
};
use crate::params::{
    OSSL_PARAM_locate, OSSL_PARAM_set_BN, OSSL_PARAM_set_int, OSSL_PARAM_set_long,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_utf8_string, OsslParam,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};

/// `int ossl_param_build_set_int(OSSL_PARAM_BLD *bld, OSSL_PARAM *p, const char *key, int num)`
/// — `crypto/param_build_set.c:22-31`.
///
/// # Safety
///
/// `bld` is NULL or a live builder, `p` NULL or a key-terminated descriptor array, `key` NULL or
/// NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn ossl_param_build_set_int(
    bld: *mut OSSL_PARAM_BLD,
    p: *mut OsslParam,
    key: *const c_char,
    num: c_int,
) -> c_int {
    if !bld.is_null() {
        // SAFETY: `bld` is live and `key` is NULL or NUL-terminated, per the contract.
        return unsafe { OSSL_PARAM_BLD_push_int(bld, key, num) };
    }
    // SAFETY: `p` is NULL or a descriptor array; `locate` walks it and answers NULL when absent.
    let p = unsafe { OSSL_PARAM_locate(p, key) };
    if !p.is_null() {
        // SAFETY: `p` is the located live entry.
        return unsafe { OSSL_PARAM_set_int(p, num) };
    }
    1
}

/// `int ossl_param_build_set_long(OSSL_PARAM_BLD *bld, OSSL_PARAM *p, const char *key, long num)`
/// — `crypto/param_build_set.c:33-42`.
///
/// # Safety
///
/// As [`ossl_param_build_set_int`].
#[no_mangle]
pub(crate) unsafe extern "C" fn ossl_param_build_set_long(
    bld: *mut OSSL_PARAM_BLD,
    p: *mut OsslParam,
    key: *const c_char,
    num: c_long,
) -> c_int {
    if !bld.is_null() {
        // SAFETY: `bld` is live and `key` is NULL or NUL-terminated, per the contract.
        return unsafe { OSSL_PARAM_BLD_push_long(bld, key, num) };
    }
    // SAFETY: `p` is NULL or a descriptor array.
    let p = unsafe { OSSL_PARAM_locate(p, key) };
    if !p.is_null() {
        // SAFETY: `p` is the located live entry.
        return unsafe { OSSL_PARAM_set_long(p, num) };
    }
    1
}

/// `int ossl_param_build_set_utf8_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p, const char *key,
/// const char *buf)` — `crypto/param_build_set.c:44-53`.
///
/// # Safety
///
/// As [`ossl_param_build_set_int`]; `buf` is NULL or NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn ossl_param_build_set_utf8_string(
    bld: *mut OSSL_PARAM_BLD,
    p: *mut OsslParam,
    key: *const c_char,
    buf: *const c_char,
) -> c_int {
    if !bld.is_null() {
        // SAFETY: `bld` is live; `key`/`buf` are NULL or NUL-terminated.
        return unsafe { OSSL_PARAM_BLD_push_utf8_string(bld, key, buf, 0) };
    }
    // SAFETY: `p` is NULL or a descriptor array.
    let p = unsafe { OSSL_PARAM_locate(p, key) };
    if !p.is_null() {
        // SAFETY: `p` is the located live entry.
        return unsafe { OSSL_PARAM_set_utf8_string(p, buf) };
    }
    1
}

/// `int ossl_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p, const char *key,
/// const unsigned char *data, size_t data_len)` — `crypto/param_build_set.c:55-67`.
///
/// # Safety
///
/// As [`ossl_param_build_set_int`]; `data` is readable for `data_len` bytes.
#[no_mangle]
pub(crate) unsafe extern "C" fn ossl_param_build_set_octet_string(
    bld: *mut OSSL_PARAM_BLD,
    p: *mut OsslParam,
    key: *const c_char,
    data: *const c_uchar,
    data_len: usize,
) -> c_int {
    if !bld.is_null() {
        // SAFETY: `bld` is live; `data` is readable for `data_len` bytes.
        return unsafe { OSSL_PARAM_BLD_push_octet_string(bld, key, data.cast(), data_len) };
    }
    // SAFETY: `p` is NULL or a descriptor array.
    let p = unsafe { OSSL_PARAM_locate(p, key) };
    if !p.is_null() {
        // SAFETY: `p` is the located live entry.
        return unsafe { OSSL_PARAM_set_octet_string(p, data.cast(), data_len) };
    }
    1
}

/// `int ossl_param_build_set_bn_pad(OSSL_PARAM_BLD *bld, OSSL_PARAM *p, const char *key,
/// const BIGNUM *bn, size_t sz)` — `crypto/param_build_set.c:69-89`.
///
/// The in-place arm is the one with the shape a reader should notice: a NULL `p->data` is the
/// authority's **size probe**, so the required size is written to `p->return_size` and the call
/// answers 1 without touching the BIGNUM; a probe whose `sz` exceeds `p->data_size` raises
/// `CRYPTO_R_TOO_SMALL_BUFFER` (`:82`) and answers 0; and only a buffer wide enough has its
/// `data_size` narrowed to `sz` and the value written through `OSSL_PARAM_set_BN`.
///
/// # Safety
///
/// As [`ossl_param_build_set_int`]; `bn` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn ossl_param_build_set_bn_pad(
    bld: *mut OSSL_PARAM_BLD,
    p: *mut OsslParam,
    key: *const c_char,
    bn: *const BigNum,
    sz: usize,
) -> c_int {
    if !bld.is_null() {
        // SAFETY: `bld` is live; `bn` is NULL or live.
        return unsafe { OSSL_PARAM_BLD_push_BN_pad(bld, key, bn, sz) };
    }
    // SAFETY: `p` is NULL or a descriptor array.
    let p = unsafe { OSSL_PARAM_locate(p, key) };
    if !p.is_null() {
        // SAFETY: `p` is the located live entry.
        unsafe {
            if (*p).data.is_null() {
                // Size probe: NULL data means "report the required size".
                (*p).return_size = sz;
                return 1;
            }
            if sz > (*p).data_size {
                // SAFETY: a compile-time-constant site (`param_build_set.c:82`,
                // CRYPTO_R_TOO_SMALL_BUFFER).
                raise_site(&err_sites::PARAM_BUILD_SET_82);
                return 0;
            }
            (*p).data_size = sz;
            return OSSL_PARAM_set_BN(p, bn);
        }
    }
    1
}

/// `int ossl_param_build_set_bn(OSSL_PARAM_BLD *bld, OSSL_PARAM *p, const char *key,
/// const BIGNUM *bn)` — `crypto/param_build_set.c:91-101`.
///
/// # Safety
///
/// As [`ossl_param_build_set_int`]; `bn` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn ossl_param_build_set_bn(
    bld: *mut OSSL_PARAM_BLD,
    p: *mut OsslParam,
    key: *const c_char,
    bn: *const BigNum,
) -> c_int {
    if !bld.is_null() {
        // SAFETY: `bld` is live; `bn` is NULL or live.
        return unsafe { OSSL_PARAM_BLD_push_BN(bld, key, bn) };
    }
    // SAFETY: `p` is NULL or a descriptor array.
    let p = unsafe { OSSL_PARAM_locate(p, key) };
    if !p.is_null() {
        // SAFETY: `p` is the located live entry. The authority spells `> 0` because its own
        // setter answers 1 or 0 and the comparison is what makes a negative a failure.
        return (unsafe { OSSL_PARAM_set_BN(p, bn) } > 0) as c_int;
    }
    1
}

/// `int ossl_param_build_set_multi_key_bn(OSSL_PARAM_BLD *bld, OSSL_PARAM *params,
/// const char *names[], STACK_OF(BIGNUM_const) *stk)` — `crypto/param_build_set.c:103-128`.
///
/// The two arms walk the name array and the stack together, stopping at the first NULL name —
/// which is why a stack shorter than the name list simply stops early rather than failing. The
/// builder arm skips a NULL value but keeps going; the in-place arm skips an absent key but
/// keeps going. That asymmetry is the authority's.
///
/// # Safety
///
/// `bld` is NULL or a live builder, `params` NULL or a key-terminated descriptor array, `names`
/// a NULL-terminated array of NUL-terminated strings, `stk` a live stack of `const BIGNUM *`.
#[no_mangle]
pub(crate) unsafe extern "C" fn ossl_param_build_set_multi_key_bn(
    bld: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
    names: *const *const c_char,
    stk: *const OpenSslStack,
) -> c_int {
    // SAFETY: `stk` is a live stack per the contract.
    let sz = unsafe { OPENSSL_sk_num(stk) };

    if !bld.is_null() {
        let mut i = 0;
        // SAFETY: `names` is NULL-terminated; `stk` is live and `i < sz` bounds it.
        unsafe {
            while i < sz && !(*names.offset(i as isize)).is_null() {
                // SAFETY: `i` is within the stack's `sz` entries.
                let bn = OPENSSL_sk_value(stk, i).cast::<BigNum>();
                if !bn.is_null() && OSSL_PARAM_BLD_push_BN(bld, *names.offset(i as isize), bn) == 0
                {
                    return 0;
                }
                i += 1;
            }
        }
        return 1;
    }

    let mut i = 0;
    // SAFETY: `names` is NULL-terminated; `stk` is live and `i < sz` bounds it.
    unsafe {
        while i < sz && !(*names.offset(i as isize)).is_null() {
            // SAFETY: `i` is within the stack's `sz` entries.
            let bn = OPENSSL_sk_value(stk, i).cast::<BigNum>();
            let p = OSSL_PARAM_locate(params, *names.offset(i as isize));
            if !p.is_null() && !bn.is_null() && OSSL_PARAM_set_BN(p, bn) == 0 {
                return 0;
            }
            i += 1;
        }
    }
    1
}
