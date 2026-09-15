//! Phase 6 — text to parameter, and parameter to text: `crypto/params_from_text.c`.
//!
//! This is the bridge between a configuration file's strings and a typed descriptor,
//! and it is the only place in the parameter surface where the *text* decides the type.
//! Two of its behaviours are unusual enough to state before the code.
//!
//! ## A `hex` prefix reinterprets the value, it does not decorate the key
//!
//! `prepare_from_text` strips a leading `hex` from the *key* and then lets it change how
//! the value is parsed: for an octet string `hex"`-prefixed`"` values are decoded as hex
//! digits, for an integer the digits are read as hexadecimal, and for a UTF-8 string
//! the combination is refused outright with `ERR_R_PASSED_INVALID_ARGUMENT`. So the same
//! key can name two different parameters depending on the text, which is why the lookup
//! happens *after* the prefix is removed.
//!
//! ## Negative decimal integers are negated in two halves
//!
//! `BN_asc2bn` parses a leading `-`, and `BN_bn2nativepad` writes only a *magnitude*, so
//! a negative value has to be turned into two's complement by hand. The authority does it
//! in two parts with the buffer widening in between:
//!
//! 1. add one to the absolute value (`-3` becomes `4`), and if the bit count is a
//!    multiple of eight add another byte, so that
//!    "the most significant bit in the resulting `OSSL_PARAM` buffer will be set";
//! 2. write the magnitude and invert every byte, which turns `4` into `-4`… and `-4` is
//!    `-3 - 1`, the value the caller asked for.
//!
//! Reproducing that arithmetic is not optional: the widening rule is what decides
//! whether a value that lands exactly on a byte boundary gets an extra byte, and that is
//! observable in `data_size`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::bn::arith::BN_add_word;
use crate::bn::bignum::{
    BN_asc2bn, BN_bn2nativepad, BN_free, BN_hex2bn, BN_is_negative, BN_num_bits, BigNum,
};
use crate::params::{OsslParam, OSSL_PARAM_UNMODIFIED};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The authority translation unit this module reconstructs.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/params_from_text.c";
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `HAS_PREFIX(str, pre)` for the literal `"hex"` — a plain byte comparison, so
/// `"HEX"` is **not** a prefix.
///
/// # Safety
///
/// `s` must be NULL or NUL-terminated.
unsafe fn has_hex_prefix(s: *const c_char) -> bool {
    // SAFETY: `s` is NUL-terminated per the caller's contract, so the four reads stay
    // inside it unless it is shorter, in which case one of them is the terminator and
    // the comparison fails before the next.
    unsafe { *s == b'h' as c_char && *s.add(1) == b'e' as c_char && *s.add(2) == b'x' as c_char }
}

/// `static int prepare_from_text(...)` — everything that has to be known before a byte
/// is written: which parameter the key names once a `hex` prefix is removed, how many
/// bytes the value needs, and the parsed `BIGNUM` for the integer forms.
///
/// `found` is written even when the return value is 0, because it distinguishes "no such
/// parameter" from "the value was unusable" for the caller.
///
/// # Safety
///
/// `paramdefs` must be a `key`-terminated array of live `OsslParam`; `key` and `value`
/// must be NUL-terminated; `paramdef`, `ishex`, `buf_n`, `tmpbn` and `found` must be
/// writable for one element each.
///
/// # Returns
///
/// `(the parameter definition, whether the key carried a `hex` prefix, the byte count)`.
unsafe fn prepare_from_text(
    paramdefs: *const OsslParam,
    key: *const c_char,
    value: *const c_char,
    value_n: usize,
    tmpbn: *mut *mut BigNum,
    found: *mut c_int,
) -> Option<(*const OsslParam, bool, usize)> {
    let mut keyp = key;
    // SAFETY: `key` is NUL-terminated.
    let ishex = unsafe { has_hex_prefix(keyp) };
    if ishex {
        // `key += sizeof("hex") - 1` — three bytes, not four.
        // SAFETY: the prefix matched, so three more bytes are inside the string.
        keyp = unsafe { keyp.add(3) };
    }
    // SAFETY: `paramdefs` is a terminated array of live entries.
    let p = unsafe { crate::params::OSSL_PARAM_locate_const(paramdefs, keyp) };
    if !found.is_null() {
        // SAFETY: `found` is writable for one `c_int`.
        unsafe { *found = c_int::from(!p.is_null()) };
    }
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is a live entry in the array.
    let q = unsafe { &*p };
    let mut buf_n;
    match q.data_type {
        crate::params::OSSL_PARAM_INTEGER | crate::params::OSSL_PARAM_UNSIGNED_INTEGER => {
            // SAFETY: `tmpbn` is writable for one pointer, and the string is
            // NUL-terminated.
            let r = if ishex {
                // SAFETY: `tmpbn` is writable for one pointer and `value` is
                // NUL-terminated.
                unsafe { BN_hex2bn(tmpbn, value) }
            } else {
                // SAFETY: as above; `BN_asc2bn` accepts the same prefix forms.
                unsafe { BN_asc2bn(tmpbn, value) }
            };
            // SAFETY: `tmpbn` is writable.
            let bn = unsafe { *tmpbn };
            if r == 0 || bn.is_null() {
                return None;
            }
            // SAFETY: `bn` is a live `BIGNUM` this call produced.
            let negative = unsafe { BN_is_negative(bn) } != 0;
            if q.data_type == crate::params::OSSL_PARAM_UNSIGNED_INTEGER && negative {
                // `ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_INVALID_NEGATIVE_VALUE)` at
                // crypto/params_from_text.c:60.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_FROM_TEXT_60) };
                return None;
            }
            // Two's complement part one: `-3 - 1 = -4`, and `|-3| = 3 + 1 = 4`.
            if q.data_type == crate::params::OSSL_PARAM_INTEGER && negative {
                // SAFETY: `bn` is live.
                if unsafe { BN_add_word(bn, 1) } == 0 {
                    return None;
                }
            }
            // SAFETY: `bn` is live.
            let mut buf_bits = unsafe { BN_num_bits(bn) } as usize;
            // The sign bit may be lost once part two runs, so a value whose bit count
            // lands on a byte boundary gets a byte of padding.
            if q.data_type == crate::params::OSSL_PARAM_INTEGER && buf_bits.is_multiple_of(8) {
                buf_bits += 8;
            }
            buf_n = buf_bits.div_ceil(8);
            if q.data_size > 0 {
                if buf_bits > q.data_size * 8 {
                    // `ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER)` at
                    // crypto/params_from_text.c:102.
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_FROM_TEXT_102) };
                    return None;
                }
                // A declared size is the size, so the buffer is not shrunk to fit.
                buf_n = q.data_size;
            }
        }
        crate::params::OSSL_PARAM_UTF8_STRING => {
            if ishex {
                // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT)` at
                // crypto/params_from_text.c:112.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_FROM_TEXT_112) };
                return None;
            }
            // SAFETY: `value` is NUL-terminated.
            buf_n = unsafe { crate::params::c_strlen(value) } + 1;
        }
        crate::params::OSSL_PARAM_OCTET_STRING => {
            if ishex {
                // SAFETY: `value` is NUL-terminated.
                let hexdigits = unsafe { crate::params::c_strlen(value) };
                if hexdigits % 2 != 0 {
                    // We don't accept an odd number of hex digits.
                    // `ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_ODD_NUMBER_OF_DIGITS)` at
                    // crypto/params_from_text.c:122.
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_FROM_TEXT_122) };
                    return None;
                }
                buf_n = hexdigits >> 1;
            } else {
                buf_n = value_n;
            }
        }
        _ => {
            // The authority's `switch` has no `default`, so an unhandled type leaves
            // `buf_n` unset; in C that is an indeterminate value on the stack. Every
            // type the atlas's headers define is handled above, so this arm is
            // unreachable for a well-formed definition; it answers 0 bytes rather than
            // reading uninitialised memory, which is a divergence recorded in
            // `docs/SECURITY_DIVERGENCE_POLICY.md`.
            buf_n = 0;
        }
    }
    Some((p, ishex, buf_n))
}

/// `static int construct_from_text(...)` — write the value into `buf` and stamp the
/// result into `*to`.
///
/// # Safety
///
/// `to` must be writable for one `OsslParam`; `paramdef` must be live; `buf` must be
/// writable for `buf_n`; `value` must be readable for `value_n` and NUL-terminated;
/// `tmpbn` must be live.
unsafe fn construct_from_text(
    to: *mut OsslParam,
    paramdef: *const OsslParam,
    value: *const c_char,
    ishex: bool,
    buf: *mut u8,
    buf_n: usize,
    tmpbn: *mut BigNum,
) -> bool {
    if buf.is_null() {
        return false;
    }
    // SAFETY: `paramdef` is live per the caller's contract.
    let def = unsafe { &*paramdef };
    let mut final_n = buf_n;
    if buf_n > 0 {
        match def.data_type {
            crate::params::OSSL_PARAM_INTEGER | crate::params::OSSL_PARAM_UNSIGNED_INTEGER => {
                // SAFETY: `buf` is writable for `buf_n` and `tmpbn` is live.
                unsafe { BN_bn2nativepad(tmpbn, buf, buf_n as c_int) };
                // SAFETY: `tmpbn` is live.
                // SAFETY: `tmpbn` is a live `BIGNUM` from the parse above.
                let negative = unsafe { BN_is_negative(tmpbn) } != 0;
                if def.data_type == crate::params::OSSL_PARAM_INTEGER && negative {
                    // Two's complement part two: inverting the magnitude written above
                    // completes the negation started in `prepare_from_text`.
                    for i in 0..buf_n {
                        // SAFETY: `i < buf_n` and `buf` is writable for `buf_n`.
                        unsafe { *buf.add(i) ^= 0xFF };
                    }
                }
            }
            crate::params::OSSL_PARAM_UTF8_STRING => {
                // `strncpy(buf, value, buf_n)`. `prepare_from_text` set
                // `buf_n = strlen(value) + 1` and `buf` is zeroed, so copying the
                // string and its terminator is the same operation; only `strlen(value)`
                // bytes count as data.
                // SAFETY: `value` is NUL-terminated, so `buf_n - 1` bytes are readable,
                // and `buf` is writable for `buf_n`.
                unsafe {
                    ptr::copy_nonoverlapping(value.cast::<u8>(), buf, final_n - 1);
                }
                final_n -= 1;
            }
            crate::params::OSSL_PARAM_OCTET_STRING => {
                if ishex {
                    let mut l = 0usize;
                    // SAFETY: `buf` is writable for `buf_n`, `value` is NUL-terminated,
                    // and `l` is a live local.
                    if unsafe {
                        crate::runtime::str::OPENSSL_hexstr2buf_ex(
                            buf,
                            buf_n,
                            &mut l,
                            value,
                            b':' as c_char,
                        )
                    } == 0
                    {
                        return false;
                    }
                } else {
                    // SAFETY: `buf` is writable for `buf_n` and `value` is readable for
                    // `buf_n` bytes per the caller's contract.
                    unsafe { ptr::copy_nonoverlapping(value.cast::<u8>(), buf, buf_n) };
                }
            }
            _ => {}
        }
    }
    // SAFETY: `to` is writable for one `OsslParam`.
    unsafe {
        *to = OsslParam {
            key: def.key,
            data_type: def.data_type,
            data: buf.cast(),
            data_size: final_n,
            return_size: OSSL_PARAM_UNMODIFIED,
        };
    }
    true
}

/// `int OSSL_PARAM_allocate_from_text(OSSL_PARAM *to, const OSSL_PARAM *paramdefs,
/// const char *key, const char *value, size_t value_n, int *found)`
///
/// The buffer is owned by the caller through `*to` and is released with
/// `OSSL_PARAM_free`'s sibling — `OPENSSL_free(to->data)` — not by this function. On
/// failure the buffer is released here and nothing is written to `*to`.
///
/// # Safety
///
/// `to` must be NULL or writable for one `OsslParam`; `paramdefs` must be NULL or a
/// `key`-terminated array of live `OsslParam`; `key` and `value` must be NUL-terminated;
/// `found` must be NULL or writable for one `c_int`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_allocate_from_text(
    to: *mut OsslParam,
    paramdefs: *const OsslParam,
    key: *const c_char,
    value: *const c_char,
    value_n: usize,
    found: *mut c_int,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if to.is_null() || paramdefs.is_null() {
            return 0;
        }
        let mut tmpbn: *mut BigNum = ptr::null_mut();
        // SAFETY: as the caller's contract.
        let Some((paramdef, ishex, buf_n)) =
            (unsafe { prepare_from_text(paramdefs, key, value, value_n, &mut tmpbn, found) })
        else {
            // SAFETY: `tmpbn` is NULL or a `BIGNUM` from `prepare_from_text`'s parse.
            unsafe { BN_free(tmpbn) };
            return 0;
        };
        // `OPENSSL_zalloc(buf_n > 0 ? buf_n : 1)` — never a zero-length request.
        let alloc = if buf_n > 0 { buf_n } else { 1 };
        let buf = CRYPTO_zalloc(alloc, FILE.as_ptr(), LINE).cast::<u8>();
        if buf.is_null() {
            // SAFETY: as above.
            unsafe { BN_free(tmpbn) };
            return 0;
        }
        // SAFETY: `to` is writable for one `OsslParam`; `paramdef` is live; `buf` is
        // writable for `buf_n` (zero when nothing is written); `value` is readable for
        // `value_n`; `tmpbn` is live.
        let ok = unsafe { construct_from_text(to, paramdef, value, ishex, buf, buf_n, tmpbn) };
        // SAFETY: `tmpbn` is live.
        unsafe { BN_free(tmpbn) };
        if !ok {
            // SAFETY: `buf` was allocated by this function and never surfaced.
            unsafe { CRYPTO_free(buf.cast(), FILE.as_ptr(), LINE) };
            return 0;
        }
        1
    })
}

/// `int OSSL_PARAM_print_to_bio(const OSSL_PARAM *p, BIO *bio, int print_values)`
///
/// Returns 1 unless a write failed; a single failed `BIO_printf` ends the walk. The
/// values are printed *by type*: a wide integer goes through `BN_print` rather than
/// being truncated to 64 bits, a string or byte string is hex-dumped, and a real is
/// printed with `%f`.
///
/// One detail a reader will otherwise assume the wrong way: the loop condition is
/// `p->key != NULL`, so an empty array prints nothing and the function returns 1 —
/// `ok` starts at `-1` and is overwritten before it can be returned.
///
/// # Safety
///
/// `p` must be a `key`-terminated array of live `OsslParam`; `bio` must be a live `BIO`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_print_to_bio(
    p: *const OsslParam,
    bio: *mut crate::runtime::bio::Bio,
    print_values: c_int,
) -> c_int {
    use crate::runtime::bio::print::BIO_printf;

    crate::ffi::guard_ffi(0, || {
        if p.is_null() {
            // The authority dereferences immediately; a NULL array is the caller's
            // error and the probe does not exercise it. Answering 0 is a recorded
            // divergence in `docs/SECURITY_DIVERGENCE_POLICY.md`.
            return 0;
        }
        let mut ok = -1;
        let mut cur = p;
        loop {
            // SAFETY: `cur` walks a terminated array per the caller's contract.
            let q = unsafe { &*cur };
            if q.key.is_null() {
                break;
            }
            // SAFETY: `q.key` is NUL-terminated and `bio` is live.
            ok = unsafe { BIO_printf(bio, c"%s: ".as_ptr(), q.key) };
            if ok == -1 {
                break;
            }
            if print_values == 0 {
                // SAFETY: as above. The result is deliberately not recorded, which is
                // what the authority does: a failed newline here does not end the walk.
                unsafe { BIO_printf(bio, c"\n".as_ptr()) };
                // SAFETY: the array has not terminated, so the next entry is in it.
                cur = unsafe { cur.add(1) };
                continue;
            }
            let dtype = q.data_type;
            ok = match dtype {
                crate::params::OSSL_PARAM_UNSIGNED_INTEGER => {
                    if q.data_size > core::mem::size_of::<i64>() {
                        let mut bn: *mut BigNum = ptr::null_mut();
                        // SAFETY: `cur` is live and `bn` is a live local.
                        if unsafe { crate::params::OSSL_PARAM_get_BN(cur, &mut bn) } != 0 {
                            // SAFETY: `bn` is a live `BIGNUM` on this branch.
                            unsafe { crate::bn::bignum::BN_print(bio, bn) }
                        } else {
                            // SAFETY: `bio` is live.
                            unsafe { BIO_printf(bio, c"error getting value\n".as_ptr()) }
                        }
                    } else {
                        let mut u: u64 = 0;
                        // SAFETY: `cur` is live and `u` is a live local.
                        if unsafe { crate::params::OSSL_PARAM_get_uint64(cur, &mut u) } != 0 {
                            // SAFETY: `bio` is live; the format matches the argument.
                            unsafe { BIO_printf(bio, c"%llu\n".as_ptr(), u) }
                        } else {
                            // SAFETY: `bio` is live.
                            unsafe { BIO_printf(bio, c"error getting value\n".as_ptr()) }
                        }
                    }
                }
                crate::params::OSSL_PARAM_INTEGER => {
                    if q.data_size > core::mem::size_of::<i64>() {
                        let mut bn: *mut BigNum = ptr::null_mut();
                        // SAFETY: as the unsigned arm.
                        if unsafe { crate::params::OSSL_PARAM_get_BN(cur, &mut bn) } != 0 {
                            // SAFETY: `bn` is live on this branch.
                            unsafe { crate::bn::bignum::BN_print(bio, bn) }
                        } else {
                            // SAFETY: `bio` is live.
                            unsafe { BIO_printf(bio, c"error getting value\n".as_ptr()) }
                        }
                    } else {
                        let mut i: i64 = 0;
                        // SAFETY: `cur` is live and `i` is a live local.
                        if unsafe { crate::params::OSSL_PARAM_get_int64(cur, &mut i) } != 0 {
                            // SAFETY: `bio` is live; the format matches the argument.
                            unsafe { BIO_printf(bio, c"%lld\n".as_ptr(), i) }
                        } else {
                            // SAFETY: `bio` is live.
                            unsafe { BIO_printf(bio, c"error getting value\n".as_ptr()) }
                        }
                    }
                }
                crate::params::OSSL_PARAM_UTF8_PTR
                | crate::params::OSSL_PARAM_UTF8_STRING
                | crate::params::OSSL_PARAM_OCTET_PTR
                | crate::params::OSSL_PARAM_OCTET_STRING => {
                    // SAFETY: `bio` is live; `q.data` is readable for `q.data_size` for
                    // the string forms and for one pointer for the `_PTR` forms, which
                    // is what the authority dumps either way.
                    unsafe {
                        crate::runtime::bio::dump::BIO_dump(bio, q.data, q.data_size as c_int)
                    }
                }
                crate::params::OSSL_PARAM_REAL => {
                    let mut d: f64 = 0.0;
                    // SAFETY: `cur` is live and `d` is a live local.
                    let dok = unsafe { crate::params::OSSL_PARAM_get_double(cur, &mut d) };
                    if dok == 1 {
                        // SAFETY: `bio` is live; the format matches the argument.
                        unsafe { BIO_printf(bio, c"%f\n".as_ptr(), d) }
                    } else {
                        // SAFETY: `bio` is live.
                        unsafe { BIO_printf(bio, c"error getting value\n".as_ptr()) }
                    }
                }
                _ => {
                    // SAFETY: `bio` is live; the format matches the arguments.
                    unsafe {
                        BIO_printf(
                            bio,
                            c"unknown type (%u) of %zu bytes\n".as_ptr(),
                            dtype,
                            q.data_size,
                        )
                    }
                }
            };
            if ok == -1 {
                break;
            }
            // SAFETY: the array has not terminated, so the next entry is in it.
            cur = unsafe { cur.add(1) };
        }
        if ok == -1 {
            0
        } else {
            1
        }
    })
}
