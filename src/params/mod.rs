//! Phase 6 — the parameter descriptor: `crypto/params.c`, and its three siblings.
//!
//! An `OSSL_PARAM` is the type every provider call is made of. A caller builds an
//! array of them, terminated by a `key == NULL` entry, and passes it to an operation
//! as the whole of the argument and result list; the provider reads the ones it knows
//! by name and writes results back into the same buffers. Everything above this
//! module — dispatch tables, fetches, `EVP_*`, X.509 through the encoder — speaks in
//! these, so a defect here is not local. That is why the surface is 81 exports rather
//! than a handful of helpers.
//!
//! The module tree mirrors the authority's own file boundaries, because those are what
//! the ownership atlas and the raise-site coordinates are keyed on:
//!
//! * this module — `crypto/params.c`: the struct, the type constants, the integer
//!   conversions, the string and pointer forms, `BN`, `double`, `locate`, `modified`
//!   and the constructors;
//! * [`dup`] — `crypto/params_dup.c`: `OSSL_PARAM_dup`, `OSSL_PARAM_merge` and
//!   `OSSL_PARAM_free`, including the secure-block convention that lets one
//!   allocation carry both the array and the data it points at;
//! * [`from_text`] — `crypto/params_from_text.c`: `OSSL_PARAM_allocate_from_text` and
//!   `OSSL_PARAM_print_to_bio`, the translation between a configuration file's strings
//!   and a typed descriptor;
//! * [`build`] — `crypto/param_build.c`: `OSSL_PARAM_BLD_*`, the builder that gives a
//!   provider a way to *return* a parameter list it had no buffer for.
//!
//! ## The three things that are easy to get wrong
//!
//! **The integer plane is a conversion library, not a set of casts.** A parameter
//! carries its own width and its own signedness, and the caller's accessor carries a
//! different width and a different signedness. `params.c` has a width-independent core
//! — `copy_integer` and the four `*_from_*` wrappers — that sign-extends, refuses to
//! truncate a value that would not fit, and refuses to read a negative number through
//! an unsigned accessor. On top of that, each accessor has a fast path for the two or
//! three widths the compiler can see. The fast paths are not equivalent to the general
//! path by construction and the differences are observable: `OSSL_PARAM_get_int32` on a
//! four-byte `INTEGER` reads it directly, where the general path would reject the same
//! bytes if their sign disagreed with the destination. Both are reproduced, in the
//! authority's order, because a court compares the answers and there is no way to tell
//! from outside which path produced one.
//!
//! **`return_size` is not a length, it is a state.** A parameter is *modified* when
//! `return_size` differs from `OSSL_PARAM_UNMODIFIED`, and a setter whose `data` is
//! NULL is not a failure: it records the size the caller would need and answers
//! success. That is how a provider asks "how big is this?" without owning a buffer, and
//! it is why almost every setter here has an early `data == NULL` arm that answers 1. A
//! compatibility layer that treated `data == NULL` as an error would break every size
//! query.
//!
//! **"Native order" is little-endian on this platform, and the code says so nowhere.**
//! `copy_integer` branches on `IS_BIG_ENDIAN`; the integer buffers a parameter carries
//! are in the host's byte order, not network order, which is the opposite of
//! `ASN1_INTEGER` one stratum below. This module takes the little-endian branch of every
//! such branch, and each is marked with the preprocessor condition it answers.
//!
//! ## Error coordinates
//!
//! `params.c` spells its eight refusals as file-local macros and invokes them bare, so
//! its raise sites come from the *invocation* line rather than from the definition;
//! `forensics/tools/gen_err_raise_sites.py` reads the file's own `#define`s to attribute
//! them, which is `docs/DECISIONS.md` D101. The `err_sites::PARAMS_*` constants below are
//! the generated sites, and each call names the reason the authority raises.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

use crate::bn::bignum::BigNum;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_zalloc;
use crate::runtime::time::TimeT;

pub mod build;
pub mod dup;
pub mod from_text;

/// The authority translation unit this module reconstructs.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/params.c";
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `OSSL_PARAM_UNMODIFIED` — `return_size`'s "nothing has written this yet" value.
pub(crate) const OSSL_PARAM_UNMODIFIED: usize = usize::MAX;

/// `OSSL_PARAM_INTEGER` — arbitrary width, native byte order, signed.
pub const OSSL_PARAM_INTEGER: c_uint = 1;
/// `OSSL_PARAM_UNSIGNED_INTEGER` — the same, unsigned.
pub const OSSL_PARAM_UNSIGNED_INTEGER: c_uint = 2;
/// `OSSL_PARAM_REAL` — a native `double`.
pub const OSSL_PARAM_REAL: c_uint = 3;
/// `OSSL_PARAM_UTF8_STRING` — a NUL-terminated string held in the descriptor.
pub const OSSL_PARAM_UTF8_STRING: c_uint = 4;
/// `OSSL_PARAM_OCTET_STRING` — a byte string held in the descriptor.
pub const OSSL_PARAM_OCTET_STRING: c_uint = 5;
/// `OSSL_PARAM_UTF8_PTR` — a pointer to a NUL-terminated string.
pub const OSSL_PARAM_UTF8_PTR: c_uint = 6;
/// `OSSL_PARAM_OCTET_PTR` — a pointer to a byte string.
pub const OSSL_PARAM_OCTET_PTR: c_uint = 7;

/// The authority's `struct ossl_param_st` — `include/openssl/core.h`.
///
/// Field order and widths are the ABI. `data_type` is `unsigned int`, so `data` sits at
/// offset 16 and the struct is 40 bytes on the admitted platform; `ABI-LAYOUT` checks
/// both against the installed header.
/// Every field is trivially copyable and the authority treats a descriptor as a
/// value, which is what `OSSL_PARAM_construct_*` returning one by value and
/// `OSSL_PARAM_merge` copying entries both rely on.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct OsslParam {
    /// The parameter's name, or NULL for the terminating entry.
    pub key: *const c_char,
    /// One of the `OSSL_PARAM_*` type constants, or `0` on the terminator.
    pub data_type: c_uint,
    /// The buffer the caller supplies, or NULL to ask how large one would need to be.
    pub data: *mut c_void,
    /// The size of `data`, or the size the parameter would occupy.
    pub data_size: usize,
    /// Written by whoever fills the parameter; `OSSL_PARAM_UNMODIFIED` until then.
    pub return_size: usize,
}

/// Read a `*const OsslParam` as a reference.
///
/// # Safety
///
/// `p` must be null or point to a live `OsslParam` that is not mutated for the lifetime
/// of the returned borrow.
pub(crate) unsafe fn as_ref<'a>(p: *const OsslParam) -> Option<&'a OsslParam> {
    if p.is_null() {
        // SAFETY: no dereference happens on this branch.
        None
    } else {
        // SAFETY: null-or-live per this function's contract; the borrow is tied to the
        // caller's.
        Some(unsafe { &*p })
    }
}

/// The authority's `ossl_param_construct`.
pub(crate) fn construct(
    key: *const c_char,
    data_type: c_uint,
    data: *mut c_void,
    data_size: usize,
) -> OsslParam {
    OsslParam {
        key,
        data_type,
        data,
        data_size,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `OSSL_PARAM_END` — the all-zero terminating entry.
pub(crate) const END: OsslParam = OsslParam {
    key: ptr::null(),
    data_type: 0,
    data: ptr::null_mut(),
    data_size: 0,
    return_size: 0,
};

/// `strcmp` over two NUL-terminated strings, without libc.
///
/// # Safety
///
/// Both arguments must be NUL-terminated.
unsafe fn str_eq(a: *const c_char, b: *const c_char) -> bool {
    let mut i = 0usize;
    loop {
        // SAFETY: both strings are NUL-terminated per the caller's contract, so each
        // read is inside its own string.
        let (x, y) = unsafe { (*a.add(i), *b.add(i)) };
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
        i += 1;
    }
}

/// `OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key)`
///
/// Walks the array to the terminating entry and returns the first match. A NULL array or
/// a NULL key is not an error and raises nothing: it answers NULL.
///
/// # Safety
///
/// `p` must be NULL or a `key`-terminated array of live `OsslParam`, and `key` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_locate(
    p: *mut OsslParam,
    key: *const c_char,
) -> *mut OsslParam {
    guard_ffi(ptr::null_mut(), || {
        if p.is_null() || key.is_null() {
            return ptr::null_mut();
        }
        let mut cur = p;
        loop {
            // SAFETY: `cur` walks a key-terminated array per the caller's contract.
            let entry = unsafe { &*cur };
            if entry.key.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: both keys are NUL-terminated.
            if unsafe { str_eq(key, entry.key) } {
                return cur;
            }
            // SAFETY: the array has not terminated, so the next entry is still in it.
            cur = unsafe { cur.add(1) };
        }
    })
}

/// `const OSSL_PARAM *OSSL_PARAM_locate_const(const OSSL_PARAM *p, const char *key)`
///
/// The authority casts the constness away and calls the non-const form; so does this,
/// because the entry returned is the same one either way.
///
/// # Safety
///
/// As [`OSSL_PARAM_locate`].
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_locate_const(
    p: *const OsslParam,
    key: *const c_char,
) -> *const OsslParam {
    // SAFETY: the caller's contract; the cast only discards `const`.
    unsafe { OSSL_PARAM_locate(p.cast_mut(), key) }
}

/// `int OSSL_PARAM_modified(const OSSL_PARAM *p)`
///
/// # Safety
///
/// `p` must be NULL or a live `OsslParam`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_modified(p: *const OsslParam) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per the caller's contract.
        match unsafe { as_ref(p) } {
            Some(q) => c_int::from(q.return_size != OSSL_PARAM_UNMODIFIED),
            None => 0,
        }
    })
}

/// `void OSSL_PARAM_set_all_unmodified(OSSL_PARAM *p)`
///
/// # Safety
///
/// `p` must be NULL or a `key`-terminated array of live `OsslParam`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_all_unmodified(p: *mut OsslParam) {
    guard_ffi((), || {
        if p.is_null() {
            return;
        }
        let mut cur = p;
        loop {
            // SAFETY: `cur` walks a key-terminated array per the caller's contract.
            let entry = unsafe { &mut *cur };
            if entry.key.is_null() {
                return;
            }
            entry.return_size = OSSL_PARAM_UNMODIFIED;
            // SAFETY: the array has not terminated, so the next entry is still in it.
            cur = unsafe { cur.add(1) };
        }
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_end(void)`
#[no_mangle]
pub extern "C" fn OSSL_PARAM_construct_end() -> OsslParam {
    END
}

// ---------------------------------------------------------------------------------
// The integer plane
// ---------------------------------------------------------------------------------

/// `static unsigned int real_shift(void)` — the number of bits in a `double`'s
/// significand, which is what decides whether an integer converts to a `double`
/// exactly. `sizeof(double) == 4` is the UEFI case and unreachable here, but the
/// authority keeps the branch and the value `53` is the one that is used.
fn real_shift() -> c_uint {
    if core::mem::size_of::<f64>() == 4 {
        24
    } else {
        53
    }
}

/// `static int is_negative(const void *number, size_t s)`
///
/// Reads only the byte that holds the sign in the host's byte order — the last one
/// little-endian, the first one big-endian.
///
/// # Safety
///
/// `number` must be readable for `s` bytes, with `s >= 1`.
unsafe fn is_negative(number: *const c_void, s: usize) -> bool {
    let n = number.cast::<u8>();
    // Little-endian: `IS_BIG_ENDIAN ? n[0] : n[s - 1]`.
    // SAFETY: the caller promises `s >= 1` readable bytes, so `s - 1` is in bounds.
    unsafe { (*n.add(s - 1) & 0x80) != 0 }
}

/// `static int check_sign_bytes(const unsigned char *p, size_t n, unsigned char s)`
///
/// # Safety
///
/// `p` must be readable for `n` bytes.
unsafe fn check_sign_bytes(p: *const u8, n: usize, s: u8) -> bool {
    for i in 0..n {
        // SAFETY: `i < n` and the caller promises `n` readable bytes.
        if unsafe { *p.add(i) } != s {
            return false;
        }
    }
    true
}

/// `static int copy_integer(unsigned char *dest, size_t dest_len, const unsigned char
/// *src, size_t src_len, unsigned char pad, int signed_int)`
///
/// The width-independent conversion. Two refusals matter: extending with a pad byte is
/// always allowed, but *shortening* requires the discarded bytes to be the pad byte
/// **and**, for a signed value, the kept byte's sign bit to agree with the pad — the
/// authority's own comment gives `-253 = 0xff03 -> 0x03 = 3` as the thing it is avoiding.
///
/// This is the little-endian arm of the authority's `#if`, which is the admitted
/// platform's.
///
/// # Safety
///
/// `dest` must be writable for `dest_len` bytes; `src` readable for `src_len`.
unsafe fn copy_integer(
    dest: *mut u8,
    dest_len: usize,
    src: *const u8,
    src_len: usize,
    pad: u8,
    signed_int: bool,
) -> bool {
    if src_len < dest_len {
        let n = dest_len - src_len;
        // SAFETY: `dest` is writable for `dest_len`, and `dest_len >= src_len`.
        unsafe {
            ptr::write_bytes(dest.add(src_len), pad, n);
            ptr::copy_nonoverlapping(src, dest, src_len);
        }
        return true;
    }
    let n = src_len - dest_len;
    // SAFETY: `src` is readable for `src_len` and `dest_len <= src_len`.
    let dropped_ok = unsafe { check_sign_bytes(src.add(dest_len), n, pad) };
    // SAFETY: `dest_len <= src_len` and `dest_len >= 1` for every caller, so `dest_len - 1`
    // is in bounds.
    let sign_ok = !signed_int || unsafe { ((pad ^ *src.add(dest_len - 1)) & 0x80) == 0 };
    if !dropped_ok || !sign_ok {
        // `err_out_of_range` — CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_138) };
        return false;
    }
    // SAFETY: `dest` is writable for `dest_len` and `src` readable for that much.
    unsafe { ptr::copy_nonoverlapping(src, dest, dest_len) };
    true
}

/// `static int signed_from_signed(...)` — sign-extends with the source's own sign.
///
/// # Safety
///
/// As [`copy_integer`]; `src_len >= 1`.
unsafe fn signed_from_signed(
    dest: *mut c_void,
    dest_len: usize,
    src: *const c_void,
    src_len: usize,
) -> bool {
    // SAFETY: the caller promises `src_len >= 1` readable bytes.
    let pad = if unsafe { is_negative(src, src_len) } {
        0xff
    } else {
        0
    };
    // SAFETY: as `copy_integer`.
    unsafe { copy_integer(dest.cast(), dest_len, src.cast(), src_len, pad, true) }
}

/// `static int signed_from_unsigned(...)` — zero-extends, but still refuses a lossy
/// narrowing.
///
/// # Safety
///
/// As [`copy_integer`].
unsafe fn signed_from_unsigned(
    dest: *mut c_void,
    dest_len: usize,
    src: *const c_void,
    src_len: usize,
) -> bool {
    // SAFETY: as `copy_integer`.
    unsafe { copy_integer(dest.cast(), dest_len, src.cast(), src_len, 0, true) }
}

/// `static int unsigned_from_signed(...)` — refuses a negative source outright, which is
/// a different reason from a value that merely does not fit.
///
/// # Safety
///
/// As [`copy_integer`]; `src_len >= 1`.
unsafe fn unsigned_from_signed(
    dest: *mut c_void,
    dest_len: usize,
    src: *const c_void,
    src_len: usize,
) -> bool {
    // SAFETY: the caller promises `src_len >= 1` readable bytes.
    if unsafe { is_negative(src, src_len) } {
        // `err_unsigned_negative` at crypto/params.c:185 —
        // CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_185) };
        return false;
    }
    // SAFETY: as `copy_integer`.
    unsafe { copy_integer(dest.cast(), dest_len, src.cast(), src_len, 0, false) }
}

/// `static int unsigned_from_unsigned(...)`.
///
/// # Safety
///
/// As [`copy_integer`].
unsafe fn unsigned_from_unsigned(
    dest: *mut c_void,
    dest_len: usize,
    src: *const c_void,
    src_len: usize,
) -> bool {
    // SAFETY: as `copy_integer`.
    unsafe { copy_integer(dest.cast(), dest_len, src.cast(), src_len, 0, false) }
}

/// `static int general_get_int(const OSSL_PARAM *p, void *val, size_t val_size)`.
///
/// # Safety
///
/// `p` must be live and `val` writable for `val_size`.
unsafe fn general_get_int(p: &OsslParam, val: *mut c_void, val_size: usize) -> bool {
    if p.data.is_null() {
        // `err_null_argument` at crypto/params.c:202 — ERR_R_PASSED_NULL_PARAMETER.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_202) };
        return false;
    }
    match p.data_type {
        // SAFETY: `val` is writable for `val_size` and `p.data` readable for
        // `p.data_size` per the caller's contract.
        // SAFETY: `val` is writable for `val_size` and `p.data` readable for
        // `p.data_size` per the caller's contract.
        OSSL_PARAM_INTEGER => unsafe { signed_from_signed(val, val_size, p.data, p.data_size) },
        // SAFETY: as above, with the unsigned source converted to signed.
        OSSL_PARAM_UNSIGNED_INTEGER => unsafe {
            signed_from_unsigned(val, val_size, p.data, p.data_size)
        },
        _ => {
            // `err_not_integer` at crypto/params.c:209 —
            // CRYPTO_R_PARAM_NOT_INTEGER_TYPE.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_209) };
            false
        }
    }
}

/// `static int general_set_int(OSSL_PARAM *p, void *val, size_t val_size)`.
///
/// # Safety
///
/// `p` must be live and, when `p.data` is non-NULL, writable for `p.data_size`.
unsafe fn general_set_int(p: &mut OsslParam, val: *const c_void, val_size: usize) -> bool {
    if p.data.is_null() {
        // A size query: the caller is asking how many bytes it would need.
        p.return_size = val_size;
        return true;
    }
    let r = match p.data_type {
        // SAFETY: `p.data` is writable for `p.data_size` and `val` readable for
        // `val_size` per the caller's contract.
        // SAFETY: `p.data` is writable for `p.data_size` and `val` readable for
        // `val_size` per the caller's contract.
        OSSL_PARAM_INTEGER => unsafe { signed_from_signed(p.data, p.data_size, val, val_size) },
        // SAFETY: as above, with the signed source refused if it is negative.
        OSSL_PARAM_UNSIGNED_INTEGER => unsafe {
            unsigned_from_signed(p.data, p.data_size, val, val_size)
        },
        _ => {
            // `err_not_integer` at crypto/params.c:227.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_227) };
            false
        }
    };
    p.return_size = if r { p.data_size } else { val_size };
    r
}

/// `static int general_get_uint(const OSSL_PARAM *p, void *val, size_t val_size)`.
///
/// # Safety
///
/// `p` must be live and `val` writable for `val_size`.
unsafe fn general_get_uint(p: &OsslParam, val: *mut c_void, val_size: usize) -> bool {
    if p.data.is_null() {
        // `err_null_argument` at crypto/params.c:237.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_237) };
        return false;
    }
    match p.data_type {
        // SAFETY: as `general_get_int`.
        // SAFETY: as `general_get_int`.
        OSSL_PARAM_INTEGER => unsafe { unsigned_from_signed(val, val_size, p.data, p.data_size) },
        // SAFETY: as above, with both sides unsigned.
        OSSL_PARAM_UNSIGNED_INTEGER => unsafe {
            unsigned_from_unsigned(val, val_size, p.data, p.data_size)
        },
        _ => {
            // `err_not_integer` at crypto/params.c:244.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_244) };
            false
        }
    }
}

/// `static int general_set_uint(OSSL_PARAM *p, void *val, size_t val_size)`.
///
/// # Safety
///
/// `p` must be live and, when `p.data` is non-NULL, writable for `p.data_size`.
unsafe fn general_set_uint(p: &mut OsslParam, val: *const c_void, val_size: usize) -> bool {
    if p.data.is_null() {
        p.return_size = val_size;
        return true;
    }
    let r = match p.data_type {
        // SAFETY: as `general_set_int`.
        // SAFETY: as `general_set_int`.
        OSSL_PARAM_INTEGER => unsafe { signed_from_unsigned(p.data, p.data_size, val, val_size) },
        // SAFETY: as above, with both sides unsigned.
        OSSL_PARAM_UNSIGNED_INTEGER => unsafe {
            unsigned_from_unsigned(p.data, p.data_size, val, val_size)
        },
        _ => {
            // `err_not_integer` at crypto/params.c:262.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_262) };
            false
        }
    };
    p.return_size = if r { p.data_size } else { val_size };
    r
}

// --- the width-specific accessors -------------------------------------------------
//
// Each accessor's body is the authority's, including its fast path. `c_int` is four
// bytes and `c_long` is eight on the admitted platform, so the `switch` on `sizeof`
// resolves at compile time and the general path is what remains when no case matches.

/// `int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val)`
///
/// # Safety
///
/// `p` must be NULL or live and `val` NULL or writable for one `int`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_int(p: *const OsslParam, val: *mut c_int) -> c_int {
    guard_ffi(0, || {
        // `sizeof(int) == sizeof(int32_t)` on the admitted platform.
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_get_int32(p, val.cast()) }
    })
}

/// `int OSSL_PARAM_set_int(OSSL_PARAM *p, int val)`
///
/// # Safety
///
/// `p` must be NULL or live and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_int(p: *mut OsslParam, val: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_set_int32(p, val) }
    })
}

/// `int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val)`
///
/// # Safety
///
/// `p` must be NULL or live and `val` NULL or writable for one `unsigned int`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_uint(p: *const OsslParam, val: *mut c_uint) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_get_uint32(p, val.cast()) }
    })
}

/// `int OSSL_PARAM_set_uint(OSSL_PARAM *p, unsigned int val)`
///
/// # Safety
///
/// `p` must be NULL or live and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_uint(p: *mut OsslParam, val: c_uint) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_set_uint32(p, val) }
    })
}

/// `int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val)`
///
/// # Safety
///
/// `p` must be NULL or live and `val` NULL or writable for one `long`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_long(p: *const OsslParam, val: *mut c_long) -> c_int {
    guard_ffi(0, || {
        // `sizeof(long int) == sizeof(int64_t)` on the admitted platform.
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_get_int64(p, val.cast()) }
    })
}

/// `int OSSL_PARAM_set_long(OSSL_PARAM *p, long int val)`
///
/// # Safety
///
/// `p` must be NULL or live and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_long(p: *mut OsslParam, val: c_long) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_set_int64(p, val) }
    })
}

/// `int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, unsigned long int *val)`
///
/// # Safety
///
/// `p` must be NULL or live and `val` NULL or writable for one `unsigned long`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_ulong(p: *const OsslParam, val: *mut c_ulong) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_get_uint64(p, val.cast()) }
    })
}

/// `int OSSL_PARAM_set_ulong(OSSL_PARAM *p, unsigned long int val)`
///
/// # Safety
///
/// `p` must be NULL or live and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_ulong(p: *mut OsslParam, val: c_ulong) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_set_uint64(p, val) }
    })
}

/// `int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, size_t *val)`
///
/// # Safety
///
/// `p` must be NULL or live and `val` NULL or writable for one `size_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_size_t(p: *const OsslParam, val: *mut usize) -> c_int {
    guard_ffi(0, || {
        // `sizeof(size_t) == sizeof(uint64_t)` on the admitted platform.
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_get_uint64(p, val.cast()) }
    })
}

/// `int OSSL_PARAM_set_size_t(OSSL_PARAM *p, size_t val)`
///
/// # Safety
///
/// `p` must be NULL or live and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_size_t(p: *mut OsslParam, val: usize) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_set_uint64(p, val as u64) }
    })
}

/// `int OSSL_PARAM_get_time_t(const OSSL_PARAM *p, time_t *val)`
///
/// # Safety
///
/// `p` must be NULL or live and `val` NULL or writable for one `time_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_time_t(p: *const OsslParam, val: *mut TimeT) -> c_int {
    guard_ffi(0, || {
        // `sizeof(time_t) == sizeof(int64_t)` on the admitted platform.
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_get_int64(p, val.cast()) }
    })
}

/// `int OSSL_PARAM_set_time_t(OSSL_PARAM *p, time_t val)`
///
/// # Safety
///
/// `p` must be NULL or live and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_time_t(p: *mut OsslParam, val: TimeT) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract; the cast is width-preserving here.
        unsafe { OSSL_PARAM_set_int64(p, val) }
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for an `int`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_int(
    key: *const c_char,
    buf: *mut c_int,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_INTEGER,
            buf.cast(),
            core::mem::size_of::<c_int>(),
        )
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for an `unsigned int`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_uint(
    key: *const c_char,
    buf: *mut c_uint,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_UNSIGNED_INTEGER,
            buf.cast(),
            core::mem::size_of::<c_uint>(),
        )
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_long(const char *key, long int *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for a `long`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_long(
    key: *const c_char,
    buf: *mut c_long,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_INTEGER,
            buf.cast(),
            core::mem::size_of::<c_long>(),
        )
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for an
/// `unsigned long`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_ulong(
    key: *const c_char,
    buf: *mut c_ulong,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_UNSIGNED_INTEGER,
            buf.cast(),
            core::mem::size_of::<c_ulong>(),
        )
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_int32(const char *key, int32_t *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for an `int32_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_int32(
    key: *const c_char,
    buf: *mut i32,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_INTEGER,
            buf.cast(),
            core::mem::size_of::<i32>(),
        )
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for a `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_uint32(
    key: *const c_char,
    buf: *mut u32,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_UNSIGNED_INTEGER,
            buf.cast(),
            core::mem::size_of::<u32>(),
        )
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_int64(const char *key, int64_t *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for an `int64_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_int64(
    key: *const c_char,
    buf: *mut i64,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_INTEGER,
            buf.cast(),
            core::mem::size_of::<i64>(),
        )
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for a `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_uint64(
    key: *const c_char,
    buf: *mut u64,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_UNSIGNED_INTEGER,
            buf.cast(),
            core::mem::size_of::<u64>(),
        )
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for a `size_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_size_t(
    key: *const c_char,
    buf: *mut usize,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_UNSIGNED_INTEGER,
            buf.cast(),
            core::mem::size_of::<usize>(),
        )
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_time_t(const char *key, time_t *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for a `time_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_time_t(
    key: *const c_char,
    buf: *mut TimeT,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_INTEGER,
            buf.cast(),
            core::mem::size_of::<TimeT>(),
        )
    })
}

/// `int OSSL_PARAM_get_int32(const OSSL_PARAM *p, int32_t *val)`
///
/// # Safety
///
/// `p` must be NULL or live; `val` NULL or writable for one `int32_t`; `p.data`
/// readable for `p.data_size` when it is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_int32(p: *const OsslParam, val: *mut i32) -> c_int {
    guard_ffi(0, || {
        if val.is_null() || p.is_null() {
            // `err_null_argument` at crypto/params.c:396.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_396) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &*p };
        if q.data.is_null() {
            // `err_null_argument` at crypto/params.c:401.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_401) };
            return 0;
        }
        match q.data_type {
            OSSL_PARAM_INTEGER => {
                // The fast path: exactly the destination width, or a wider source that
                // must be checked for fit.
                match q.data_size {
                    4 => {
                        // SAFETY: `q.data_size` is 4, so the source holds an `int32_t`.
                        unsafe { *val = q.data.cast::<i32>().read() };
                        return 1;
                    }
                    8 => {
                        // SAFETY: `q.data_size` is 8, so the source holds an `int64_t`.
                        let i64v = unsafe { q.data.cast::<i64>().read() };
                        if (i32::MIN as i64..=i32::MAX as i64).contains(&i64v) {
                            // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                            unsafe { *val = i64v as i32 };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_419) };
                        return 0;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                unsafe { c_int::from(general_get_int(q, val.cast(), core::mem::size_of::<i32>())) }
            }
            OSSL_PARAM_UNSIGNED_INTEGER => {
                match q.data_size {
                    4 => {
                        // SAFETY: `q.data_size` is 4, so the source holds a `uint32_t`.
                        let u32v = unsafe { q.data.cast::<u32>().read() };
                        if u32v <= i32::MAX as u32 {
                            // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                            unsafe { *val = u32v as i32 };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_437) };
                        return 0;
                    }
                    8 => {
                        // SAFETY: `q.data_size` is 8, so the source holds a `uint64_t`.
                        let u64v = unsafe { q.data.cast::<u64>().read() };
                        if u64v <= i32::MAX as u64 {
                            // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                            unsafe { *val = u64v as i32 };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_445) };
                        return 0;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                unsafe { c_int::from(general_get_int(q, val.cast(), core::mem::size_of::<i32>())) }
            }
            OSSL_PARAM_REAL => {
                if q.data_size == core::mem::size_of::<f64>() {
                    // SAFETY: `q.data_size` is 8, so the source holds a `double`.
                    let d = unsafe { q.data.cast::<f64>().read() };
                    if d >= f64::from(i32::MIN)
                        && d <= f64::from(i32::MAX)
                        && d == (d as i32 as f64)
                    {
                        // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                        unsafe { *val = d as i32 };
                        return 1;
                    }
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_462) };
                    return 0;
                }
                // `err_unsupported_real` at crypto/params.c:465.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_465) };
                0
            }
            _ => {
                // `err_bad_type` at crypto/params.c:469.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_469) };
                0
            }
        }
    })
}

/// `int OSSL_PARAM_set_int32(OSSL_PARAM *p, int32_t val)`
///
/// # Safety
///
/// `p` must be NULL or live, and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_int32(p: *mut OsslParam, val: i32) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            // `err_null_argument` at crypto/params.c:476.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_476) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        match q.data_type {
            OSSL_PARAM_INTEGER => {
                q.return_size = core::mem::size_of::<i32>();
                if q.data.is_null() {
                    return 1;
                }
                match q.data_size {
                    4 => {
                        // SAFETY: `q.data` is writable for `q.data_size` = 4 bytes.
                        unsafe { q.data.cast::<i32>().write(val) };
                        return 1;
                    }
                    8 => {
                        q.return_size = core::mem::size_of::<i64>();
                        // SAFETY: writable for 8 bytes.
                        unsafe { q.data.cast::<i64>().write(i64::from(val)) };
                        return 1;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe {
                    general_set_int(q, (&val as *const i32).cast(), core::mem::size_of::<i32>())
                })
            }
            OSSL_PARAM_UNSIGNED_INTEGER if val >= 0 => {
                q.return_size = core::mem::size_of::<u32>();
                if q.data.is_null() {
                    return 1;
                }
                match q.data_size {
                    4 => {
                        // SAFETY: writable for 4 bytes.
                        unsafe { q.data.cast::<u32>().write(val as u32) };
                        return 1;
                    }
                    8 => {
                        q.return_size = core::mem::size_of::<u64>();
                        // SAFETY: writable for 8 bytes.
                        unsafe { q.data.cast::<u64>().write(val as u64) };
                        return 1;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe {
                    general_set_int(q, (&val as *const i32).cast(), core::mem::size_of::<i32>())
                })
            }
            OSSL_PARAM_REAL => {
                q.return_size = core::mem::size_of::<f64>();
                if q.data.is_null() {
                    return 1;
                }
                if q.data_size != core::mem::size_of::<f64>() {
                    // `err_unsupported_real` at crypto/params.c:533.
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_533) };
                    return 0;
                }
                let shift = real_shift();
                if shift < 8 * core::mem::size_of::<i32>() as c_uint - 1 {
                    let u32v = val.unsigned_abs();
                    if (u32v >> shift) != 0 {
                        // `err_inexact` at crypto/params.c:526.
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_526) };
                        return 0;
                    }
                }
                // SAFETY: writable for 8 bytes.
                unsafe { q.data.cast::<f64>().write(f64::from(val)) };
                1
            }
            _ => {
                // `err_bad_type` at crypto/params.c:537.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_537) };
                0
            }
        }
    })
}

/// `int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, uint32_t *val)`
///
/// # Safety
///
/// As [`OSSL_PARAM_get_int32`].
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_uint32(p: *const OsslParam, val: *mut u32) -> c_int {
    guard_ffi(0, || {
        if val.is_null() || p.is_null() {
            // `err_null_argument` at crypto/params.c:550.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_550) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &*p };
        if q.data.is_null() {
            // `err_null_argument` at crypto/params.c:555.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_555) };
            return 0;
        }
        match q.data_type {
            OSSL_PARAM_UNSIGNED_INTEGER => {
                match q.data_size {
                    4 => {
                        // SAFETY: 4 readable bytes holding a `uint32_t`.
                        unsafe { *val = q.data.cast::<u32>().read() };
                        return 1;
                    }
                    8 => {
                        // SAFETY: 8 readable bytes holding a `uint64_t`.
                        let u64v = unsafe { q.data.cast::<u64>().read() };
                        if u64v <= u32::MAX as u64 {
                            // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                            unsafe { *val = u64v as u32 };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_573) };
                        return 0;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe { general_get_uint(q, val.cast(), core::mem::size_of::<u32>()) })
            }
            OSSL_PARAM_INTEGER => {
                match q.data_size {
                    4 => {
                        // SAFETY: 4 readable bytes holding an `int32_t`.
                        let i32v = unsafe { q.data.cast::<i32>().read() };
                        if i32v >= 0 {
                            // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                            unsafe { *val = i32v as u32 };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_590) };
                        return 0;
                    }
                    8 => {
                        // SAFETY: 8 readable bytes holding an `int64_t`.
                        let i64v = unsafe { q.data.cast::<i64>().read() };
                        if i64v >= 0 && i64v <= u32::MAX as i64 {
                            // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                            unsafe { *val = i64v as u32 };
                            return 1;
                        }
                        if i64v < 0 {
                            // SAFETY: a compile-time-constant site.
                            unsafe { raise_site(&err_sites::PARAMS_599) };
                        } else {
                            // SAFETY: a compile-time-constant site.
                            unsafe { raise_site(&err_sites::PARAMS_601) };
                        }
                        return 0;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe { general_get_uint(q, val.cast(), core::mem::size_of::<u32>()) })
            }
            OSSL_PARAM_REAL => {
                if q.data_size == core::mem::size_of::<f64>() {
                    // SAFETY: 8 readable bytes holding a `double`.
                    let d = unsafe { q.data.cast::<f64>().read() };
                    if d >= 0.0 && d <= f64::from(u32::MAX) && d == (d as u32 as f64) {
                        // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                        unsafe { *val = d as u32 };
                        return 1;
                    }
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_617) };
                    return 0;
                }
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_620) };
                0
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_624) };
                0
            }
        }
    })
}

/// `int OSSL_PARAM_set_uint32(OSSL_PARAM *p, uint32_t val)`
///
/// # Safety
///
/// `p` must be NULL or live, and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_uint32(p: *mut OsslParam, val: u32) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_631) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        match q.data_type {
            OSSL_PARAM_UNSIGNED_INTEGER => {
                q.return_size = core::mem::size_of::<u32>();
                if q.data.is_null() {
                    return 1;
                }
                match q.data_size {
                    4 => {
                        // SAFETY: writable for 4 bytes.
                        unsafe { q.data.cast::<u32>().write(val) };
                        return 1;
                    }
                    8 => {
                        q.return_size = core::mem::size_of::<u64>();
                        // SAFETY: writable for 8 bytes.
                        unsafe { q.data.cast::<u64>().write(u64::from(val)) };
                        return 1;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe {
                    general_set_uint(q, (&val as *const u32).cast(), core::mem::size_of::<u32>())
                })
            }
            OSSL_PARAM_INTEGER => {
                q.return_size = core::mem::size_of::<i32>();
                if q.data.is_null() {
                    return 1;
                }
                match q.data_size {
                    4 => {
                        if val <= i32::MAX as u32 {
                            // SAFETY: writable for 4 bytes.
                            unsafe { q.data.cast::<i32>().write(val as i32) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_663) };
                        return 0;
                    }
                    8 => {
                        q.return_size = core::mem::size_of::<i64>();
                        // SAFETY: writable for 8 bytes.
                        unsafe { q.data.cast::<i64>().write(i64::from(val)) };
                        return 1;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe {
                    general_set_uint(q, (&val as *const u32).cast(), core::mem::size_of::<u32>())
                })
            }
            OSSL_PARAM_REAL => {
                if q.data.is_null() {
                    q.return_size = core::mem::size_of::<f64>();
                    return 1;
                }
                if q.data_size != core::mem::size_of::<f64>() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_691) };
                    return 0;
                }
                let shift = real_shift();
                if shift < 8 * core::mem::size_of::<u32>() as c_uint && (val >> shift) != 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_684) };
                    return 0;
                }
                // SAFETY: writable for 8 bytes.
                unsafe { q.data.cast::<f64>().write(f64::from(val)) };
                q.return_size = core::mem::size_of::<f64>();
                1
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_695) };
                0
            }
        }
    })
}

/// `int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val)`
///
/// # Safety
///
/// As [`OSSL_PARAM_get_int32`].
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_int64(p: *const OsslParam, val: *mut i64) -> c_int {
    guard_ffi(0, || {
        if val.is_null() || p.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_708) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &*p };
        if q.data.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_713) };
            return 0;
        }
        match q.data_type {
            OSSL_PARAM_INTEGER => {
                match q.data_size {
                    4 => {
                        // SAFETY: 4 readable bytes holding an `int32_t`.
                        unsafe { *val = i64::from(q.data.cast::<i32>().read()) };
                        return 1;
                    }
                    8 => {
                        // SAFETY: 8 readable bytes holding an `int64_t`.
                        unsafe { *val = q.data.cast::<i64>().read() };
                        return 1;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe { general_get_int(q, val.cast(), core::mem::size_of::<i64>()) })
            }
            OSSL_PARAM_UNSIGNED_INTEGER => {
                match q.data_size {
                    4 => {
                        // SAFETY: 4 readable bytes holding a `uint32_t`.
                        unsafe { *val = i64::from(q.data.cast::<u32>().read()) };
                        return 1;
                    }
                    8 => {
                        // SAFETY: 8 readable bytes holding a `uint64_t`.
                        let u64v = unsafe { q.data.cast::<u64>().read() };
                        if u64v <= i64::MAX as u64 {
                            // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                            unsafe { *val = u64v as i64 };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_743) };
                        return 0;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe { general_get_int(q, val.cast(), core::mem::size_of::<i64>()) })
            }
            OSSL_PARAM_REAL => {
                if q.data_size == core::mem::size_of::<f64>() {
                    // SAFETY: 8 readable bytes holding a `double`.
                    let d = unsafe { q.data.cast::<f64>().read() };
                    // The authority subtracts 65535 from `INT64_MAX` and adds 65536.0
                    // back, so that the comparison does not depend on a `double` being
                    // able to represent `INT64_MAX`. The arithmetic is reproduced
                    // rather than simplified.
                    let bound = (i64::MAX - 65535) as f64 + 65536.0;
                    if d >= i64::MIN as f64 && d < bound && d == (d as i64 as f64) {
                        // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                        unsafe { *val = d as i64 };
                        return 1;
                    }
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_766) };
                    return 0;
                }
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_769) };
                0
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_773) };
                0
            }
        }
    })
}

/// `int OSSL_PARAM_set_int64(OSSL_PARAM *p, int64_t val)`
///
/// # Safety
///
/// `p` must be NULL or live, and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_int64(p: *mut OsslParam, val: i64) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_780) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        match q.data_type {
            OSSL_PARAM_INTEGER => {
                if q.data.is_null() {
                    q.return_size = core::mem::size_of::<i64>();
                    return 1;
                }
                match q.data_size {
                    4 => {
                        if (i32::MIN as i64..=i32::MAX as i64).contains(&val) {
                            q.return_size = core::mem::size_of::<i32>();
                            // SAFETY: writable for 4 bytes.
                            unsafe { q.data.cast::<i32>().write(val as i32) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_797) };
                        return 0;
                    }
                    8 => {
                        q.return_size = core::mem::size_of::<i64>();
                        // SAFETY: writable for 8 bytes.
                        unsafe { q.data.cast::<i64>().write(val) };
                        return 1;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe {
                    general_set_int(q, (&val as *const i64).cast(), core::mem::size_of::<i64>())
                })
            }
            OSSL_PARAM_UNSIGNED_INTEGER if val >= 0 => {
                if q.data.is_null() {
                    q.return_size = core::mem::size_of::<u64>();
                    return 1;
                }
                match q.data_size {
                    4 => {
                        if val <= u32::MAX as i64 {
                            q.return_size = core::mem::size_of::<u32>();
                            // SAFETY: writable for 4 bytes.
                            unsafe { q.data.cast::<u32>().write(val as u32) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_819) };
                        return 0;
                    }
                    8 => {
                        q.return_size = core::mem::size_of::<u64>();
                        // SAFETY: writable for 8 bytes.
                        unsafe { q.data.cast::<u64>().write(val as u64) };
                        return 1;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe {
                    general_set_int(q, (&val as *const i64).cast(), core::mem::size_of::<i64>())
                })
            }
            OSSL_PARAM_REAL => {
                if q.data.is_null() {
                    q.return_size = core::mem::size_of::<f64>();
                    return 1;
                }
                if q.data_size != core::mem::size_of::<f64>() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_847) };
                    return 0;
                }
                if (val.unsigned_abs() >> real_shift()) == 0 {
                    q.return_size = core::mem::size_of::<f64>();
                    // SAFETY: writable for 8 bytes.
                    unsafe { q.data.cast::<f64>().write(val as f64) };
                    return 1;
                }
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_844) };
                0
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_851) };
                0
            }
        }
    })
}

/// `int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, uint64_t *val)`
///
/// # Safety
///
/// As [`OSSL_PARAM_get_int32`].
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_uint64(p: *const OsslParam, val: *mut u64) -> c_int {
    guard_ffi(0, || {
        if val.is_null() || p.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_863) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &*p };
        if q.data.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_868) };
            return 0;
        }
        if q.data_type == OSSL_PARAM_UNSIGNED_INTEGER {
            match q.data_size {
                4 => {
                    // SAFETY: 4 readable bytes holding a `uint32_t`.
                    unsafe { *val = u64::from(q.data.cast::<u32>().read()) };
                    return 1;
                }
                8 => {
                    // SAFETY: 8 readable bytes holding a `uint64_t`.
                    unsafe { *val = q.data.cast::<u64>().read() };
                    return 1;
                }
                _ => {}
            }
            // SAFETY: as the caller's contract.
            return c_int::from(unsafe {
                general_get_uint(q, val.cast(), core::mem::size_of::<u64>())
            });
        }
        if q.data_type == OSSL_PARAM_INTEGER {
            match q.data_size {
                4 => {
                    // SAFETY: 4 readable bytes holding an `int32_t`.
                    let i32v = unsafe { q.data.cast::<i32>().read() };
                    if i32v >= 0 {
                        // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                        unsafe { *val = i32v as u64 };
                        return 1;
                    }
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_896) };
                    return 0;
                }
                8 => {
                    // SAFETY: 8 readable bytes holding an `int64_t`.
                    let i64v = unsafe { q.data.cast::<i64>().read() };
                    if i64v >= 0 {
                        // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                        unsafe { *val = i64v as u64 };
                        return 1;
                    }
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_904) };
                    return 0;
                }
                _ => {}
            }
            // SAFETY: as the caller's contract.
            return c_int::from(unsafe {
                general_get_uint(q, val.cast(), core::mem::size_of::<u64>())
            });
        }
        if q.data_type == OSSL_PARAM_REAL {
            if q.data_size == core::mem::size_of::<f64>() {
                // SAFETY: 8 readable bytes holding a `double`.
                let d = unsafe { q.data.cast::<f64>().read() };
                let bound = (u64::MAX - 65535) as f64 + 65536.0;
                if d >= 0.0 && d < bound && d == (d as u64 as f64) {
                    // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                    unsafe { *val = d as u64 };
                    return 1;
                }
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_927) };
                return 0;
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_930) };
            return 0;
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_934) };
        0
    })
}

/// `int OSSL_PARAM_set_uint64(OSSL_PARAM *p, uint64_t val)`
///
/// # Safety
///
/// `p` must be NULL or live, and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_uint64(p: *mut OsslParam, val: u64) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_941) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        match q.data_type {
            OSSL_PARAM_UNSIGNED_INTEGER => {
                if q.data.is_null() {
                    q.return_size = core::mem::size_of::<u64>();
                    return 1;
                }
                match q.data_size {
                    4 => {
                        if val <= u32::MAX as u64 {
                            q.return_size = core::mem::size_of::<u32>();
                            // SAFETY: writable for 4 bytes.
                            unsafe { q.data.cast::<u32>().write(val as u32) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_959) };
                        return 0;
                    }
                    8 => {
                        q.return_size = core::mem::size_of::<u64>();
                        // SAFETY: writable for 8 bytes.
                        unsafe { q.data.cast::<u64>().write(val) };
                        return 1;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe {
                    general_set_uint(q, (&val as *const u64).cast(), core::mem::size_of::<u64>())
                })
            }
            OSSL_PARAM_INTEGER => {
                if q.data.is_null() {
                    q.return_size = core::mem::size_of::<i64>();
                    return 1;
                }
                match q.data_size {
                    4 => {
                        if val <= i32::MAX as u64 {
                            q.return_size = core::mem::size_of::<i32>();
                            // SAFETY: writable for 4 bytes.
                            unsafe { q.data.cast::<i32>().write(val as i32) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_981) };
                        return 0;
                    }
                    8 => {
                        if val <= i64::MAX as u64 {
                            q.return_size = core::mem::size_of::<i64>();
                            // SAFETY: writable for 8 bytes.
                            unsafe { q.data.cast::<i64>().write(val as i64) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_989) };
                        return 0;
                    }
                    _ => {}
                }
                // SAFETY: as the caller's contract.
                c_int::from(unsafe {
                    general_set_uint(q, (&val as *const u64).cast(), core::mem::size_of::<u64>())
                })
            }
            OSSL_PARAM_REAL => {
                if q.data_size != core::mem::size_of::<f64>() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_1006) };
                    return 0;
                }
                if (val >> real_shift()) == 0 {
                    q.return_size = core::mem::size_of::<f64>();
                    // SAFETY: writable for 8 bytes.
                    unsafe { q.data.cast::<f64>().write(val as f64) };
                    return 1;
                }
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_1003) };
                0
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_1010) };
                0
            }
        }
    })
}

// ---------------------------------------------------------------------------------
// The real plane
// ---------------------------------------------------------------------------------

/// `int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val)`
///
/// Unreachable-by-configuration note: the authority guards this family with
/// `#ifndef OPENSSL_SYS_UEFI`, which the admitted profile does not define, so the
/// symbols exist and are what this reproduces. The `REAL` arm reads a host `double`
/// out of the descriptor; the integer arms convert only when the conversion is exact,
/// which is what `real_shift` decides.
///
/// # Safety
///
/// `p` must be NULL or live; `val` NULL or writable for one `double`; `p.data`
/// readable for `p.data_size` when it is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_double(p: *const OsslParam, val: *mut f64) -> c_int {
    guard_ffi(0, || {
        if val.is_null() || p.is_null() {
            // `err_null_argument` at crypto/params.c:1184.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1184) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &*p };
        if q.data.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1184) };
            return 0;
        }
        if q.data_type == OSSL_PARAM_REAL {
            if q.data_size == core::mem::size_of::<f64>() {
                // SAFETY: 8 readable bytes holding a `double`.
                unsafe { *val = q.data.cast::<f64>().read() };
                return 1;
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1194) };
            return 0;
        }
        if q.data_type == OSSL_PARAM_UNSIGNED_INTEGER {
            match q.data_size {
                4 => {
                    // SAFETY: 4 readable bytes holding a `uint32_t`.
                    unsafe { *val = f64::from(q.data.cast::<u32>().read()) };
                    return 1;
                }
                8 => {
                    // SAFETY: 8 readable bytes holding a `uint64_t`.
                    let u64v = unsafe { q.data.cast::<u64>().read() };
                    if (u64v >> real_shift()) == 0 {
                        // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                        unsafe { *val = u64v as f64 };
                        return 1;
                    }
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_1207) };
                    return 0;
                }
                _ => {}
            }
        } else if q.data_type == OSSL_PARAM_INTEGER {
            match q.data_size {
                4 => {
                    // SAFETY: 4 readable bytes holding an `int32_t`.
                    unsafe { *val = f64::from(q.data.cast::<i32>().read()) };
                    return 1;
                }
                8 => {
                    // SAFETY: 8 readable bytes holding an `int64_t`.
                    let i64v = unsafe { q.data.cast::<i64>().read() };
                    let u64v = i64v.unsigned_abs();
                    if (u64v >> real_shift()) == 0 {
                        // SAFETY: `val` is the caller's out-parameter, checked non-NULL above.
                        unsafe { *val = 0.0 + i64v as f64 };
                        return 1;
                    }
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_1222) };
                    return 0;
                }
                _ => {}
            }
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1226) };
        0
    })
}

/// `int OSSL_PARAM_set_double(OSSL_PARAM *p, double val)`
///
/// The bounds are the authority's, and they are deliberately *half-open*: an unsigned
/// destination accepts `0 <= val < 2^32`, a signed one `-2^31 <= val < 2^31`. `2^31`
/// itself is rejected for `int32`, which is what the authority's `d_pow_31` bound says
/// and is one off from what a "fits in an int32" reading would give.
///
/// # Safety
///
/// `p` must be NULL or live, and writable for `p.data_size` when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_double(p: *mut OsslParam, val: f64) -> c_int {
    guard_ffi(0, || {
        // The authority spells these as `(double)((uint32_t)1 << 31)` and its multiples,
        // which are exact in binary floating point.
        let d_pow_31 = 2147483648.0f64;
        let d_pow_32 = 2.0 * d_pow_31;
        let d_pow_63 = 2.0 * d_pow_31 * d_pow_31;
        let d_pow_64 = 4.0 * d_pow_31 * d_pow_31;

        if p.is_null() {
            // `err_null_argument` at crypto/params.c:1239.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1239) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        match q.data_type {
            OSSL_PARAM_REAL => {
                if q.data.is_null() {
                    q.return_size = core::mem::size_of::<f64>();
                    return 1;
                }
                if q.data_size == core::mem::size_of::<f64>() {
                    q.return_size = core::mem::size_of::<f64>();
                    // SAFETY: writable for 8 bytes.
                    unsafe { q.data.cast::<f64>().write(val) };
                    return 1;
                }
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_1255) };
                0
            }
            OSSL_PARAM_UNSIGNED_INTEGER => {
                if q.data.is_null() {
                    // The authority's comment: "Unclear how this is usable, the
                    // parameter's type is integral. Its size should be the size of some
                    // integral type." It answers `sizeof(double)` regardless.
                    q.return_size = core::mem::size_of::<f64>();
                    return 1;
                }
                if val != (val as u64) as f64 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_1267) };
                    return 0;
                }
                match q.data_size {
                    4 => {
                        if val >= 0.0 && val < d_pow_32 {
                            q.return_size = core::mem::size_of::<u32>();
                            // SAFETY: writable for 4 bytes.
                            unsafe { q.data.cast::<u32>().write(val as u32) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_1277) };
                        0
                    }
                    8 => {
                        if val >= 0.0 && val < d_pow_64 {
                            q.return_size = core::mem::size_of::<u64>();
                            // SAFETY: writable for 8 bytes.
                            unsafe { q.data.cast::<u64>().write(val as u64) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_1285) };
                        0
                    }
                    _ => {
                        // The authority falls out of the `switch` to the shared
                        // `err_bad_type` label at the end of the function.
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_1320) };
                        0
                    }
                }
            }
            OSSL_PARAM_INTEGER => {
                if q.data.is_null() {
                    q.return_size = core::mem::size_of::<f64>();
                    return 1;
                }
                if val != (val as i64) as f64 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_1298) };
                    return 0;
                }
                match q.data_size {
                    4 => {
                        if val >= -d_pow_31 && val < d_pow_31 {
                            q.return_size = core::mem::size_of::<i32>();
                            // SAFETY: writable for 4 bytes.
                            unsafe { q.data.cast::<i32>().write(val as i32) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_1308) };
                        0
                    }
                    8 => {
                        if val >= -d_pow_63 && val < d_pow_63 {
                            q.return_size = core::mem::size_of::<i64>();
                            // SAFETY: writable for 8 bytes.
                            unsafe { q.data.cast::<i64>().write(val as i64) };
                            return 1;
                        }
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_1316) };
                        0
                    }
                    _ => {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_1320) };
                        0
                    }
                }
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_1320) };
                0
            }
        }
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for a `double`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_double(
    key: *const c_char,
    buf: *mut f64,
) -> OsslParam {
    guard_ffi(END, || {
        construct(
            key,
            OSSL_PARAM_REAL,
            buf.cast(),
            core::mem::size_of::<f64>(),
        )
    })
}

// ---------------------------------------------------------------------------------
// The BN plane
// ---------------------------------------------------------------------------------

/// `int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val)`
///
/// The value is *reused*: `BN_native2bn` writes into `*val` when it is non-NULL and
/// allocates when it is not, which is what makes a caller able to keep one `BIGNUM`
/// across a call. On failure the authority raises `ERR_R_BN_LIB` from its own
/// coordinates and leaves `*val` alone.
///
/// # Safety
///
/// `p` must be NULL or live; `val` NULL or writable for one `BIGNUM *`; `p.data`
/// readable for `p.data_size`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_BN(p: *const OsslParam, val: *mut *mut BigNum) -> c_int {
    guard_ffi(0, || {
        if val.is_null() || p.is_null() {
            // `err_null_argument` at crypto/params.c:1088.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1088) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &*p };
        if q.data.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1088) };
            return 0;
        }
        // SAFETY: `val` is writable for one pointer.
        let existing = unsafe { *val };
        let b = match q.data_type {
            OSSL_PARAM_UNSIGNED_INTEGER => {
                // SAFETY: `q.data` is readable for `q.data_size`, and `existing` is
                // NULL or a live BIGNUM per the caller's contract.
                unsafe {
                    crate::bn::bignum::BN_native2bn(q.data.cast(), q.data_size as c_int, existing)
                }
            }
            OSSL_PARAM_INTEGER => {
                // SAFETY: as above.
                unsafe {
                    crate::bn::bignum::BN_signed_native2bn(
                        q.data.cast(),
                        q.data_size as c_int,
                        existing,
                    )
                }
            }
            _ => {
                // `err_bad_type` at crypto/params.c:1100.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_1100) };
                ptr::null_mut()
            }
        };
        if b.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1105) };
            return 0;
        }
        // SAFETY: `val` is writable for one pointer.
        unsafe { *val = b };
        1
    })
}

/// `int OSSL_PARAM_set_BN(OSSL_PARAM *p, const BIGNUM *val)`
///
/// The required buffer size is `BN_num_bytes` plus one byte for the sign when the
/// destination is signed, and never zero — "We make sure that at least one byte is
/// used, so zero is properly set". A signed destination one byte short is a
/// `CRYPTO_R_TOO_SMALL_BUFFER` failure, not a truncation.
///
/// # Safety
///
/// `p` must be NULL or live; `val` NULL or a live `BIGNUM`; `p.data` writable for
/// `p.data_size`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_BN(p: *mut OsslParam, val: *const BigNum) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            // `err_null_argument` at crypto/params.c:1118.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1118) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        if val.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1123) };
            return 0;
        }
        // SAFETY: `val` is live per the caller's contract.
        let negative = unsafe { crate::bn::bignum::BN_is_negative(val) } != 0;
        if q.data_type == OSSL_PARAM_UNSIGNED_INTEGER && negative {
            // `err_bad_type` at crypto/params.c:1127.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1127) };
            return 0;
        }
        // SAFETY: `val` is live.
        let bits = unsafe { crate::bn::bignum::BN_num_bits(val) } as usize;
        // `BN_num_bytes(a)` is the macro `(BN_num_bits(a) + 7) / 8`.
        let mut bytes = bits.div_ceil(8);
        if q.data_type == OSSL_PARAM_INTEGER {
            // One extra byte for the sign extension.
            bytes += 1;
        }
        if bytes == 0 {
            bytes += 1;
        }
        if q.data.is_null() {
            q.return_size = bytes;
            return 1;
        }
        if q.data_size >= bytes {
            match q.data_type {
                OSSL_PARAM_UNSIGNED_INTEGER => {
                    // SAFETY: `q.data` is writable for `q.data_size` and `val` is live.
                    if unsafe {
                        crate::bn::bignum::BN_bn2nativepad(val, q.data.cast(), q.data_size as c_int)
                    } < 0
                    {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_1148) };
                        return 0;
                    }
                }
                OSSL_PARAM_INTEGER => {
                    // SAFETY: as above.
                    if unsafe {
                        crate::bn::bignum::BN_signed_bn2native(
                            val,
                            q.data.cast(),
                            q.data_size as c_int,
                        )
                    } < 0
                    {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::PARAMS_1154) };
                        return 0;
                    }
                }
                _ => {
                    // `err_bad_type` at crypto/params.c:1159.
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PARAMS_1159) };
                    return 0;
                }
            }
            q.return_size = q.data_size;
            return 1;
        }
        q.return_size = bytes;
        // `err_too_small` at crypto/params.c:1166 — CRYPTO_R_TOO_SMALL_BUFFER.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1166) };
        0
    })
}

// ---------------------------------------------------------------------------------
// The string and pointer planes
// ---------------------------------------------------------------------------------

/// `static int get_string_internal(const OSSL_PARAM *p, void **val, size_t *max_len,
/// size_t *used_len, unsigned int type)`
///
/// Two contracts intertwine here. `used_len` is written *before* the `data == NULL`
/// check, so a caller that passes only `used_len` and no `val` learns the length even
/// when the parameter has no value. And when `*val == NULL` the function allocates
/// `data_size + 1` for a UTF-8 string — always one more byte than the data, so a
/// NUL can be appended by the caller.
///
/// # Safety
///
/// `p` must be live; `val` NULL or writable for one pointer; `max_len` NULL or
/// writable for one `size_t`; `used_len` NULL or writable for one `size_t`; and when
/// `*val` is non-NULL it must be writable for `*max_len` bytes.
unsafe fn get_string_internal(
    p: &OsslParam,
    val: *mut *mut c_void,
    max_len: *mut usize,
    used_len: *mut usize,
    type_: c_uint,
) -> bool {
    if (val.is_null() && used_len.is_null()) || p.data_type != type_ {
        if p.data_type != type_ {
            // `err_bad_type` at crypto/params.c:1341.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1341) };
        } else {
            // `err_null_argument` at crypto/params.c:1337.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1337) };
        }
        return false;
    }
    let sz = p.data_size;
    // A UTF-8 string always wants a terminator; a zero-length value of any other type
    // still wants a byte so the allocation is not a zero-length request.
    let alloc_sz = sz + usize::from(type_ == OSSL_PARAM_UTF8_STRING || sz == 0);
    if !used_len.is_null() {
        // SAFETY: `used_len` is writable for one `size_t`.
        unsafe { *used_len = sz };
    }
    if p.data.is_null() {
        // `err_null_argument` at crypto/params.c:1356.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1356) };
        return false;
    }
    if val.is_null() {
        return true;
    }
    // SAFETY: `val` is writable for one pointer and `max_len` is non-NULL whenever
    // `val` is used for reading it below; the authority requires the pair.
    let mut cur = unsafe { *val };
    if cur.is_null() {
        // `OPENSSL_malloc(alloc_sz)`, which is `CRYPTO_zalloc`'s sibling: the
        // authority uses malloc here, so the bytes are *not* zeroed.
        let fresh = crate::runtime::mem::CRYPTO_malloc(alloc_sz, FILE.as_ptr(), LINE);
        if fresh.is_null() {
            return false;
        }
        cur = fresh;
        // SAFETY: `val` and `max_len` are writable for one element each.
        unsafe {
            *val = cur;
            *max_len = alloc_sz;
        }
    }
    // SAFETY: `max_len` is non-NULL on every path that reaches here with a non-NULL
    // `val`, per the caller's contract.
    let cap = unsafe { *max_len };
    if cap < sz {
        // `err_too_small` at crypto/params.c:1373.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1373) };
        return false;
    }
    // SAFETY: `cur` is writable for `cap >= sz` bytes and `p.data` is readable for
    // `sz`; the two allocations are distinct.
    unsafe { ptr::copy_nonoverlapping(p.data.cast::<u8>(), cur.cast::<u8>(), sz) };
    true
}

/// `static int set_string_internal(OSSL_PARAM *p, const void *val, size_t len,
/// unsigned int type)`
///
/// A UTF-8 destination with room for one more byte than the value gets a terminator;
/// one with exactly `len` bytes does not, and that is not a failure.
///
/// # Safety
///
/// `p` must be live and writable for `p.data_size` when `p.data` is not NULL; `val`
/// readable for `len`.
unsafe fn set_string_internal(
    p: &mut OsslParam,
    val: *const c_void,
    len: usize,
    type_: c_uint,
) -> bool {
    if p.data_type != type_ {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1422) };
        return false;
    }
    p.return_size = len;
    if p.data.is_null() {
        return true;
    }
    if p.data_size < len {
        // `err_too_small` at crypto/params.c:1429.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1429) };
        return false;
    }
    // SAFETY: `p.data` is writable for `p.data_size >= len` and `val` is readable for
    // `len`.
    unsafe { ptr::copy_nonoverlapping(val.cast::<u8>(), p.data.cast::<u8>(), len) };
    if type_ == OSSL_PARAM_UTF8_STRING && p.data_size > len {
        // SAFETY: `p.data_size > len`, so index `len` is in bounds.
        unsafe { *p.data.cast::<u8>().add(len) = 0 };
    }
    true
}

/// `static int get_ptr_internal_skip_checks(...)` — the indirection a `*_PTR`
/// parameter carries: the descriptor holds a pointer, and this is what reads it out.
///
/// # Safety
///
/// `p.data` must be readable for one pointer; `val` writable for one pointer.
unsafe fn get_ptr_internal_skip_checks(
    p: &OsslParam,
    val: *mut *const c_void,
    used_len: *mut usize,
) {
    if !used_len.is_null() {
        // SAFETY: `used_len` is writable for one `size_t`.
        unsafe { *used_len = p.data_size };
    }
    // SAFETY: `p.data` is readable for one pointer per the caller's contract.
    unsafe { *val = p.data.cast::<*const c_void>().read() };
}

/// `static int get_ptr_internal(...)`.
///
/// # Safety
///
/// As [`get_ptr_internal_skip_checks`], with `val` NULL or writable.
unsafe fn get_ptr_internal(
    p: &OsslParam,
    val: *mut *const c_void,
    used_len: *mut usize,
    type_: c_uint,
) -> bool {
    if val.is_null() {
        // `err_null_argument` at crypto/params.c:1488.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1488) };
        return false;
    }
    if p.data_type != type_ {
        // `err_bad_type` at crypto/params.c:1492.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1492) };
        return false;
    }
    // SAFETY: as the caller's contract.
    unsafe { get_ptr_internal_skip_checks(p, val, used_len) };
    true
}

/// `static int set_ptr_internal(...)`.
///
/// # Safety
///
/// `p` must be live and writable for one pointer when `p.data` is not NULL.
unsafe fn set_ptr_internal(
    p: &mut OsslParam,
    val: *const c_void,
    type_: c_uint,
    len: usize,
) -> bool {
    if p.data_type != type_ {
        // `err_bad_type` at crypto/params.c:1513.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1513) };
        return false;
    }
    p.return_size = len;
    if !p.data.is_null() {
        // SAFETY: `p.data` is writable for one pointer per the caller's contract.
        unsafe { p.data.cast::<*const c_void>().write(val) };
    }
    true
}

/// `static int get_string_ptr_internal(const OSSL_PARAM *p, const void **val,
/// size_t *used_len, unsigned int ref_type, unsigned int type)`
///
/// The bridge between the two shapes: a `*_PTR` parameter is dereferenced, and a
/// `*_STRING` parameter hands back the descriptor's own buffer. That is what lets a
/// caller read a string parameter without copying it, and it is why the returned
/// pointer's lifetime belongs to the descriptor rather than to the caller.
///
/// # Safety
///
/// `p` must be live; `val` NULL or writable for one pointer; `used_len` NULL or
/// writable for one `size_t`; `p.data` readable for one pointer when the type is
/// `ref_type`.
unsafe fn get_string_ptr_internal(
    p: &OsslParam,
    val: *mut *const c_void,
    used_len: *mut usize,
    ref_type: c_uint,
    type_: c_uint,
) -> bool {
    if val.is_null() {
        // `err_null_argument` at crypto/params.c:1676.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1676) };
        return false;
    }
    if p.data_type == ref_type {
        // SAFETY: as the caller's contract.
        unsafe { get_ptr_internal_skip_checks(p, val, used_len) };
        return true;
    }
    if p.data_type != type_ {
        // `err_bad_type` at crypto/params.c:1684.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAMS_1684) };
        return false;
    }
    if !used_len.is_null() {
        // SAFETY: `used_len` is writable for one `size_t`.
        unsafe { *used_len = p.data_size };
    }
    // SAFETY: `val` is writable for one pointer.
    unsafe { *val = p.data.cast_const() };
    true
}

/// `int OSSL_PARAM_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len)`
///
/// One extra contract over the internal helper: the copy is NUL-terminated, and when
/// `data_size` disagrees with `max_len` the authority measures the real string with
/// `OPENSSL_strnlen` rather than trusting `data_size` — its comment records that a
/// parameter's `data_size` has been seen to be out of bounds. If no byte is left for
/// the terminator it refuses with `CRYPTO_R_NO_SPACE_FOR_TERMINATING_NULL`.
///
/// # Safety
///
/// `p` must be NULL or live; `val` NULL or writable for one pointer; and when `*val`
/// is non-NULL it must be writable for `max_len` bytes; `p.data` readable for
/// `p.data_size`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_utf8_string(
    p: *const OsslParam,
    val: *mut *mut c_char,
    max_len: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null-or-live per the caller's contract.
        let Some(q) = (unsafe { as_ref(p) }) else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1337) };
            return 0;
        };
        let mut cap = max_len;
        // SAFETY: `val` is NULL or writable for one pointer; `cap` is a live local;
        // `q.data` is readable for `q.data_size`.
        let ret = unsafe {
            get_string_internal(
                q,
                val.cast(),
                &mut cap,
                ptr::null_mut(),
                OSSL_PARAM_UTF8_STRING,
            )
        };
        let mut data_length = q.data_size;
        if !ret {
            return 0;
        }
        if data_length >= cap {
            // SAFETY: `q.data` is readable for `q.data_size`, and `OPENSSL_strnlen`
            // bounds its own scan by that length.
            data_length =
                unsafe { crate::runtime::str::OPENSSL_strnlen(q.data.cast(), data_length) };
        }
        if data_length >= cap {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1403) };
            return 0;
        }
        if !val.is_null() {
            // SAFETY: `*val` is non-NULL by now — `get_string_internal` allocated it —
            // and `data_length < cap <= its allocation`.
            unsafe { **val.add(data_length) = 0 };
        }
        1
    })
}

/// `int OSSL_PARAM_get_octet_string(const OSSL_PARAM *p, void **val, size_t max_len,
/// size_t *used_len)`
///
/// # Safety
///
/// `p` must be NULL or live; `val` NULL or writable for one pointer; `used_len` NULL
/// or writable for one `size_t`; and when `*val` is non-NULL it must be writable for
/// `max_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_octet_string(
    p: *const OsslParam,
    val: *mut *mut c_void,
    max_len: usize,
    used_len: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null-or-live per the caller's contract.
        let Some(q) = (unsafe { as_ref(p) }) else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1337) };
            return 0;
        };
        let mut cap = max_len;
        // SAFETY: as `OSSL_PARAM_get_utf8_string`, with the octet type.
        c_int::from(unsafe {
            get_string_internal(q, val, &mut cap, used_len, OSSL_PARAM_OCTET_STRING)
        })
    })
}

/// `int OSSL_PARAM_set_utf8_string(OSSL_PARAM *p, const char *val)`
///
/// # Safety
///
/// `p` must be NULL or live and writable for `p.data_size` when `p.data` is not NULL;
/// `val` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_utf8_string(
    p: *mut OsslParam,
    val: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if p.is_null() || val.is_null() {
            // `err_null_argument` at crypto/params.c:1443.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1443) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        // SAFETY: `val` is NUL-terminated, so `strlen` stays inside it; `q` is live and
        // writable for `q.data_size`.
        // SAFETY: `val` is NUL-terminated per the caller's contract.
        let len = unsafe { c_strlen(val) };
        // SAFETY: `q` is live and writable for `q.data_size`; `val` is readable for
        // `len`.
        c_int::from(unsafe { set_string_internal(q, val.cast(), len, OSSL_PARAM_UTF8_STRING) })
    })
}

/// `int OSSL_PARAM_set_octet_string(OSSL_PARAM *p, const void *val, size_t len)`
///
/// # Safety
///
/// `p` must be NULL or live and writable for `p.data_size` when `p.data` is not NULL;
/// `val` NULL or readable for `len`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_octet_string(
    p: *mut OsslParam,
    val: *const c_void,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        if p.is_null() || val.is_null() {
            // `err_null_argument` at crypto/params.c:1454.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1454) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        // SAFETY: `val` is readable for `len`; `q` is live and writable for
        // `q.data_size`.
        c_int::from(unsafe { set_string_internal(q, val, len, OSSL_PARAM_OCTET_STRING) })
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize)`
///
/// A zero `bsize` with a non-NULL `buf` means "measure it", which is the only
/// constructor here that reads its buffer.
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or a NUL-terminated string when
/// `bsize` is 0, and writable for `bsize` otherwise.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_utf8_string(
    key: *const c_char,
    buf: *mut c_char,
    bsize: usize,
) -> OsslParam {
    guard_ffi(END, || {
        let mut size = bsize;
        if !buf.is_null() && size == 0 {
            // SAFETY: `buf` is NUL-terminated when `bsize` is 0, per the contract.
            size = unsafe { c_strlen(buf) };
        }
        construct(key, OSSL_PARAM_UTF8_STRING, buf.cast(), size)
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf, size_t bsize)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for `bsize`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_octet_string(
    key: *const c_char,
    buf: *mut c_void,
    bsize: usize,
) -> OsslParam {
    guard_ffi(END, || construct(key, OSSL_PARAM_OCTET_STRING, buf, bsize))
}

/// `OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf, size_t bsize)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for one pointer.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_utf8_ptr(
    key: *const c_char,
    buf: *mut *mut c_char,
    bsize: usize,
) -> OsslParam {
    guard_ffi(END, || {
        construct(key, OSSL_PARAM_UTF8_PTR, buf.cast(), bsize)
    })
}

/// `OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf, size_t bsize)`
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for one pointer.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_octet_ptr(
    key: *const c_char,
    buf: *mut *mut c_void,
    bsize: usize,
) -> OsslParam {
    guard_ffi(END, || {
        construct(key, OSSL_PARAM_OCTET_PTR, buf.cast(), bsize)
    })
}

/// `int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, const char **val)`
///
/// # Safety
///
/// `p` must be NULL or live; `val` NULL or writable for one pointer; `p.data`
/// readable for one pointer.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_utf8_ptr(
    p: *const OsslParam,
    val: *mut *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null-or-live per the caller's contract.
        let Some(q) = (unsafe { as_ref(p) }) else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1488) };
            return 0;
        };
        // SAFETY: as the caller's contract.
        c_int::from(unsafe {
            get_ptr_internal(q, val.cast(), ptr::null_mut(), OSSL_PARAM_UTF8_PTR)
        })
    })
}

/// `int OSSL_PARAM_get_octet_ptr(const OSSL_PARAM *p, const void **val, size_t *used_len)`
///
/// # Safety
///
/// As [`OSSL_PARAM_get_utf8_ptr`], with `used_len` NULL or writable for one `size_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_octet_ptr(
    p: *const OsslParam,
    val: *mut *const c_void,
    used_len: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null-or-live per the caller's contract.
        let Some(q) = (unsafe { as_ref(p) }) else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1488) };
            return 0;
        };
        // SAFETY: as the caller's contract.
        c_int::from(unsafe { get_ptr_internal(q, val, used_len, OSSL_PARAM_OCTET_PTR) })
    })
}

/// `int OSSL_PARAM_set_utf8_ptr(OSSL_PARAM *p, const char *val)`
///
/// A NULL `val` is accepted and records a used length of 0, rather than being an
/// argument error — the only setter here of which that is true.
///
/// # Safety
///
/// `p` must be NULL or live and writable for one pointer when `p.data` is not NULL;
/// `val` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_utf8_ptr(p: *mut OsslParam, val: *const c_char) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            // `err_null_argument` at crypto/params.c:1525.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1525) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        let len = if val.is_null() {
            0
        } else {
            // SAFETY: `val` is NUL-terminated per the caller's contract.
            unsafe { c_strlen(val) }
        };
        // SAFETY: `q` is live; `p.data` is writable for one pointer when non-NULL.
        c_int::from(unsafe { set_ptr_internal(q, val.cast(), OSSL_PARAM_UTF8_PTR, len) })
    })
}

/// `int OSSL_PARAM_set_octet_ptr(OSSL_PARAM *p, const void *val, size_t used_len)`
///
/// # Safety
///
/// `p` must be NULL or live and writable for one pointer when `p.data` is not NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_octet_ptr(
    p: *mut OsslParam,
    val: *const c_void,
    used_len: usize,
) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            // `err_null_argument` at crypto/params.c:1537.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1537) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        q.return_size = 0;
        // SAFETY: `q` is live; `p.data` is writable for one pointer when non-NULL.
        c_int::from(unsafe { set_ptr_internal(q, val, OSSL_PARAM_OCTET_PTR, used_len) })
    })
}

/// `int OSSL_PARAM_get_utf8_string_ptr(const OSSL_PARAM *p, const char **val)`
///
/// Accepts either shape: a `UTF8_PTR` is dereferenced, a `UTF8_STRING` hands back the
/// descriptor's own buffer.
///
/// # Safety
///
/// `p` must be NULL or live; `val` NULL or writable for one pointer; `p.data` readable
/// for one pointer when the type is `OSSL_PARAM_UTF8_PTR`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_utf8_string_ptr(
    p: *const OsslParam,
    val: *mut *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null-or-live per the caller's contract.
        let Some(q) = (unsafe { as_ref(p) }) else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1676) };
            return 0;
        };
        // SAFETY: as the caller's contract.
        c_int::from(unsafe {
            get_string_ptr_internal(
                q,
                val.cast(),
                ptr::null_mut(),
                OSSL_PARAM_UTF8_PTR,
                OSSL_PARAM_UTF8_STRING,
            )
        })
    })
}

/// `int OSSL_PARAM_get_octet_string_ptr(const OSSL_PARAM *p, const void **val,
/// size_t *used_len)`
///
/// # Safety
///
/// As [`OSSL_PARAM_get_utf8_string_ptr`], with `used_len` NULL or writable for one
/// `size_t`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_get_octet_string_ptr(
    p: *const OsslParam,
    val: *mut *const c_void,
    used_len: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null-or-live per the caller's contract.
        let Some(q) = (unsafe { as_ref(p) }) else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1676) };
            return 0;
        };
        // SAFETY: as the caller's contract.
        c_int::from(unsafe {
            get_string_ptr_internal(
                q,
                val,
                used_len,
                OSSL_PARAM_OCTET_PTR,
                OSSL_PARAM_OCTET_STRING,
            )
        })
    })
}

/// `int OSSL_PARAM_set_octet_string_or_ptr(OSSL_PARAM *p, const void *val, size_t len)`
///
/// Dispatches on the destination's own type, so one setter serves a parameter whose
/// type the caller does not control.
///
/// # Safety
///
/// `p` must be NULL or live; when `p.data` is non-NULL it must be writable for
/// `p.data_size` (string form) or for one pointer (pointer form); `val` readable for
/// `len` in the string form.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_set_octet_string_or_ptr(
    p: *mut OsslParam,
    val: *const c_void,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            // `err_null_argument` at crypto/params.c:1712.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAMS_1712) };
            return 0;
        }
        // SAFETY: `p` is live per the caller's contract.
        let q = unsafe { &mut *p };
        match q.data_type {
            OSSL_PARAM_OCTET_STRING => {
                // SAFETY: forwarded; see [`OSSL_PARAM_set_octet_string`].
                unsafe { OSSL_PARAM_set_octet_string(p, val, len) }
            }
            OSSL_PARAM_OCTET_PTR => {
                // SAFETY: forwarded; see [`OSSL_PARAM_set_octet_ptr`].
                unsafe { OSSL_PARAM_set_octet_ptr(p, val, len) }
            }
            _ => {
                // `err_bad_type` at crypto/params.c:1721.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAMS_1721) };
                0
            }
        }
    })
}

/// `strlen`, without libc.
///
/// # Safety
///
/// `s` must be NUL-terminated.
pub(crate) unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated per the caller's contract, so the loop stops at the
    // terminator.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

// ---------------------------------------------------------------------------------
// The internal helpers params.c defines for other strata
// ---------------------------------------------------------------------------------
//
// None of these four is reachable from an export of this stratum: `params.c` defines
// them for `crypto/evp` and `crypto/kdf`, which are Phase 7's. They are implemented now
// because they are part of the translation unit this module reconstructs and because
// getting them wrong later would be harder to find than to write correctly here, and
// they carry an `allow(dead_code)` for the same reason `err_reasons.rs` does: the row is
// a reconstruction of an authority fact surface, not an unused implementation.

#[allow(dead_code)] // unreachable until the stratum that calls it lands
/// `int ossl_param_get1_octet_string_from_param(const OSSL_PARAM *p, unsigned char
/// **out, size_t *out_len)`
///
/// Three-valued: `1` on success, `0` on failure, and `-1` when there is **no such
/// parameter** — which is not an error and is what lets a caller distinguish "absent"
/// from "present but unusable". The output is untouched unless the answer is success,
/// so an existing allocation survives a miss.
///
/// When the parameter exists and carries data, the copy goes through
/// [`OSSL_PARAM_get_octet_string`] with a maximum of 0, which is the allocate-your-own
/// path. An *absent* or *empty* parameter clears `*out` and sets `*out_len` to 0.
///
/// # Safety
///
/// `p` must be NULL or live; `out` and `out_len` must be writable for one element each;
/// `*out` must be NULL or a block of `*out_len` bytes from this allocator.
pub(crate) unsafe fn ossl_param_get1_octet_string_from_param(
    p: *const OsslParam,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    if p.is_null() {
        return -1;
    }
    // SAFETY: `p` is live per the caller's contract.
    let q = unsafe { &*p };
    let mut buf: *mut c_void = ptr::null_mut();
    let mut len = 0usize;
    if !q.data.is_null() && q.data_size > 0 {
        // SAFETY: `p` is live; `buf` and `len` are live locals.
        if unsafe { OSSL_PARAM_get_octet_string(p, &mut buf, 0, &mut len) } == 0 {
            return 0;
        }
    }
    // SAFETY: `*out` is NULL or a block of `*out_len` bytes from this allocator, and
    // `out`/`out_len` are writable.
    unsafe {
        if !(*out).is_null() {
            crate::runtime::mem::CRYPTO_clear_free((*out).cast(), *out_len, FILE.as_ptr(), LINE);
        }
        *out = buf.cast();
        *out_len = len;
    }
    1
}

#[allow(dead_code)] // unreachable until the stratum that calls it lands
/// `int ossl_param_get1_octet_string(const OSSL_PARAM *params, const char *name,
/// unsigned char **out, size_t *out_len)`
///
/// The named form of [`ossl_param_get1_octet_string_from_param`]; an absent name
/// answers `-1`, exactly as a NULL parameter does.
///
/// # Safety
///
/// `params` must be NULL or a `key`-terminated array of live `OsslParam`; `name` NULL
/// or NUL-terminated; `out` and `out_len` as
/// [`ossl_param_get1_octet_string_from_param`].
pub(crate) unsafe fn ossl_param_get1_octet_string(
    params: *const OsslParam,
    name: *const c_char,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    // SAFETY: the caller's contract.
    let p = unsafe { OSSL_PARAM_locate_const(params, name) };
    // SAFETY: as the caller's contract.
    unsafe { ossl_param_get1_octet_string_from_param(p, out, out_len) }
}

#[allow(dead_code)] // unreachable until the stratum that calls it lands
/// `static int setbuf_fromparams(size_t n, OSSL_PARAM *p[], unsigned char *out,
/// size_t *outlen)` — concatenate `n` octet-string parameters.
///
/// The authority drives this through `WPACKET`, with `out == NULL` selecting a
/// "null" packet that only counts. `crypto/packet.c` is Phase 7's, and this helper is
/// not reachable from any Phase 6 export, so the packet is reproduced here as the two
/// operations actually used: refuse a non-`OCTET_STRING` element, and refuse a copy
/// that does not fit the caller's buffer. The one behaviour the reproduction does not
/// carry is `WPACKET_init_static_len`'s `ossl_assert(buf != NULL && len > 0)`, so a
/// zero-length *counted* buffer is a refusal here too — the same answer, by a direct
/// test rather than by an assertion. It will be re-based on the real `WPACKET` when
/// that stratum lands; see `docs/DECISIONS.md` D103.
///
/// # Safety
///
/// `params` must be readable for `n` live `OsslParam`; when `out` is non-NULL it must
/// be writable for `*outlen` bytes and `outlen` must be writable for one `size_t`.
unsafe fn setbuf_fromparams(
    n: usize,
    params: *const *const OsslParam,
    out: *mut u8,
    outlen: *mut usize,
) -> bool {
    if params.is_null() || outlen.is_null() {
        return false;
    }
    let counting_only = out.is_null();
    let cap = if counting_only {
        // SAFETY: `outlen` is writable per the caller's contract.
        unsafe { *outlen }
    } else {
        // SAFETY: `outlen` is writable, and a zero-length counted buffer is what
        // `WPACKET_init_static_len` refuses.
        let c = unsafe { *outlen };
        if c == 0 {
            return false;
        }
        c
    };
    let mut written = 0usize;
    for i in 0..n {
        // SAFETY: `params` is readable for `n` pointers per the caller's contract.
        let p = unsafe { *params.add(i) };
        if p.is_null() {
            return false;
        }
        // SAFETY: each element is live per the caller's contract.
        let q = unsafe { &*p };
        if q.data_type != OSSL_PARAM_OCTET_STRING {
            return false;
        }
        if q.data.is_null() || q.data_size == 0 {
            continue;
        }
        let next = written + q.data_size;
        if !counting_only {
            if next > cap {
                return false;
            }
            // SAFETY: `out` is writable for `cap >= next` bytes and `q.data` is readable
            // for `q.data_size`; the regions are distinct.
            unsafe { ptr::copy_nonoverlapping(q.data.cast::<u8>(), out.add(written), q.data_size) };
        }
        written = next;
    }
    // SAFETY: `outlen` is writable for one `size_t`.
    unsafe { *outlen = written };
    true
}

#[allow(dead_code)] // unreachable until the stratum that calls it lands
/// `int ossl_param_get1_concat_octet_string(size_t n, OSSL_PARAM *params[],
/// unsigned char **out, size_t *out_len)` — the concatenation of `n` octet-string
/// parameters into one allocation.
///
/// A zero-length concatenation still allocates one zero byte, so the caller always
/// receives a pointer it can release. `n == 0` is a success that changes nothing.
///
/// # Safety
///
/// `params` must be readable for `n` pointers to live `OsslParam`; `out` and `out_len`
/// must be writable for one element each, with `*out` NULL or a block of `*out_len`
/// bytes from this allocator.
pub(crate) unsafe fn ossl_param_get1_concat_octet_string(
    n: usize,
    params: *const *const OsslParam,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    if n == 0 {
        return 1;
    }
    let mut sz = 0usize;
    // SAFETY: as the caller's contract; `out` is NULL so nothing is written.
    if !unsafe { setbuf_fromparams(n, params, ptr::null_mut(), &mut sz) } {
        return 0;
    }
    if sz == 0 {
        // `OPENSSL_zalloc(1)` — one byte, so the caller has something to release.
        let z = CRYPTO_zalloc(1, FILE.as_ptr(), LINE);
        if z.is_null() {
            return 0;
        }
        // SAFETY: `out`/`out_len` are writable and `*out` is releaseable.
        unsafe {
            if !(*out).is_null() {
                crate::runtime::mem::CRYPTO_clear_free(
                    (*out).cast(),
                    *out_len,
                    FILE.as_ptr(),
                    LINE,
                );
            }
            *out = z.cast();
            *out_len = 1;
        }
        return 1;
    }
    let res = CRYPTO_zalloc(sz, FILE.as_ptr(), LINE);
    if res.is_null() {
        return 0;
    }
    let mut cap = sz;
    // SAFETY: `res` is writable for `sz` bytes, which the counting pass has shown is
    // enough; `params` is readable for `n` pointers.
    if !unsafe { setbuf_fromparams(n, params, res.cast(), &mut cap) } {
        // SAFETY: `res` is a block of `sz` bytes from this allocator.
        unsafe { crate::runtime::mem::CRYPTO_clear_free(res, sz, FILE.as_ptr(), LINE) };
        return 0;
    }
    // SAFETY: `out`/`out_len` are writable and `*out` is releaseable.
    unsafe {
        if !(*out).is_null() {
            crate::runtime::mem::CRYPTO_clear_free((*out).cast(), *out_len, FILE.as_ptr(), LINE);
        }
        *out = res.cast();
        *out_len = cap;
    }
    1
}

/// `OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf, size_t
/// bsize)`
///
/// An `UNSIGNED_INTEGER` parameter over the caller's own buffer, which is how a
/// provider passes a number too wide for any native type. The signedness is not
/// selectable here — a caller that needs two's complement uses
/// [`OSSL_PARAM_set_BN`] on a parameter whose `data_type` it set itself.
///
/// # Safety
///
/// `key` must be NULL or NUL-terminated; `buf` NULL or writable for `bsize`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_construct_BN(
    key: *const c_char,
    buf: *mut u8,
    bsize: usize,
) -> OsslParam {
    crate::ffi::guard_ffi(END, || {
        construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf.cast(), bsize)
    })
}
