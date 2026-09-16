//! Phase 6 — the parameter builder: `crypto/param_build.c`.
//!
//! Every other way of producing an `OSSL_PARAM` array requires the caller to own a
//! buffer for each value *before* it knows how large the values are. A provider
//! returning, say, a signature has the opposite problem: it knows the values and not
//! how the caller wants them laid out. `OSSL_PARAM_BLD_push_*` therefore *records* the
//! values — a copy of a small scalar, a pointer for a string or a `BIGNUM` — and
//! [`OSSL_PARAM_BLD_to_param`] lays them out afterwards in **one** allocation, with the
//! `OSSL_PARAM` array at the front and the values immediately behind it.
//!
//! ## Two blocks, not one, and the difference is not cosmetic
//!
//! A builder counts its blocks twice: `total_blocks` for values going into ordinary
//! memory and `secure_blocks` for values that came from the secure heap. `to_param`
//! allocates a secure block only when `secure_blocks` is non-zero, and attaches it to the
//! array through the same terminator convention `OSSL_PARAM_dup` uses, so
//! `OSSL_PARAM_free` releases both. A scalar that is never secure therefore costs nothing
//! extra, and a value that *is* secure never lands in ordinary memory — which is the
//! whole point for a private key.
//!
//! ## `to_param` consumes the builder
//!
//! After a successful `to_param` the builder is empty: both block counts are reset and
//! every recorded value is freed, so the same builder can be reused for the next
//! parameter set. Its *key* pointers are not copied at any point, so a caller must keep
//! its key strings alive until `to_param` has run — and the returned array's keys point
//! at the caller's literals rather than at copies.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

use crate::bn::bignum::{
    BN_bn2nativepad, BN_get_flags, BN_is_negative, BN_num_bits, BN_signed_bn2native, BigNum,
};
use crate::params::dup::{
    ossl_param_bytes_to_blocks, ossl_param_set_secure_block, AlignedBlock, OSSL_PARAM_ALIGN_SIZE,
};
use crate::params::{OsslParam, OSSL_PARAM_UNMODIFIED};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::secure::{CRYPTO_secure_allocated, CRYPTO_secure_free, CRYPTO_secure_malloc};

/// The authority translation unit this module reconstructs.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/param_build.c";
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `BN_FLG_SECURE` — the flag `push_BN` reads to decide which block a value belongs in.
const BN_FLG_SECURE: c_int = 0x08;

/// `static int param_push_num(OSSL_PARAM_BLD *bld, const char *key, void *num,
/// size_t size, int type)` refuses a scalar wider than the recorder's union.
///
/// The authority's `OSSL_PARAM_BLD_DEF::num` is a union of `ossl_intmax_t`,
/// `ossl_uintmax_t` and `double`, so it is exactly eight bytes — which is why a
/// `long`/`int64_t`/`double` fits and nothing wider does.
const PARAM_BLD_NUM_BYTES: usize = 8;

/// `typedef struct { const char *key; int type; int secure; size_t size; size_t
/// alloc_blocks; const BIGNUM *bn; const void *string; union { … } num; }
/// OSSL_PARAM_BLD_DEF`
///
/// Private to the authority and private here. `bn` and `string` are mutually exclusive
/// by construction: a push sets exactly one of them, or neither for a scalar.
struct ParamBldDef {
    key: *const c_char,
    type_: c_uint,
    secure: bool,
    size: usize,
    alloc_blocks: usize,
    bn: *const BigNum,
    string: *const c_void,
    num: [u8; PARAM_BLD_NUM_BYTES],
}

/// `struct ossl_param_bld_st` — the builder itself.
///
/// The authority's `params` member is a `STACK_OF(OSSL_PARAM_BLD_DEF)`; this is a `Vec`
/// of the same pointers. Both are private, both preserve insertion order (which is the
/// order the parameter array is written in), and the stack's failure mode — a growth
/// failure — has no observable difference from a `Vec`'s, because a `push` that cannot
/// allocate is a failure either way.
// The name is the authority's own typedef, and `ABI-PROTOTYPE` resolves an export
// by its declared name, so it is kept rather than camel-cased.
#[allow(non_camel_case_types)]
pub struct OSSL_PARAM_BLD {
    total_blocks: usize,
    secure_blocks: usize,
    params: Vec<*mut ParamBldDef>,
}

impl OSSL_PARAM_BLD {
    /// `sk_OSSL_PARAM_BLD_DEF_num(bld->params)`.
    fn len(&self) -> usize {
        self.params.len()
    }

    /// `sk_OSSL_PARAM_BLD_DEF_value(bld->params, i)`.
    fn at(&self, i: usize) -> *mut ParamBldDef {
        self.params[i]
    }
}

/// `static OSSL_PARAM_BLD_DEF *param_push(OSSL_PARAM_BLD *bld, const char *key,
/// size_t size, size_t alloc, int type, int secure)`
///
/// `size` is what the descriptor will report as `data_size`; `alloc` is what has to be
/// reserved for the value, and the two differ for a UTF-8 string, whose `alloc` is one
/// byte larger for the terminator.
///
/// # Safety
///
/// `bld` must be live and `key` must outlive the builder.
unsafe fn param_push(
    bld: &mut OSSL_PARAM_BLD,
    key: *const c_char,
    size: usize,
    alloc: usize,
    type_: c_uint,
    secure: bool,
) -> *mut ParamBldDef {
    let pd = CRYPTO_zalloc(core::mem::size_of::<ParamBldDef>(), FILE.as_ptr(), LINE)
        .cast::<ParamBldDef>();
    if pd.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pd` is a fresh zeroed block of exactly this type.
    unsafe {
        (*pd).key = key;
        (*pd).type_ = type_;
        (*pd).size = size;
        (*pd).alloc_blocks = ossl_param_bytes_to_blocks(alloc);
        (*pd).secure = secure;
    }
    // SAFETY: `pd` is live.
    let blocks = unsafe { (*pd).alloc_blocks };
    if secure {
        bld.secure_blocks += blocks;
    } else {
        bld.total_blocks += blocks;
    }
    bld.params.push(pd);
    pd
}

/// `static int param_push_num(OSSL_PARAM_BLD *bld, const char *key, void *num,
/// size_t size, int type)`
///
/// The scalar is *copied* into the recorder, so the caller's local may go out of scope.
///
/// # Safety
///
/// `bld` must be live; `key` must outlive it; `num` must be readable for `size` bytes.
unsafe fn param_push_num(
    bld: &mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: *const c_void,
    size: usize,
    type_: c_uint,
) -> c_int {
    // SAFETY: the caller's contract.
    let pd = unsafe { param_push(bld, key, size, size, type_, false) };
    if pd.is_null() {
        // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at
        // crypto/param_build.c:80.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAM_BUILD_80) };
        return 0;
    }
    if size > PARAM_BLD_NUM_BYTES {
        // A scalar this wide cannot be recorded; the authority raises for it rather than
        // truncating. `CRYPTO_R_TOO_MANY_BYTES` at crypto/param_build.c:84.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAM_BUILD_84) };
        return 0;
    }
    // SAFETY: `pd.num` is eight bytes and `size <= PARAM_BLD_NUM_BYTES`; `num` is
    // readable for `size`.
    unsafe { ptr::copy_nonoverlapping(num.cast::<u8>(), (*pd).num.as_mut_ptr(), size) };
    1
}

/// `OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void)`
#[no_mangle]
pub extern "C" fn OSSL_PARAM_BLD_new() -> *mut OSSL_PARAM_BLD {
    crate::ffi::guard_ffi(ptr::null_mut(), || {
        let r = CRYPTO_zalloc(core::mem::size_of::<OSSL_PARAM_BLD>(), FILE.as_ptr(), LINE)
            .cast::<OSSL_PARAM_BLD>();
        if !r.is_null() {
            // SAFETY: `r` is a fresh zeroed block; writing a `Vec` over it is the
            // initialisation the authority's `sk_..._new_null()` performs.
            unsafe {
                r.write(OSSL_PARAM_BLD {
                    total_blocks: 0,
                    secure_blocks: 0,
                    params: Vec::new(),
                })
            };
        }
        r
    })
}

/// `static void free_all_params(OSSL_PARAM_BLD *bld)` — releases every recorded value,
/// and the `BIGNUM` a `push_BN` recorded is *not* one of them: the caller keeps ownership
/// of a `BIGNUM` it passed, which is why `to_param` can read it after the push.
fn free_all_params(bld: &mut OSSL_PARAM_BLD) {
    for pd in bld.params.drain(..) {
        // SAFETY: `pd` is a block from this allocator that nothing else holds.
        unsafe { CRYPTO_free(pd.cast(), FILE.as_ptr(), LINE) };
    }
}

/// `void OSSL_PARAM_BLD_free(OSSL_PARAM_BLD *bld)`
///
/// # Safety
///
/// `bld` must be NULL or a builder returned by [`OSSL_PARAM_BLD_new`] that has not been
/// freed.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_free(bld: *mut OSSL_PARAM_BLD) {
    crate::ffi::guard_ffi((), || {
        if bld.is_null() {
            return;
        }
        // SAFETY: `bld` is live per the caller's contract.
        let b = unsafe { &mut *bld };
        free_all_params(b);
        // SAFETY: `b` is live; its `params` field is a live `Vec`.
        unsafe { ptr::drop_in_place(&mut b.params) };
        // SAFETY: `bld` is a block from this allocator and has been emptied.
        unsafe { CRYPTO_free(bld.cast(), FILE.as_ptr(), LINE) };
    })
}

// The twelve scalar pushes.
//
// Each is written out rather than generated by a `macro_rules!`. D98 recorded that the
// prototype court refuses a macro body that puts a metavariable in a *type* position —
// deliberately, because reading one would mean guessing what the type expands to — so a
// macro here would make ten exports unreadable and therefore unchecked by either plane.
// The repetition is the price of being read.

/// `int OSSL_PARAM_BLD_push_int(OSSL_PARAM_BLD *bld, const char *key, an `int` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_int(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: c_int,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_125) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const c_int).cast(),
                core::mem::size_of::<c_int>(),
                crate::params::OSSL_PARAM_INTEGER,
            )
        }
    })
}

/// `int OSSL_PARAM_BLD_push_uint(OSSL_PARAM_BLD *bld, const char *key, an `unsigned int` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_uint(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: u32,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_136) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const u32).cast(),
                core::mem::size_of::<u32>(),
                crate::params::OSSL_PARAM_UNSIGNED_INTEGER,
            )
        }
    })
}

/// `int OSSL_PARAM_BLD_push_long(OSSL_PARAM_BLD *bld, const char *key, a `long int` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_long(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: c_long,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_148) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const c_long).cast(),
                core::mem::size_of::<c_long>(),
                crate::params::OSSL_PARAM_INTEGER,
            )
        }
    })
}

/// `int OSSL_PARAM_BLD_push_ulong(OSSL_PARAM_BLD *bld, const char *key, an `unsigned long int` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_ulong(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: c_ulong,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_159) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const c_ulong).cast(),
                core::mem::size_of::<c_ulong>(),
                crate::params::OSSL_PARAM_UNSIGNED_INTEGER,
            )
        }
    })
}

/// `int OSSL_PARAM_BLD_push_int32(OSSL_PARAM_BLD *bld, const char *key, an `int32_t` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_int32(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: i32,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_171) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const i32).cast(),
                core::mem::size_of::<i32>(),
                crate::params::OSSL_PARAM_INTEGER,
            )
        }
    })
}

/// `int OSSL_PARAM_BLD_push_uint32(OSSL_PARAM_BLD *bld, const char *key, a `uint32_t` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_uint32(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: u32,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_182) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const u32).cast(),
                core::mem::size_of::<u32>(),
                crate::params::OSSL_PARAM_UNSIGNED_INTEGER,
            )
        }
    })
}

/// `int OSSL_PARAM_BLD_push_int64(OSSL_PARAM_BLD *bld, const char *key, an `int64_t` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_int64(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: i64,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_194) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const i64).cast(),
                core::mem::size_of::<i64>(),
                crate::params::OSSL_PARAM_INTEGER,
            )
        }
    })
}

/// `int OSSL_PARAM_BLD_push_uint64(OSSL_PARAM_BLD *bld, const char *key, a `uint64_t` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_uint64(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: u64,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_205) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const u64).cast(),
                core::mem::size_of::<u64>(),
                crate::params::OSSL_PARAM_UNSIGNED_INTEGER,
            )
        }
    })
}

/// `int OSSL_PARAM_BLD_push_size_t(OSSL_PARAM_BLD *bld, const char *key, a `size_t` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_size_t(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: usize,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_217) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const usize).cast(),
                core::mem::size_of::<usize>(),
                crate::params::OSSL_PARAM_UNSIGNED_INTEGER,
            )
        }
    })
}

/// `int OSSL_PARAM_BLD_push_time_t(OSSL_PARAM_BLD *bld, const char *key, a `time_t` val)`
///
/// The value is copied; the key must outlive the builder and is not copied at all.
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_time_t(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: crate::runtime::time::TimeT,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at this
            // function's own line in crypto/param_build.c.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_229) };
            return 0;
        }
        // SAFETY: `bld` is live per the caller's contract; `key` outlives it; `num` is a
        // live local readable for its own size.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const crate::runtime::time::TimeT).cast(),
                core::mem::size_of::<crate::runtime::time::TimeT>(),
                crate::params::OSSL_PARAM_INTEGER,
            )
        }
    })
}

/// `OSSL_PARAM_BLD_push_double(OSSL_PARAM_BLD *bld, const char *key, double num)`
///
/// # Safety
///
/// `bld` must be NULL or a live builder and `key` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_double(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    num: f64,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_241) };
            return 0;
        }
        // SAFETY: `bld` is live; `num` is a live local.
        unsafe {
            param_push_num(
                &mut *bld,
                key,
                (&num as *const f64).cast(),
                8,
                crate::params::OSSL_PARAM_REAL,
            )
        }
    })
}

/// `static int push_BN(OSSL_PARAM_BLD *bld, const char *key, const BIGNUM *bn,
/// size_t sz, int type)`
///
/// A NULL `bn` is *not* an error: it records a zero-length (or caller-padded) parameter
/// with no value, which is how a provider announces a parameter whose value it does not
/// have. The size arithmetic is the authority's: `BN_num_bytes` is the magnitude's
/// length, a `sz` smaller than that is a `CRYPTO_R_TOO_SMALL_BUFFER`, a zero `sz` becomes
/// one byte "so zero is properly set", and a secure `BIGNUM` moves the value to the
/// secure block.
///
/// # Safety
///
/// `bld` must be live; `key` must outlive it; `bn` must be NULL or a live `BIGNUM` that
/// outlives the builder.
unsafe fn push_bn(
    bld: &mut OSSL_PARAM_BLD,
    key: *const c_char,
    bn: *const BigNum,
    mut sz: usize,
    type_: c_uint,
) -> c_int {
    // `bld` is a reference, so the authority's `bld == NULL` test is the callers'
    // business — and every caller has it: they raise at their own line before reaching
    // here. What remains is the key test.
    if key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PARAM_BUILD_255) };
        return 0;
    }
    if type_ != crate::params::OSSL_PARAM_UNSIGNED_INTEGER
        && type_ != crate::params::OSSL_PARAM_INTEGER
    {
        // `ossl_assert` with no raise: the authority returns 0 silently here, because
        // the condition is a programming error rather than a caller error.
        return 0;
    }
    let mut secure = false;
    if !bn.is_null() {
        // SAFETY: `bn` is live per the caller's contract.
        let negative = unsafe { BN_is_negative(bn) } != 0;
        if type_ == crate::params::OSSL_PARAM_UNSIGNED_INTEGER && negative {
            // `ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_UNSUPPORTED, "Negative big numbers
            // are unsupported for OSSL_PARAM_UNSIGNED_INTEGER")` at
            // crypto/param_build.c:265.
            // SAFETY: a compile-time-constant site, and the message is a static string.
            unsafe {
                crate::runtime::err::raise_site_data(
                    &err_sites::PARAM_BUILD_265,
                    c"Negative big numbers are unsupported for OSSL_PARAM_UNSIGNED_INTEGER"
                        .as_ptr(),
                )
            };
            return 0;
        }
        // SAFETY: `bn` is live. `BN_num_bytes(a)` is the macro
        // `(BN_num_bits(a) + 7) / 8`.
        let bits = unsafe { BN_num_bits(bn) } as usize;
        let n = bits.div_ceil(8);
        if sz < n {
            // `CRYPTO_R_TOO_SMALL_BUFFER` at crypto/param_build.c:276.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_276) };
            return 0;
        }
        // SAFETY: `bn` is live.
        if unsafe { BN_get_flags(bn, BN_FLG_SECURE) } == BN_FLG_SECURE {
            secure = true;
        }
        // The `n < 0` arm at crypto/param_build.c:272 is unreachable here: `BN_num_bits`
        // is not negative for any live `BIGNUM`, so `(bits + 7) / 8` cannot be. The
        // generated site exists and is not called; `docs/DECISIONS.md` D103 records that
        // rather than a fabricated call.
        if sz == 0 {
            sz += 1;
        }
    }
    // SAFETY: `bld` is live; `key` outlives it.
    let pd = unsafe { param_push(bld, key, sz, sz, type_, secure) };
    if pd.is_null() {
        return 0;
    }
    // SAFETY: `pd` is live.
    unsafe { (*pd).bn = bn };
    1
}

/// `OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld, const char *key, const BIGNUM *bn)`
///
/// A negative `BIGNUM` becomes a *signed* parameter one byte wider than its magnitude,
/// and a non-negative one an unsigned parameter of exactly its magnitude. Which of the
/// two a caller gets is therefore a property of the value, not of the call.
///
/// # Safety
///
/// `bld` must be NULL or a live builder; `key` NULL or NUL-terminated; `bn` NULL or a
/// live `BIGNUM` that outlives the builder.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_BN(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    bn: *const BigNum,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_297) };
            return 0;
        }
        let negative = if bn.is_null() {
            false
        } else {
            // SAFETY: `bn` is live on this branch.
            (unsafe { BN_is_negative(bn) }) != 0
        };
        // SAFETY: `bld` is live; `bn` is NULL or live.
        unsafe {
            if negative {
                let bits = BN_num_bits(bn) as usize;
                push_bn(
                    &mut *bld,
                    key,
                    bn,
                    bits.div_ceil(8) + 1,
                    crate::params::OSSL_PARAM_INTEGER,
                )
            } else {
                let sz = if bn.is_null() {
                    0
                } else {
                    (BN_num_bits(bn) as usize).div_ceil(8)
                };
                push_bn(
                    &mut *bld,
                    key,
                    bn,
                    sz,
                    crate::params::OSSL_PARAM_UNSIGNED_INTEGER,
                )
            }
        }
    })
}

/// `OSSL_PARAM_BLD_push_BN_pad(OSSL_PARAM_BLD *bld, const char *key, const BIGNUM *bn,
/// size_t sz)`
///
/// The `sz` is honoured for an unsigned value and **ignored** for a negative one, which
/// is the reverse of what the name suggests and is the authority's own asymmetry: a
/// signed value must be exactly as wide as its magnitude plus a sign byte, or the
/// encoding would not be two's complement.
///
/// # Safety
///
/// As [`OSSL_PARAM_BLD_push_BN`].
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_BN_pad(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    bn: *const BigNum,
    sz: usize,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_312) };
            return 0;
        }
        let negative = if bn.is_null() {
            false
        } else {
            // SAFETY: `bn` is live on this branch.
            (unsafe { BN_is_negative(bn) }) != 0
        };
        // SAFETY: `bld` is live; `bn` is NULL or live.
        unsafe {
            if negative {
                let bits = BN_num_bits(bn) as usize;
                push_bn(
                    &mut *bld,
                    key,
                    bn,
                    bits.div_ceil(8),
                    crate::params::OSSL_PARAM_INTEGER,
                )
            } else {
                push_bn(
                    &mut *bld,
                    key,
                    bn,
                    sz,
                    crate::params::OSSL_PARAM_UNSIGNED_INTEGER,
                )
            }
        }
    })
}

/// `OSSL_PARAM_BLD_push_utf8_string(OSSL_PARAM_BLD *bld, const char *key, const char
/// *buf, size_t bsize)`
///
/// A zero `bsize` means "measure it". The value is *not* copied here — the pointer is
/// recorded and read by `to_param` — so the caller's buffer must outlive the builder.
/// A buffer that came from the secure heap puts the value in the secure block.
///
/// # Safety
///
/// `bld` must be NULL or live; `key` NULL or NUL-terminated; `buf` NULL or
/// NUL-terminated when `bsize` is 0, and readable for `bsize` otherwise.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_utf8_string(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    buf: *const c_char,
    bsize: usize,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() || buf.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_329) };
            return 0;
        }
        let size = if bsize == 0 {
            // SAFETY: `buf` is NUL-terminated per the caller's contract.
            unsafe { crate::params::c_strlen(buf) }
        } else {
            bsize
        };
        let secure = CRYPTO_secure_allocated(buf.cast()) != 0;
        // SAFETY: `bld` is live; `key` outlives it.
        let pd = unsafe {
            param_push(
                &mut *bld,
                key,
                size,
                size + 1,
                crate::params::OSSL_PARAM_UTF8_STRING,
                secure,
            )
        };
        if pd.is_null() {
            return 0;
        }
        // SAFETY: `pd` is live.
        unsafe { (*pd).string = buf.cast() };
        1
    })
}

/// `OSSL_PARAM_BLD_push_utf8_ptr(OSSL_PARAM_BLD *bld, const char *key, char *buf,
/// size_t bsize)`
///
/// # Safety
///
/// `bld` must be NULL or live; `key` NULL or NUL-terminated; `buf` NULL or NUL-terminated
/// when `bsize` is 0, and readable for one pointer's worth of string otherwise.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_utf8_ptr(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    buf: *mut c_char,
    bsize: usize,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() || buf.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_349) };
            return 0;
        }
        let mut size = bsize;
        if size == 0 {
            // SAFETY: `buf` is NUL-terminated per the caller's contract.
            size = unsafe { crate::params::c_strlen(buf) };
        }
        // `alloc` is `sizeof(buf)` — a pointer's worth, not the string's.
        // SAFETY: `bld` is live; `key` outlives it.
        let pd = unsafe {
            param_push(
                &mut *bld,
                key,
                size,
                core::mem::size_of::<*const c_char>(),
                crate::params::OSSL_PARAM_UTF8_PTR,
                false,
            )
        };
        if pd.is_null() {
            return 0;
        }
        // SAFETY: `pd` is live.
        unsafe { (*pd).string = buf.cast() };
        1
    })
}

/// `OSSL_PARAM_BLD_push_octet_string(OSSL_PARAM_BLD *bld, const char *key,
/// const void *buf, size_t bsize)`
///
/// Unlike the UTF-8 string form, a NULL `buf` is accepted **when `bsize` is 0**, and a
/// NULL `buf` with a non-zero `bsize` is the argument error.
///
/// # Safety
///
/// `bld` must be NULL or live; `key` NULL or NUL-terminated; `buf` NULL or readable for
/// `bsize`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_octet_string(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    buf: *const c_void,
    bsize: usize,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() || (buf.is_null() && bsize != 0) {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_369) };
            return 0;
        }
        let secure = CRYPTO_secure_allocated(buf) != 0;
        // SAFETY: `bld` is live; `key` outlives it.
        let pd = unsafe {
            param_push(
                &mut *bld,
                key,
                bsize,
                bsize,
                crate::params::OSSL_PARAM_OCTET_STRING,
                secure,
            )
        };
        if pd.is_null() {
            return 0;
        }
        // SAFETY: `pd` is live.
        unsafe { (*pd).string = buf };
        1
    })
}

/// `OSSL_PARAM_BLD_push_octet_ptr(OSSL_PARAM_BLD *bld, const char *key, void *buf,
/// size_t bsize)`
///
/// # Safety
///
/// `bld` must be NULL or live; `key` NULL or NUL-terminated; `buf` NULL or such that a
/// pointer to it is meaningful when `bsize` is non-zero.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_push_octet_ptr(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    buf: *mut c_void,
    bsize: usize,
) -> c_int {
    crate::ffi::guard_ffi(0, || {
        if bld.is_null() || key.is_null() || (buf.is_null() && bsize != 0) {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_387) };
            return 0;
        }
        // SAFETY: `bld` is live; `key` outlives it.
        let pd = unsafe {
            param_push(
                &mut *bld,
                key,
                bsize,
                core::mem::size_of::<*mut c_void>(),
                crate::params::OSSL_PARAM_OCTET_PTR,
                false,
            )
        };
        if pd.is_null() {
            return 0;
        }
        // SAFETY: `pd` is live.
        unsafe { (*pd).string = buf };
        1
    })
}

/// `static OSSL_PARAM *param_bld_convert(OSSL_PARAM_BLD *bld, OSSL_PARAM *param,
/// OSSL_PARAM_ALIGNED_BLOCK *blk, OSSL_PARAM_ALIGNED_BLOCK *secure)`
///
/// The layout pass. Each recorded value is written into the block it was counted for,
/// and each descriptor's `data` is pointed at it. The `_PTR` forms write a pointer
/// *into* the block — the block holds a pointer, and the descriptor's `data` points at
/// that — which is the single most easily-lost detail here.
///
/// Returns the terminator slot, which the caller turns into the secure-block descriptor
/// when there is one.
///
/// # Safety
///
/// `param` must be writable for `bld.len() + 1` entries; `blk` and `secure` must be
/// writable for the blocks the builder counted for each.
unsafe fn param_bld_convert(
    bld: &OSSL_PARAM_BLD,
    param: *mut OsslParam,
    blk: *mut u8,
    secure: *mut u8,
) -> *mut OsslParam {
    let num = bld.len();
    let mut blk_cur = blk;
    let mut secure_cur = secure;
    for i in 0..num {
        // SAFETY: `i < num`, so this is a recorded definition.
        let pd = unsafe { &*bld.at(i) };
        // SAFETY: `param` is writable for `num + 1` entries.
        unsafe {
            *param.add(i) = OsslParam {
                key: pd.key,
                data_type: pd.type_,
                data: ptr::null_mut(),
                data_size: pd.size,
                return_size: OSSL_PARAM_UNMODIFIED,
            };
        }
        let p: *mut u8 = if pd.secure {
            let here = secure_cur;
            // SAFETY: `secure_cur` advances within the secure block the caller sized.
            secure_cur = unsafe { secure_cur.add(pd.alloc_blocks * OSSL_PARAM_ALIGN_SIZE) };
            here
        } else {
            let here = blk_cur;
            // SAFETY: `blk_cur` advances within the ordinary block the caller sized.
            blk_cur = unsafe { blk_cur.add(pd.alloc_blocks * OSSL_PARAM_ALIGN_SIZE) };
            here
        };
        // SAFETY: `param` is writable for `num + 1` entries.
        unsafe { (*param.add(i)).data = p.cast() };
        if !pd.bn.is_null() {
            // SAFETY: `pd.bn` is live; `p` is writable for `pd.size` bytes.
            unsafe {
                if pd.type_ == crate::params::OSSL_PARAM_UNSIGNED_INTEGER {
                    BN_bn2nativepad(pd.bn, p, pd.size as c_int);
                } else {
                    BN_signed_bn2native(pd.bn, p, pd.size as c_int);
                }
            }
        } else if pd.type_ == crate::params::OSSL_PARAM_OCTET_PTR
            || pd.type_ == crate::params::OSSL_PARAM_UTF8_PTR
        {
            // The block holds the pointer itself.
            // SAFETY: `p` is writable for a pointer.
            unsafe { p.cast::<*const c_void>().write(pd.string) };
        } else if pd.type_ == crate::params::OSSL_PARAM_OCTET_STRING
            || pd.type_ == crate::params::OSSL_PARAM_UTF8_STRING
        {
            if !pd.string.is_null() {
                // SAFETY: `p` is writable for `pd.size` and `pd.string` readable for it.
                unsafe { ptr::copy_nonoverlapping(pd.string.cast::<u8>(), p, pd.size) };
            } else {
                // SAFETY: as above.
                unsafe { ptr::write_bytes(p, 0, pd.size) };
            }
            if pd.type_ == crate::params::OSSL_PARAM_UTF8_STRING {
                // The UTF-8 string's `alloc` was one byte larger than its `size`, so the
                // terminator slot exists.
                // SAFETY: `p` is writable for `pd.size + 1`.
                unsafe { *p.add(pd.size) = 0 };
            }
        } else {
            // A scalar, or a NULL BIGNUM. A recorded scalar is at most
            // `PARAM_BLD_NUM_BYTES`, but a `push_BN(NULL, sz)` may record a larger
            // `size`, which is zero-filled rather than read out of the eight-byte
            // recorder.
            if pd.size > PARAM_BLD_NUM_BYTES {
                // SAFETY: `p` is writable for `pd.size`.
                unsafe { ptr::write_bytes(p, 0, pd.size) };
            } else if pd.size > 0 {
                // SAFETY: `p` is writable for `pd.size` and `pd.num` is readable for it.
                unsafe { ptr::copy_nonoverlapping(pd.num.as_ptr(), p, pd.size) };
            }
        }
    }
    // SAFETY: `param` is writable for `num + 1` entries, so index `num` is the
    // terminator. The authority uses `OSSL_PARAM_construct_end()` here, which is the
    // all-zero entry.
    unsafe { (*param.add(num)) = crate::params::END };
    // SAFETY: one past the last written entry, still inside the caller's storage.
    unsafe { param.add(num) }
}

/// `OSSL_PARAM *OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld)`
///
/// One ordinary allocation always, one secure allocation only when a secure value was
/// pushed. On success the builder is emptied so it can be reused.
///
/// # Safety
///
/// `bld` must be NULL or a live builder.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_BLD_to_param(bld: *mut OSSL_PARAM_BLD) -> *mut OsslParam {
    crate::ffi::guard_ffi(ptr::null_mut(), || {
        if bld.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PARAM_BUILD_459) };
            return ptr::null_mut();
        }
        // SAFETY: `bld` is live per the caller's contract.
        let b = unsafe { &mut *bld };
        let num = b.len();
        let p_blks = ossl_param_bytes_to_blocks((1 + num) * core::mem::size_of::<OsslParam>());
        let total = OSSL_PARAM_ALIGN_SIZE * (p_blks + b.total_blocks);
        let ss = OSSL_PARAM_ALIGN_SIZE * b.secure_blocks;

        let mut secure_block: *mut u8 = ptr::null_mut();
        if ss > 0 {
            // SAFETY: a plain size argument.
            let s = unsafe { CRYPTO_secure_malloc(ss, FILE.as_ptr(), LINE) };
            if s.is_null() {
                // `CRYPTO_R_SECURE_MALLOC_FAILURE` at crypto/param_build.c:471.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PARAM_BUILD_471) };
                return ptr::null_mut();
            }
            secure_block = s.cast();
        }
        let params = CRYPTO_malloc(total, FILE.as_ptr(), LINE);
        if params.is_null() {
            // SAFETY: `secure_block` is NULL or the secure block just allocated.
            unsafe { CRYPTO_secure_free(secure_block.cast(), FILE.as_ptr(), LINE) };
            return ptr::null_mut();
        }
        let params = params.cast::<OsslParam>();
        // `blk = p_blks + (OSSL_PARAM_ALIGNED_BLOCK *)(params)` — the values start after
        // the array, at a block boundary.
        // SAFETY: `p_blks` blocks fit inside `total`, which `params` was allocated for.
        let blk = unsafe { params.cast::<AlignedBlock>().add(p_blks).cast::<u8>() };
        // SAFETY: `params` is writable for `num + 1` entries; `blk` and `secure_block` are
        // writable for the blocks counted above.
        let last = unsafe { param_bld_convert(b, params, blk, secure_block) };
        // SAFETY: `last` is the terminator slot inside the new array.
        unsafe { ossl_param_set_secure_block(last, secure_block.cast(), ss) };

        // The builder is emptied so it can be reused.
        b.total_blocks = 0;
        b.secure_blocks = 0;
        free_all_params(b);
        params
    })
}
