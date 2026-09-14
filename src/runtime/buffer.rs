//! Phase 4 — `BUF_MEM`, the growable buffer object.
//!
//! `BUF_MEM` is a **public** structure (`openssl/buffer.h` defines all four
//! members), so unlike `BIO` its layout is ABI: a caller that obtains one through
//! `BIO_get_mem_ptr` reads `->data`, `->length` and `->max` directly. This module
//! therefore reproduces the authority's four fields exactly and implements the
//! five exported operations on them.
//!
//! ## Growth policy is observable
//!
//! `BUF_MEM_grow` over-allocates to `(len + 3) / 3 * 4` — a 4/3 factor with a
//! cap that keeps the result below `2**31` — and the resulting **`max`** is
//! visible to the caller. The cap is not cosmetic: exceeding it raises
//! `ERR_LIB_BUF`/`ERR_R_PASSED_INVALID_ARGUMENT` and returns 0. Both are
//! reproduced, including the exact `LIMIT_BEFORE_EXPANSION` bound.
//!
//! ## `grow` and `grow_clean` differ in one place
//!
//! They are identical except when the buffer must be *reallocated*: `grow` uses
//! `realloc` (which may expose uninitialised tail bytes) and `grow_clean` uses
//! `CRYPTO_clear_realloc` (which zeroes and, on shrink, cleanses). The BIO memory
//! method writes through `grow_clean`, so the difference is on a hot path.

use core::ffi::{c_char, c_ulong, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{BUFFER_125, BUFFER_88};
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_clear_realloc, CRYPTO_realloc, CRYPTO_zalloc};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc};

/// `BUF_MEM_FLAG_SECURE`.
pub const BUF_MEM_FLAG_SECURE: c_ulong = 0x01;

/// `LIMIT_BEFORE_EXPANSION` — the largest `n` for which `(n + 3) / 3 * 4` still
/// fits in a 31-bit signed result. Copied from the authority because it is the
/// exact boundary at which `BUF_MEM_grow` starts failing.
const LIMIT_BEFORE_EXPANSION: usize = 0x5fff_fffc;

/// The C `BUF_MEM` structure (`openssl/buffer.h`).
///
/// Public and caller-inspectable, so the field order, names and types are ABI.
/// `Copy` mirrors C's struct-assignment semantics, which the memory BIO relies on
/// when it copies the write header over the read header.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BufMem {
    /// Current number of valid bytes.
    pub length: usize,
    /// The allocation; `NULL` before the first `grow`.
    pub data: *mut c_char,
    /// The allocation size.
    pub max: usize,
    /// `BUF_MEM_FLAG_SECURE` when the block came from the secure heap.
    pub flags: c_ulong,
}

/// `BUF_MEM *BUF_MEM_new(void)`
///
/// The authority zero-allocates, so `data` is NULL, `length` and `max` are 0 and
/// `flags` is 0.
#[no_mangle]
pub extern "C" fn BUF_MEM_new() -> *mut BufMem {
    guard_ffi(ptr::null_mut(), || {
        CRYPTO_zalloc(core::mem::size_of::<BufMem>(), ptr::null(), 0).cast()
    })
}

/// `BUF_MEM *BUF_MEM_new_ex(unsigned long flags)`
///
/// Only the `flags` member differs from [`BUF_MEM_new`]; nothing is allocated
/// from the secure heap until a `grow` actually needs memory.
#[no_mangle]
pub extern "C" fn BUF_MEM_new_ex(flags: c_ulong) -> *mut BufMem {
    guard_ffi(ptr::null_mut(), || {
        let p = BUF_MEM_new();
        if !p.is_null() {
            // SAFETY: `p` is a freshly allocated `BUF_MEM`.
            unsafe { (*p).flags = flags };
        }
        p
    })
}

/// `void BUF_MEM_free(BUF_MEM *a)`
///
/// The data block is *cleansed* before release, through the secure variant when
/// the buffer was flagged secure, because a `BUF_MEM` routinely holds key
/// material.
#[no_mangle]
pub unsafe extern "C" fn BUF_MEM_free(a: *mut BufMem) {
    guard_ffi((), || {
        let Some(m) = (unsafe { a.as_mut() }) else {
            return;
        };
        if !m.data.is_null() {
            if m.flags & BUF_MEM_FLAG_SECURE != 0 {
                // SAFETY: `data` came from the secure heap with capacity `max`.
                unsafe { CRYPTO_secure_clear_free(m.data.cast(), m.max, ptr::null(), 0) };
            } else {
                // SAFETY: `data` came from `CRYPTO_*alloc` with capacity `max`.
                unsafe { CRYPTO_clear_free(m.data.cast(), m.max, ptr::null(), 0) };
            }
        }
        // SAFETY: `a` was allocated by `BUF_MEM_new`.
        unsafe { CRYPTO_clear_free(a.cast(), core::mem::size_of::<BufMem>(), ptr::null(), 0) };
    })
}

/// The authority's `static char *sec_alloc_realloc(BUF_MEM *, size_t)`.
///
/// # Safety
/// `str` must be a live `BUF_MEM`.
unsafe fn sec_alloc_realloc(m: *mut BufMem, len: usize) -> *mut c_char {
    // SAFETY: a secure allocation request of `len` bytes.
    let ret: *mut c_char = unsafe { CRYPTO_secure_malloc(len, ptr::null(), 0).cast() };
    if !unsafe { (*m).data }.is_null() {
        if !ret.is_null() {
            // SAFETY: the new block is `len` bytes, the old holds `length` valid
            // bytes, and `length <= len` at every call site.
            unsafe {
                ptr::copy_nonoverlapping((*m).data, ret, (*m).length);
                CRYPTO_secure_clear_free((*m).data.cast(), (*m).length, ptr::null(), 0);
                (*m).data = ptr::null_mut();
            }
        }
    }
    ret
}

/// `size_t BUF_MEM_grow(BUF_MEM *str, size_t len)`
///
/// Returns `len` on success and 0 on failure. Shrinking within the existing
/// allocation is free; growth reallocates to `(len + 3) / 3 * 4` and zeroes the
/// newly exposed region.
#[no_mangle]
pub unsafe extern "C" fn BUF_MEM_grow(m: *mut BufMem, len: usize) -> usize {
    guard_ffi(0, || {
        let Some(str_) = (unsafe { m.as_mut() }) else {
            return 0;
        };
        if str_.length >= len {
            str_.length = len;
            return len;
        }
        if str_.max >= len {
            if !str_.data.is_null() {
                // SAFETY: `data` has `max >= len` bytes and `length < len`.
                unsafe {
                    ptr::write_bytes(
                        str_.data.add(str_.length).cast::<u8>(),
                        0,
                        len - str_.length,
                    )
                };
            }
            str_.length = len;
            return len;
        }
        if len > LIMIT_BEFORE_EXPANSION {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BUFFER_88) };
            return 0;
        }
        let n = (len + 3) / 3 * 4;
        let ret: *mut c_char = if str_.flags & BUF_MEM_FLAG_SECURE != 0 {
            // SAFETY: `str_` is live.
            unsafe { sec_alloc_realloc(m, n) }
        } else {
            // SAFETY: `data` is NULL or a `CRYPTO_*alloc` block of `max` bytes.
            unsafe { CRYPTO_realloc(str_.data.cast(), n, ptr::null(), 0).cast() }
        };
        if ret.is_null() {
            return 0;
        }
        str_.data = ret;
        str_.max = n;
        // SAFETY: the region `[length, len)` is inside the new allocation.
        unsafe { ptr::write_bytes(ret.add(str_.length).cast::<u8>(), 0, len - str_.length) };
        str_.length = len;
        len
    })
}

/// `size_t BUF_MEM_grow_clean(BUF_MEM *str, size_t len)`
///
/// As [`BUF_MEM_grow`], but the release of the old block is a *cleansing* one and
/// the growth uses `CRYPTO_clear_realloc`, so a shrink does not leave the
/// discarded tail readable in memory.
#[no_mangle]
pub unsafe extern "C" fn BUF_MEM_grow_clean(m: *mut BufMem, len: usize) -> usize {
    guard_ffi(0, || {
        let Some(str_) = (unsafe { m.as_mut() }) else {
            return 0;
        };
        if str_.length >= len {
            if !str_.data.is_null() {
                // SAFETY: `data` has `length >= len` valid bytes.
                unsafe { ptr::write_bytes(str_.data.add(len).cast::<u8>(), 0, str_.length - len) };
            }
            str_.length = len;
            return len;
        }
        if str_.max >= len {
            // SAFETY: `data` has `max >= len` bytes and `length < len`.
            unsafe {
                ptr::write_bytes(
                    str_.data.add(str_.length).cast::<u8>(),
                    0,
                    len - str_.length,
                )
            };
            str_.length = len;
            return len;
        }
        if len > LIMIT_BEFORE_EXPANSION {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BUFFER_125) };
            return 0;
        }
        let n = (len + 3) / 3 * 4;
        let ret: *mut c_char = if str_.flags & BUF_MEM_FLAG_SECURE != 0 {
            // SAFETY: `str_` is live.
            unsafe { sec_alloc_realloc(m, n) }
        } else {
            // SAFETY: `data` is NULL or a `CRYPTO_*alloc` block of `max` bytes.
            unsafe { CRYPTO_clear_realloc(str_.data.cast(), str_.max, n, ptr::null(), 0).cast() }
        };
        if ret.is_null() {
            return 0;
        }
        str_.data = ret;
        str_.max = n;
        // SAFETY: the region `[length, len)` is inside the new allocation.
        unsafe { ptr::write_bytes(ret.add(str_.length).cast::<u8>(), 0, len - str_.length) };
        str_.length = len;
        len
    })
}

/// `void BUF_reverse(unsigned char *out, const unsigned char *in, size_t size)`
///
/// In-place when `in` is NULL. A zero `size` with a NULL `in` is a no-op; with a
/// non-NULL `in` the authority computes `out + size - 1`, so `size == 0` is still
/// well defined only because no byte is then written.
#[no_mangle]
pub unsafe extern "C" fn BUF_reverse(out: *mut u8, input: *const u8, size: usize) {
    guard_ffi((), || {
        if out.is_null() {
            return;
        }
        if !input.is_null() {
            let mut o = unsafe { out.add(size.wrapping_sub(1)) };
            let mut i = input;
            for _ in 0..size {
                // SAFETY: `o` and `i` stay within their buffers by construction.
                unsafe {
                    *o = *i;
                    o = o.sub(1);
                    i = i.add(1);
                }
            }
        } else {
            let mut lo = out;
            let mut hi = unsafe { out.add(size.wrapping_sub(1)) };
            for _ in 0..size / 2 {
                // SAFETY: `lo < hi` throughout, both within `out`.
                unsafe {
                    let c = *hi;
                    *hi = *lo;
                    *lo = c;
                    hi = hi.sub(1);
                    lo = lo.add(1);
                }
            }
        }
    })
}

/// Convenience for the memory BIO: a NULL-safe copy of one `BUF_MEM` header.
///
/// # Safety
/// Both pointers must be valid `BUF_MEM`s (or NULL).
pub unsafe fn copy_header(dst: *mut BufMem, src: *const BufMem) {
    // SAFETY: the caller guarantees both are live.
    unsafe { ptr::copy_nonoverlapping(src, dst, 1) };
}

/// A `BUF_MEM` whose `data` pointer the caller must keep valid.
///
/// Used by the memory BIO for the read pointer, which is a header copy and never
/// owns its allocation.
pub type BufMemPtr = *mut BufMem;

/// The `c_void` form of a `BUF_MEM`, for the `BIO_ctrl` interface.
///
/// # Safety
/// `p` must be NULL or a live `BUF_MEM`.
pub unsafe fn as_void(p: *mut BufMem) -> *mut c_void {
    p.cast()
}

/// The inverse of [`as_void`].
///
/// # Safety
/// `p` must be NULL or a live `BUF_MEM`.
pub unsafe fn from_void(p: *mut c_void) -> *mut BufMem {
    p.cast()
}
