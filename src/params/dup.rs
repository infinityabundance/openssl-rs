//! Phase 6 — parameter duplication and merging: `crypto/params_dup.c`.
//!
//! ## One allocation carries the array and the data it points at
//!
//! [`OSSL_PARAM_dup`] is not a deep copy of an array of pointers. The authority
//! allocates a single aligned block, places the `OSSL_PARAM` array at its start and the
//! copied *values* immediately after it, and points each entry's `data` into that same
//! block. Freeing the array therefore frees the values, which is what makes
//! `OSSL_PARAM_free` a single call and why a caller must not release a duplicated
//! entry's `data`.
//!
//! The one thing that does not fit in the block is secure memory: a value that lives in
//! the secure heap has to be copied into the secure heap, so a duplicate needs **two**
//! allocations. The convention that keeps that invisible to `OSSL_PARAM_free` is the
//! last entry — the `key == NULL` terminator — which becomes a *secure block
//! descriptor*: `data_type` is set to the reserved value `127`
//! (`OSSL_PARAM_ALLOCATED_END`), `data` to the secure block and `data_size` to its
//! size. `OSSL_PARAM_free` walks to the terminator and, only if it finds that marker,
//! releases the second block. A parameter list that never held a secure value has an
//! ordinary all-zero terminator, so the same free path serves both.
//!
//! Reproducing the *layout* matters even though the layout is private, because the
//! terminator's `data_type` and the absence of a separate allocation for values are
//! both observable through `OSSL_PARAM_free`'s behaviour and through the pointers a
//! caller reads back.
//!
//! ## Merging is shallow, and it is case-insensitive
//!
//! [`OSSL_PARAM_merge`] sorts both lists by key with `OPENSSL_strcasecmp`, walks them
//! and copies the entries — pointers included — into a fresh array, **preferring the
//! second list's entry when the keys match**. So the result's `data` pointers alias the
//! inputs' and the caller keeps ownership of both. Nothing is copied and nothing is
//! freed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::params::OsslParam;
use crate::runtime::err::err_sites;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::secure::{
    CRYPTO_secure_allocated, CRYPTO_secure_clear_free, CRYPTO_secure_zalloc,
};

/// The authority translation unit this module reconstructs.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/params_dup.c";
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `OSSL_PARAM_ALLOCATED_END` — the reserved `data_type` the terminator carries when
/// the array came from [`OSSL_PARAM_dup`] and a secure block is attached to it.
pub(crate) const OSSL_PARAM_ALLOCATED_END: u32 = 127;

/// `OSSL_PARAM_MERGE_LIST_MAX` — the number of entries each input list may contribute
/// to a merge. The authority's two lists are fixed-size arrays of
/// `OSSL_PARAM_MERGE_LIST_MAX + 1` pointers and silently stop at the limit.
const OSSL_PARAM_MERGE_LIST_MAX: usize = 128;

/// `CRYPTO_R_INTEGER_OVERFLOW`, the reason `ossl_size_add`/`ossl_size_mul` report.
const CRYPTO_R_INTEGER_OVERFLOW: c_int = 127;

/// `OSSL_PARAM_ALIGNED_BLOCK` — the union whose alignment the block arithmetic is
/// expressed in. `OSSL_UNION_ALIGN` is `double`/`ossl_uintmax_t`/`void *`, whose most
/// pessimistic alignment is 8 on the admitted platform, so the block is eight bytes
/// and `OSSL_PARAM_ALIGN_SIZE` is `size_of::<AlignedBlock>()`.
#[repr(C, align(8))]
pub(crate) struct AlignedBlock([u8; 8]);

/// `OSSL_PARAM_ALIGN_SIZE` — `sizeof(OSSL_PARAM_ALIGNED_BLOCK)`.
pub(crate) const OSSL_PARAM_ALIGN_SIZE: usize = core::mem::size_of::<AlignedBlock>();

/// `size_t ossl_param_bytes_to_blocks(size_t bytes)`
pub(crate) fn ossl_param_bytes_to_blocks(bytes: usize) -> usize {
    bytes.div_ceil(OSSL_PARAM_ALIGN_SIZE)
}

/// OSSL_PARAM_BUF — the authority's private two-block accumulator. `alloc` is the base
/// of the allocation, `cur` the write cursor inside it, `blocks` the number of blocks
/// already reserved, and `alloc_sz` the allocated size in bytes.
#[derive(Clone, Copy)]
struct ParamBuf {
    alloc: *mut u8,
    cur: *mut u8,
    blocks: usize,
    alloc_sz: usize,
}

impl ParamBuf {
    const fn empty() -> Self {
        ParamBuf {
            alloc: ptr::null_mut(),
            cur: ptr::null_mut(),
            blocks: 0,
            alloc_sz: 0,
        }
    }
}

/// `ossl_report_alloc_err_ex(OPENSSL_FILE, OPENSSL_LINE, CRYPTO_R_INTEGER_OVERFLOW)`,
/// as `ossl_size_add` and `ossl_size_mul` reach it.
///
/// `ossl_size_add`/`ossl_size_mul` are not raise *macros*, so the raise-site generator
/// does not record them; but the coordinate they produce is still the authority's own —
/// `__FILE__` is this translation unit's and `__LINE__` is the call in
/// `ossl_param_buf_alloc`. The `__FILE__` string is therefore taken from a generated
/// constant of this same file rather than spelled out, and the function name is NULL
/// because `ossl_report_alloc_err_ex` passes NULL to `ERR_set_debug`.
fn raise_size_overflow(line: c_int) {
    // SAFETY: the `file` pointer is a static string in the generated table.
    unsafe {
        crate::runtime::err::raise_with(
            crate::runtime::mem::ERR_LIB_CRYPTO,
            CRYPTO_R_INTEGER_OVERFLOW,
            err_sites::PARAMS_DUP_113.file.as_ptr(),
            line,
        )
    };
}

/// `static int ossl_param_buf_alloc(OSSL_PARAM_BUF *out, size_t extra_blocks,
/// int is_secure)`
///
/// `extra_blocks` is what the caller is about to write, `out.blocks` what it has
/// counted so far; the allocation covers both, and `cur` starts *after* the
/// `extra_blocks` region so the two do not overlap.
///
/// # Safety
///
/// `out` must be writable for one `ParamBuf`.
unsafe fn ossl_param_buf_alloc(out: &mut ParamBuf, extra_blocks: usize, is_secure: bool) -> bool {
    // `ossl_size_add(extra_blocks, out->blocks, &num_blocks, OPENSSL_FILE,
    // OPENSSL_LINE)` at crypto/params_dup.c:41.
    let Some(num_blocks) = extra_blocks.checked_add(out.blocks) else {
        raise_size_overflow(41);
        return false;
    };
    // `ossl_size_mul(num_blocks, OSSL_PARAM_ALIGN_SIZE, &sz, ...)` at line 43.
    let Some(sz) = num_blocks.checked_mul(OSSL_PARAM_ALIGN_SIZE) else {
        raise_size_overflow(43);
        return false;
    };
    let alloc = if is_secure {
        // SAFETY: a plain size argument.
        unsafe { CRYPTO_secure_zalloc(sz, FILE.as_ptr(), LINE) }
    } else {
        CRYPTO_zalloc(sz, FILE.as_ptr(), LINE)
    };
    if alloc.is_null() {
        return false;
    }
    out.alloc = alloc.cast();
    out.alloc_sz = sz;
    // `out->cur = out->alloc + extra_blocks` — block arithmetic, so `extra_blocks`
    // *blocks*, not bytes.
    // SAFETY: `extra_blocks <= num_blocks`, so the offset is inside the allocation.
    out.cur = unsafe { out.alloc.add(extra_blocks * OSSL_PARAM_ALIGN_SIZE) };
    true
}

/// `void ossl_param_set_secure_block(OSSL_PARAM *last, void *secure_buffer,
/// size_t secure_buffer_sz)`
///
/// Turns the terminator into the marker [`OSSL_PARAM_free`] looks for. `data_size` is
/// the *secure block's* size, not a value length.
///
/// # Safety
///
/// `last` must be writable for one `OsslParam`.
pub(crate) unsafe fn ossl_param_set_secure_block(
    last: *mut OsslParam,
    secure_buffer: *mut c_void,
    secure_buffer_sz: usize,
) {
    // SAFETY: writable for one `OsslParam` per the caller's contract.
    unsafe {
        (*last).key = ptr::null();
        (*last).data_size = secure_buffer_sz;
        (*last).data = secure_buffer;
        (*last).data_type = OSSL_PARAM_ALLOCATED_END;
    }
}

/// `static OSSL_PARAM *ossl_param_dup(const OSSL_PARAM *src, OSSL_PARAM *dst,
/// OSSL_PARAM_BUF buf[OSSL_PARAM_BUF_MAX], int *param_count)`
///
/// One pass serves both the measurement and the copy: with `dst == NULL` it only
/// accumulates block counts into `buf`, and with a destination it copies. The `_PTR`
/// forms are the exception to "copy the value": they copy the *pointer*, because that
/// is what the descriptor holds.
///
/// # Safety
///
/// `src` must be a `key`-terminated array of live `OsslParam`. When `dst` is non-NULL
/// it must be writable for one entry per element of `src` plus a terminator, and each
/// `buf` entry's `cur` must be writable for the blocks that element needs.
unsafe fn ossl_param_dup(
    src: *const OsslParam,
    dst: *mut OsslParam,
    buf: &mut [ParamBuf; 2],
    param_count: *mut c_int,
) -> *mut OsslParam {
    let has_dst = !dst.is_null();
    let mut in_cur = src;
    let mut out_cur = dst;
    loop {
        // SAFETY: `in_cur` walks a key-terminated array per the caller's contract.
        let entry = unsafe { &*in_cur };
        if entry.key.is_null() {
            break;
        }
        // `CRYPTO_secure_allocated(in->data)` — a range test on the secure heap, not a
        // liveness test.
        let is_secure = usize::from(CRYPTO_secure_allocated(entry.data) != 0);
        if has_dst {
            // SAFETY: `out_cur` is writable for one entry, and the source is live.
            unsafe {
                *out_cur = OsslParam {
                    key: entry.key,
                    data_type: entry.data_type,
                    data: buf[is_secure].cur.cast(),
                    data_size: entry.data_size,
                    return_size: entry.return_size,
                };
            }
        }
        let param_sz = if entry.data_type == crate::params::OSSL_PARAM_OCTET_PTR
            || entry.data_type == crate::params::OSSL_PARAM_UTF8_PTR
        {
            // The value *is* a pointer, so eight bytes of payload.
            let n = core::mem::size_of::<*const c_void>();
            if has_dst {
                // SAFETY: `entry.data` is readable for one pointer, and `out_cur.data`
                // is the destination cursor, writable for at least that many bytes.
                let v = unsafe { entry.data.cast::<*const c_void>().read() };
                // SAFETY: `(*out_cur).data` is the destination cursor, writable for at
                // least `size_of::<*const c_void>()` bytes.
                unsafe { (*out_cur).data.cast::<*const c_void>().write(v) };
            }
            n
        } else {
            if has_dst {
                // SAFETY: `entry.data` is readable for `entry.data_size` and
                // `(*out_cur).data` is the destination cursor, writable for it.
                unsafe {
                    ptr::copy_nonoverlapping(
                        entry.data.cast::<u8>(),
                        (*out_cur).data.cast::<u8>(),
                        entry.data_size,
                    )
                };
            }
            entry.data_size
        };
        let param_sz = if entry.data_type == crate::params::OSSL_PARAM_UTF8_STRING {
            param_sz + 1
        } else {
            param_sz
        };
        let blks = ossl_param_bytes_to_blocks(param_sz);
        if has_dst {
            // SAFETY: one entry per element of `src`, inside the storage the first pass
            // sized.
            out_cur = unsafe { out_cur.add(1) };
            // SAFETY: block arithmetic inside the buffer `ossl_param_buf_alloc` sized.
            buf[is_secure].cur = unsafe { buf[is_secure].cur.add(blks * OSSL_PARAM_ALIGN_SIZE) };
        } else {
            buf[is_secure].blocks += blks;
        }
        if !param_count.is_null() {
            // SAFETY: writable for one `c_int` per the caller's contract.
            unsafe { *param_count += 1 };
        }
        // SAFETY: the array has not terminated, so the next entry is still in it.
        in_cur = unsafe { in_cur.add(1) };
    }
    out_cur
}

/// `OSSL_PARAM *OSSL_PARAM_dup(const OSSL_PARAM *src)`
///
/// Two passes: the first measures, the second copies. The measurement pass is what
/// decides whether a second, secure allocation is needed, and it also counts the
/// terminator — `param_count` starts at 1 so that the terminator is inside the array
/// the public block reserves.
///
/// # Safety
///
/// `src` must be NULL or a `key`-terminated array of live `OsslParam` whose `data`
/// fields are readable for their own `data_size`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_dup(src: *const OsslParam) -> *mut OsslParam {
    crate::ffi::guard_ffi(ptr::null_mut(), || {
        if src.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at
            // crypto/params_dup.c:113.
            // SAFETY: a compile-time-constant site.
            unsafe { crate::runtime::err::raise_site(&err_sites::PARAMS_DUP_113) };
            return ptr::null_mut();
        }
        let mut buf = [ParamBuf::empty(), ParamBuf::empty()];
        let mut param_count: c_int = 1; // Include the terminator in the count.
                                        // First pass: count parameters and blocks.
                                        // SAFETY: `src` is a terminated array of live entries per the caller's
                                        // contract; `dst` is NULL, so nothing is written.
        unsafe { ossl_param_dup(src, ptr::null_mut(), &mut buf, &mut param_count) };

        // SAFETY: `param_count >= 1`, so the multiplication is in range for any real
        // array.
        let param_blocks =
            ossl_param_bytes_to_blocks(param_count as usize * core::mem::size_of::<OsslParam>());
        // SAFETY: `buf` is a live pair.
        if !unsafe { ossl_param_buf_alloc(&mut buf[0], param_blocks, false) } {
            return ptr::null_mut();
        }
        if buf[1].blocks > 0 {
            // SAFETY: as above.
            if !unsafe { ossl_param_buf_alloc(&mut buf[1], 0, true) } {
                // SAFETY: the public block was just allocated and is not yet observable.
                unsafe { CRYPTO_free(buf[0].alloc.cast(), FILE.as_ptr(), LINE) };
                return ptr::null_mut();
            }
        }
        let dst = buf[0].alloc.cast::<OsslParam>();
        // SAFETY: `dst` is the base of the public block, which the first pass sized.
        let last = unsafe { ossl_param_dup(src, dst, &mut buf, ptr::null_mut()) };
        // SAFETY: `last` is the terminator slot inside the public block.
        unsafe { ossl_param_set_secure_block(last, buf[1].alloc.cast(), buf[1].alloc_sz) };
        dst
    })
}

/// `static int compare_params(const void *left, const void *right)` — the comparator
/// both sorts use. Case-insensitive, and it NULLs nothing: the arrays are terminated by
/// a NULL *pointer* that the sorts exclude by length.
fn compare_params(a: &*const OsslParam, b: &*const OsslParam) -> core::cmp::Ordering {
    // SAFETY: both entries are live, having been collected from terminated arrays.
    let (ka, kb) = unsafe { ((**a).key, (**b).key) };
    // SAFETY: `OPENSSL_strcasecmp` reads two NUL-terminated strings, which both keys
    // are.
    let d = unsafe { crate::runtime::str::OPENSSL_strcasecmp(ka, kb) };
    d.cmp(&0)
}

/// `OSSL_PARAM *OSSL_PARAM_merge(const OSSL_PARAM *p1, const OSSL_PARAM *p2)`
///
/// Sorts both lists by key and merges them, taking **`p2`'s** entry when the keys are
/// equal, so `p2` overrides. The result is a fresh array whose entries alias the
/// inputs' `data` pointers.
///
/// Two limits are the authority's and are reproduced rather than removed: each input
/// contributes at most [`OSSL_PARAM_MERGE_LIST_MAX`] entries, and two NULL inputs is
/// the only argument error.
///
/// The sort is `qsort` in the authority, whose order among *equal* keys within one list
/// is unspecified; the sort here is stable, so the relative order of equal keys is the
/// one the caller passed. That difference is not observable for a well-formed list —
/// duplicate keys in one list are a caller error and the authority makes no promise
/// about them either — and it is recorded as a residual rather than hidden.
///
/// # Safety
///
/// Each non-NULL argument must be a `key`-terminated array of live `OsslParam`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_merge(
    p1: *const OsslParam,
    p2: *const OsslParam,
) -> *mut OsslParam {
    crate::ffi::guard_ffi(ptr::null_mut(), || {
        if p1.is_null() && p2.is_null() {
            // `ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER)` at
            // crypto/params_dup.c:164.
            // SAFETY: a compile-time-constant site.
            unsafe { crate::runtime::err::raise_site(&err_sites::PARAMS_DUP_164) };
            return ptr::null_mut();
        }
        let mut list1: Vec<*const OsslParam> = Vec::with_capacity(OSSL_PARAM_MERGE_LIST_MAX);
        let mut list2: Vec<*const OsslParam> = Vec::with_capacity(OSSL_PARAM_MERGE_LIST_MAX);
        for (src, list) in [(p1, &mut list1), (p2, &mut list2)] {
            if src.is_null() {
                continue;
            }
            let mut cur = src;
            loop {
                // SAFETY: `cur` walks a key-terminated array per the caller's contract.
                let entry = unsafe { &*cur };
                if entry.key.is_null() || list.len() >= OSSL_PARAM_MERGE_LIST_MAX {
                    break;
                }
                list.push(cur);
                // SAFETY: the array has not terminated, so the next entry is in it.
                cur = unsafe { cur.add(1) };
            }
        }
        if list1.is_empty() && list2.is_empty() {
            // `ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_NO_PARAMS_TO_MERGE)` at
            // crypto/params_dup.c:182.
            // SAFETY: a compile-time-constant site.
            unsafe { crate::runtime::err::raise_site(&err_sites::PARAMS_DUP_182) };
            return ptr::null_mut();
        }
        list1.sort_by(compare_params);
        list2.sort_by(compare_params);

        // `OPENSSL_calloc(n1 + n2 + 1, sizeof(*p1))` — zeroed, so the terminator is
        // already in place if the loop ever leaves a slot unused.
        let count = list1.len() + list2.len() + 1;
        let params = CRYPTO_zalloc(
            count * core::mem::size_of::<OsslParam>(),
            FILE.as_ptr(),
            LINE,
        )
        .cast::<OsslParam>();
        if params.is_null() {
            return ptr::null_mut();
        }
        let mut dst = params;
        let (mut i, mut j) = (0usize, 0usize);
        loop {
            if i == list1.len() {
                // Tacks `list2`'s remainder on.
                while j < list2.len() {
                    // SAFETY: both entries are live; `dst` is inside the allocation, whose
                    // size covers `count` entries and at most `count - 1` are written.
                    unsafe {
                        *dst = *list2[j];
                        dst = dst.add(1);
                    }
                    j += 1;
                }
                break;
            }
            if j == list2.len() {
                while i < list1.len() {
                    // SAFETY: as above.
                    unsafe {
                        *dst = *list1[i];
                        dst = dst.add(1);
                    }
                    i += 1;
                }
                break;
            }
            // SAFETY: both entries are live.
            let (ka, kb) = unsafe { ((*list1[i]).key, (*list2[j]).key) };
            // SAFETY: two NUL-terminated keys.
            let diff = unsafe { crate::runtime::str::OPENSSL_strcasecmp(ka, kb) };
            // SAFETY: `dst` is inside the allocation; at most `count - 1` entries are
            // written because the loop consumes `list1.len() + list2.len()` entries in
            // total and stops one short of `count`.
            unsafe {
                if diff == 0 {
                    // Same key: the second list wins and both cursors advance.
                    *dst = *list2[j];
                    j += 1;
                    i += 1;
                } else if diff > 0 {
                    *dst = *list2[j];
                    j += 1;
                } else {
                    *dst = *list1[i];
                    i += 1;
                }
                dst = dst.add(1);
            }
        }
        params
    })
}

/// `void OSSL_PARAM_free(OSSL_PARAM *params)`
///
/// The terminator decides whether a second allocation exists: `data_type == 127` means
/// [`OSSL_PARAM_dup`] attached a secure block, whose contents are cleansed before
/// release. For any other array this is a single `OPENSSL_free`, so a caller may pass
/// either a duplicated array or one it allocated itself — which is the property that
/// makes the two indistinguishable from outside.
///
/// # Safety
///
/// `params` must be NULL or an array whose terminator has `data_type == 0`, or one
/// returned by [`OSSL_PARAM_dup`].
#[no_mangle]
pub unsafe extern "C" fn OSSL_PARAM_free(params: *mut OsslParam) {
    crate::ffi::guard_ffi((), || {
        if params.is_null() {
            return;
        }
        let mut p = params;
        loop {
            // SAFETY: `p` walks a key-terminated array per the caller's contract.
            let entry = unsafe { &*p };
            if entry.key.is_null() {
                break;
            }
            // SAFETY: the array has not terminated, so the next entry is in it.
            p = unsafe { p.add(1) };
        }
        // SAFETY: `p` is the terminator, live per the caller's contract.
        let terminator = unsafe { &*p };
        if terminator.data_type == OSSL_PARAM_ALLOCATED_END {
            // `OPENSSL_secure_clear_free(p->data, p->data_size)` — the size recorded is
            // the secure *block's*, not a value length.
            // SAFETY: `data` is the secure block recorded by
            // `ossl_param_set_secure_block`, and `data_size` is its size.
            unsafe {
                CRYPTO_secure_clear_free(terminator.data, terminator.data_size, FILE.as_ptr(), LINE)
            };
        }
        // SAFETY: `params` is the array allocated by `OSSL_PARAM_dup`.
        unsafe { CRYPTO_free(params.cast(), FILE.as_ptr(), LINE) };
    })
}
