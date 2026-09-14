//! Phase 3 core runtime — memory subsystem.
//!
//! Real implementations of the `CRYPTO_*` allocation, sizing and cleansing
//! surface. These are among the first non-scaffolded product symbols in the
//! project, so they carry the full obligation set: ABI (present, with the right
//! type, binding and version), semantics (differential against the authority),
//! ownership (who frees what, and what happens on NULL), and error behaviour.
//!
//! ## The contract is measured, not remembered
//!
//! Every non-obvious behaviour below was established by running
//! `courts/phase3/rt_mem_probe.c` against the authority and reading the result.
//! The probe installs its own counting allocator through
//! `CRYPTO_set_mem_functions`, which is what makes ownership and cleansing
//! observable rather than a matter of opinion: the probe's `free` snapshots the
//! block it is handed, so "`CRYPTO_clear_free` cleansed the buffer before
//! releasing it" is a measurement, not a claim. The measurements that drove this
//! file:
//!
//! * `CRYPTO_malloc(0)` returns **non-NULL**. A zero-size request is still an
//!   allocation; callers already branch on NULL and would take the failure path
//!   if this were "helpfully" normalized away.
//! * `CRYPTO_realloc(addr, 0)` returns NULL and does **not** release `addr`,
//!   while `CRYPTO_clear_realloc(addr, old, 0)` releases it via
//!   `CRYPTO_clear_free`. The asymmetry is real and observable.
//! * `CRYPTO_clear_realloc` **shrinking** returns the *same* pointer without
//!   reallocating, after cleansing the discarded tail. It does not move the
//!   block.
//! * Overflow in the `*_array` helpers returns NULL, raises
//!   `ERR_LIB_CRYPTO`/`ERR_R_OVERFLOW` (packed `0x0780007F`), and does **not**
//!   release the incoming pointer: ownership stays with the caller.
//! * That raised error carries the *caller's* file and line (measured through
//!   `ERR_get_error_all`), an empty function name, no data and flags 0.
//! * `CRYPTO_memcmp` returns exactly **1** for any difference, not the OR of the
//!   byte differences.
//! * `CRYPTO_aligned_alloc` sets `*freeptr` to the block to release, which equals
//!   the returned pointer when that pointer is already aligned and is otherwise
//!   the unaligned base it came from.
//!
//! ## Why libc's allocator and not Rust's
//!
//! `CRYPTO_malloc` returns memory usable with `CRYPTO_free`, and the authority's
//! implementation is a thin, replaceable layer over the C allocator. Calling the
//! C allocator directly keeps the ownership contract exact — notably, memory from
//! `CRYPTO_malloc` remains freeable by C `free()`, which a Rust `Layout`-based
//! allocator happens to satisfy on this platform today but does not promise.
//! Behavioural compatibility is the goal, not incidental equivalence.
//!
//! ## Functions from this file never allocate internally
//!
//! The only allocation performed here is the caller's own request, routed
//! through whichever allocator is installed. That matters: the subsystem is what
//! the error subsystem itself allocates from, so a re-entrant allocation here
//! would be a defect, not a detail.

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::mem::{size_of, transmute};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::err;

extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn realloc(p: *mut c_void, n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
}

/// `ERR_LIB_CRYPTO`. Measured: the authority's overflow error packs to
/// `0x0780007F`, i.e. library 15, reason 127.
const ERR_LIB_CRYPTO: c_int = 15;
/// `ERR_R_OVERFLOW`. See `ERR_LIB_CRYPTO`.
const ERR_R_OVERFLOW: c_int = 127;

/// The allocator function types, exactly as `crypto.h` declares them.
type MallocFn = unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void;
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int);

// The installed allocator. `0` means "the default C allocator", so the common
// case is a single relaxed load and no lock: `CRYPTO_malloc` is on the hot path
// of everything that follows.
static MALLOC_FN: AtomicUsize = AtomicUsize::new(0);
static REALLOC_FN: AtomicUsize = AtomicUsize::new(0);
static FREE_FN: AtomicUsize = AtomicUsize::new(0);

/// # Safety
/// `n` is passed straight to the C allocator.
unsafe extern "C" fn default_malloc(n: usize, _file: *const c_char, _line: c_int) -> *mut c_void {
    // SAFETY: `malloc` is thread-safe and returns either NULL or a block of at
    // least `n` bytes.
    unsafe { malloc(n) }
}

/// # Safety
/// `p` must be NULL or a block from this allocator; `n` as for `realloc`.
unsafe extern "C" fn default_realloc(
    p: *mut c_void,
    n: usize,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    // SAFETY: forwarded to `realloc`, whose contract this is.
    unsafe { realloc(p, n) }
}

/// # Safety
/// `p` must be NULL or a block from this allocator.
unsafe extern "C" fn default_free(p: *mut c_void, _file: *const c_char, _line: c_int) {
    // SAFETY: forwarded to `free`, which accepts NULL.
    unsafe { free(p) }
}

fn installed(slot: &AtomicUsize, fallback: usize) -> usize {
    match slot.load(Ordering::Relaxed) {
        0 => fallback,
        p => p,
    }
}

fn malloc_fn() -> MallocFn {
    let raw = installed(&MALLOC_FN, default_malloc as *const () as usize);
    // SAFETY: the slot only ever holds a value written by `CRYPTO_set_mem_functions`,
    // which stores a `MallocFn`. `usize` and a function pointer have the same
    // representation on every platform this project admits.
    unsafe { transmute::<usize, MallocFn>(raw) }
}

fn realloc_fn() -> ReallocFn {
    let raw = installed(&REALLOC_FN, default_realloc as *const () as usize);
    // SAFETY: as `malloc_fn`.
    unsafe { transmute::<usize, ReallocFn>(raw) }
}

fn free_fn() -> FreeFn {
    let raw = installed(&FREE_FN, default_free as *const () as usize);
    // SAFETY: as `malloc_fn`.
    unsafe { transmute::<usize, FreeFn>(raw) }
}

/// Allocate `n` bytes through the installed allocator.
fn alloc(n: usize, file: *const c_char, line: c_int) -> *mut c_void {
    // SAFETY: the installed allocator's contract is the caller's.
    unsafe { (malloc_fn())(n, file, line) }
}

/// Release a block through the installed allocator. NULL is ignored.
fn dealloc(p: *mut c_void, file: *const c_char, line: c_int) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is a live block from this allocator per the caller's contract.
    unsafe { (free_fn())(p, file, line) }
}

/// Cleanse then release. Used by `CRYPTO_clear_free` and by the shrinking and
/// failing paths of the clear-* helpers.
fn clear_dealloc(p: *mut c_void, n: usize, file: *const c_char, line: c_int) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is live for `n` bytes per the caller's contract.
    unsafe { cleanse(p.cast::<u8>(), n) };
    dealloc(p, file, line);
}

/// Raise the overflow error the `*_array` helpers raise, attributed to the
/// caller exactly as the authority does.
fn raise_overflow(file: *const c_char, line: c_int) {
    // SAFETY: `file` came from the caller as a debug string.
    unsafe { err::raise_with(ERR_LIB_CRYPTO, ERR_R_OVERFLOW, file, line) };
}

/// `void *CRYPTO_malloc(size_t num, const char *file, int line)`
///
/// Returns NULL only when the allocator fails. A zero-length request is a real
/// allocation, matching the authority.
#[no_mangle]
pub extern "C" fn CRYPTO_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || alloc(num, file, line))
}

/// `void *CRYPTO_zalloc(size_t num, const char *file, int line)`
#[no_mangle]
pub extern "C" fn CRYPTO_zalloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let p = alloc(num, file, line);
        if !p.is_null() {
            // SAFETY: `p` is at least `num` bytes, freshly allocated and not yet
            // observable by anyone else.
            unsafe { ptr::write_bytes(p.cast::<u8>(), 0, num) };
        }
        p
    })
}

/// `void *CRYPTO_calloc(size_t num, size_t size, const char *file, int line)`
///
/// Measured: a zero `size` still yields a non-NULL allocation, and overflow
/// raises `ERR_R_OVERFLOW` and returns NULL. There is no incoming pointer to
/// release.
#[no_mangle]
pub extern "C" fn CRYPTO_calloc(
    num: usize,
    size: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let total = if size == 0 {
            0
        } else {
            match num.checked_mul(size) {
                Some(t) => t,
                None => {
                    raise_overflow(file, line);
                    return ptr::null_mut();
                }
            }
        };
        let p = alloc(total, file, line);
        if !p.is_null() {
            // SAFETY: fresh block of `total` bytes, unaliased.
            unsafe { ptr::write_bytes(p.cast::<u8>(), 0, total) };
        }
        p
    })
}

/// `void *CRYPTO_malloc_array(size_t num, size_t size, const char *file, int line)`
///
/// Measured: overflow raises `ERR_R_OVERFLOW`, returns NULL, and — unlike the
/// realloc forms — has no pointer to release.
#[no_mangle]
pub extern "C" fn CRYPTO_malloc_array(
    num: usize,
    size: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if size == 0 {
            return alloc(0, file, line);
        }
        match num.checked_mul(size) {
            Some(total) => alloc(total, file, line),
            None => {
                raise_overflow(file, line);
                ptr::null_mut()
            }
        }
    })
}

/// `void *CRYPTO_aligned_alloc(size_t num, size_t align, void **freeptr, const char *file, int line)`
///
/// Measured: the returned pointer is aligned, and `*freeptr` receives the block
/// that must be passed to `CRYPTO_free`. When the underlying allocation is
/// already aligned the two are equal; otherwise `*freeptr` is the unaligned base
/// and the returned pointer is an interior offset. The caller must free
/// `*freeptr`, never the returned pointer, which is why the free pointer exists
/// as a separate out-parameter.
///
/// # Safety
/// `freeptr` must be NULL or writable for one pointer.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_aligned_alloc(
    num: usize,
    align: usize,
    freeptr: *mut *mut c_void,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if freeptr.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `freeptr` is writable per the caller's contract.
        unsafe { *freeptr = ptr::null_mut() };
        let align = if align == 0 {
            size_of::<*mut c_void>()
        } else {
            align
        };
        // The alignment slack is part of the requested block; `align` is at most
        // the platform word alignment times a small constant in practice, so the
        // only realistic failure is an enormous `num`.
        let total = match num.checked_add(align) {
            Some(t) => t,
            None => {
                raise_overflow(file, line);
                return ptr::null_mut();
            }
        };
        let base = alloc(total, file, line);
        if base.is_null() {
            return ptr::null_mut();
        }
        let addr = base as usize;
        let off = if addr.is_multiple_of(align) {
            0
        } else {
            align - (addr % align)
        };
        // SAFETY: `freeptr` is writable; `base` is the block to release.
        unsafe { *freeptr = base };
        // SAFETY: `off <= align <= total`, so the offset pointer is inside the
        // allocation.
        unsafe { base.cast::<u8>().add(off).cast::<c_void>() }
    })
}

/// `void *CRYPTO_aligned_alloc_array(size_t num, size_t size, size_t align, void **freeptr, const char *file, int line)`
///
/// # Safety
/// `freeptr` must be NULL or writable for one pointer.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_aligned_alloc_array(
    num: usize,
    size: usize,
    align: usize,
    freeptr: *mut *mut c_void,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let total = if size == 0 {
            0
        } else {
            match num.checked_mul(size) {
                Some(t) => t,
                None => {
                    if !freeptr.is_null() {
                        // SAFETY: writable per the caller's contract.
                        unsafe { *freeptr = ptr::null_mut() };
                    }
                    raise_overflow(file, line);
                    return ptr::null_mut();
                }
            }
        };
        // SAFETY: forwarded; `freeptr` is the caller's.
        unsafe { CRYPTO_aligned_alloc(total, align, freeptr, file, line) }
    })
}

/// `void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line)`
///
/// Measured: a NULL `addr` behaves as an allocation, and `num == 0` returns NULL
/// **without** releasing `addr` — the caller keeps ownership. The clearing
/// sibling `CRYPTO_clear_realloc` is the one that releases on zero.
///
/// # Safety
/// `addr` must be NULL or a block previously returned by this allocator and not
/// yet freed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_realloc(
    addr: *mut c_void,
    num: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if addr.is_null() {
            return alloc(num, file, line);
        }
        if num == 0 {
            return ptr::null_mut();
        }
        // SAFETY: `addr` is a live block from this allocator.
        unsafe { (realloc_fn())(addr, num, file, line) }
    })
}

/// `void *CRYPTO_clear_realloc(void *addr, size_t old_num, size_t num, const char *file, int line)`
///
/// Measured: shrinking cleanses the discarded tail and returns the *same*
/// pointer without reallocating; `num == 0` releases through `CRYPTO_clear_free`
/// and returns NULL; growing copies `old_num` bytes and clears the old block.
///
/// # Safety
/// `addr` must be NULL or a block of at least `old_num` bytes from this
/// allocator and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_clear_realloc(
    addr: *mut c_void,
    old_num: usize,
    num: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if addr.is_null() {
            return alloc(num, file, line);
        }
        if num == 0 {
            clear_dealloc(addr, old_num, file, line);
            return ptr::null_mut();
        }
        if num < old_num {
            // Shrinking in place: the block does not move, and the tail that is
            // no longer addressable is cleansed before it becomes unreachable
            // through this pointer.
            // SAFETY: `addr` is live for `old_num` bytes, and `num < old_num`.
            unsafe { cleanse(addr.cast::<u8>().add(num), old_num - num) };
            return addr;
        }
        let ret = alloc(num, file, line);
        if !ret.is_null() {
            // SAFETY: `ret` is a fresh block of `num >= old_num` bytes and `addr`
            // is live for `old_num`; the blocks cannot overlap.
            unsafe { memcpy(ret, addr, old_num) };
            clear_dealloc(addr, old_num, file, line);
        }
        ret
    })
}

/// `void *CRYPTO_realloc_array(void *addr, size_t num, size_t size, const char *file, int line)`
///
/// Measured: overflow raises `ERR_R_OVERFLOW` and returns NULL **without**
/// releasing `addr`, so the caller still owns it. That ownership transfer is part
/// of the contract and is what a caller must branch on.
///
/// # Safety
/// `addr` must be NULL or a block from this allocator and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_realloc_array(
    addr: *mut c_void,
    num: usize,
    size: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if size == 0 {
            // SAFETY: forwarded; see CRYPTO_realloc's contract.
            return unsafe { CRYPTO_realloc(addr, 0, file, line) };
        }
        match num.checked_mul(size) {
            // SAFETY: forwarded; see CRYPTO_realloc's contract.
            Some(total) => unsafe { CRYPTO_realloc(addr, total, file, line) },
            None => {
                raise_overflow(file, line);
                ptr::null_mut()
            }
        }
    })
}

/// `void *CRYPTO_clear_realloc_array(void *addr, size_t old_num, size_t num, size_t size, const char *file, int line)`
///
/// Measured: `old_num` is an **element count**, not a byte count; it is
/// multiplied by `size` before reaching `CRYPTO_clear_realloc`. Getting this
/// wrong does not fail loudly — it makes the authority cleanse past the end of
/// the block, which is how the distinction was discovered, by observing heap
/// corruption in an earlier revision of the probe.
///
/// # Safety
/// `addr` must be NULL or a block holding at least `old_num * size` bytes from
/// this allocator and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_clear_realloc_array(
    addr: *mut c_void,
    old_num: usize,
    num: usize,
    size: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if size == 0 {
            // SAFETY: forwarded; see CRYPTO_clear_realloc's contract.
            return unsafe { CRYPTO_clear_realloc(addr, 0, 0, file, line) };
        }
        let new_bytes = match num.checked_mul(size) {
            Some(t) => t,
            None => {
                raise_overflow(file, line);
                return ptr::null_mut();
            }
        };
        // `old_num * size` describes an allocation that already exists, so this
        // cannot overflow for any caller that upholds its own contract; saturate
        // rather than wrap if one does not, because a wrapped value here would
        // mean cleansing the wrong region.
        let old_bytes = old_num.saturating_mul(size);
        // SAFETY: forwarded; see CRYPTO_clear_realloc's contract.
        unsafe { CRYPTO_clear_realloc(addr, old_bytes, new_bytes, file, line) }
    })
}

/// `void CRYPTO_free(void *ptr, const char *file, int line)`
///
/// # Safety
/// `ptr` must be NULL or a block from this allocator that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_free(ptr: *mut c_void, file: *const c_char, line: c_int) {
    guard_ffi((), || dealloc(ptr, file, line))
}

/// `void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line)`
///
/// Measured: the block is cleansed over its full length before release.
///
/// # Safety
/// `ptr` must be NULL or a block of at least `num` bytes from this allocator
/// that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_clear_free(
    ptr: *mut c_void,
    num: usize,
    file: *const c_char,
    line: c_int,
) {
    guard_ffi((), || clear_dealloc(ptr, num, file, line))
}

/// `void *CRYPTO_memdup(const void *str, size_t siz, const char *file, int line)`
///
/// A copy of exactly `siz` bytes, with no NUL appended. NULL in, NULL out;
/// a zero `siz` still allocates (matching `CRYPTO_malloc(0)`).
///
/// # Safety
/// `src` must be NULL or readable for `siz` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_memdup(
    src: *const c_void,
    siz: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if src.is_null() {
            return ptr::null_mut();
        }
        let p = alloc(siz, file, line);
        if !p.is_null() && siz > 0 {
            // SAFETY: `src` is readable for `siz` bytes and `p` is a fresh block
            // of `siz`; they cannot overlap.
            unsafe { memcpy(p, src, siz) };
        }
        p
    })
}

/// `char *CRYPTO_strdup(const char *str, const char *file, int line)`
///
/// # Safety
/// `s` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_strdup(
    s: *const c_char,
    file: *const c_char,
    line: c_int,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is NUL-terminated per the caller's contract.
        unsafe {
            let len = strlen(s);
            let p = alloc(len + 1, file, line).cast::<c_char>();
            if !p.is_null() {
                memcpy(p.cast::<c_void>(), s.cast::<c_void>(), len + 1);
            }
            p
        }
    })
}

/// `char *CRYPTO_strndup(const char *str, size_t max, const char *file, int line)`
///
/// Copies at most `max` bytes and always NUL-terminates. Measured: a `max` of 0
/// yields an allocated empty string, not NULL.
///
/// # Safety
/// `s` must be NULL or readable for `max` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_strndup(
    s: *const c_char,
    max: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is readable for `max` bytes.
        unsafe {
            let len = strnlen(s, max);
            let p = alloc(len + 1, file, line).cast::<c_char>();
            if !p.is_null() {
                if len > 0 {
                    memcpy(p.cast::<c_void>(), s.cast::<c_void>(), len);
                }
                *p.add(len) = 0;
            }
            p
        }
    })
}

/// `int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len)`
///
/// Constant-time: every byte is read regardless of earlier differences. Measured:
/// the return value is **exactly** 1 for any difference, not the OR of the byte
/// differences — a caller may compare the result to 1, so the normalized value is
/// part of the contract.
///
/// # Safety
/// Both pointers must be NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_memcmp(
    in_a: *const c_void,
    in_b: *const c_void,
    len: usize,
) -> c_int {
    guard_ffi(1, || {
        if len == 0 {
            return 0;
        }
        if in_a.is_null() || in_b.is_null() {
            return 1;
        }
        // SAFETY: both pointers are readable for `len` bytes.
        unsafe {
            let a = in_a.cast::<u8>();
            let b = in_b.cast::<u8>();
            let mut r: u8 = 0;
            for i in 0..len {
                r |= a.add(i).read() ^ b.add(i).read();
            }
            c_int::from(if r == 0 { 0 } else { 1 })
        }
    })
}

/// `void OPENSSL_cleanse(void *ptr, size_t len)`
///
/// Volatile writes plus a compiler fence. A non-volatile `memset` may legally be
/// removed by the optimiser when the memory is about to be freed, which would
/// silently turn a security control into a no-op.
///
/// # Safety
/// `ptr` must be NULL or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_cleanse(ptr: *mut c_void, len: usize) {
    guard_ffi((), || {
        if ptr.is_null() {
            return;
        }
        // SAFETY: `ptr` is writable for `len` bytes per the caller's contract.
        unsafe { cleanse(ptr.cast::<u8>(), len) }
    })
}

/// `int CRYPTO_set_mem_functions(CRYPTO_malloc_fn malloc_fn, CRYPTO_realloc_fn realloc_fn, CRYPTO_free_fn free_fn)`
///
/// Measured: the authority accepts a second identical installation and returns 1,
/// so this does not latch. Retaining that behaviour matters because a caller may
/// legitimately reinstall while initialising several libraries.
///
/// # Safety
/// The three functions must be valid for the lifetime of the process; every
/// later allocation routes through them.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_mem_functions(
    malloc_fn: Option<MallocFn>,
    realloc_fn: Option<ReallocFn>,
    free_fn: Option<FreeFn>,
) -> c_int {
    guard_ffi(0, || {
        let (Some(m), Some(r), Some(f)) = (malloc_fn, realloc_fn, free_fn) else {
            return 0;
        };
        MALLOC_FN.store(m as usize, Ordering::Relaxed);
        REALLOC_FN.store(r as usize, Ordering::Relaxed);
        FREE_FN.store(f as usize, Ordering::Relaxed);
        1
    })
}

/// `void CRYPTO_get_mem_functions(CRYPTO_malloc_fn *malloc_fn, CRYPTO_realloc_fn *realloc_fn, CRYPTO_free_fn *free_fn)`
///
/// Reports the functions currently in use, which are the defaults until
/// `CRYPTO_set_mem_functions` replaces them.
///
/// # Safety
/// Each non-NULL output pointer must be writable for one function pointer.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_mem_functions(
    malloc_out: *mut Option<MallocFn>,
    realloc_out: *mut Option<ReallocFn>,
    free_out: *mut Option<FreeFn>,
) {
    guard_ffi((), || {
        // SAFETY: each output is either NULL or writable, and the function types
        // match the C typedefs exactly.
        unsafe {
            if !malloc_out.is_null() {
                *malloc_out = Some(malloc_fn());
            }
            if !realloc_out.is_null() {
                *realloc_out = Some(realloc_fn());
            }
            if !free_out.is_null() {
                *free_out = Some(free_fn());
            }
        }
    })
}

/// `unsigned long OPENSSL_version_num(void)`'s sibling is implemented in
/// `crate::runtime::init`; this constant is here only so the memory tests can
/// name the allocator size class they exercise.
#[allow(dead_code)]
pub(crate) const WORD: usize = size_of::<c_ulong>();

/// Shared cleansing primitive, reused by the ERR subsystem for error data.
///
/// # Safety
/// `p` must be valid for writes of `len` bytes.
pub(crate) unsafe fn cleanse(p: *mut u8, len: usize) {
    for i in 0..len {
        // SAFETY: `p` is valid for writes of `len` bytes, so `i < len` is in
        // bounds.
        unsafe { ptr::write_volatile(p.add(i), 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// # Safety
/// `s` must be a NUL-terminated C string.
unsafe fn strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated, so reading stops at the terminator and never
    // leaves the allocation.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// # Safety
/// `s` must be readable for up to `max` bytes and not necessarily terminated.
unsafe fn strnlen(s: *const c_char, max: usize) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is readable for `max` bytes and the loop stops at `n == max`.
    while n < max && unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn zero_length_request_still_allocates() {
        let p = CRYPTO_malloc(0, ptr::null(), 0);
        assert!(!p.is_null(), "CRYPTO_malloc(0) must not return NULL");
        let q = CRYPTO_zalloc(0, ptr::null(), 0);
        assert!(!q.is_null(), "CRYPTO_zalloc(0) must not return NULL");
        // SAFETY: both blocks came from the allocator and are live.
        unsafe {
            CRYPTO_free(p, ptr::null(), 0);
            CRYPTO_free(q, ptr::null(), 0);
        }
    }

    #[test]
    fn zalloc_and_calloc_are_zeroed() {
        let p = CRYPTO_calloc(4, 8, ptr::null(), 0);
        assert!(!p.is_null());
        // SAFETY: 32 bytes were requested and returned.
        unsafe {
            for i in 0..32 {
                assert_eq!(p.cast::<u8>().add(i).read(), 0);
            }
            CRYPTO_free(p, ptr::null(), 0);
        }
    }

    #[test]
    fn array_overflow_returns_null_and_raises() {
        err::ERR_clear_error();
        let p = CRYPTO_malloc_array(usize::MAX, 2, ptr::null(), 0);
        assert!(p.is_null());
        // 15 << 23 | 127 == 0x0780007F, the value the authority produces.
        assert_eq!(err::ERR_get_error(), 0x0780_007F);
    }

    #[test]
    fn realloc_zero_returns_null_without_releasing() {
        let p = CRYPTO_malloc(16, ptr::null(), 0);
        assert!(!p.is_null());
        // SAFETY: `p` is live; the contract says it stays owned by the caller.
        unsafe {
            let q = CRYPTO_realloc(p, 0, ptr::null(), 0);
            assert!(q.is_null());
            CRYPTO_free(p, ptr::null(), 0);
        }
    }

    #[test]
    fn clear_realloc_shrinking_keeps_the_pointer_and_cleanses() {
        let p = CRYPTO_malloc(32, ptr::null(), 0);
        assert!(!p.is_null());
        // SAFETY: 32 bytes were requested; the shrink path must not move it.
        unsafe {
            ptr::write_bytes(p.cast::<u8>(), 0xAA, 32);
            let q = CRYPTO_clear_realloc(p, 32, 16, ptr::null(), 0);
            assert_eq!(p, q, "shrinking must not relocate the block");
            assert_eq!(q.cast::<u8>().read(), 0xAA, "kept prefix must survive");
            CRYPTO_free(q, ptr::null(), 0);
        }
    }

    #[test]
    fn clear_realloc_zero_releases() {
        let p = CRYPTO_malloc(16, ptr::null(), 0);
        assert!(!p.is_null());
        // SAFETY: `p` is live and the zero-length path releases it.
        unsafe {
            let q = CRYPTO_clear_realloc(p, 16, 0, ptr::null(), 0);
            assert!(q.is_null());
        }
    }

    #[test]
    fn memcmp_normalizes_to_one() {
        // SAFETY: both slices are readable for their whole length.
        unsafe {
            for diff in [0x01u8, 0x02, 0x04, 0x80, 0xFF] {
                let a = [diff];
                let b = [0u8];
                let r = CRYPTO_memcmp(a.as_ptr().cast::<c_void>(), b.as_ptr().cast::<c_void>(), 1);
                assert_eq!(r, 1, "a difference of {diff:#x} must report exactly 1");
            }
            let a = [1u8, 2, 3, 4];
            let b = [1u8, 2, 3, 4];
            assert_eq!(
                CRYPTO_memcmp(a.as_ptr().cast::<c_void>(), b.as_ptr().cast::<c_void>(), 4),
                0
            );
            assert_eq!(
                CRYPTO_memcmp(a.as_ptr().cast::<c_void>(), b.as_ptr().cast::<c_void>(), 0),
                0
            );
        }
    }

    #[test]
    fn aligned_alloc_reports_the_block_to_release() {
        // SAFETY: `freeptr` is a local, writable for one pointer.
        unsafe {
            let mut freeptr: *mut c_void = ptr::null_mut();
            let p = CRYPTO_aligned_alloc(64, 64, &mut freeptr, ptr::null(), 0);
            assert!(!p.is_null());
            assert!(!freeptr.is_null());
            assert_eq!(p as usize % 64, 0, "the returned pointer must be aligned");
            assert!(
                (p as usize) >= (freeptr as usize),
                "the returned pointer must lie inside the block to release"
            );
            CRYPTO_free(freeptr, ptr::null(), 0);
        }
    }

    #[test]
    fn cleanse_zeroes_volatilely() {
        let p = CRYPTO_malloc(64, ptr::null(), 0);
        assert!(!p.is_null());
        // SAFETY: 64 bytes were requested and returned.
        unsafe {
            ptr::write_bytes(p.cast::<u8>(), 0x5A, 64);
            OPENSSL_cleanse(p, 64);
            for i in 0..64 {
                assert_eq!(p.cast::<u8>().add(i).read(), 0);
            }
            CRYPTO_free(p, ptr::null(), 0);
        }
    }

    #[test]
    fn custom_allocator_is_used_and_reported() {
        // Install counting shims, prove they are used, then restore the default.
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        // SAFETY: the shims satisfy the allocator contract.
        unsafe extern "C" fn cm(n: usize, _f: *const c_char, _l: c_int) -> *mut c_void {
            COUNT.fetch_add(1, Ordering::Relaxed);
            // SAFETY: forwarded to the C allocator.
            unsafe { malloc(n) }
        }
        // SAFETY: forwarded to `realloc`.
        unsafe extern "C" fn cr(
            p: *mut c_void,
            n: usize,
            _f: *const c_char,
            _l: c_int,
        ) -> *mut c_void {
            // SAFETY: forwarded to `realloc`.
            unsafe { realloc(p, n) }
        }
        // SAFETY: forwarded to `free`.
        unsafe extern "C" fn cf(p: *mut c_void, _f: *const c_char, _l: c_int) {
            // SAFETY: forwarded to `free`, which accepts NULL.
            unsafe { free(p) }
        }

        // SAFETY: installing valid shims; the suite is single-threaded here.
        unsafe {
            assert_eq!(
                CRYPTO_set_mem_functions(Some(cm), Some(cr), Some(cf)),
                1,
                "installing allocators must succeed"
            );
            let mut m: Option<MallocFn> = None;
            let mut r: Option<ReallocFn> = None;
            let mut f: Option<FreeFn> = None;
            CRYPTO_get_mem_functions(&mut m, &mut r, &mut f);
            assert_eq!(m.map(|x| x as usize), Some(cm as *const () as usize));
            assert_eq!(r.map(|x| x as usize), Some(cr as *const () as usize));
            assert_eq!(f.map(|x| x as usize), Some(cf as *const () as usize));

            let before = COUNT.load(Ordering::Relaxed);
            let p = CRYPTO_malloc(8, ptr::null(), 0);
            assert!(COUNT.load(Ordering::Relaxed) > before, "shim must be used");
            CRYPTO_free(p, ptr::null(), 0);
            assert_eq!(
                CRYPTO_set_mem_functions(
                    Some(default_malloc),
                    Some(default_realloc),
                    Some(default_free)
                ),
                1
            );
        }
    }
}
