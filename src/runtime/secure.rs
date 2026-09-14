//! Phase 3 core runtime — secure memory (`CRYPTO_secure_*`).
//!
//! OpenSSL's "secure heap": an arena carved from a dedicated `mmap` that is
//! locked into RAM, excluded from core dumps, flanked by `PROT_NONE` guard pages,
//! and cleansed before memory is released. It is the storage the library puts
//! private keys and other long-lived secrets in, so its *observable* properties —
//! which pointer counts as secure, what `actual_size` reports, what `used`
//! accounts, whether a release leaves plaintext behind — are part of the contract
//! and are reproduced here, not approximated.
//!
//! ## Mechanism (real secure memory, not a malloc wrapper)
//!
//! One anonymous `MAP_PRIVATE` mapping per initialised heap, laid out as:
//!
//! ```text
//!   +---------+------------------------+---------+
//!   | guard   | arena                  | guard   |
//!   | PROT_    | rw, mlocked,           | PROT_   |
//!   | NONE    | MADV_DONTDUMP          | NONE    |
//!   +---------+------------------------+---------+
//!   ^         ^                        ^
//!   map_base  map_base+page            map_base+round_up(page+arena_size)
//! ```
//!
//! The authority does exactly this (`crypto/mem_sec.c`): the whole mapping is
//! created read/write, the two guard pages are `mprotect(PROT_NONE)`d, and the
//! arena is `mlock`ed and `madvise(MADV_DONTDUMP)`ed. The arena is *not* paged out
//! or protected per allocation: allocation granularity is `minsize` (16 bytes by
//! default), which is sub-page, so per-chunk `PROT_NONE` is not even expressible.
//! The security property for free memory is instead **cleanse-before-release**,
//! which this module performs for every release path.
//!
//! ## Allocation semantics reproduced (measured against the authority)
//!
//! Differential probes (`court/scratch/secprobe*.c`) established:
//!
//! * `CRYPTO_secure_malloc_init` returns 1 on success, 2 when the mapping was
//!   created but a hardening step failed (guard page, `mlock`, `madvise`), 0 on a
//!   clean failure, and **0 when already initialised**. Invalid arguments
//!   (non-power-of-two size, zero size, non-power-of-two `minsize` > 16) make the
//!   authority `OPENSSL_die`/abort; a candidate does not reproduce that UB, so it
//!   returns 0 instead (see Divergences).
//! * `minsize` <= `sizeof(SH_LIST)` (16 on x86-64) is raised to 16; otherwise it
//!   must be a power of two and is used as given.
//! * `CRYPTO_secure_actual_size` is the **rounded-up** chunk size — the smallest
//!   power-of-two multiple of `minsize` that is `>=` the request (1→16, 17→32,
//!   33→64, 100→128, 1000→1024) — not the requested size.
//! * `CRYPTO_secure_malloc(0)` returns a `minsize` chunk, **not** NULL (unlike
//!   [`crate::runtime::mem::CRYPTO_malloc`], which returns NULL for zero).
//! * `CRYPTO_secure_used` is the sum of the `actual_size` of every live secure
//!   allocation.
//! * `CRYPTO_secure_allocated` is `WITHIN_ARENA(ptr)`: 1 for *any* address in
//!   `[arena, arena+arena_size)` (interior addresses included), 0 for NULL, a
//!   plain-allocator pointer, or when uninitialised.
//! * `CRYPTO_secure_free` **and** `CRYPTO_secure_clear_free` both cleanse the
//!   whole `actual_size` before releasing. For a secure pointer
//!   `CRYPTO_secure_clear_free` ignores its `num` argument (the probes show
//!   `clear_free(p, 1)` zeroes all 128 bytes of a 100-byte request). For a
//!   non-secure pointer it cleanses `num` bytes and then frees.
//! * `CRYPTO_secure_malloc_done` returns 1 and tears the heap down only when
//!   `used == 0`; with live allocations it returns 0 and stays initialised. A
//!   second `done` returns 1 again. `done` before any `init` returns 1.
//! * On allocation failure (exhaustion or request larger than the arena) the
//!   authority returns NULL and raises `CRYPTO_R_SECURE_MALLOC_FAILURE` (111) in
//!   lib `CRYPTO`, **unless** called with `file == NULL && line == 0`, in which
//!   case it raises nothing. `CRYPTO_secure_malloc_array`/`_calloc` raise
//!   `CRYPTO_R_INTEGER_OVERFLOW` (127) on multiplication overflow.
//! * With no heap initialised, `CRYPTO_secure_malloc`/`_zalloc`/`_array`/`_calloc`
//!   **fall back** to the plain allocator; the result is classified
//!   `allocated == 0` and no error is raised.
//!
//! ## Recorded divergences from the authority
//!
//! Per `docs/UNSAFE.md` §5, authority UB is recorded, not imitated:
//!
//! 1. `CRYPTO_secure_used()` and `CRYPTO_secure_actual_size()` **segfault** in
//!    the authority when the heap is not initialised (they take a NULL rwlock).
//!    This candidate returns 0. The same applies after `done`.
//! 2. `CRYPTO_secure_actual_size(ptr)` on a non-secure pointer **aborts** in the
//!    authority (`OPENSSL_assert(WITHIN_ARENA(ptr))`). This candidate returns 0.
//! 3. Invalid `init` arguments abort in the authority; this candidate returns 0
//!    (a clean failure value) instead.
//!
//! ## `OPENSSL_secure_*`
//!
//! The `OPENSSL_secure_malloc`, `OPENSSL_secure_free`, ... names in `crypto.h`
//! are **macros** ([`crypto.h`] lines 138–151) that expand to the `CRYPTO_*`
//! entry points with `OPENSSL_FILE`/`OPENSSL_LINE`. `nm -D` on the authority's
//! `libcrypto.so.3` shows they are **not exported symbols**, so this module
//! deliberately defines no such symbol.
//!
//! ## Thread safety (the assumption this module makes)
//!
//! `CRYPTO_secure_malloc_init`/`_done` are **not** documented thread-safe. OpenSSL
//! guards allocation with a rwlock but performs init/teardown outside it. This
//! module serialises *all* state access (including init/teardown) behind one
//! process-wide [`Mutex`]. That is a strictly stronger guarantee than the
//! authority's, and it means a caller that races `_done` against an allocation
//! gets a consistent result here; the authority leaves that race undefined.
//!
//! ## SAFETY invariant catalogue
//!
//! The `unsafe` blocks in this module rely on exactly these preconditions:
//!
//! * **S1** — `map_base`/`map_size` describe a live anonymous mapping returned by
//!   `mmap`, not yet `munmap`ped, for as long as the owning [`Heap`] exists.
//! * **S2** — `arena == map_base + page_size` and `arena + arena_size` lies inside
//!   that mapping, so arena-relative reads and writes are in bounds.
//! * **S3** — every `offset`/`size` pair passed to `cleanse` names a live or
//!   just-released allocation tracked by [`Heap::allocs`], hence lies within the
//!   arena.
//! * **S4** — a pointer accepted by `free`/`cleanse` is either NULL, a live
//!   allocation owned by this heap, or a plain-allocator allocation the caller
//!   owns (the C ABI contract, stated per function under `# Safety`).
//! * **S5** — `file` is NULL or a NUL-terminated C string (the OpenSSL error-hook
//!   contract), because it is forwarded to `ERR_set_debug`.
//!
//! [`crypto.h`]: ../forensics/authorities/prefix/openssl-3.6.4-production/include/openssl/crypto.h

use core::ffi::{c_char, c_int, c_void};
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::ffi::guard_ffi;
use crate::runtime::err::{openssl_rs_err_set_error, ERR_new, ERR_set_debug};
use crate::runtime::mem::{cleanse, CRYPTO_malloc, CRYPTO_zalloc};

// --- Linux syscall surface -------------------------------------------------
//
// The admitted platform is `linux-x86_64` (`docs/AUTHORITY_POLICY.md`), and these
// are declared exactly as the C ABI presents them. `mmap`'s final argument is
// `off_t` (64-bit `long` on this platform).

extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        off: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int;
    fn mlock(addr: *mut c_void, len: usize) -> c_int;
    fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int;
    fn getpagesize() -> c_int;
    /// The plain C allocator, used for the non-secure-pointer release path. The
    /// authority routes that to `CRYPTO_free`, which in the default profile is
    /// `free`; `CRYPTO_free` is not defined by this crate yet, so the equivalent
    /// libc call is made directly (same observable behaviour).
    fn free(ptr: *mut c_void);
}

const PROT_NONE: c_int = 0;
const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_PRIVATE: c_int = 0x02;
const MAP_ANONYMOUS: c_int = 0x20;
const MADV_DONTDUMP: c_int = 16;

// --- ERR identity ----------------------------------------------------------
//
// Values taken from the authority's installed headers:
// `ERR_LIB_CRYPTO` (err.h:87), `CRYPTO_R_SECURE_MALLOC_FAILURE` (cryptoerr.h:45)
// and `CRYPTO_R_INTEGER_OVERFLOW` (cryptoerr.h:29).

const ERR_LIB_CRYPTO: c_int = 15;
const CRYPTO_R_SECURE_MALLOC_FAILURE: c_int = 111;
const CRYPTO_R_INTEGER_OVERFLOW: c_int = 127;

/// `sizeof(SH_LIST)` in the authority's `mem_sec.c`: two pointers. On x86-64 this
/// is 16, which is the smallest chunk the secure heap deals in.
const SH_LIST_SIZE: usize = 2 * core::mem::size_of::<usize>();

/// Outcome of attempting a secure allocation, used to fold three cases — no heap,
/// none-free, success — out of a single locked critical section.
enum SecureAlloc {
    /// No heap is initialised; the caller must use the plain-allocator fallback.
    Uninitialized,
    /// The heap exists but has no chunk large enough.
    Failed,
    /// A chunk was allocated at this address.
    Ok(*mut c_void),
}

/// The secure heap. All fields are integers/owners so the type is `Send` and can
/// live in the process-wide [`Mutex`].
struct Heap {
    /// Base address of the `mmap` (the leading guard page). S1.
    map_base: usize,
    /// Length passed to `mmap`, and to `munmap` on teardown. S1.
    map_size: usize,
    /// First byte of the usable arena. S2.
    arena: usize,
    /// Usable arena length in bytes. S2.
    arena_size: usize,
    /// Number of buddy free lists; list `i` holds chunks of `arena_size >> i`
    /// bytes, so list 0 is the whole arena and list `nlists - 1` is `minsize`.
    nlists: usize,
    /// Buddy free lists, holding arena-relative offsets.
    free_lists: Vec<Vec<usize>>,
    /// Live allocations: arena-relative offset -> free-list index. The index
    /// yields the chunk size used by `actual_size`, `used` and release cleansing.
    allocs: BTreeMap<usize, usize>,
    /// Sum of the `actual_size` of live allocations, i.e. `CRYPTO_secure_used`.
    used: usize,
}

impl Drop for Heap {
    fn drop(&mut self) {
        if self.map_base != 0 && self.map_size != 0 {
            // SAFETY: S1 — this Heap owns the mapping, and `Drop` runs once, so it
            // is unmapped exactly once.
            unsafe {
                munmap(self.map_base as *mut c_void, self.map_size);
            }
        }
    }
}

/// The one heap this process has. `None` means uninitialised.
static HEAP: Mutex<Option<Heap>> = Mutex::new(None);

/// Run `f` with exclusive access to the heap state.
///
/// Poisoning (a panic unwound out of a critical section) is recovered rather than
/// propagated: the FFI boundary already converts that panic into a documented
/// failure value, and refusing all further calls would turn one defect into a
/// permanently unusable subsystem.
fn with_heap<R>(f: impl FnOnce(&mut Option<Heap>) -> R) -> R {
    let mut guard = match HEAP.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut guard)
}

/// The OS page size, with the authority's 4096 fallback.
fn page_size() -> usize {
    // SAFETY: `getpagesize` has no preconditions and no side effects.
    let p = unsafe { getpagesize() };
    if p > 0 {
        p as usize
    } else {
        4096
    }
}

/// `floor(log2(v))` for `v >= 1`. Mirrors the authority's freelist-sizing loop
/// rather than relying on a trailing-zero count being meaningful off powers of two.
fn log2_floor(mut v: usize) -> usize {
    let mut n = 0;
    while v > 1 {
        v >>= 1;
        n += 1;
    }
    n
}

impl Heap {
    /// Create the mapping and its bookkeeping. Returns the heap and the value
    /// `CRYPTO_secure_malloc_init` should return (1, or 2 for a partial hardening
    /// failure), or `Err(())` for a parameter that the authority rejects before
    /// mapping anything.
    fn new(size: usize, minsize: usize) -> Result<(Heap, c_int), ()> {
        // The authority asserts these; a candidate records the UB and returns a
        // clean failure instead (Divergence 3).
        if size == 0 || (size & (size - 1)) != 0 {
            return Err(());
        }
        let minsize = if minsize <= SH_LIST_SIZE {
            SH_LIST_SIZE.next_power_of_two()
        } else {
            minsize
        };
        if (minsize & (minsize - 1)) != 0 {
            return Err(());
        }
        // At least four chunks, or the authority's bitmap is too small and it
        // fails cleanly (`sh_init`: `bittable_size >> 3 == 0`).
        let chunks = size / minsize;
        if chunks < 4 {
            return Err(());
        }
        let nlists = log2_floor(chunks * 2);

        let pg = page_size();
        let map_size = pg
            .checked_add(size)
            .and_then(|v| v.checked_add(pg))
            .ok_or(())?;
        // SAFETY: `mmap` has no pointer preconditions; its arguments are a length
        // we just validated and constant flag bits. It returns MAP_FAILED or a
        // fresh, page-aligned, zero-filled private mapping.
        let map = unsafe {
            mmap(
                core::ptr::null_mut(),
                map_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if map as usize == usize::MAX {
            return Err(());
        }
        let map_base = map as usize;
        let arena = map_base + pg;

        // The authority records a hardening failure but still returns a usable
        // heap, so a non-1 return here does not mean "uninitialised".
        let mut ret = 1;
        // SAFETY: the leading `pg` bytes are inside the mapping (S1).
        if unsafe { mprotect(map_base as *mut c_void, pg, PROT_NONE) } < 0 {
            ret = 2;
        }
        let aligned = (pg + size).saturating_add(pg - 1) & !(pg - 1);
        // SAFETY: this may fall outside the mapping for a small arena, in which
        // case `mprotect` fails harmlessly and is recorded — exactly the
        // authority's behaviour, which is why the return can be 2.
        if unsafe { mprotect((map_base + aligned) as *mut c_void, pg, PROT_NONE) } < 0 {
            ret = 2;
        }
        // SAFETY: `arena..arena+size` is inside the mapping (S2).
        if unsafe { mlock(arena as *mut c_void, size) } < 0 {
            ret = 2;
        }
        // SAFETY: same range as the `mlock` above.
        if unsafe { madvise(arena as *mut c_void, size, MADV_DONTDUMP) } < 0 {
            ret = 2;
        }

        let mut free_lists = Vec::with_capacity(nlists);
        for _ in 0..nlists {
            free_lists.push(Vec::new());
        }
        // The whole arena starts as one free list-0 chunk.
        free_lists[0].push(0);

        Ok((
            Heap {
                map_base,
                map_size,
                arena,
                arena_size: size,
                nlists,
                free_lists,
                allocs: BTreeMap::new(),
                used: 0,
            },
            ret,
        ))
    }

    /// Is `ptr` inside the arena? This is the authority's `WITHIN_ARENA`, which is
    /// deliberately coarse: it does not require the address to be an allocation
    /// start.
    fn contains(&self, ptr: *const c_void) -> bool {
        let a = ptr as usize;
        a >= self.arena && a < self.arena + self.arena_size
    }

    /// Allocate a chunk of the rounded-up size, returning `(offset, chunk_size)`.
    fn alloc(&mut self, size: usize) -> Option<(usize, usize)> {
        if size > self.arena_size {
            return None;
        }
        // Smallest chunk (largest list index) whose size is >= the request.
        let mut list = self.nlists - 1;
        while list > 0 && (self.arena_size >> list) < size {
            list -= 1;
        }
        // Find any free chunk at least that large.
        let mut slist = list;
        while slist > 0 && self.free_lists[slist].is_empty() {
            slist -= 1;
        }
        // Split the found chunk down to the requested size, leaving the lower
        // buddy free at each level and descending into the upper one.
        let mut off = self.free_lists[slist].pop()?;
        while slist < list {
            slist += 1;
            let half = self.arena_size >> slist;
            self.free_lists[slist].push(off);
            off += half;
        }
        let chunk = self.arena_size >> list;
        self.allocs.insert(off, list);
        self.used += chunk;
        Some((off, chunk))
    }

    /// Release `ptr` if it belongs to this heap. Returns `false` for a pointer
    /// outside the arena, meaning the caller must use the plain allocator.
    ///
    /// The whole usable allocation is cleansed before it re-enters the free lists,
    /// which is where the security property actually lives.
    fn free(&mut self, ptr: *const c_void) -> bool {
        if !self.contains(ptr) {
            return false;
        }
        let off = ptr as usize - self.arena;
        if let Some(list) = self.allocs.remove(&off) {
            let size = self.arena_size >> list;
            // SAFETY: S3 — `off..off+size` is the live allocation being released.
            unsafe {
                cleanse((self.arena + off) as *mut u8, size);
            }
            self.used -= size;
            self.coalesce(off, list);
        }
        // Within the arena but not an allocation start is caller UB in the
        // authority (it would corrupt the bitmap); here it is a safe no-op.
        true
    }

    /// Return a chunk to its free list, merging with free buddies up to the
    /// largest free block (standard buddy coalescing).
    fn coalesce(&mut self, off: usize, list: usize) {
        let mut cur_off = off;
        let mut cur_list = list;
        while cur_list > 0 {
            let size = self.arena_size >> cur_list;
            let buddy = cur_off ^ size;
            match self.free_lists[cur_list].iter().position(|&x| x == buddy) {
                Some(pos) => {
                    self.free_lists[cur_list].swap_remove(pos);
                    cur_off = cur_off.min(buddy);
                    cur_list -= 1;
                }
                None => break,
            }
        }
        self.free_lists[cur_list].push(cur_off);
    }

    /// Usable size of the allocation starting at `ptr`, or 0 if `ptr` is not an
    /// allocation start. Sizes are the rounded-up chunk sizes.
    fn actual_size(&self, ptr: *const c_void) -> usize {
        if !self.contains(ptr) {
            return 0;
        }
        let off = ptr as usize - self.arena;
        match self.allocs.get(&off) {
            Some(&list) => self.arena_size >> list,
            None => 0,
        }
    }
}

/// Raise the authority's allocation error, honouring its suppression rule: no
/// error is raised when called with neither a file nor a line, which prevents a
/// recursive failure while the error queue is itself being allocated.
///
/// # Safety
/// S5 — `file` must be NULL or a NUL-terminated C string.
unsafe fn report_secure_alloc_failure(file: *const c_char, line: c_int, reason: c_int) {
    if file.is_null() && line == 0 {
        return;
    }
    ERR_new();
    // SAFETY: S5 — `file` is NULL or NUL-terminated; `func` is NULL, which
    // `ERR_set_debug` accepts.
    unsafe {
        ERR_set_debug(file, line, core::ptr::null());
    }
    // SAFETY: `msg` is NULL; the setter accepts the absence of textual data.
    unsafe {
        openssl_rs_err_set_error(ERR_LIB_CRYPTO, reason, core::ptr::null());
    }
}

/// `int CRYPTO_secure_malloc_init(size_t sz, size_t minsize)`
///
/// Returns 1 on success, 2 when the heap is usable but a hardening step failed,
/// 0 on failure or when already initialised. Invalid arguments return 0 rather
/// than reproducing the authority's abort (Divergence 3).
#[no_mangle]
pub extern "C" fn CRYPTO_secure_malloc_init(size: usize, minsize: usize) -> c_int {
    guard_ffi(0, || {
        with_heap(|slot| {
            if slot.is_some() {
                // Already initialised: the authority leaves `ret` at 0.
                return 0;
            }
            match Heap::new(size, minsize) {
                Ok((heap, ret)) => {
                    *slot = Some(heap);
                    ret
                }
                Err(()) => 0,
            }
        })
    })
}

/// `int CRYPTO_secure_malloc_done(void)`
///
/// Tears the heap down and returns 1 only when nothing is live; with live
/// allocations it returns 0 and leaves the heap initialised. Safe to call when no
/// heap exists (returns 1) and more than once (returns 1).
#[no_mangle]
pub extern "C" fn CRYPTO_secure_malloc_done() -> c_int {
    guard_ffi(0, || {
        with_heap(|slot| {
            if slot.as_ref().is_none_or(|h| h.used == 0) {
                // `None` (never initialised) or fully free: the authority's
                // `sh_done` is a no-op in the former case and a teardown in the
                // latter, and both return 1.
                *slot = None;
                1
            } else {
                0
            }
        })
    })
}

/// `int CRYPTO_secure_malloc_initialized(void)`
#[no_mangle]
pub extern "C" fn CRYPTO_secure_malloc_initialized() -> c_int {
    guard_ffi(0, || with_heap(|slot| c_int::from(slot.is_some())))
}

/// `void *CRYPTO_secure_malloc(size_t num, const char *file, int line)`
///
/// Returns a secure chunk, or — when no heap is initialised — a plain-allocator
/// block, which `CRYPTO_secure_allocated` then reports as non-secure. A request
/// larger than the arena fails with NULL.
///
/// # Safety
/// S5 — `file` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_malloc(
    num: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        let outcome = with_heap(|slot| match slot {
            None => SecureAlloc::Uninitialized,
            Some(h) => match h.alloc(num) {
                Some((off, _size)) => SecureAlloc::Ok((h.arena + off) as *mut c_void),
                None => SecureAlloc::Failed,
            },
        });
        match outcome {
            SecureAlloc::Uninitialized => CRYPTO_malloc(num, file, line),
            SecureAlloc::Ok(p) => p,
            SecureAlloc::Failed => {
                // SAFETY: S5.
                unsafe { report_secure_alloc_failure(file, line, CRYPTO_R_SECURE_MALLOC_FAILURE) };
                core::ptr::null_mut()
            }
        }
    })
}

/// `void *CRYPTO_secure_zalloc(size_t num, const char *file, int line)`
///
/// As [`CRYPTO_secure_malloc`], but the whole usable allocation is zeroed before
/// it is returned. (Secure memory is zeroed on release too, so plain
/// `CRYPTO_secure_malloc` also observes zeroes; zeroing here makes the contract
/// independent of that invariant.)
///
/// # Safety
/// S5 — `file` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_zalloc(
    num: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        let outcome = with_heap(|slot| match slot {
            None => SecureAlloc::Uninitialized,
            Some(h) => match h.alloc(num) {
                Some((off, size)) => {
                    let addr = h.arena + off;
                    // SAFETY: S2/S3 — `addr..addr+size` is the freshly allocated
                    // chunk inside the arena.
                    unsafe {
                        cleanse(addr as *mut u8, size);
                    }
                    SecureAlloc::Ok(addr as *mut c_void)
                }
                None => SecureAlloc::Failed,
            },
        });
        match outcome {
            SecureAlloc::Uninitialized => CRYPTO_zalloc(num, file, line),
            SecureAlloc::Ok(p) => p,
            SecureAlloc::Failed => {
                // SAFETY: S5.
                unsafe { report_secure_alloc_failure(file, line, CRYPTO_R_SECURE_MALLOC_FAILURE) };
                core::ptr::null_mut()
            }
        }
    })
}

/// `void *CRYPTO_secure_malloc_array(size_t num, size_t size, const char *file, int line)`
///
/// Overflow-checked `num * size`, then [`CRYPTO_secure_malloc`]. On overflow it
/// raises `CRYPTO_R_INTEGER_OVERFLOW` and returns NULL.
///
/// # Safety
/// S5 — `file` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_malloc_array(
    num: usize,
    size: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || match num.checked_mul(size) {
        None => {
            // SAFETY: S5.
            unsafe { report_secure_alloc_failure(file, line, CRYPTO_R_INTEGER_OVERFLOW) };
            core::ptr::null_mut()
        }
        // SAFETY: S5 — `file` is forwarded unchanged.
        Some(bytes) => unsafe { CRYPTO_secure_malloc(bytes, file, line) },
    })
}

/// `void *CRYPTO_secure_calloc(size_t num, size_t size, const char *file, int line)`
///
/// Overflow-checked `num * size`, then [`CRYPTO_secure_zalloc`].
///
/// # Safety
/// S5 — `file` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_calloc(
    num: usize,
    size: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || match num.checked_mul(size) {
        None => {
            // SAFETY: S5.
            unsafe { report_secure_alloc_failure(file, line, CRYPTO_R_INTEGER_OVERFLOW) };
            core::ptr::null_mut()
        }
        // SAFETY: S5 — `file` is forwarded unchanged.
        Some(bytes) => unsafe { CRYPTO_secure_zalloc(bytes, file, line) },
    })
}

/// `void CRYPTO_secure_free(void *ptr, const char *file, int line)`
///
/// Releases a secure allocation after cleansing its whole usable size. A pointer
/// outside the arena is released with the plain allocator, exactly as the
/// authority routes it to `CRYPTO_free`.
///
/// # Safety
/// S4 — `ptr` must be NULL, a live allocation from this module, or a plain
/// allocation owned by the caller, and must not be used again afterwards. Because
/// this call is idempotent on NULL, all four combinations below are valid.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_free(ptr: *mut c_void, _file: *const c_char, _line: c_int) {
    guard_ffi((), || {
        if ptr.is_null() {
            return;
        }
        let owned_by_heap = with_heap(|slot| slot.as_mut().is_some_and(|h| h.free(ptr.cast())));
        if !owned_by_heap {
            // SAFETY: S4 — a non-secure pointer the caller owns; released once.
            unsafe {
                free(ptr);
            }
        }
    })
}

/// `void CRYPTO_secure_clear_free(void *ptr, size_t num, const char *file, int line)`
///
/// For a secure pointer this is identical to [`CRYPTO_secure_free`]: the whole
/// usable allocation is cleansed and `num` is ignored (measured). For a non-secure
/// pointer, `num` bytes are cleansed and then the block is freed.
///
/// # Safety
/// S4 — `ptr` must be NULL, a live allocation from this module, or a plain
/// allocation owned by the caller; if it is not a secure allocation it must be
/// readable for `num` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_clear_free(
    ptr: *mut c_void,
    num: usize,
    _file: *const c_char,
    _line: c_int,
) {
    guard_ffi((), || {
        if ptr.is_null() {
            return;
        }
        let owned_by_heap = with_heap(|slot| slot.as_mut().is_some_and(|h| h.free(ptr.cast())));
        if !owned_by_heap {
            // SAFETY: S4 — plain allocation, readable for `num` bytes, released
            // once.
            unsafe {
                cleanse(ptr.cast::<u8>(), num);
                free(ptr);
            }
        }
    })
}

/// `int CRYPTO_secure_allocated(const void *ptr)`
///
/// 1 for any address inside the arena (the authority's coarse `WITHIN_ARENA`
/// test, which accepts interior addresses), 0 otherwise — including NULL, plain
/// allocator pointers, and every address when no heap is initialised.
#[no_mangle]
pub extern "C" fn CRYPTO_secure_allocated(ptr: *const c_void) -> c_int {
    guard_ffi(0, || {
        with_heap(|slot| match slot {
            Some(h) if !ptr.is_null() && h.contains(ptr) => 1,
            _ => 0,
        })
    })
}

/// `size_t CRYPTO_secure_actual_size(void *ptr)`
///
/// The usable size of a secure allocation, i.e. the rounded-up chunk size, or 0
/// for anything that is not an allocation start. Unlike the authority this never
/// aborts or dereferences the pointer (Divergences 1 and 2).
#[no_mangle]
pub extern "C" fn CRYPTO_secure_actual_size(ptr: *mut c_void) -> usize {
    guard_ffi(0, || {
        with_heap(|slot| slot.as_ref().map_or(0, |h| h.actual_size(ptr)))
    })
}

/// `size_t CRYPTO_secure_used(void)`
///
/// Sum of the usable sizes of all live secure allocations. Returns 0 when no heap
/// is initialised, where the authority instead faults (Divergence 1).
#[no_mangle]
pub extern "C" fn CRYPTO_secure_used() -> usize {
    guard_ffi(0, || with_heap(|slot| slot.as_ref().map_or(0, |h| h.used)))
}

/// Read raw arena bytes at `offset..offset+len` (test-only).
///
/// This is how the security property — "released memory is already zero" — is
/// observed directly, without relying on a subsequent allocation returning the
/// same chunk.
#[cfg(test)]
fn test_arena_bytes(offset: usize, len: usize) -> Vec<u8> {
    with_heap(|slot| match slot {
        Some(h)
            if offset
                .checked_add(len)
                .is_some_and(|end| end <= h.arena_size) =>
        {
            // SAFETY: the guard above establishes that the range is within the
            // arena (S2), and the arena remains mapped while the heap exists.
            unsafe { core::slice::from_raw_parts((h.arena + offset) as *const u8, len).to_vec() }
        }
        _ => Vec::new(),
    })
}

/// Arena-relative offset of `ptr`, if it is inside the arena (test-only).
#[cfg(test)]
fn test_offset_of(ptr: *const c_void) -> Option<usize> {
    with_heap(|slot| match slot {
        Some(h) if h.contains(ptr) => Some(ptr as usize - h.arena),
        _ => None,
    })
}

#[cfg(test)]
// `unwrap_used` is denied for product code, where a panic on the FFI path is a
// hazard. In tests a failing unwrap is the desired loud failure, so it is allowed
// here rather than weakened crate-wide (the same convention as `src/ffi/mod.rs`).
// The `undocumented_unsafe_blocks` allowance follows the same reasoning: every
// test-side unsafe block is a direct call to the API under test with pointers to
// values the test owns, so the invariant is stated once rather than 9 times.
#[allow(clippy::undocumented_unsafe_blocks)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Serialises tests, which share one process-wide heap.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// A non-NULL file argument, so error paths are exercised (the authority
    /// suppresses errors only for `file == NULL && line == 0`).
    fn file() -> *const c_char {
        c"secure-test".as_ptr().cast()
    }

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Bring the process to the uninitialised state. Safe when nothing is live;
    /// tests always release what they allocate.
    fn reset() {
        let _ = CRYPTO_secure_malloc_done();
    }

    fn init_ok(size: usize, minsize: usize) {
        let r = CRYPTO_secure_malloc_init(size, minsize);
        assert!(r == 1 || r == 2, "init({size},{minsize}) returned {r}");
        assert_eq!(CRYPTO_secure_malloc_initialized(), 1);
    }

    // Thin wrappers so each `unsafe` block carries its SAFETY comment once.
    // Every call upholds the wrapped function's contract: `file()` is a
    // NUL-terminated C string, and every pointer passed in is a live allocation
    // owned by the calling test.

    fn sm(num: usize) -> *mut c_void {
        // SAFETY: S5 — `file()` is NUL-terminated; `num == 0` is permitted.
        unsafe { CRYPTO_secure_malloc(num, file(), 1) }
    }

    fn sz(num: usize) -> *mut c_void {
        // SAFETY: as `sm`.
        unsafe { CRYPTO_secure_zalloc(num, file(), 1) }
    }

    fn sm_silent(num: usize) -> *mut c_void {
        // SAFETY: NULL file with line 0 is permitted (S5); the authority
        // suppresses the error, which the exhaustion test relies on.
        unsafe { CRYPTO_secure_malloc(num, core::ptr::null(), 0) }
    }

    fn sma(num: usize, size: usize) -> *mut c_void {
        // SAFETY: as `sm`.
        unsafe { CRYPTO_secure_malloc_array(num, size, file(), 1) }
    }

    fn sc(num: usize, size: usize) -> *mut c_void {
        // SAFETY: as `sm`.
        unsafe { CRYPTO_secure_calloc(num, size, file(), 1) }
    }

    fn sf(p: *mut c_void) {
        // SAFETY: S4 — `p` is NULL or a live allocation owned by the caller.
        unsafe { CRYPTO_secure_free(p, file(), 1) };
    }

    fn scf(p: *mut c_void, num: usize) {
        // SAFETY: S4 — `p` is NULL, a live secure allocation, or a plain
        // allocation readable for `num` bytes.
        unsafe { CRYPTO_secure_clear_free(p, num, file(), 1) };
    }

    fn plain_malloc(num: usize) -> *mut c_void {
        crate::runtime::mem::CRYPTO_malloc(num, file(), 1)
    }

    fn plain_clear_free(p: *mut c_void, num: usize) {
        // SAFETY: `p` is a plain allocation of `num` bytes owned by the caller.
        unsafe { crate::runtime::mem::CRYPTO_clear_free(p, num, file(), 1) };
    }

    fn first_byte(p: *const c_void) -> u8 {
        // SAFETY: callers pass a non-NULL pointer into a readable allocation.
        unsafe { *p.cast::<u8>() }
    }

    fn one_past(p: *const c_void) -> *const c_void {
        // SAFETY: callers pass a non-NULL pointer into an allocation of at least
        // two bytes, so `p + 1` is in bounds.
        unsafe { p.cast::<u8>().add(1) }.cast()
    }

    fn fill(p: *mut c_void, byte: u8, len: usize) {
        // SAFETY: callers pass a live allocation of exactly `len` bytes.
        unsafe { core::ptr::write_bytes(p.cast::<u8>(), byte, len) };
    }

    #[test]
    fn calloc_zeroes_and_release_classification_is_a_range_check() {
        let _guard = lock();
        reset();
        if CRYPTO_secure_malloc_init(1 << 20, 16) == 0 {
            return;
        }
        let p = sc(4, 8);
        assert!(!p.is_null(), "secure calloc must allocate");
        // SAFETY: `p` is a live allocation of 4 * 8 bytes.
        unsafe {
            let b = p.cast::<u8>();
            for i in 0..32 {
                assert_eq!(b.add(i).read(), 0, "secure calloc must zero its block");
            }
        }
        fill(p, 0x5A, 32);
        scf(p, 32);
        // MEASURED (`courts/phase3/rt_secure_probe.c`): `CRYPTO_secure_allocated`
        // is a RANGE test, not a liveness test. It answers 1 for a released block
        // and 1 for an interior pointer, and 0 for NULL and for a pointer from the
        // plain allocator. Asserting 0 here after the release is the natural but
        // WRONG reading of the name, which is why the probe exists.
        assert_eq!(CRYPTO_secure_allocated(p), 1, "range check, not liveness");
        // SAFETY: `p + 1` is still inside the arena, so the range check sees it.
        let interior = unsafe { p.cast::<u8>().add(1) }.cast::<c_void>();
        assert_eq!(CRYPTO_secure_allocated(interior), 1);
        assert_eq!(CRYPTO_secure_allocated(core::ptr::null()), 0);
        // `actual_size` on a released block ABORTS the authority (measured); the
        // candidate returns 0 instead, which is one of the recorded safety
        // divergences (see the module documentation).
        assert_eq!(CRYPTO_secure_actual_size(p), 0);
        let _ = CRYPTO_secure_malloc_done();
    }

    #[test]
    fn init_initialized_done_lifecycle_and_double_done() {
        let _guard = lock();
        reset();
        assert_eq!(CRYPTO_secure_malloc_initialized(), 0);

        let r = CRYPTO_secure_malloc_init(1 << 20, 16);
        assert!(r == 1 || r == 2, "init returned {r}");
        assert_eq!(CRYPTO_secure_malloc_initialized(), 1);

        // A second init while initialised returns 0 and does not disturb state.
        assert_eq!(CRYPTO_secure_malloc_init(1 << 20, 16), 0);
        assert_eq!(CRYPTO_secure_malloc_initialized(), 1);

        assert_eq!(CRYPTO_secure_malloc_done(), 1);
        assert_eq!(CRYPTO_secure_malloc_initialized(), 0);
        // Double done: still 1, still uninitialised.
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
        assert_eq!(CRYPTO_secure_malloc_initialized(), 0);
    }

    #[test]
    fn done_is_refused_while_allocations_are_live() {
        let _guard = lock();
        reset();
        init_ok(1 << 20, 16);

        let p = sm(64);
        assert!(!p.is_null());
        assert_eq!(
            CRYPTO_secure_malloc_done(),
            0,
            "done must refuse with live memory"
        );
        assert_eq!(CRYPTO_secure_malloc_initialized(), 1);

        sf(p);
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
        assert_eq!(CRYPTO_secure_malloc_initialized(), 0);
    }

    #[test]
    fn allocate_before_init_falls_back_to_the_plain_allocator() {
        let _guard = lock();
        reset();
        assert_eq!(CRYPTO_secure_malloc_initialized(), 0);

        let p = sm(64);
        assert!(
            !p.is_null(),
            "uninitialised secure_malloc falls back, not NULL"
        );
        assert_eq!(
            CRYPTO_secure_allocated(p),
            0,
            "fallback memory is not secure"
        );

        // used/actual_size are safe to call here and report 0; the authority
        // faults (Divergence 1).
        assert_eq!(CRYPTO_secure_used(), 0);
        assert_eq!(CRYPTO_secure_actual_size(p), 0);
        sf(p);

        let z = sz(64);
        assert!(!z.is_null());
        assert_eq!(first_byte(z), 0, "zalloc must be zeroed");
        sf(z);
    }

    #[test]
    fn allocated_classifies_secure_plain_null_and_interior_pointers() {
        let _guard = lock();
        reset();
        init_ok(1 << 20, 16);

        let s = sm(64);
        assert!(!s.is_null());
        assert_eq!(CRYPTO_secure_allocated(s), 1);
        assert_eq!(CRYPTO_secure_allocated(core::ptr::null()), 0);

        // Interior address inside the arena: the authority's coarse test says 1.
        assert_eq!(
            CRYPTO_secure_allocated(one_past(s)),
            1,
            "arena membership is coarse, as in the authority"
        );

        let n = plain_malloc(64);
        assert!(!n.is_null());
        assert_eq!(CRYPTO_secure_allocated(n), 0, "plain pointer is not secure");
        plain_clear_free(n, 64);

        sf(s);
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn actual_size_rounds_up_to_a_power_of_two_multiple_of_minsize() {
        let _guard = lock();
        reset();
        init_ok(1 << 20, 16);

        let cases: [(usize, usize); 9] = [
            (1, 16),
            (15, 16),
            (16, 16),
            (17, 32),
            (32, 32),
            (33, 64),
            (100, 128),
            (1000, 1024),
            (1 << 20, 1 << 20),
        ];
        for (req, want) in cases {
            let p = sm(req);
            assert!(!p.is_null(), "secure_malloc({req}) failed");
            assert_eq!(CRYPTO_secure_actual_size(p), want, "request {req}");
            assert_eq!(CRYPTO_secure_allocated(p), 1);
            assert_eq!(CRYPTO_secure_used(), want);
            sf(p);
            assert_eq!(CRYPTO_secure_used(), 0);
        }
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn zero_length_allocation_returns_a_minimum_chunk() {
        let _guard = lock();
        reset();
        init_ok(1 << 20, 16);

        let p = sm(0);
        assert!(!p.is_null(), "secure_malloc(0) allocates a minsize chunk");
        assert_eq!(CRYPTO_secure_actual_size(p), 16);
        let z = sz(0);
        assert!(!z.is_null());
        assert_eq!(CRYPTO_secure_actual_size(z), 16);
        let a = sma(0, 8);
        assert!(!a.is_null());
        sf(p);
        sf(z);
        sf(a);
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn minimum_chunk_size_is_normalised() {
        let _guard = lock();
        reset();
        // minsize <= 16 is raised to 16.
        init_ok(1 << 20, 0);
        let p = sm(1);
        assert_eq!(CRYPTO_secure_actual_size(p), 16);
        sf(p);
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
        // A power-of-two minsize > 16 is used as given.
        init_ok(1 << 20, 32);
        let q = sm(1);
        assert_eq!(CRYPTO_secure_actual_size(q), 32);
        let r = sm(33);
        assert_eq!(CRYPTO_secure_actual_size(r), 64);
        sf(q);
        sf(r);
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn repeated_alloc_free_cycles_return_used_to_zero() {
        let _guard = lock();
        reset();
        init_ok(1 << 20, 16);

        for _ in 0..512 {
            let p = sm(1000);
            assert!(!p.is_null());
            assert_eq!(CRYPTO_secure_actual_size(p), 1024);
            assert_eq!(CRYPTO_secure_used(), 1024);
            sf(p);
            assert_eq!(CRYPTO_secure_used(), 0);
        }
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn exhaustion_returns_null_raises_and_leaves_used_unchanged() {
        let _guard = lock();
        reset();
        init_ok(4096, 16);

        // A 3000-byte request rounds up to the whole 4096-byte arena.
        let a = sm(3000);
        assert!(!a.is_null());
        assert_eq!(CRYPTO_secure_actual_size(a), 4096);
        assert_eq!(CRYPTO_secure_used(), 4096);

        crate::runtime::err::ERR_clear_error();
        let b = sm(16);
        assert!(b.is_null(), "exhausted allocation must fail");
        assert_eq!(
            CRYPTO_secure_used(),
            4096,
            "failed allocation must not charge used"
        );
        assert_ne!(
            crate::runtime::err::ERR_peek_error(),
            0,
            "exhaustion raises CRYPTO_R_SECURE_MALLOC_FAILURE"
        );

        // A zalloc exhaustion raises too.
        crate::runtime::err::ERR_clear_error();
        let z = sz(16);
        assert!(z.is_null());
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);

        // With neither file nor line the authority suppresses the error.
        crate::runtime::err::ERR_clear_error();
        let c = sm_silent(16);
        assert!(c.is_null());
        assert_eq!(crate::runtime::err::ERR_peek_error(), 0);

        // A request larger than the arena also fails.
        let big = sm(1 << 20);
        assert!(big.is_null());

        sf(a);
        assert_eq!(CRYPTO_secure_used(), 0);
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn clear_free_cleanses_the_whole_usable_allocation_before_release() {
        let _guard = lock();
        reset();
        init_ok(1 << 20, 16);

        let p = unsafe { CRYPTO_secure_malloc(100, file(), 1) } as *mut u8;
        assert!(!p.is_null());
        let size = CRYPTO_secure_actual_size(p.cast());
        assert_eq!(size, 128);
        let off = test_offset_of(p.cast()).unwrap();

        // SAFETY: `p` is a live allocation of `size` bytes.
        unsafe { core::ptr::write_bytes(p, 0xAB, size) };
        assert!(test_arena_bytes(off, size).iter().all(|&b| b == 0xAB));

        // `num` is deliberately 1: the authority still cleanses all 128 bytes.
        unsafe { CRYPTO_secure_clear_free(p.cast(), 1, file(), 1) };

        let bytes = test_arena_bytes(off, size);
        assert_eq!(
            bytes.len(),
            size,
            "the released chunk must still be readable"
        );
        assert!(
            bytes.iter().all(|&b| b == 0),
            "clear_free left plaintext in released secure memory"
        );
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn secure_free_also_cleanses_the_whole_usable_allocation() {
        // Measured authority behaviour: unlike the conventional assumption that
        // only clear_free cleanses, secure_free does too.
        let _guard = lock();
        reset();
        init_ok(1 << 20, 16);

        let p = unsafe { CRYPTO_secure_malloc(100, file(), 1) } as *mut u8;
        let size = CRYPTO_secure_actual_size(p.cast());
        let off = test_offset_of(p.cast()).unwrap();
        // SAFETY: `p` is a live allocation of `size` bytes.
        unsafe { core::ptr::write_bytes(p, 0xCD, size) };
        assert!(test_arena_bytes(off, size).iter().all(|&b| b == 0xCD));

        unsafe { CRYPTO_secure_free(p.cast(), file(), 1) };

        let bytes = test_arena_bytes(off, size);
        assert!(
            bytes.iter().all(|&b| b == 0),
            "secure_free left plaintext in released secure memory"
        );
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn array_helpers_reject_overflow_and_raise_integer_overflow() {
        let _guard = lock();
        reset();
        init_ok(1 << 20, 16);

        crate::runtime::err::ERR_clear_error();
        let p = unsafe { CRYPTO_secure_malloc_array(usize::MAX, 2, file(), 1) };
        assert!(p.is_null());
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);

        crate::runtime::err::ERR_clear_error();
        let q = unsafe { CRYPTO_secure_calloc(usize::MAX, 2, file(), 1) };
        assert!(q.is_null());
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);

        // A valid array allocation behaves like the scalar form.
        let r = unsafe { CRYPTO_secure_malloc_array(4, 8, file(), 1) };
        assert!(!r.is_null());
        assert_eq!(CRYPTO_secure_actual_size(r), 32);
        let c = unsafe { CRYPTO_secure_calloc(4, 8, file(), 1) };
        assert!(!c.is_null());
        assert_eq!(CRYPTO_secure_actual_size(c), 32);
        assert_eq!(CRYPTO_secure_used(), 64);
        unsafe {
            CRYPTO_secure_free(r, file(), 1);
            CRYPTO_secure_free(c, file(), 1);
        }
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn free_routes_non_secure_pointers_to_the_plain_allocator() {
        let _guard = lock();
        reset();
        init_ok(1 << 20, 16);

        let n = crate::runtime::mem::CRYPTO_malloc(32, file(), 1);
        assert!(!n.is_null());
        // SAFETY: `n` is a live 32-byte plain allocation owned by this test.
        unsafe { CRYPTO_secure_free(n, file(), 1) };

        let m = crate::runtime::mem::CRYPTO_malloc(32, file(), 1);
        assert!(!m.is_null());
        // SAFETY: `m` is a live 32-byte plain allocation; cleanse reads 16 bytes.
        unsafe {
            core::ptr::write_bytes(m, 0x77, 32);
            CRYPTO_secure_clear_free(m, 16, file(), 1);
        }
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn invalid_init_arguments_return_zero_instead_of_aborting() {
        let _guard = lock();
        reset();

        assert_eq!(CRYPTO_secure_malloc_init(0, 16), 0, "zero size");
        assert_eq!(
            CRYPTO_secure_malloc_init(1000, 16),
            0,
            "non-power-of-two size"
        );
        assert_eq!(
            CRYPTO_secure_malloc_init(4096, 5000),
            0,
            "non-power-of-two minsize"
        );
        assert_eq!(CRYPTO_secure_malloc_init(4096, 2048), 0, "too few chunks");
        assert_eq!(CRYPTO_secure_malloc_initialized(), 0);

        // A valid init still works after a rejected one.
        init_ok(1 << 20, 16);
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }
}
