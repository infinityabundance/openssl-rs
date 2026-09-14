//! Phase 3 core runtime — the `OPENSSL_sk_*` stack.
//!
//! The stack is OpenSSL's ubiquitous dynamic array. Almost every collection in
//! the public API is a `STACK_OF(T)`, so its semantics — index validity, what
//! `push`/`pop` do at the boundaries, insertion ordering, the failure values and
//! the errors raised — are load-bearing for the whole library.
//!
//! ## Opacity
//!
//! `OPENSSL_STACK` is opaque to callers, so the internal representation is ours
//! to choose and is not part of the ABI. The public obligation is the behaviour,
//! so this module stores elements in a `Vec` rather than reproducing the
//! authority's array-and-capacity layout. What it *does* reproduce is the
//! authority's `num_alloc` bookkeeping, because that value decides whether
//! `sk_reserve` reports `CRYPTO_R_TOO_MANY_RECORDS` and whether a caller-visible
//! `OPENSSL_sk_reserve` succeeds — observable facts, not private layout.
//!
//! ## Signatures, measured
//!
//! From the authority's installed `safestack.h`, and confirmed by the RT-STACK
//! probe:
//!
//! * `OPENSSL_sk_find` and `OPENSSL_sk_find_ex` return an **index**, not a
//!   pointer. `sk_TYPE_find` in `safestack.h` is `int`.
//! * the comparator receives **pointers to the elements**, not the elements:
//!   `typedef int (*sk_TYPE_compfunc)(const T *const *a, const T *const *b)`.
//!   Calling it with the element values instead is a real defect, because a
//!   generated comparator dereferences its arguments.
//! * on an ordered stack, lookup uses `ossl_bsearch`, so `find_ex` answers the
//!   *nearest* element on a miss and `find_all` counts runs of equal elements.
//!
//! ## Errors are part of the surface
//!
//! Several operations raise onto the thread-local `ERR` queue, and a caller can
//! observe the raise through `ERR_get_error_all`, including the authority source
//! coordinates it carries. The coordinates come from the generated
//! [`crate::runtime::err::err_sites`] table, which
//! `forensics/tools/gen_err_raise_sites.py` derives from the pinned source and
//! the admitted build record.
//!
//! ## Safety divergences
//!
//! Two authority behaviours are faults rather than documented failures and are
//! therefore deliberately not reproduced; both are recorded in
//! `docs/SECURITY_DIVERGENCE_POLICY.md` and marked in the probe:
//!
//! * `OPENSSL_sk_set_cmp_func(NULL, …)` dereferences a NULL stack;
//! * `OPENSSL_sk_pop_free(st, NULL)` on a stack holding non-NULL elements with
//!   no thunk installed calls a NULL function pointer.
//!
//! Here they return NULL / skip the callback instead of faulting.

use core::ffi::{c_int, c_void};

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};

/// Opaque handle matching the C `OPENSSL_STACK *`.
#[repr(C)]
pub struct OpenSslStack {
    _private: [u8; 0],
}

type CompFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type CopyFn = unsafe extern "C" fn(*const c_void) -> *mut c_void;
/// `OPENSSL_sk_freefunc_thunk`: a typed destructor adapter installed by a
/// generated `sk_TYPE_pop_free`.
type FreeThunk = unsafe extern "C" fn(Option<FreeFn>, *mut c_void);

/// `min_nodes` — the same floor the authority applies to its first allocation.
const MIN_NODES: c_int = 4;
/// `max_nodes` — on this target `SIZE_MAX / sizeof(void *)` exceeds `INT_MAX`,
/// so the authority caps at `INT_MAX`.
const MAX_NODES: c_int = c_int::MAX;

/// `OSSL_BSEARCH_VALUE_ON_NOMATCH`.
const BSEARCH_VALUE_ON_NOMATCH: c_int = 0x01;
/// `OSSL_BSEARCH_FIRST_VALUE_ON_MATCH`.
const BSEARCH_FIRST_VALUE_ON_MATCH: c_int = 0x02;

struct Inner {
    items: Vec<*const c_void>,
    /// The authority's `num_alloc`. `0` means the element array has not been
    /// allocated yet, which is how the authority distinguishes a postponed
    /// allocation from an allocated-but-empty one.
    num_alloc: c_int,
    comp: Option<CompFn>,
    sorted: bool,
    free_thunk: Option<FreeThunk>,
}

/// # Safety
/// `p` must be a pointer returned by one of this module's constructors, or NULL.
unsafe fn inner<'a>(p: *mut OpenSslStack) -> Option<&'a mut Inner> {
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` was produced by `Box::into_raw` in `from_boxes`, so it points
    // to a live, aligned `Inner`. The returned reference's lifetime is tied to
    // the caller's, which is the C caller's responsibility to keep single-threaded
    // and non-aliasing — the same contract the authority's `OPENSSL_STACK` has.
    Some(unsafe { &mut *(p as *mut Inner) })
}

fn from_boxes(items: Vec<*const c_void>, comp: Option<CompFn>) -> *mut OpenSslStack {
    let num_alloc = items.capacity().min(c_int::MAX as usize) as c_int;
    Box::into_raw(Box::new(Inner {
        items,
        num_alloc,
        comp,
        sorted: false,
        free_thunk: None,
    })) as *mut OpenSslStack
}

/// `compute_growth(target, current)` — the authority's Fibonacci-ratio growth.
///
/// Returns 0 on arithmetic overflow, which the caller turns into
/// `CRYPTO_R_TOO_MANY_RECORDS`. The overflow arm needs a stack with roughly
/// 1.3 billion elements to reach, so the probe records the site as
/// resource-bound rather than claiming it; the arithmetic itself is reproduced
/// faithfully so the condition is not simply omitted.
fn compute_growth(target: c_int, current: c_int) -> c_int {
    // Compared in `i64` because `max_nodes` is `INT_MAX` on this target; the
    // comparison is written against the authority's expression rather than
    // simplified away, so the overflow arm stays visible.
    let cap = MAX_NODES as i64;
    let mut current = current;
    while current < target {
        if (current as i64) >= cap {
            return 0;
        }
        let widened = (current as i64) * 8;
        if widened > c_int::MAX as i64 {
            return 0;
        }
        current = (widened / 5) as c_int;
        if (current as i64) >= cap {
            current = MAX_NODES;
        }
    }
    current
}

/// `sk_reserve(st, n, exact)`.
///
/// Returns false on failure, having raised the same error the authority raises.
///
/// # Safety
/// `st` must be a live stack from this module's constructors.
unsafe fn sk_reserve(st: &mut Inner, n: c_int, exact: bool) -> bool {
    if n > MAX_NODES - (st.items.len() as c_int) {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::STACK_186) };
        return false;
    }

    let mut num_alloc = (st.items.len() as c_int) + n;
    if num_alloc < MIN_NODES {
        num_alloc = MIN_NODES;
    }

    if st.num_alloc == 0 {
        if st.items.try_reserve(num_alloc as usize).is_err() {
            return false;
        }
        st.num_alloc = num_alloc;
        return true;
    }

    if !exact {
        if num_alloc <= st.num_alloc {
            return true;
        }
        num_alloc = compute_growth(num_alloc, st.num_alloc);
        if num_alloc == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::STACK_212) };
            return false;
        }
    } else if num_alloc == st.num_alloc {
        return true;
    }

    let extra = num_alloc as usize - st.items.len();
    if st.items.try_reserve(extra).is_err() {
        return false;
    }
    st.num_alloc = num_alloc;
    true
}

/// `internal_delete`.
///
/// # Safety
/// `st` must be live and `loc` a valid index.
unsafe fn internal_delete(st: &mut Inner, loc: usize) -> *const c_void {
    st.items.remove(loc)
}

/// `ossl_bsearch` reduced to the stack's element type.
///
/// Returns the index of the probed position, or -1 when the flags ask for NULL
/// on a miss. `key` is the address of the caller's key pointer and `slots` the
/// element array, because the authority's comparator compares *pointers to
/// elements*.
///
/// # Safety
/// `comp` must be usable on `key` and every slot; `slots` must have `num`
/// readable elements.
unsafe fn bsearch(
    key: *const c_void,
    slots: *const *const c_void,
    num: c_int,
    comp: CompFn,
    flags: c_int,
) -> c_int {
    if num == 0 {
        return -1;
    }
    let mut l: c_int = 0;
    let mut h: c_int = num;
    let mut i: c_int = 0;
    let mut c: c_int = 0;
    while l < h {
        i = l + (h - l) / 2;
        // SAFETY: `i < num` by the loop bounds, so the slot is in range; `key`
        // is the caller's key pointer and `comp` is the caller's comparator.
        c = unsafe { comp(key, slots.add(i as usize).cast::<c_void>()) };
        if c < 0 {
            h = i;
        } else if c > 0 {
            l = i + 1;
        } else {
            break;
        }
    }
    if c != 0 && (flags & BSEARCH_VALUE_ON_NOMATCH) == 0 {
        return -1;
    }
    if c == 0 && (flags & BSEARCH_FIRST_VALUE_ON_MATCH) != 0 {
        while i > 0 {
            // SAFETY: `i - 1` is in range.
            let prev = unsafe { comp(key, slots.add((i - 1) as usize).cast::<c_void>()) };
            if prev != 0 {
                break;
            }
            i -= 1;
        }
    }
    i
}

/// `internal_find`, reproduced including which out-parameters it does and does
/// not touch on each early return.
///
/// # Safety
/// `st` must be live or NULL; `data` must be acceptable to the comparator when
/// one is installed; `pnum` must be NULL or writable.
unsafe fn internal_find(
    st: *mut OpenSslStack,
    data: *const c_void,
    ret_val_options: c_int,
    pnum_matched: *mut c_int,
) -> c_int {
    // SAFETY: `st` is live or NULL per the caller's contract.
    let Some(s) = (unsafe { inner(st) }) else {
        return -1;
    };
    if s.items.is_empty() {
        return -1;
    }
    let mut count: c_int = 0;
    let pnum: *mut c_int = if pnum_matched.is_null() {
        &mut count
    } else {
        pnum_matched
    };

    let slots = s.items.as_ptr();

    let Some(comp) = s.comp else {
        // No comparator: identity of the element pointers decides.
        for (i, &slot) in s.items.iter().enumerate() {
            if slot == data {
                // SAFETY: `pnum` is NULL-checked above and points at a live int.
                unsafe { *pnum = 1 };
                return i as c_int;
            }
        }
        // SAFETY: as above.
        unsafe { *pnum = 0 };
        return -1;
    };

    if data.is_null() {
        // The authority returns here without touching `*pnum`.
        return -1;
    }

    // Address of the caller's key pointer: the comparator's first argument.
    let key: *const c_void = (&raw const data).cast::<c_void>();

    if !s.sorted {
        let mut res: c_int = -1;
        for i in 0..s.items.len() {
            // SAFETY: `i` is a valid index; `key`/slots are as described above.
            let r = unsafe { comp(key, slots.add(i).cast::<c_void>()) };
            if r == 0 {
                if res == -1 {
                    res = i as c_int;
                }
                // SAFETY: `pnum` points at a live int.
                unsafe { *pnum += 1 };
                if pnum_matched.is_null() {
                    return i as c_int;
                }
            }
        }
        if res == -1 {
            // SAFETY: `pnum` points at a live int.
            unsafe { *pnum = 0 };
        }
        return res;
    }

    let mut opts = ret_val_options;
    if !pnum_matched.is_null() {
        opts |= BSEARCH_FIRST_VALUE_ON_MATCH;
    }
    // SAFETY: `slots` holds `len` elements; `key` and `comp` are the caller's.
    let hit = unsafe { bsearch(key, slots, s.items.len() as c_int, comp, opts) };
    if !pnum_matched.is_null() {
        // SAFETY: `pnum` points at a live int.
        unsafe { *pnum = 0 };
        if hit >= 0 {
            let mut p = hit;
            while (p as usize) < s.items.len() {
                // SAFETY: `p` is in range.
                let r = unsafe { comp(key, slots.add(p as usize).cast::<c_void>()) };
                if r != 0 {
                    break;
                }
                // SAFETY: `pnum` points at a live int.
                unsafe { *pnum += 1 };
                p += 1;
            }
        }
    }
    hit
}

/// `OPENSSL_STACK *OPENSSL_sk_new(OPENSSL_sk_compfunc cmp)`
#[no_mangle]
pub extern "C" fn OPENSSL_sk_new(cmp: Option<CompFn>) -> *mut OpenSslStack {
    guard_ffi(core::ptr::null_mut(), || from_boxes(Vec::new(), cmp))
}

/// `OPENSSL_STACK *OPENSSL_sk_new_null(void)`
#[no_mangle]
pub extern "C" fn OPENSSL_sk_new_null() -> *mut OpenSslStack {
    guard_ffi(core::ptr::null_mut(), || from_boxes(Vec::new(), None))
}

/// `OPENSSL_STACK *OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc c, int n)`
#[no_mangle]
pub extern "C" fn OPENSSL_sk_new_reserve(cmp: Option<CompFn>, n: c_int) -> *mut OpenSslStack {
    guard_ffi(core::ptr::null_mut(), || {
        let p = from_boxes(Vec::new(), cmp);
        if n <= 0 {
            return p;
        }
        // SAFETY: `p` came from `from_boxes` a moment ago and is not aliased.
        let ok = unsafe { inner(p) }.is_some_and(|s| unsafe { sk_reserve(s, n, true) });
        if !ok {
            // SAFETY: `p` is still exclusively owned here.
            unsafe { OPENSSL_sk_free(p) };
            return core::ptr::null_mut();
        }
        p
    })
}

/// `OPENSSL_STACK *OPENSSL_sk_set_thunks(OPENSSL_STACK *st, OPENSSL_sk_freefunc_thunk f_thunk)`
///
/// Installs the typed destructor adapter used by generated `sk_TYPE_pop_free`.
/// A NULL stack is a no-op that returns NULL, exactly as the authority does.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_set_thunks(
    st: *mut OpenSslStack,
    f_thunk: Option<FreeThunk>,
) -> *mut OpenSslStack {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is NULL or live per the caller's contract.
        if let Some(s) = unsafe { inner(st) } {
            s.free_thunk = f_thunk;
        }
        st
    })
}

/// `int OPENSSL_sk_reserve(OPENSSL_STACK *st, int n)`
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_reserve(st: *mut OpenSslStack, n: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `st` is NULL or live per the caller's contract.
        let Some(s) = (unsafe { inner(st) }) else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::STACK_251) };
            return 0;
        };
        if n < 0 {
            return 1;
        }
        // SAFETY: `s` is live.
        c_int::from(unsafe { sk_reserve(s, n, true) })
    })
}

/// `void OPENSSL_sk_free(OPENSSL_STACK *st)`
///
/// Frees the stack but not the elements; freeing elements is `pop_free`, which
/// takes the caller's destructor. Conflating the two is a classic leak or
/// double-free.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors, and must
/// not be used again after this call.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_free(st: *mut OpenSslStack) {
    guard_ffi((), || {
        if st.is_null() {
            return;
        }
        // SAFETY: `st` came from this module's constructors and is not used
        // again by the caller.
        unsafe {
            drop(Box::from_raw(st as *mut Inner));
        }
    })
}

/// `void OPENSSL_sk_pop_free(OPENSSL_STACK *st, OPENSSL_sk_freefunc func)`
///
/// # Safety
/// `st` must be NULL or a live stack, and `func` (or the installed thunk) must
/// be a destructor valid for every element on it.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_pop_free(st: *mut OpenSslStack, func: Option<FreeFn>) {
    guard_ffi((), || {
        // SAFETY: `st` is live; `func`, when present, is the caller's destructor
        // for the element type it pushed.
        unsafe {
            let Some(s) = inner(st) else { return };
            let thunk = s.free_thunk;
            for &item in s.items.iter() {
                if item.is_null() {
                    continue;
                }
                let elem = item as *mut c_void;
                match (thunk, func) {
                    // The generated adapter runs the typed destructor.
                    (Some(t), f) => t(f, elem),
                    (None, Some(f)) => f(elem),
                    // The authority calls a NULL function pointer here. That is
                    // a fault, not a failure: the element is left untouched and
                    // the divergence is recorded.
                    (None, None) => {}
                }
            }
            drop(Box::from_raw(st as *mut Inner));
        }
    })
}

/// `int OPENSSL_sk_num(const OPENSSL_STACK *st)` — -1 for a NULL stack.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_num(st: *const OpenSslStack) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `st` is either NULL or live.
        unsafe {
            match inner(st as *mut OpenSslStack) {
                Some(s) => s.items.len() as c_int,
                None => -1,
            }
        }
    })
}

/// `void *OPENSSL_sk_value(const OPENSSL_STACK *st, int i)` — NULL when out of range.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_value(st: *const OpenSslStack, i: c_int) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is either NULL or live.
        unsafe {
            let Some(s) = inner(st as *mut OpenSslStack) else {
                return core::ptr::null();
            };
            if i < 0 || (i as usize) >= s.items.len() {
                return core::ptr::null();
            }
            s.items[i as usize]
        }
    })
}

/// `void *OPENSSL_sk_set(OPENSSL_STACK *st, int i, const void *data)`
///
/// Replacing an element invalidates the sort order, and both failure modes raise
/// on the `ERR` queue: a NULL stack raises `ERR_R_PASSED_NULL_PARAMETER`, an
/// out-of-range index raises `ERR_R_PASSED_INVALID_ARGUMENT` **with the index as
/// data** (`i=%d`).
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_set(
    st: *mut OpenSslStack,
    i: c_int,
    data: *const c_void,
) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is live or NULL per the caller's contract.
        unsafe {
            let Some(s) = inner(st) else {
                // SAFETY: the site is a compile-time constant.
                raise_site(&err_sites::STACK_482);
                return core::ptr::null();
            };
            if i < 0 || (i as usize) >= s.items.len() {
                let msg = format!("i={i}\0");
                // SAFETY: `msg` is NUL-terminated and outlives the call; the
                // site is a compile-time constant.
                raise_site_data(&err_sites::STACK_486, msg.as_ptr().cast());
                return core::ptr::null();
            }
            s.items[i as usize] = data;
            s.sorted = false;
            data
        }
    })
}

/// `int OPENSSL_sk_push(OPENSSL_STACK *st, const void *data)` — the new count, or 0 on failure.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_push(st: *mut OpenSslStack, data: *const c_void) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `st` is live or NULL.
        let Some(s) = (unsafe { inner(st) }) else {
            return 0;
        };
        let loc = s.items.len() as c_int;
        // SAFETY: `s` is live.
        unsafe { OPENSSL_sk_insert(st, data, loc) }
    })
}

/// `int OPENSSL_sk_insert(OPENSSL_STACK *sk, const void *data, int where)`
///
/// A `where` at or beyond the end appends, and **a negative `where` appends
/// too** — the authority treats any out-of-range position as "at the end",
/// which is measured by the RT-STACK probe and is not the same as rejecting it.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_insert(
    st: *mut OpenSslStack,
    data: *const c_void,
    where_: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            let Some(s) = inner(st) else {
                raise_site(&err_sites::STACK_271);
                return 0;
            };
            if s.items.len() as c_int == MAX_NODES {
                raise_site(&err_sites::STACK_275);
                return 0;
            }
            if !sk_reserve(s, 1, false) {
                return 0;
            }
            let idx = if where_ < 0 || (where_ as usize) >= s.items.len() {
                s.items.len()
            } else {
                where_ as usize
            };
            s.items.insert(idx, data);
            s.sorted = false;
            s.items.len() as c_int
        }
    })
}

/// `void *OPENSSL_sk_pop(OPENSSL_STACK *st)`
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_pop(st: *mut OpenSslStack) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            if s.items.is_empty() {
                return core::ptr::null();
            }
            internal_delete(s, s.items.len() - 1)
        }
    })
}

/// `void *OPENSSL_sk_shift(OPENSSL_STACK *st)`
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_shift(st: *mut OpenSslStack) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            if s.items.is_empty() {
                return core::ptr::null();
            }
            internal_delete(s, 0)
        }
    })
}

/// `int OPENSSL_sk_unshift(OPENSSL_STACK *st, const void *data)`
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_unshift(st: *mut OpenSslStack, data: *const c_void) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded unchanged; `insert` handles NULL by raising.
        unsafe { OPENSSL_sk_insert(st, data, 0) }
    })
}

/// `void *OPENSSL_sk_delete(OPENSSL_STACK *st, int loc)`
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_delete(st: *mut OpenSslStack, loc: c_int) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            if loc < 0 || (loc as usize) >= s.items.len() {
                return core::ptr::null();
            }
            internal_delete(s, loc as usize)
        }
    })
}

/// `void *OPENSSL_sk_delete_ptr(OPENSSL_STACK *st, const void *p)`
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_delete_ptr(
    st: *mut OpenSslStack,
    p: *const c_void,
) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            match s.items.iter().position(|&x| x == p) {
                Some(i) => internal_delete(s, i),
                None => core::ptr::null(),
            }
        }
    })
}

/// `void OPENSSL_sk_zero(OPENSSL_STACK *st)` — clears without freeing elements.
///
/// The authority zeroes the array and resets the count but leaves the `sorted`
/// flag alone, so a sorted stack stays "sorted" after being emptied. That is
/// observable through `OPENSSL_sk_is_sorted` and is reproduced rather than
/// tidied up.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_zero(st: *mut OpenSslStack) {
    guard_ffi((), || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            if let Some(s) = inner(st) {
                if s.items.is_empty() {
                    return;
                }
                s.items.clear();
            }
        }
    })
}

/// `void OPENSSL_sk_sort(OPENSSL_STACK *st)`
///
/// Sorting is a no-op without a comparator, and a comparator-less stack is
/// therefore not marked sorted.
///
/// # Safety
/// `st` must be NULL or a live stack, and its comparator (if any) must be a
/// total order valid for the elements pushed onto it.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_sort(st: *mut OpenSslStack) {
    guard_ffi((), || {
        // SAFETY: `st` is live; `comp` is the caller's ordering over pointers to
        // the caller's own element type, so invoking it is sound.
        unsafe {
            let Some(s) = inner(st) else { return };
            if s.sorted {
                return;
            }
            let Some(comp) = s.comp else { return };
            // The authority sorts the array of element pointers with `qsort`;
            // the comparator is therefore invoked on pointers-to-slots.
            s.items.sort_by(|a, b| {
                let r = comp(
                    (a as *const *const c_void).cast::<c_void>(),
                    (b as *const *const c_void).cast::<c_void>(),
                );
                r.cmp(&0)
            });
            s.sorted = true;
        }
    })
}

/// `int OPENSSL_sk_is_sorted(const OPENSSL_STACK *st)`
///
/// The authority answers 1 only for a stack that is *known* sorted, which is why
/// this reports the flag rather than checking the order: a comparator may itself
/// be inconsistent, so checking would answer a different question.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_is_sorted(st: *const OpenSslStack) -> c_int {
    guard_ffi(1, || {
        // SAFETY: `st` is either NULL or live.
        unsafe {
            match inner(st as *mut OpenSslStack) {
                Some(s) => c_int::from(s.sorted),
                None => 1,
            }
        }
    })
}

/// `OPENSSL_sk_compfunc OPENSSL_sk_set_cmp_func(OPENSSL_STACK *sk, OPENSSL_sk_compfunc c)`
///
/// Returns the *previous* comparator, and setting a different one invalidates
/// any previous sort.
///
/// # Safety
/// `st` must be a live stack from this module's constructors. The authority
/// dereferences NULL; this returns NULL instead, a recorded safety divergence.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_set_cmp_func(
    st: *mut OpenSslStack,
    cmp: Option<CompFn>,
) -> Option<CompFn> {
    guard_ffi(None, || {
        // SAFETY: `st` is live per the caller's contract.
        unsafe {
            let s = inner(st)?;
            let old = s.comp;
            // The authority compares the function pointers directly, so a
            // re-set with the same comparator preserves the sorted flag.
            let same = core::ptr::eq(
                s.comp.map(|f| f as *const ()).unwrap_or(core::ptr::null()),
                cmp.map(|f| f as *const ()).unwrap_or(core::ptr::null()),
            );
            if !same {
                s.sorted = false;
            }
            s.comp = cmp;
            old
        }
    })
}

/// `int OPENSSL_sk_find(OPENSSL_STACK *st, const void *data)`
///
/// Returns an index, or -1. With a comparator the search is by ordering, and on
/// a sorted stack it is a binary search, so the answer is the *first* equal
/// element rather than any equal element.
///
/// # Safety
/// `st` must be NULL or a live stack, and `data` must be a value its comparator
/// (or pointer identity) can validly examine.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_find(st: *mut OpenSslStack, data: *const c_void) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `st` is live or NULL; the comparator and key come from the
        // caller, whose contract is to make them mutually valid.
        unsafe {
            internal_find(
                st,
                data,
                BSEARCH_FIRST_VALUE_ON_MATCH,
                core::ptr::null_mut(),
            )
        }
    })
}

/// `int OPENSSL_sk_find_ex(OPENSSL_STACK *st, const void *data)`
///
/// Same search as `find`, except that on a sorted stack a miss reports the
/// nearest element instead of -1 (`OSSL_BSEARCH_VALUE_ON_NOMATCH`). On an
/// unordered stack it is an identity search like `find`.
///
/// # Safety
/// `st` must be NULL or a live stack, and `data` must be a value its comparator
/// (or pointer identity) can validly examine.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_find_ex(st: *mut OpenSslStack, data: *const c_void) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: as in `find`.
        unsafe { internal_find(st, data, BSEARCH_VALUE_ON_NOMATCH, core::ptr::null_mut()) }
    })
}

/// `int OPENSSL_sk_find_all(OPENSSL_STACK *st, const void *data, int *pnum)`
///
/// `*pnum` receives the **number of equal elements**, not an index. Note the
/// cases where the authority returns without touching `*pnum` at all: an empty
/// or NULL stack, and (with a comparator installed) a NULL `data`.
///
/// # Safety
/// `st` must be NULL or a live stack; `pnum` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_find_all(
    st: *mut OpenSslStack,
    data: *const c_void,
    pnum: *mut c_int,
) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: as in `find`; `pnum` is NULL or writable per the contract.
        unsafe { internal_find(st, data, BSEARCH_FIRST_VALUE_ON_MATCH, pnum) }
    })
}

/// `OPENSSL_STACK *OPENSSL_sk_dup(const OPENSSL_STACK *st)`
///
/// Shallow: the elements are shared, not copied. A NULL source is **not** an
/// error — the authority returns a fresh empty stack, and so does this. The
/// sorted flag, comparator, thunk and requested capacity are all carried over,
/// because the authority copies the whole structure before reallocating the
/// element array.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_dup(st: *const OpenSslStack) -> *mut OpenSslStack {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is either NULL or live.
        unsafe {
            let Some(s) = inner(st as *mut OpenSslStack) else {
                return from_boxes(Vec::new(), None);
            };
            let empty = s.items.is_empty();
            let items = if empty { Vec::new() } else { s.items.clone() };
            let comp = s.comp;
            let sorted = s.sorted;
            let thunk = s.free_thunk;
            let num_alloc = s.num_alloc;
            let p = from_boxes(items, comp);
            if let Some(d) = inner(p) {
                d.sorted = sorted;
                d.free_thunk = thunk;
                // A source with no elements has had its array postponed, so the
                // copy reports capacity zero rather than the source's.
                d.num_alloc = if empty { 0 } else { num_alloc };
            }
            p
        }
    })
}

/// `OPENSSL_STACK *OPENSSL_sk_deep_copy(const OPENSSL_STACK *, OPENSSL_sk_copyfunc c, OPENSSL_sk_freefunc f)`
///
/// The copy function is applied per element; on failure the partial copy is
/// unwound with the caller's destructor, which is why `f` is required. A NULL
/// source returns a fresh empty stack, never NULL.
///
/// # Safety
/// `st` must be NULL or a live stack; `copy`/`free_fn` must be valid for every
/// element on it.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_deep_copy(
    st: *const OpenSslStack,
    copy: Option<CopyFn>,
    free_fn: Option<FreeFn>,
) -> *mut OpenSslStack {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is either NULL or live; `copy`/`free_fn` are the caller's
        // element-type handlers.
        unsafe {
            let Some(s) = inner(st as *mut OpenSslStack) else {
                return from_boxes(Vec::new(), None);
            };
            if s.items.is_empty() {
                let comp = s.comp;
                let sorted = s.sorted;
                let thunk = s.free_thunk;
                let p = from_boxes(Vec::new(), comp);
                if let Some(d) = inner(p) {
                    d.sorted = sorted;
                    d.free_thunk = thunk;
                }
                return p;
            }
            // `copy == NULL` with elements present is a fault in the authority
            // (it calls through a NULL pointer); returning NULL is the recorded
            // safer behaviour.
            let Some(copy) = copy else {
                return core::ptr::null_mut();
            };
            let mut out: Vec<*const c_void> = Vec::with_capacity(s.items.len());
            let mut made: Vec<*const c_void> = Vec::new();
            for &item in s.items.iter() {
                if item.is_null() {
                    // The authority leaves the destination slot as the calloc'd
                    // NULL, so the element *positions* are preserved.
                    out.push(core::ptr::null());
                    continue;
                }
                let c = copy(item);
                if c.is_null() {
                    if let Some(f) = free_fn {
                        for &m in made.iter() {
                            f(m as *mut c_void);
                        }
                    }
                    return core::ptr::null_mut();
                }
                out.push(c);
                made.push(c);
            }
            let comp = s.comp;
            let sorted = s.sorted;
            let thunk = s.free_thunk;
            let p = from_boxes(out, comp);
            if let Some(d) = inner(p) {
                d.sorted = sorted;
                d.free_thunk = thunk;
                d.num_alloc = core::cmp::max(s.items.len() as c_int, MIN_NODES);
            }
            p
        }
    })
}
