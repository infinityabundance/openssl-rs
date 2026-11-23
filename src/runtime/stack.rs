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
//!
//! ## Ownership classification (this batch)
//!
//! `OPENSSL_STACK` is a **deliberately Rust-owned representation**: the opaque
//! [`OpenSslStack`] handle points at an `Inner` allocated by `Box::into_raw` in
//! `from_boxes`, whose element array is a Rust `Vec`, and the exported
//! `OPENSSL_sk_*` lifecycle (`OPENSSL_sk_free` / `OPENSSL_sk_pop_free`) owns and
//! releases it with `Box::from_raw`. No allocation or release in this module
//! crosses the `CRYPTO_*` seam. The consequence is explicit: an installed
//! `CRYPTO_set_mem_functions` hook does not observe the header or the `Vec`
//! element storage, and the Rust representation's byte size is not the
//! authority's C `OPENSSL_STACK` size — allocating it at `size_of::<Inner>()`
//! would make the hook observe the wrong byte count, violating §6's exact-size
//! rule. This is the recorded compatibility residual **P1**, retained and **not**
//! a `SAFETY_DISCHARGED` claim.

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

/// The authority's cast at the `void *` boundary.
///
/// `OPENSSL_STACK` stores `const void **data`, and every accessor that hands a
/// slot back declares `void *` and casts: `return (void *)st->data[i];`. Dropping
/// that cast would declare `const void *` where the authority declares `void *`,
/// which a caller can observe and which the prototype court reports. The internal
/// representation stays `const void *`; only the exported boundary casts.
fn expose(p: *const c_void) -> *mut c_void {
    p as *mut c_void
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
            // Test-only negative control: a release requested for the stack whose
            // own `pop_free` loop is still running is withheld and recorded.
            // Unarmed (every ordinary build and test) this is `true`.
            #[cfg(test)]
            if !test_hooks::permit_release(st) {
                return;
            }
            drop(Box::from_raw(st as *mut Inner));
        }
    })
}

/// `void OPENSSL_sk_pop_free(OPENSSL_STACK *st, OPENSSL_sk_freefunc func)`
///
/// ## Failure atomicity (HAZ-16) and destruction order
///
/// The authority walks the element array from index 0 upward and releases the
/// enclosing stack only after the loop. That has two defects: a destructor sees
/// the whole stack, including the element being destroyed, and an interruption
/// leaves already-released elements reachable through `sk_value`, where a retry
/// releases them a second time.
///
/// This implementation **detaches the whole element array** with `mem::take`
/// before the first destructor. The detach is constant time, the stack is empty
/// from the first destructor onward, and the destructors run in the authority's
/// order: element 0 first, element n−1 last. No destructor can observe a
/// released element through `sk_num`/`sk_value`, and a retry after an
/// interruption finds an empty stack and frees it without invoking any
/// destructor a second time. The total work is O(n): one constant-time detach
/// and one visit per element.
///
/// The `&mut Inner` borrow ends before the first callback, so a destructor that
/// re-enters the stack interface (for example `OPENSSL_sk_num`) does not alias
/// the borrow held by this function.
///
/// **Interruption (panic path).** The detached array is a local `Vec`. If a
/// destructor panics, `guard_ffi` catches the unwind and the array is dropped:
/// its elements are raw pointers, which have no destructor, so the elements
/// whose destructors had not yet run are **leaked**. They are never destroyed a
/// second time. The stack remains alive and empty, and a caller that retries
/// `pop_free` frees the stack and destroys nothing. Leaking the remainder is the
/// recorded behaviour; double destruction is excluded.
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
            // Detach in constant time and end the borrow before any callback.
            // Resetting `num_alloc` records that the element array is no longer
            // allocated, which is the state `sk_reserve` distinguishes.
            let (items, thunk) = {
                let Some(s) = inner(st) else { return };
                let thunk = s.free_thunk;
                let items = core::mem::take(&mut s.items);
                s.num_alloc = 0;
                (items, thunk)
            };
            // Forward iteration over the detached array: the authority's order,
            // with every element already unreachable from the stack.
            {
                // Test-only: records the stack whose destructor loop is running so
                // the release canary can recognise a re-entrant release of it.
                #[cfg(test)]
                let _scope = test_hooks::PopFreeScope::enter(st);
                for item in items {
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
                    #[cfg(test)]
                    test_hooks::maybe_panic_mid_pop_free();
                }
            }
            // Test-only negative control, inactive unless the canary is armed.
            #[cfg(test)]
            if !test_hooks::permit_release(st) {
                return;
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
pub unsafe extern "C" fn OPENSSL_sk_value(st: *const OpenSslStack, i: c_int) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is either NULL or live.
        unsafe {
            let Some(s) = inner(st as *mut OpenSslStack) else {
                return core::ptr::null_mut();
            };
            if i < 0 || (i as usize) >= s.items.len() {
                return core::ptr::null_mut();
            }
            expose(s.items[i as usize])
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
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is live or NULL per the caller's contract.
        unsafe {
            let Some(s) = inner(st) else {
                // SAFETY: the site is a compile-time constant.
                raise_site(&err_sites::STACK_482);
                return core::ptr::null_mut();
            };
            if i < 0 || (i as usize) >= s.items.len() {
                let msg = format!("i={i}\0");
                // SAFETY: `msg` is NUL-terminated and outlives the call; the
                // site is a compile-time constant.
                raise_site_data(&err_sites::STACK_486, msg.as_ptr().cast());
                return core::ptr::null_mut();
            }
            s.items[i as usize] = data;
            s.sorted = false;
            expose(data)
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

/// Test-only insertion fault injection for the CMS ownership controls.
///
/// `#[cfg(test)]`-only and thread-local, so a test that forces the next insert to fail cannot
/// disturb a concurrently running test and the module does not exist in a release build
/// (AGENTS §13: test-only bypasses never ship). The fault models the only fallible step of an
/// insert after the capacity check: `sk_reserve` answering false, as a real allocation failure
/// does, without raising (see `sk_reserve`'s `try_reserve` arms).
#[cfg(test)]
pub(crate) mod test_hooks {
    use core::cell::Cell;

    std::thread_local! {
        static INSERT_FAILURES: Cell<usize> = const { Cell::new(0) };
        /// Destructors left to run before the injected panic; `None` disables it.
        static POP_FREE_PANIC: Cell<Option<usize>> = const { Cell::new(None) };
        /// Set while the release canary is armed on this thread.
        static CANARY_ARMED: Cell<bool> = const { Cell::new(false) };
        /// The stack whose `pop_free` loop is running on this thread, if any.
        static POP_FREE_ACTIVE: Cell<Option<usize>> = const { Cell::new(None) };
        /// Set when the canary withheld a release that would have been the second.
        static REENTRANT_RELEASE: Cell<bool> = const { Cell::new(false) };
    }

    /// Make the next `OPENSSL_sk_insert` on this thread answer 0 without inserting.
    pub(crate) fn fail_next_insert() {
        INSERT_FAILURES.with(|n| n.set(1));
    }

    /// Disarms the injected panic when the test leaves scope, including on a panic.
    pub(crate) struct PopFreeArmed;

    impl Drop for PopFreeArmed {
        fn drop(&mut self) {
            POP_FREE_PANIC.with(|f| f.set(None));
        }
    }

    /// Panic immediately after the destructor with zero-based index `index` has run
    /// in `OPENSSL_sk_pop_free` on this thread. Every destructor before it runs
    /// normally, so the first, a middle and the last position are all reachable.
    pub(crate) fn arm_pop_free_panic_after(index: usize) -> PopFreeArmed {
        POP_FREE_PANIC.with(|f| f.set(Some(index)));
        PopFreeArmed
    }

    /// The historical name for a panic after the first destructor.
    pub(crate) fn arm_mid_pop_free() -> PopFreeArmed {
        arm_pop_free_panic_after(0)
    }

    #[allow(clippy::panic)] // the injected defect is the point of the hook
    pub(crate) fn maybe_panic_mid_pop_free() {
        POP_FREE_PANIC.with(|f| match f.get() {
            None => {}
            Some(0) => {
                f.set(None);
                panic!("injected defect: panic after an element was released");
            }
            Some(remaining) => f.set(Some(remaining - 1)),
        });
    }

    /// Disarms the release canary when the test leaves scope, including on a
    /// panic, so an interrupted control cannot defer a later test's release.
    pub(crate) struct CanaryArmed;

    impl Drop for CanaryArmed {
        fn drop(&mut self) {
            CANARY_ARMED.with(|f| f.set(false));
            POP_FREE_ACTIVE.with(|f| f.set(None));
            REENTRANT_RELEASE.with(|f| f.set(false));
        }
    }

    /// Arm the release canary for this thread.
    ///
    /// This is the negative control for the class-3 input "a destructor releases the
    /// stack it is running on". The canary records that a release was requested for
    /// the stack whose own `pop_free` loop is still on the frame, and withholds it so
    /// the control can observe the request without performing the second release. It
    /// changes no behaviour unless armed, and it is absent from release builds.
    pub(crate) fn arm_release_canary() -> CanaryArmed {
        CANARY_ARMED.with(|f| f.set(true));
        POP_FREE_ACTIVE.with(|f| f.set(None));
        REENTRANT_RELEASE.with(|f| f.set(false));
        CanaryArmed
    }

    /// Whether the canary withheld a release during the armed scope.
    pub(crate) fn reentrant_release_seen() -> bool {
        REENTRANT_RELEASE.with(Cell::get)
    }

    /// Records the stack whose destructor loop is running, restoring the previous
    /// value on drop so a nested `pop_free` (a sibling stack, or the same stack) is
    /// accounted for by the frame that entered it.
    pub(crate) struct PopFreeScope {
        previous: Option<usize>,
        armed: bool,
    }

    impl PopFreeScope {
        pub(crate) fn enter(st: *mut super::OpenSslStack) -> Self {
            let armed = CANARY_ARMED.with(Cell::get);
            let previous = POP_FREE_ACTIVE.with(Cell::get);
            if armed {
                POP_FREE_ACTIVE.with(|f| f.set(Some(st as usize)));
            }
            Self { previous, armed }
        }
    }

    impl Drop for PopFreeScope {
        fn drop(&mut self) {
            if self.armed {
                POP_FREE_ACTIVE.with(|f| f.set(self.previous));
            }
        }
    }

    /// Whether the caller may perform the enclosing release now.
    ///
    /// `false` means a release for `st` was requested while that same stack's own
    /// `pop_free` loop was still running: the request is recorded and withheld, so
    /// the enclosing call performs the single release. Unarmed, this always
    /// answers `true` and the release path is unchanged.
    pub(crate) fn permit_release(st: *mut super::OpenSslStack) -> bool {
        if !CANARY_ARMED.with(Cell::get) {
            return true;
        }
        if POP_FREE_ACTIVE.with(Cell::get) == Some(st as usize) {
            REENTRANT_RELEASE.with(|f| f.set(true));
            return false;
        }
        true
    }

    /// Consume one pending fault, if any.
    pub(crate) fn take_insert_failure() -> bool {
        INSERT_FAILURES.with(|n| {
            let pending = n.get();
            if pending == 0 {
                false
            } else {
                n.set(pending - 1);
                true
            }
        })
    }
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
            #[cfg(test)]
            if test_hooks::take_insert_failure() {
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
pub unsafe extern "C" fn OPENSSL_sk_pop(st: *mut OpenSslStack) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null_mut();
            };
            if s.items.is_empty() {
                return core::ptr::null_mut();
            }
            expose(internal_delete(s, s.items.len() - 1))
        }
    })
}

/// `void *OPENSSL_sk_shift(OPENSSL_STACK *st)`
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_shift(st: *mut OpenSslStack) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null_mut();
            };
            if s.items.is_empty() {
                return core::ptr::null_mut();
            }
            expose(internal_delete(s, 0))
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
pub unsafe extern "C" fn OPENSSL_sk_delete(st: *mut OpenSslStack, loc: c_int) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null_mut();
            };
            if loc < 0 || (loc as usize) >= s.items.len() {
                return core::ptr::null_mut();
            }
            expose(internal_delete(s, loc as usize))
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
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is live or NULL.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null_mut();
            };
            match s.items.iter().position(|&x| x == p) {
                Some(i) => expose(internal_delete(s, i)),
                None => core::ptr::null_mut(),
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

#[cfg(test)]
mod tests {
    //! The `OPENSSL_sk_new_reserve` capacity invariant the CMS `get1_*` helpers rely on, and the
    //! negative control for the test-only insert fault hook.
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// After a successful `OPENSSL_sk_new_reserve(None, n)`, the next `n` appends must not grow
    /// the array and must not fail. `num_alloc` and the `Vec` capacity are the observable record:
    /// `num_alloc` changes only in `sk_reserve`, and the capacity only on a `Vec` reallocation.
    #[test]
    fn a_reserved_stack_absorbs_its_reservation_without_growth() {
        let marker = 0u8;
        let p = (&raw const marker).cast::<c_void>();
        for n in [1usize, 2, 4, 5, 9, 33] {
            // SAFETY: `st` is this module's allocation, exclusively owned here; every element is
            // `p`, a live local pointer.
            unsafe {
                let st = OPENSSL_sk_new_reserve(None, n as c_int);
                assert!(!st.is_null());
                let reserved = inner(st).unwrap().num_alloc;
                let capacity = inner(st).unwrap().items.capacity();
                assert_eq!(reserved, core::cmp::max(n as c_int, MIN_NODES));
                assert!(capacity >= n);
                for i in 0..n {
                    assert_eq!(OPENSSL_sk_push(st, p), (i + 1) as c_int);
                }
                let s = inner(st).unwrap();
                assert_eq!(s.items.len(), n);
                assert_eq!(s.num_alloc, reserved, "a push took the growth path");
                assert_eq!(s.items.capacity(), capacity, "the Vec reallocated");
                OPENSSL_sk_free(st);
            }
        }
    }

    /// What a caller-visible element must observe about its own release.
    struct Probe {
        id: u32,
        released: core::cell::Cell<u32>,
    }

    thread_local! {
        /// Destructor order observed on this thread.
        static DESTRUCTION_LOG: core::cell::RefCell<Vec<u32>> =
            const { core::cell::RefCell::new(Vec::new()) };
        /// The stack a destructor inspects; NULL disables the inspection.
        static OBSERVED_STACK: core::cell::Cell<*mut OpenSslStack> =
            const { core::cell::Cell::new(core::ptr::null_mut()) };
        /// `(sk_num, sk_value(0) is NULL)` sampled at every destructor.
        static OBSERVED_STATE: core::cell::RefCell<Vec<(c_int, bool)>> =
            const { core::cell::RefCell::new(Vec::new()) };
        /// Elements a mutating destructor inserts, indexed by the destructor's identity.
        static PUSH_MARKERS: core::cell::RefCell<Vec<*const c_void>> =
            const { core::cell::RefCell::new(Vec::new()) };
        /// `(destructor identity, push result)` for the mutating destructor.
        static PUSH_RESULTS: core::cell::RefCell<Vec<(u32, c_int)>> =
            const { core::cell::RefCell::new(Vec::new()) };
        /// The stack a recursively destroying destructor releases.
        static RECURSIVE_STACK: core::cell::Cell<*mut OpenSslStack> =
            const { core::cell::Cell::new(core::ptr::null_mut()) };
        /// `1` for `sk_free`, `2` for `sk_pop_free`; disarmed after the first call.
        static RECURSIVE_FORM: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
        /// Number of recursive release attempts.
        static RECURSIVE_ATTEMPTS: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
        /// Whether a sibling element has been revoked by an earlier destructor.
        static SIBLING_INVALIDATED: core::cell::RefCell<Vec<bool>> =
            const { core::cell::RefCell::new(Vec::new()) };
        /// `(destructor identity, sibling already invalidated at delivery)`.
        static SIBLING_DELIVERY: core::cell::RefCell<Vec<(u32, bool)>> =
            const { core::cell::RefCell::new(Vec::new()) };
    }

    /// A destructor that records the release instead of freeing, so a double release
    /// is observable as a count of two rather than as undefined behaviour.
    unsafe extern "C" fn record_release(p: *mut c_void) {
        // `cast` is safe; the dereference below is the unsafe operation.
        let probe = p.cast::<Probe>();
        // SAFETY: every element in the tests below is a live `Probe`.
        unsafe { (*probe).released.set((*probe).released.get() + 1) };
    }

    /// As `record_release`, and additionally logs the identity and, when a stack
    /// is armed, samples the stack's own view at the moment of the callback.
    ///
    /// Calling `OPENSSL_sk_num`/`OPENSSL_sk_value` here is legal because
    /// `OPENSSL_sk_pop_free` ends its `Inner` borrow before the first callback.
    unsafe extern "C" fn record_destruction(p: *mut c_void) {
        let probe = p.cast::<Probe>();
        // SAFETY: every element in the tests below is a live `Probe`.
        unsafe {
            (*probe).released.set((*probe).released.get() + 1);
            DESTRUCTION_LOG.with(|log| log.borrow_mut().push((*probe).id));
            let st = OBSERVED_STACK.with(core::cell::Cell::get);
            if !st.is_null() {
                let num = OPENSSL_sk_num(st);
                let first = OPENSSL_sk_value(st, 0);
                OBSERVED_STATE.with(|state| state.borrow_mut().push((num, first.is_null())));
            }
        }
    }

    fn reset_observers() {
        DESTRUCTION_LOG.with(|log| log.borrow_mut().clear());
        OBSERVED_STACK.with(|st| st.set(core::ptr::null_mut()));
        OBSERVED_STATE.with(|state| state.borrow_mut().clear());
        PUSH_MARKERS.with(|m| m.borrow_mut().clear());
        PUSH_RESULTS.with(|r| r.borrow_mut().clear());
        RECURSIVE_STACK.with(|st| st.set(core::ptr::null_mut()));
        RECURSIVE_FORM.with(|f| f.set(0));
        RECURSIVE_ATTEMPTS.with(|c| c.set(0));
        SIBLING_INVALIDATED.with(|v| v.borrow_mut().clear());
        SIBLING_DELIVERY.with(|v| v.borrow_mut().clear());
    }

    /// A destructor that, in addition to counting its own release, inserts a fresh
    /// element onto the stack it is running for.
    unsafe extern "C" fn record_and_push(p: *mut c_void) {
        let probe = p.cast::<Probe>();
        // SAFETY: every element handed to this destructor is a live `Probe`, and the
        // markers it inserts are `Probe`s too.
        unsafe {
            (*probe).released.set((*probe).released.get() + 1);
            let st = OBSERVED_STACK.with(core::cell::Cell::get);
            if st.is_null() {
                return;
            }
            let marker = PUSH_MARKERS.with(|m| {
                m.borrow()
                    .get((*probe).id as usize)
                    .copied()
                    .unwrap_or(core::ptr::null())
            });
            if marker.is_null() {
                return;
            }
            let count = OPENSSL_sk_push(st, marker);
            PUSH_RESULTS.with(|r| r.borrow_mut().push(((*probe).id, count)));
        }
    }

    /// A destructor that releases the stack it is running for, once.
    unsafe extern "C" fn record_and_release_stack(p: *mut c_void) {
        let probe = p.cast::<Probe>();
        // SAFETY: every element handed to this destructor is a live `Probe`, and the
        // stack is the one the enclosing call owns.
        unsafe {
            (*probe).released.set((*probe).released.get() + 1);
            let form = RECURSIVE_FORM.with(|f| f.replace(0));
            if form == 0 {
                return;
            }
            RECURSIVE_ATTEMPTS.with(|c| c.set(c.get() + 1));
            let st = RECURSIVE_STACK.with(core::cell::Cell::get);
            if form == 1 {
                OPENSSL_sk_free(st);
            } else {
                OPENSSL_sk_pop_free(st, Some(record_destruction));
            }
        }
    }

    /// A destructor that revokes the two elements after it.
    unsafe extern "C" fn record_and_revoke_siblings(p: *mut c_void) {
        let probe = p.cast::<Probe>();
        // SAFETY: every element handed to this destructor is a live `Probe`.
        unsafe {
            (*probe).released.set((*probe).released.get() + 1);
            let id = (*probe).id;
            let invalidated = SIBLING_INVALIDATED.with(|v| {
                let mut v = v.borrow_mut();
                let seen = v.get(id as usize).copied().unwrap_or(false);
                if id == 0 {
                    for slot in v.iter_mut().skip(1) {
                        *slot = true;
                    }
                }
                seen
            });
            SIBLING_DELIVERY.with(|v| v.borrow_mut().push((id, invalidated)));
        }
    }

    /// The authority destroys elements in index order. Destroying from the end
    /// changes an observable sequence for caller-supplied C destructors, so the
    /// candidate must destroy first to last.
    #[test]
    fn pop_free_destroys_elements_first_to_last() {
        reset_observers();
        // SAFETY: the stack is this test's own allocation and every probe outlives it.
        unsafe {
            let probes: [Probe; 5] = core::array::from_fn(|id| Probe {
                id: id as u32,
                released: core::cell::Cell::new(0),
            });
            let st = OPENSSL_sk_new_null();
            assert!(!st.is_null());
            for (i, probe) in probes.iter().enumerate() {
                assert_eq!(
                    OPENSSL_sk_push(st, (&raw const *probe).cast()),
                    (i + 1) as c_int
                );
            }
            OPENSSL_sk_pop_free(st, Some(record_destruction));
            let observed = DESTRUCTION_LOG.with(|log| log.borrow().clone());
            assert_eq!(
                observed.as_slice(),
                &[0, 1, 2, 3, 4],
                "destruction must follow the authority's first-to-last order"
            );
            assert!(probes.iter().all(|probe| probe.released.get() == 1));
        }
    }

    /// The HAZ-16 invariant: at every destructor invocation the stack no longer
    /// contains the element being destroyed (nor any other element).
    #[test]
    fn every_destructor_runs_with_the_stack_already_empty() {
        reset_observers();
        // SAFETY: the stack is this test's own allocation and every probe outlives it.
        unsafe {
            let probes: [Probe; 3] = core::array::from_fn(|id| Probe {
                id: id as u32,
                released: core::cell::Cell::new(0),
            });
            let st = OPENSSL_sk_new_null();
            assert!(!st.is_null());
            for (i, probe) in probes.iter().enumerate() {
                assert_eq!(
                    OPENSSL_sk_push(st, (&raw const *probe).cast()),
                    (i + 1) as c_int
                );
            }
            OBSERVED_STACK.with(|observed| observed.set(st));
            OPENSSL_sk_pop_free(st, Some(record_destruction));
            OBSERVED_STACK.with(|observed| observed.set(core::ptr::null_mut()));
            let states = OBSERVED_STATE.with(|state| state.borrow().clone());
            assert_eq!(states.len(), 3, "every destructor sampled the stack");
            for (index, (num, first_is_null)) in states.iter().enumerate() {
                assert_eq!(*num, 0, "destructor {index} observed a non-empty stack");
                assert!(
                    *first_is_null,
                    "destructor {index} observed a reachable element"
                );
            }
            assert!(probes.iter().all(|probe| probe.released.get() == 1));
        }
    }

    /// A defect that panics after one element has been released must not leave that
    /// element reachable from the stack, and a retry must not destroy anything
    /// twice. Before the HAZ-16 fix the array was iterated in place, so
    /// `sk_num`/`sk_value` exposed a released element and a retry released it a
    /// second time.
    ///
    /// The repaired body detaches the whole array before the first destructor, so
    /// after an interruption the stack is empty and the not-yet-destroyed elements
    /// are leaked rather than destroyed twice.
    #[test]
    fn a_panic_during_pop_free_leaves_no_reachable_element_and_a_retry_is_safe() {
        let _guard = crate::test_support::lock_global_state();
        reset_observers();
        // SAFETY: the stack is this test's own allocation and every probe outlives it.
        unsafe {
            let probes: [Probe; 3] = core::array::from_fn(|id| Probe {
                id: id as u32,
                released: core::cell::Cell::new(0),
            });
            let st = OPENSSL_sk_new_null();
            assert!(!st.is_null());
            for (i, probe) in probes.iter().enumerate() {
                assert_eq!(
                    OPENSSL_sk_push(st, (&raw const *probe).cast()),
                    (i + 1) as c_int
                );
            }

            let before = crate::ffi::panics_caught();
            let hook = test_hooks::arm_mid_pop_free();
            OPENSSL_sk_pop_free(st, Some(record_destruction));
            drop(hook);
            assert_eq!(
                crate::ffi::panics_caught(),
                before + 1,
                "the panic was caught at the FFI boundary"
            );
            assert_eq!(probes[0].released.get(), 1, "the first destructor ran once");
            assert_eq!(probes[1].released.get(), 0);
            assert_eq!(probes[2].released.get(), 0);

            // The strongest form of the finding would be a released element that
            // `sk_value` still hands out. The whole array was detached first.
            assert_eq!(OPENSSL_sk_num(st), 0, "the stack is empty");
            assert!(OPENSSL_sk_value(st, 0).is_null(), "nothing is reachable");

            // A retry is legal: it frees the stack and destroys nothing twice.
            OPENSSL_sk_pop_free(st, Some(record_destruction));
            assert_eq!(probes[0].released.get(), 1);
            assert_eq!(
                probes[1].released.get(),
                0,
                "a leaked element is not re-destroyed"
            );
            assert_eq!(
                probes[2].released.get(),
                0,
                "a leaked element is not re-destroyed"
            );
        }
    }

    /// Success path: without an injection every element is released once and the
    /// stack itself is released.
    #[test]
    fn pop_free_releases_each_element_once_on_the_success_path() {
        // SAFETY: the stack is this test's own allocation and both probes outlive it.
        unsafe {
            let first = Probe {
                id: 0,
                released: core::cell::Cell::new(0),
            };
            let second = Probe {
                id: 1,
                released: core::cell::Cell::new(0),
            };
            let st = OPENSSL_sk_new_null();
            assert!(!st.is_null());
            assert_eq!(OPENSSL_sk_push(st, (&raw const first).cast()), 1);
            assert_eq!(OPENSSL_sk_push(st, (&raw const second).cast()), 2);
            OPENSSL_sk_pop_free(st, Some(record_release));
            assert_eq!(first.released.get(), 1);
            assert_eq!(second.released.get(), 1);
        }
    }

    /// Negative control: the fault hook really does refuse an insert, without mutating the stack,
    /// and is consumed by exactly one call. Without this, the CMS controls could pass because the
    /// injection silently never fired.
    #[test]
    fn the_test_only_insert_fault_refuses_once_without_mutating() {
        let marker = 0u8;
        let p = (&raw const marker).cast::<c_void>();
        // SAFETY: `st` is this module's allocation, exclusively owned here; `p` is a live local.
        unsafe {
            let st = OPENSSL_sk_new_reserve(None, 1);
            assert!(!st.is_null());
            test_hooks::fail_next_insert();
            assert_eq!(OPENSSL_sk_push(st, p), 0);
            assert_eq!(OPENSSL_sk_num(st), 0);
            assert_eq!(OPENSSL_sk_push(st, p), 1);
            OPENSSL_sk_free(st);
        }
    }

    /// The HAZ-16 panic-path claim holds at every destructor position, not only after
    /// the first: the elements whose destructor had not run are leaked, the ones that
    /// ran are not revisited, the stack is left alive and empty, and a retry frees it
    /// without destroying anything twice.
    ///
    /// Five elements and the first, a middle and the last position are used, so a
    /// panic before the release of the last element and a panic after every element
    /// has been destroyed are both covered.
    #[test]
    fn a_panic_at_the_first_middle_and_last_destructor_leaks_only_the_remainder() {
        let _guard = crate::test_support::lock_global_state();
        const N: usize = 5;
        for &after in &[0usize, 2, N - 1] {
            reset_observers();
            // SAFETY: the stack is this test's own allocation and every probe outlives it.
            unsafe {
                let probes: [Probe; N] = core::array::from_fn(|id| Probe {
                    id: id as u32,
                    released: core::cell::Cell::new(0),
                });
                let st = OPENSSL_sk_new_null();
                assert!(!st.is_null());
                for (i, probe) in probes.iter().enumerate() {
                    assert_eq!(
                        OPENSSL_sk_push(st, (&raw const *probe).cast()),
                        (i + 1) as c_int
                    );
                }

                let before = crate::ffi::panics_caught();
                let hook = test_hooks::arm_pop_free_panic_after(after);
                OPENSSL_sk_pop_free(st, Some(record_destruction));
                drop(hook);
                assert_eq!(
                    crate::ffi::panics_caught(),
                    before + 1,
                    "panic after destructor {after} was caught at the FFI boundary"
                );
                for (i, probe) in probes.iter().enumerate() {
                    assert_eq!(
                        probe.released.get(),
                        u32::from(i <= after),
                        "element {i} with the panic after destructor {after}"
                    );
                }

                assert_eq!(OPENSSL_sk_num(st), 0, "the stack is empty after the panic");
                assert!(
                    OPENSSL_sk_value(st, 0).is_null(),
                    "no element is reachable after the panic"
                );

                // A retry is legal: it frees the stack and destroys nothing twice.
                OPENSSL_sk_pop_free(st, Some(record_destruction));
                for (i, probe) in probes.iter().enumerate() {
                    assert_eq!(
                        probe.released.get(),
                        u32::from(i <= after),
                        "a retry re-destroyed element {i}"
                    );
                }
            }
        }
    }

    /// **A destructor may mutate the stack.** The destruction set is the snapshot taken
    /// before the first callback, so an insert during destruction goes onto the live,
    /// empty stack and cannot join — or disturb — the elements being destroyed.
    ///
    /// The ownership consequence is recorded rather than hidden: an element inserted
    /// during destruction is **not** destroyed by this call, and because the enclosing
    /// stack is released when the call returns, that element is leaked.
    #[test]
    fn a_destructor_may_push_onto_the_stack_and_the_destruction_set_is_the_entry_snapshot() {
        reset_observers();
        // SAFETY: the stack is this test's own allocation; every probe — the three
        // elements and the three inserted markers — outlives it.
        unsafe {
            let markers: [Probe; 3] = core::array::from_fn(|id| Probe {
                id: 10 + id as u32,
                released: core::cell::Cell::new(0),
            });
            PUSH_MARKERS.with(|m| {
                let mut m = m.borrow_mut();
                for marker in &markers {
                    m.push((&raw const *marker).cast());
                }
            });
            let probes: [Probe; 3] = core::array::from_fn(|id| Probe {
                id: id as u32,
                released: core::cell::Cell::new(0),
            });
            let st = OPENSSL_sk_new_null();
            assert!(!st.is_null());
            for (i, probe) in probes.iter().enumerate() {
                assert_eq!(
                    OPENSSL_sk_push(st, (&raw const *probe).cast()),
                    (i + 1) as c_int
                );
            }
            OBSERVED_STACK.with(|observed| observed.set(st));
            OPENSSL_sk_pop_free(st, Some(record_and_push));
            OBSERVED_STACK.with(|observed| observed.set(core::ptr::null_mut()));

            let pushed = PUSH_RESULTS.with(|r| r.borrow().clone());
            assert_eq!(
                pushed,
                vec![(0, 1), (1, 2), (2, 3)],
                "each insert during destruction succeeded on the live, empty stack"
            );
            for (i, probe) in probes.iter().enumerate() {
                assert_eq!(
                    probe.released.get(),
                    1,
                    "snapshot element {i} was destroyed exactly once"
                );
            }
            for marker in &markers {
                assert_eq!(
                    marker.released.get(),
                    0,
                    "an element inserted during destruction is not part of the snapshot"
                );
            }
        }
    }

    /// **A destructor that releases the stack it is running on is outside the contract.**
    ///
    /// The enclosing `pop_free` releases the stack after the last callback, so a
    /// re-entrant `sk_free`/`sk_pop_free` on the same stack would be the first of two
    /// releases of one allocation (the authority has the same defect: its loop indexes
    /// `st->num`/`st->data` after the destructor has freed them). This is the recorded
    /// class-3 input "a callback frees the object it runs on"; the disposition is
    /// `UB_NOT_CLAIMED_SAFE` and the caller must not do it.
    ///
    /// The control demonstrates the request and keeps the test itself well-defined: the
    /// test-only release canary records a release requested for the stack whose own
    /// `pop_free` loop is on the frame and withholds it, so the enclosing call performs
    /// the single release. Every snapshot element is still destroyed exactly once.
    #[test]
    fn a_destructor_that_releases_the_owning_stack_is_outside_the_contract() {
        for form in [1u8, 2] {
            reset_observers();
            // SAFETY: the stack is this test's own allocation, every probe outlives it,
            // and the canary withholds the re-entrant release so exactly one release runs.
            unsafe {
                let probes: [Probe; 3] = core::array::from_fn(|id| Probe {
                    id: id as u32,
                    released: core::cell::Cell::new(0),
                });
                let st = OPENSSL_sk_new_null();
                assert!(!st.is_null());
                for (i, probe) in probes.iter().enumerate() {
                    assert_eq!(
                        OPENSSL_sk_push(st, (&raw const *probe).cast()),
                        (i + 1) as c_int
                    );
                }
                RECURSIVE_STACK.with(|cell| cell.set(st));
                RECURSIVE_FORM.with(|cell| cell.set(form));
                let _canary = test_hooks::arm_release_canary();
                OPENSSL_sk_pop_free(st, Some(record_and_release_stack));

                assert_eq!(
                    RECURSIVE_ATTEMPTS.with(core::cell::Cell::get),
                    1,
                    "the destructor attempted the re-entrant release"
                );
                assert!(
                    test_hooks::reentrant_release_seen(),
                    "the canary recorded a release request for the stack whose loop was running"
                );
                for (i, probe) in probes.iter().enumerate() {
                    assert_eq!(
                        probe.released.get(),
                        1,
                        "form {form}: element {i} was destroyed exactly once"
                    );
                }
            }
        }
    }

    /// **Sibling invalidation is outside the contract.** The stack delivers every
    /// element of the snapshot, in order, without inspecting it, so a destructor that
    /// revokes another element cannot stop that element's destructor from running.
    ///
    /// A caller must therefore give each element independent ownership (or a reference
    /// of its own); it must not free another element from a destructor. The control
    /// records the delivery, not the invalidation, and is well-defined because the
    /// revocation is simulated by a flag rather than a release.
    #[test]
    fn a_sibling_revoked_by_an_earlier_destructor_is_still_delivered() {
        reset_observers();
        // SAFETY: the stack is this test's own allocation and every probe outlives it.
        unsafe {
            let probes: [Probe; 3] = core::array::from_fn(|id| Probe {
                id: id as u32,
                released: core::cell::Cell::new(0),
            });
            SIBLING_INVALIDATED.with(|v| {
                let mut v = v.borrow_mut();
                for _ in 0..probes.len() {
                    v.push(false);
                }
            });
            let st = OPENSSL_sk_new_null();
            assert!(!st.is_null());
            for (i, probe) in probes.iter().enumerate() {
                assert_eq!(
                    OPENSSL_sk_push(st, (&raw const *probe).cast()),
                    (i + 1) as c_int
                );
            }
            OPENSSL_sk_pop_free(st, Some(record_and_revoke_siblings));

            let delivered = SIBLING_DELIVERY.with(|v| v.borrow().clone());
            assert_eq!(
                delivered,
                vec![(0, false), (1, true), (2, true)],
                "the stack delivers a revoked sibling anyway, and in the snapshot's order"
            );
            for (i, probe) in probes.iter().enumerate() {
                assert_eq!(probe.released.get(), 1, "element {i} was delivered once");
            }
        }
    }
}
