//! Phase 3 core runtime — the `OPENSSL_sk_*` stack.
//!
//! The stack is OpenSSL's ubiquitous dynamic array. Almost every collection in
//! the public API is a `STACK_OF(T)`, so its semantics — index validity, what
//! `push`/`pop` do at the boundaries, insertion ordering, and the failure values
//! — are load-bearing for the whole library.
//!
//! ## Opacity
//!
//! `OPENSSL_STACK` is opaque to callers, so the internal representation is ours
//! to choose and is not part of the ABI. The public obligation is only the
//! behaviour: this module therefore uses a `Vec` behind an opaque pointer
//! rather than reproducing the authority's internal array-and-capacity layout.
//! Reproducing a private layout would be architectural archaeology with no
//! observable payoff, which is precisely what `docs/CUSTODIAN_CONTRACT.md` §30
//! warns against.
//!
//! ## Signatures
//!
//! From the authority's installed `safestack.h`. The comparison callback is
//! `int (*)(const void *, const void *)`, invoked through a raw function
//! pointer, and its ordering is the caller's contract, not ours.

use core::ffi::{c_int, c_void};

use crate::ffi::guard_ffi;

/// Opaque handle matching the C `OPENSSL_STACK *`.
#[repr(C)]
pub struct OpenSslStack {
    _private: [u8; 0],
}

type CompFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type CopyFn = unsafe extern "C" fn(*const c_void) -> *mut c_void;

struct Inner {
    items: Vec<*const c_void>,
    comp: Option<CompFn>,
    sorted: bool,
}

/// # Safety
/// `p` must be a pointer returned by one of this module's constructors.
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
    Box::into_raw(Box::new(Inner {
        items,
        comp,
        sorted: false,
    })) as *mut OpenSslStack
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
        let cap = if n > 0 { n as usize } else { 0 };
        from_boxes(Vec::with_capacity(cap), cmp)
    })
}

/// `int OPENSSL_sk_reserve(OPENSSL_STACK *st, int n)`
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_reserve(st: *mut OpenSslStack, n: c_int) -> c_int {
    guard_ffi(1, || {
        // SAFETY: `st` is a live stack per the caller's contract.
        unsafe {
            let Some(s) = inner(st) else { return 1 };
            if n <= 0 {
                return 1;
            }
            s.items.reserve(n as usize - s.items.len().min(n as usize));
            1
        }
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
/// `st` must be NULL or a live stack, and `func` must be a destructor valid for
/// every element on it.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_pop_free(st: *mut OpenSslStack, func: Option<FreeFn>) {
    guard_ffi((), || {
        // SAFETY: `st` is live; `func`, when present, is the caller's destructor
        // for the element type it pushed.
        unsafe {
            let Some(s) = inner(st) else { return };
            if let Some(f) = func {
                for &item in s.items.iter() {
                    if !item.is_null() {
                        f(item as *mut c_void);
                    }
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
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_set(
    st: *mut OpenSslStack,
    i: c_int,
    data: *const c_void,
) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            if i < 0 || (i as usize) >= s.items.len() {
                return core::ptr::null();
            }
            s.items[i as usize] = data;
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
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else { return 0 };
            s.items.push(data);
            s.sorted = false;
            s.items.len() as c_int
        }
    })
}

/// `int OPENSSL_sk_insert(OPENSSL_STACK *sk, const void *data, int where)`
///
/// A `where` beyond the end appends; a negative `where` is a failure in the
/// authority and is treated as such here rather than being clamped silently.
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
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else { return 0 };
            if where_ < 0 {
                return 0;
            }
            let idx = (where_ as usize).min(s.items.len());
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
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            s.items.pop().unwrap_or(core::ptr::null())
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
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            if s.items.is_empty() {
                return core::ptr::null();
            }
            s.items.remove(0)
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
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else { return 0 };
            s.items.insert(0, data);
            s.sorted = false;
            s.items.len() as c_int
        }
    })
}

/// `void *OPENSSL_sk_delete(OPENSSL_STACK *st, int loc)`
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_delete(st: *mut OpenSslStack, loc: c_int) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            if loc < 0 || (loc as usize) >= s.items.len() {
                return core::ptr::null();
            }
            s.items.remove(loc as usize)
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
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            match s.items.iter().position(|&x| x == p) {
                Some(i) => s.items.remove(i),
                None => core::ptr::null(),
            }
        }
    })
}

/// `void OPENSSL_sk_zero(OPENSSL_STACK *st)` — clears without freeing elements.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_zero(st: *mut OpenSslStack) {
    guard_ffi((), || {
        // SAFETY: `st` is live.
        unsafe {
            if let Some(s) = inner(st) {
                s.items.clear();
                s.sorted = false;
            }
        }
    })
}

/// `void OPENSSL_sk_sort(OPENSSL_STACK *st)`
///
/// # Safety
/// `st` must be NULL or a live stack, and its comparator (if any) must be a
/// total order valid for the elements pushed onto it.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_sort(st: *mut OpenSslStack) {
    guard_ffi((), || {
        // SAFETY: `st` is live; `comp` is the caller's ordering over their own
        // element type, so invoking it is sound with respect to the elements.
        unsafe {
            let Some(s) = inner(st) else { return };
            if s.sorted {
                return;
            }
            if let Some(cmp) = s.comp {
                s.items.sort_by(|a, b| {
                    let r = cmp(*a, *b);
                    r.cmp(&0)
                });
            }
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
/// Returns the *previous* comparator, and setting a new one invalidates any
/// previous sort.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_set_cmp_func(
    st: *mut OpenSslStack,
    cmp: Option<CompFn>,
) -> Option<CompFn> {
    guard_ffi(None, || {
        // SAFETY: `st` is live.
        unsafe {
            let s = inner(st)?;
            let old = s.comp;
            if !core::ptr::eq(
                s.comp.map(|f| f as *const ()).unwrap_or(core::ptr::null()),
                cmp.map(|f| f as *const ()).unwrap_or(core::ptr::null()),
            ) {
                s.sorted = false;
            }
            s.comp = cmp;
            old
        }
    })
}

/// `void *OPENSSL_sk_find(OPENSSL_STACK *st, const void *data)`
///
/// # Safety
/// `st` must be NULL or a live stack, and `data` must be a value its comparator
/// (or pointer identity) can validly examine.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_find(
    st: *mut OpenSslStack,
    data: *const c_void,
) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            if let Some(cmp) = s.comp {
                // With a comparator the authority searches by ordering, so the
                // comparison result, not pointer identity, decides the match.
                return s
                    .items
                    .iter()
                    .find(|&&x| cmp(x, data) == 0)
                    .copied()
                    .unwrap_or(core::ptr::null());
            }
            s.items
                .iter()
                .find(|&&x| x == data)
                .copied()
                .unwrap_or(core::ptr::null())
        }
    })
}

/// `int OPENSSL_sk_find_all(OPENSSL_STACK *st, const void *data, int *pnum)`
///
/// Returns the first index, or -1; `*pnum` receives the index of the next
/// candidate for an ordered search. NULL `pnum` is tolerated.
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
        // SAFETY: `st` is live; `pnum`, when non-NULL, is writable per the
        // caller's contract.
        unsafe {
            let Some(s) = inner(st) else { return -1 };
            let found = s.items.iter().position(|&x| match s.comp {
                Some(cmp) => cmp(x, data) == 0,
                None => x == data,
            });
            match found {
                Some(i) => {
                    if !pnum.is_null() {
                        *pnum = i as c_int + 1;
                    }
                    i as c_int
                }
                None => -1,
            }
        }
    })
}

/// `void *OPENSSL_sk_find_ex(OPENSSL_STACK *st, const void *data)`
///
/// On an ordered stack this returns the nearest element at or after `data`,
/// which can differ from `find`. Reported as NULL for an unordered stack, which
/// is the authority's behaviour.
///
/// # Safety
/// `st` must be NULL or a live stack, and `data` must be a value its comparator
/// can validly examine.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_find_ex(
    st: *mut OpenSslStack,
    data: *const c_void,
) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: `st` is live.
        unsafe {
            let Some(s) = inner(st) else {
                return core::ptr::null();
            };
            let Some(cmp) = s.comp else {
                return core::ptr::null();
            };
            s.items
                .iter()
                .find(|&&x| cmp(x, data) >= 0)
                .copied()
                .unwrap_or(core::ptr::null())
        }
    })
}

/// `OPENSSL_STACK *OPENSSL_sk_dup(const OPENSSL_STACK *st)`
///
/// Shallow: the elements are shared, not copied.
///
/// # Safety
/// `st` must be NULL or a live stack from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_sk_dup(st: *const OpenSslStack) -> *mut OpenSslStack {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `st` is either NULL or live.
        unsafe {
            let Some(s) = inner(st as *mut OpenSslStack) else {
                return core::ptr::null_mut();
            };
            let p = from_boxes(s.items.clone(), s.comp);
            if let Some(d) = inner(p) {
                d.sorted = s.sorted;
            }
            p
        }
    })
}

/// `OPENSSL_STACK *OPENSSL_sk_deep_copy(const OPENSSL_STACK *, OPENSSL_sk_copyfunc c, OPENSSL_sk_freefunc f)`
///
/// The copy function is applied per element; on failure the partial copy is
/// unwound with the caller's destructor, which is why `f` is required.
///
/// # Safety
/// `st` must be NULL or a live stack; `copy` and `free_fn` must be valid for
/// every element on it.
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
                return core::ptr::null_mut();
            };
            let Some(copy) = copy else {
                return core::ptr::null_mut();
            };
            let mut out: Vec<*const c_void> = Vec::with_capacity(s.items.len());
            for &item in s.items.iter() {
                if item.is_null() {
                    continue;
                }
                let c = copy(item);
                if c.is_null() {
                    if let Some(f) = free_fn {
                        for &made in out.iter() {
                            if !made.is_null() {
                                f(made as *mut c_void);
                            }
                        }
                    }
                    return core::ptr::null_mut();
                }
                out.push(c);
            }
            from_boxes(out, s.comp)
        }
    })
}
