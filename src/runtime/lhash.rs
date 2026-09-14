//! Phase 3 core runtime — `OPENSSL_LH_*`, the hash table the rest of OpenSSL
//! builds its lookup structures from.
//!
//! ## What is measured, and what is not
//!
//! `courts/phase3/rt_lhash_probe.c` is compiled against the authority and against
//! the candidate and diffed. It pins down:
//!
//! * `OPENSSL_LH_strhash` over 18 inputs. This one cannot be reasoned out — it is
//!   a specific rotate-and-xor whose constants and shift widths are only knowable
//!   by measurement — and a caller observes its value directly, so the values are
//!   recorded in the tests below.
//! * The default load factor (`OPENSSL_LH_get_down_load` == 256 = `LH_LOAD_MULT`).
//! * `insert` returning the *previously stored* item for an equal key, `delete`
//!   returning the item, and both returning NULL for a key that is not present.
//! * `num_items`, `error`, `flush` (empties without releasing the items) and
//!   `free`.
//!
//! Not measured, and therefore not claimed: the `doall` family. On a table
//! created with the bare `OPENSSL_LH_new`, the authority **segfaults** in
//! `OPENSSL_LH_doall`, `OPENSSL_LH_doall_arg` and `OPENSSL_LH_doall_arg_thunk`:
//! every generated `lh_TYPE_new` installs thunks through
//! `OPENSSL_LH_set_thunks`, and the iteration entry points dereference the (NULL)
//! thunk instead of falling back to direct iteration. That is a fault boundary,
//! so the candidate iterates directly instead of reproducing the fault; see
//! `docs/SECURITY_DIVERGENCE_POLICY.md`. Because the authority's iteration order
//! could not be observed, this module makes **no order claim** and the probe
//! records the boundary rather than comparing it.
//!
//! `OPENSSL_LH_stats`, `OPENSSL_LH_node_stats` and their relatives take a
//! `BIO *` and are deferred to Phase 4 with BIO. They are not defined here, so
//! they remain `SCAFFOLDED` in the ABI shell.

use core::ffi::{c_char, c_int, c_ulong, c_void};

use crate::ffi::guard_ffi;

/// `unsigned long (*)(const void *)` — `OPENSSL_LH_HASHFUNC`.
type HashFunc = unsafe extern "C" fn(*const c_void) -> c_ulong;
/// `int (*)(const void *, const void *)` — `OPENSSL_LH_COMPFUNC`.
type CompFunc = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
/// `unsigned long (*)(const void *, OPENSSL_LH_HASHFUNC)`.
type HashThunk = unsafe extern "C" fn(*const c_void, HashFunc) -> c_ulong;
/// `int (*)(const void *, const void *, OPENSSL_LH_COMPFUNC)`.
type CompThunk = unsafe extern "C" fn(*const c_void, *const c_void, CompFunc) -> c_int;
/// `void (*)(void *)` — `OPENSSL_LH_DOALL_FUNC`.
type DoallFunc = unsafe extern "C" fn(*mut c_void);
/// `void (*)(void *, void *)` — `OPENSSL_LH_DOALL_FUNCARG`.
type DoallArgFunc = unsafe extern "C" fn(*mut c_void, *mut c_void);
/// `void (*)(void *, OPENSSL_LH_DOALL_FUNC)`.
type DoallThunk = unsafe extern "C" fn(*mut c_void, DoallFunc);
/// `void (*)(void *, void *, OPENSSL_LH_DOALL_FUNCARG)`.
type DoallArgThunk = unsafe extern "C" fn(*mut c_void, *mut c_void, DoallArgFunc);

/// `LH_LOAD_MULT`. The authority's default and only load-factor multiplier;
/// `OPENSSL_LH_get_down_load` reports `256 * this` by default.
const LH_LOAD_MULT: usize = 256;

/// Opaque handle matching the C `OPENSSL_LHASH *`.
#[repr(C)]
pub struct OpenSslLhash {
    _private: [u8; 0],
}

struct Inner {
    /// One chain per node, in node order. OpenSSL's table is a chained hash; the
    /// node count is a power of two and grows when the load factor is exceeded.
    nodes: Vec<Vec<*mut c_void>>,
    num_items: usize,
    down_load: usize,
    error: bool,
    hash_fn: Option<HashFunc>,
    comp_fn: Option<CompFunc>,
    hash_thunk: Option<HashThunk>,
    comp_thunk: Option<CompThunk>,
    doall_thunk: Option<DoallThunk>,
    doall_arg_thunk: Option<DoallArgThunk>,
}

impl Inner {
    fn hash(&self, data: *const c_void) -> usize {
        if let Some(t) = self.hash_thunk {
            if let Some(h) = self.hash_fn {
                // SAFETY: `t` is the caller's thunk and `h` its inner hash.
                return unsafe { t(data, h) } as usize;
            }
        }
        match self.hash_fn {
            // SAFETY: `data` is the caller's key; the hash function is the
            // caller's contract for it.
            Some(h) => (unsafe { h(data) }) as usize,
            None => 0,
        }
    }

    fn eq(&self, a: *const c_void, b: *const c_void) -> bool {
        if let Some(t) = self.comp_thunk {
            if let Some(c) = self.comp_fn {
                // SAFETY: as `hash`.
                return unsafe { t(a, b, c) } == 0;
            }
        }
        match self.comp_fn {
            // SAFETY: both are the caller's keys.
            Some(c) => (unsafe { c(a, b) }) == 0,
            None => a == b,
        }
    }

    /// Whether the load factor has been exceeded, mirroring the authority's
    /// `num_items > down_load * num_nodes / LH_LOAD_MULT`.
    fn needs_grow(&self) -> bool {
        self.num_items * LH_LOAD_MULT > self.down_load * self.nodes.len()
    }

    fn grow(&mut self) {
        let new_len = (self.nodes.len() * 2).max(2);
        // Take the chains out first: rehashing needs `&self` while the nodes are
        // being re-bucketed, so the two borrows cannot overlap.
        let old = core::mem::take(&mut self.nodes);
        let mut nodes: Vec<Vec<*mut c_void>> =
            core::iter::repeat_with(Vec::new).take(new_len).collect();
        for chain in old {
            for item in chain {
                let i = self.hash(item as *const c_void) % new_len;
                nodes[i].push(item);
            }
        }
        self.nodes = nodes;
    }
}

/// # Safety
/// `p` must be a pointer returned by one of this module's constructors.
unsafe fn inner<'a>(p: *mut OpenSslLhash) -> Option<&'a mut Inner> {
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` came from `Box::into_raw` in `OPENSSL_LH_new`, so it points to
    // a live, aligned `Inner`; the lifetime is the C caller's to police, exactly
    // as it is for the authority's `OPENSSL_LHASH`.
    Some(unsafe { &mut *(p as *mut Inner) })
}

fn boxed(hash_fn: Option<HashFunc>, comp_fn: Option<CompFunc>) -> *mut OpenSslLhash {
    Box::into_raw(Box::new(Inner {
        nodes: vec![Vec::new(), Vec::new()],
        num_items: 0,
        down_load: LH_LOAD_MULT,
        error: false,
        hash_fn,
        comp_fn,
        hash_thunk: None,
        comp_thunk: None,
        doall_thunk: None,
        doall_arg_thunk: None,
    })) as *mut OpenSslLhash
}

/// `unsigned long OPENSSL_LH_strhash(const char *c)`
///
/// Measured over 18 inputs by `courts/phase3/rt_lhah_probe.c`; the values are
/// asserted in this module's tests. The construction is a per-character
/// rotate-and-xor over a counter that starts at `0x100` and advances by `0x100`,
/// with the final value folded by `(ret >> 16) ^ ret`.
///
/// # Safety
/// `c` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_strhash(c: *const c_char) -> c_ulong {
    guard_ffi(0, || {
        if c.is_null() {
            return 0;
        }
        // SAFETY: `c` is NUL-terminated per the caller's contract, and the loop
        // stops at the terminator.
        unsafe {
            let mut ret: u64 = 0;
            let mut n: u64 = 0x100;
            let mut p = c;
            loop {
                let ch = *p;
                if ch == 0 {
                    break;
                }
                let v: u64 = n | (ch as u64);
                n = n.wrapping_add(0x100);
                let r = ((v >> 2) ^ v) & 0x0f;
                // `r` is 0..15, so `32 - r` is 17..32: no shift overflow. The
                // authority computes this in an `unsigned long`, so the shift runs
                // in 64 bits before the value is masked back to 32.
                ret = (ret << r) | (ret >> (32 - r));
                ret &= 0xFFFF_FFFF;
                ret ^= v.wrapping_mul(v);
                p = p.add(1);
            }
            ((ret >> 16) ^ ret) as c_ulong
        }
    })
}

/// `OPENSSL_LHASH *OPENSSL_LH_new(OPENSSL_LH_HASHFUNC h, OPENSSL_LH_COMPFUNC c)`
///
/// The table starts with two nodes and the default load factor, which is what the
/// probe measures through `OPENSSL_LH_get_down_load`.
#[no_mangle]
pub extern "C" fn OPENSSL_LH_new(h: Option<HashFunc>, c: Option<CompFunc>) -> *mut OpenSslLhash {
    guard_ffi(core::ptr::null_mut(), || boxed(h, c))
}

/// `OPENSSL_LHASH *OPENSSL_LH_set_thunks(OPENSSL_LHASH *lh, ...)`
///
/// Installs the per-type wrapper functions the generated `lh_TYPE_*` accessors
/// use. Returns `lh`, so it composes with `OPENSSL_LH_new`.
///
/// # Safety
/// `lh` must be NULL or a live table from this module's constructors.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_set_thunks(
    lh: *mut OpenSslLhash,
    hw: Option<HashThunk>,
    cw: Option<CompThunk>,
    doall_thunk: Option<DoallThunk>,
    doall_arg_thunk: Option<DoallArgThunk>,
) -> *mut OpenSslLhash {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `lh` is live per the caller's contract.
        if let Some(s) = unsafe { inner(lh) } {
            s.hash_thunk = hw;
            s.comp_thunk = cw;
            s.doall_thunk = doall_thunk;
            s.doall_arg_thunk = doall_arg_thunk;
        }
        lh
    })
}

/// `void OPENSSL_LH_free(OPENSSL_LHASH *lh)`
///
/// Releases the table, not the items: freeing items is the caller's job, and
/// conflating the two is a classic double-free.
///
/// # Safety
/// `lh` must be NULL or a live table that is not used again afterwards.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_free(lh: *mut OpenSslLhash) {
    guard_ffi((), || {
        if lh.is_null() {
            return;
        }
        // SAFETY: `lh` came from this module's constructor.
        unsafe { drop(Box::from_raw(lh as *mut Inner)) };
    })
}

/// `void OPENSSL_LH_flush(OPENSSL_LHASH *lh)`
///
/// Empties every node without releasing the items, then collapses back to the
/// initial node count. The probe confirms both effects.
///
/// # Safety
/// `lh` must be NULL or a live table.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_flush(lh: *mut OpenSslLhash) {
    guard_ffi((), || {
        // SAFETY: `lh` is live per the caller's contract.
        if let Some(s) = unsafe { inner(lh) } {
            s.nodes = vec![Vec::new(), Vec::new()];
            s.num_items = 0;
            s.error = false;
        }
    })
}

/// `void *OPENSSL_LH_insert(OPENSSL_LHASH *lh, void *data)`
///
/// Returns the item previously stored under an equal key, or NULL. The new item
/// replaces the old one — the probe measures both the return value and that
/// `num_items` does not grow on a replacement.
///
/// # Safety
/// `lh` must be NULL or a live table; `data` is the caller's item.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_insert(
    lh: *mut OpenSslLhash,
    data: *mut c_void,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh) }) else {
            return core::ptr::null_mut();
        };
        if data.is_null() {
            s.error = true;
            return core::ptr::null_mut();
        }
        let i = s.hash(data) % s.nodes.len();
        let existing = s.nodes[i]
            .iter()
            .position(|&x| s.eq(x as *const c_void, data as *const c_void));
        match existing {
            Some(pos) => {
                let old = s.nodes[i][pos];
                s.nodes[i][pos] = data;
                old
            }
            None => {
                s.nodes[i].push(data);
                s.num_items += 1;
                if s.needs_grow() {
                    s.grow();
                }
                core::ptr::null_mut()
            }
        }
    })
}

/// `void *OPENSSL_LH_delete(OPENSSL_LHASH *lh, const void *data)`
///
/// # Safety
/// `lh` must be NULL or a live table; `data` is the caller's key.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_delete(
    lh: *mut OpenSslLhash,
    data: *const c_void,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh) }) else {
            return core::ptr::null_mut();
        };
        if data.is_null() {
            return core::ptr::null_mut();
        }
        let i = s.hash(data) % s.nodes.len();
        let found = s.nodes[i].iter().position(|&x| s.eq(x, data));
        match found {
            Some(pos) => {
                let item = s.nodes[i].remove(pos);
                s.num_items -= 1;
                item
            }
            None => core::ptr::null_mut(),
        }
    })
}

/// `void *OPENSSL_LH_retrieve(OPENSSL_LHASH *lh, const void *data)`
///
/// # Safety
/// `lh` must be NULL or a live table; `data` is the caller's key.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_retrieve(
    lh: *mut OpenSslLhash,
    data: *const c_void,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh) }) else {
            return core::ptr::null_mut();
        };
        if data.is_null() {
            return core::ptr::null_mut();
        }
        let i = s.hash(data) % s.nodes.len();
        s.nodes[i]
            .iter()
            .find(|&&x| s.eq(x, data))
            .copied()
            .unwrap_or(core::ptr::null_mut())
    })
}

/// `unsigned long OPENSSL_LH_num_items(const OPENSSL_LHASH *lh)`
///
/// # Safety
/// `lh` must be NULL or a live table.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_num_items(lh: *const OpenSslLhash) -> c_ulong {
    guard_ffi(0, || {
        // SAFETY: `lh` is live per the caller's contract.
        match unsafe { inner(lh as *mut OpenSslLhash) } {
            Some(s) => s.num_items as c_ulong,
            None => 0,
        }
    })
}

/// `int OPENSSL_LH_error(OPENSSL_LHASH *lh)`
///
/// # Safety
/// `lh` must be NULL or a live table.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_error(lh: *mut OpenSslLhash) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `lh` is live per the caller's contract.
        match unsafe { inner(lh) } {
            Some(s) => c_int::from(s.error),
            None => 0,
        }
    })
}

/// `unsigned long OPENSSL_LH_get_down_load(const OPENSSL_LHASH *lh)`
///
/// # Safety
/// `lh` must be NULL or a live table.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_get_down_load(lh: *const OpenSslLhash) -> c_ulong {
    guard_ffi(0, || {
        // SAFETY: `lh` is live per the caller's contract.
        match unsafe { inner(lh as *mut OpenSslLhash) } {
            Some(s) => s.down_load as c_ulong,
            None => 0,
        }
    })
}

/// `void OPENSSL_LH_set_down_load(OPENSSL_LHASH *lh, unsigned long down_load)`
///
/// # Safety
/// `lh` must be NULL or a live table.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_set_down_load(lh: *mut OpenSslLhash, down_load: c_ulong) {
    guard_ffi((), || {
        // SAFETY: `lh` is live per the caller's contract.
        if let Some(s) = unsafe { inner(lh) } {
            s.down_load = down_load as usize;
        }
    })
}

/// `void OPENSSL_LH_doall(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNC func)`
///
/// Iterates every item. **No order claim**: the authority's iteration order on
/// an un-thunked table could not be observed, because calling this there faults
/// (see the module note). The candidate visits nodes in index order and, within a
/// node, in insertion order.
///
/// # Safety
/// `lh` must be NULL or a live table; `func` must accept every stored item.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_doall(lh: *mut OpenSslLhash, func: Option<DoallFunc>) {
    guard_ffi((), || {
        let Some(func) = func else {
            return;
        };
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh) }) else {
            return;
        };
        for chain in &s.nodes {
            for &item in chain {
                // SAFETY: `func` is the caller's callback over the caller's items.
                unsafe { func(item) };
            }
        }
    })
}

/// `void OPENSSL_LH_doall_arg(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNCARG func, void *arg)`
///
/// # Safety
/// `lh` must be NULL or a live table; `func` must accept every stored item.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_doall_arg(
    lh: *mut OpenSslLhash,
    func: Option<DoallArgFunc>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        let Some(func) = func else {
            return;
        };
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh) }) else {
            return;
        };
        for chain in &s.nodes {
            for &item in chain {
                // SAFETY: `func` is the caller's callback over the caller's items.
                unsafe { func(item, arg) };
            }
        }
    })
}

/// `void OPENSSL_LH_doall_arg_thunk(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNCARG_THUNK thunk, OPENSSL_LH_DOALL_FUNCARG func, void *arg)`
///
/// The authority exposes this as the entry point generated accessors go through.
/// When a thunk has been installed it is preferred, because that is the
/// per-type wrapper the caller wants applied; otherwise the candidate iterates
/// directly, where the authority would fault on the NULL thunk.
///
/// # Safety
/// `lh` must be NULL or a live table; `func` must accept every stored item.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_doall_arg_thunk(
    lh: *mut OpenSslLhash,
    thunk: Option<DoallArgThunk>,
    func: Option<DoallArgFunc>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        let Some(func) = func else {
            return;
        };
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh) }) else {
            return;
        };
        let installed = thunk.or(s.doall_arg_thunk);
        if let Some(t) = installed {
            // SAFETY: the thunk is the caller's wrapper for `func`.
            unsafe { t(lh.cast::<c_void>(), arg, func) };
            return;
        }
        for chain in &s.nodes {
            for &item in chain {
                // SAFETY: `func` is the caller's callback over the caller's items.
                unsafe { func(item, arg) };
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// The values measured from the authority by
    /// `courts/phase3/rt_lhash_probe.c`. `OPENSSL_LH_strhash` is observable by a
    /// caller, so an approximation is a compatibility defect, not a detail.
    const MEASURED: &[(&str, c_ulong)] = &[
        ("a", 124608),
        ("b", 125317),
        ("z", 142886),
        ("A", 103040),
        ("Z", 119717),
        ("0", 92417),
        ("9", 97968),
        (" ", 82945),
        ("cn", 3698268),
        ("CN", 854875440),
        ("commonName", 3744328667),
        ("subjectAltName", 2748284244),
        ("2.5.4.3", 349822398),
        ("1.2.840.113549.1.1.11", 2664607289),
        ("sha256", 541343278),
        (
            "a longer string with spaces and punctuation: !@#$%^&*()",
            736962178,
        ),
    ];

    #[test]
    fn strhash_reproduces_every_measured_value() {
        // SAFETY: a NULL pointer is explicitly accepted by this function.
        assert_eq!(unsafe { OPENSSL_LH_strhash(core::ptr::null()) }, 0);
        let empty = CString::new("").expect("no interior NUL");
        // SAFETY: `empty` is a live NUL-terminated string.
        assert_eq!(unsafe { OPENSSL_LH_strhash(empty.as_ptr()) }, 0);
        for (input, expected) in MEASURED {
            let c = CString::new(*input).expect("no interior NUL");
            // SAFETY: `c` is a live NUL-terminated string.
            let got = unsafe { OPENSSL_LH_strhash(c.as_ptr()) };
            assert_eq!(got, *expected, "OPENSSL_LH_strhash({input:?})");
        }
    }

    // SAFETY: both arguments are live NUL-terminated strings.
    unsafe extern "C" fn h(p: *const c_void) -> c_ulong {
        // SAFETY: forwarded; the harness only ever passes `CString` pointers.
        unsafe { OPENSSL_LH_strhash(p.cast::<c_char>()) }
    }

    // SAFETY: both arguments are live NUL-terminated strings.
    unsafe extern "C" fn cmp(a: *const c_void, b: *const c_void) -> c_int {
        // SAFETY: forwarded; the harness only ever passes `CString` pointers.
        unsafe {
            let (x, y) = (a.cast::<c_char>(), b.cast::<c_char>());
            let mut i = 0usize;
            loop {
                let (ca, cb) = (*x.add(i) as u8, *y.add(i) as u8);
                if ca != cb {
                    return c_int::from(ca) - c_int::from(cb);
                }
                if ca == 0 {
                    return 0;
                }
                i += 1;
            }
        }
    }

    fn table() -> *mut OpenSslLhash {
        OPENSSL_LH_new(Some(h), Some(cmp))
    }

    #[test]
    fn defaults_insert_retrieve_delete_match_the_authority() {
        let lh = table();
        assert!(!lh.is_null());
        // SAFETY: `lh` is a live table from this module's constructor.
        unsafe {
            assert_eq!(OPENSSL_LH_num_items(lh), 0);
            assert_eq!(OPENSSL_LH_error(lh), 0);
            assert_eq!(OPENSSL_LH_get_down_load(lh), 256);
            assert!(OPENSSL_LH_retrieve(lh, core::ptr::null()).is_null());

            let alpha = CString::new("alpha").expect("no interior NUL");
            let beta = CString::new("beta").expect("no interior NUL");
            let gamma = CString::new("gamma").expect("no interior NUL");
            // Insertion returns the previous item, which is NULL for a fresh key.
            assert!(OPENSSL_LH_insert(lh, alpha.as_ptr() as *mut c_void).is_null());
            assert!(OPENSSL_LH_insert(lh, beta.as_ptr() as *mut c_void).is_null());
            assert_eq!(OPENSSL_LH_num_items(lh), 2);
            assert!(!OPENSSL_LH_retrieve(lh, alpha.as_ptr() as *const c_void).is_null());
            assert!(OPENSSL_LH_retrieve(lh, gamma.as_ptr() as *const c_void).is_null());

            // Replacing an equal key returns the old item and does not grow the
            // table -- both measured.
            let alpha2 = CString::new("alpha").expect("no interior NUL");
            let prev = OPENSSL_LH_insert(lh, alpha2.as_ptr() as *mut c_void);
            assert_eq!(prev, alpha.as_ptr() as *mut c_void);
            assert_eq!(OPENSSL_LH_num_items(lh), 2);
            assert_eq!(
                OPENSSL_LH_retrieve(lh, alpha.as_ptr() as *const c_void),
                alpha2.as_ptr() as *mut c_void
            );

            // Delete returns the item, and a second delete returns NULL.
            assert_eq!(
                OPENSSL_LH_delete(lh, alpha2.as_ptr() as *const c_void),
                alpha2.as_ptr() as *mut c_void
            );
            assert_eq!(OPENSSL_LH_num_items(lh), 1);
            assert!(OPENSSL_LH_delete(lh, alpha2.as_ptr() as *const c_void).is_null());

            // Flush empties without releasing, and the table stays usable.
            OPENSSL_LH_flush(lh);
            assert_eq!(OPENSSL_LH_num_items(lh), 0);
            assert!(OPENSSL_LH_retrieve(lh, beta.as_ptr() as *const c_void).is_null());
            assert!(OPENSSL_LH_insert(lh, beta.as_ptr() as *mut c_void).is_null());

            OPENSSL_LH_set_down_load(lh, 4);
            assert_eq!(OPENSSL_LH_get_down_load(lh), 4);

            OPENSSL_LH_free(lh);
        }
        // SAFETY: NULL is explicitly accepted.
        unsafe { OPENSSL_LH_free(core::ptr::null_mut()) };
    }

    #[test]
    fn doall_visits_every_item_exactly_once() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        // SAFETY: single-threaded test; the counter is only touched by this
        // callback.
        unsafe extern "C" fn cb(_p: *mut c_void) {
            SEEN.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: `arg` is the caller's counter.
        unsafe extern "C" fn argcb(_p: *mut c_void, arg: *mut c_void) {
            // SAFETY: `arg` is the caller's counter.
            unsafe { *(arg as *mut usize) += 1 };
        }

        let lh = table();
        let keys: Vec<CString> = (0..64)
            .map(|i| CString::new(format!("key-{i}")).expect("no interior NUL"))
            .collect();
        // SAFETY: `lh` is live and every key outlives the table.
        unsafe {
            for k in &keys {
                OPENSSL_LH_insert(lh, k.as_ptr() as *mut c_void);
            }
            assert_eq!(OPENSSL_LH_num_items(lh), 64);
            SEEN.store(0, Ordering::Relaxed);
            OPENSSL_LH_doall(lh, Some(cb));
            assert_eq!(SEEN.load(Ordering::Relaxed), 64);
            let mut n = 0usize;
            OPENSSL_LH_doall_arg(lh, Some(argcb), (&mut n) as *mut usize as *mut c_void);
            assert_eq!(n, 64);
            OPENSSL_LH_free(lh);
        }
    }
}
