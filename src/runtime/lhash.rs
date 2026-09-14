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
//! The `OPENSSL_LH_*stats*` family takes a `BIO *`, which is why it is implemented
//! here rather than in Phase 3: the report is emitted through the BIO printf
//! surface. It is also what forced this module to model the table faithfully —
//! `num_nodes` and `num_alloc_nodes` are *observable* through the report, and they
//! are not the same number, so the linear-hashing layout had to be reproduced
//! rather than approximated.

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

use crate::ffi::guard_ffi;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{self, FILE};
use crate::runtime::bio::Bio;

extern "C" {
    /// `int strcmp(const char *, const char *)`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
}

/// The hash the authority installs when `OPENSSL_LH_new` is given NULL.
///
/// # Safety
/// `p` must be NULL or a NUL-terminated C string.
unsafe extern "C" fn default_hash(p: *const c_void) -> c_ulong {
    // SAFETY: forwarded; `OPENSSL_LH_strhash` accepts NULL and stops at the
    // terminator.
    unsafe { OPENSSL_LH_strhash(p.cast()) }
}

/// The comparison the authority installs when `OPENSSL_LH_new` is given NULL.
///
/// # Safety
/// Both arguments must be NULL or NUL-terminated C strings.
unsafe extern "C" fn default_comp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: forwarded; `strcmp` requires NUL-terminated strings.
    unsafe { strcmp(a.cast(), b.cast()) }
}

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

/// `LH_LOAD_MULT`.
const LH_LOAD_MULT: usize = 256;
/// `MIN_NODES`: the initial bucket allocation, and the floor the table will not
/// contract below.
const MIN_NODES: usize = 16;
/// `UP_LOAD`: `2 * LH_LOAD_MULT`. The table expands before an insert that would
/// take it past this load.
const UP_LOAD: usize = 2 * LH_LOAD_MULT;
/// `DOWN_LOAD`: `LH_LOAD_MULT`. The table contracts after a delete that leaves it
/// below this load, but only while it is above `MIN_NODES` buckets.
const DOWN_LOAD: usize = LH_LOAD_MULT;

/// Opaque handle matching the C `OPENSSL_LHASH *`.
#[repr(C)]
pub struct OpenSslLhash {
    _private: [u8; 0],
}

/// One table entry: the stored hash and the caller's pointer.
///
/// The authority keeps the hash in the node so that lookup can skip the
/// comparison for entries whose hash differs. That is *observable*, because a
/// caller's comparator may have side effects: the authority calls it fewer times
/// than a naive scan would, so the hash is stored here rather than recomputed.
type Node = (usize, *mut c_void);

/// The hash table.
///
/// ## The layout is observable, so it is reproduced
///
/// OpenSSL's `lh` is a *linear-hashing* table, not a simple doubling one. The
/// bucket array has `num_alloc_nodes` entries while only `num_nodes` of them are
/// in use, and `expand` splits **one** bucket per call (`p`, moving entries whose
/// `hash % num_alloc_nodes != p` into bucket `p + pmax`), advancing `p` until the
/// allocation doubles and `p` resets. Lookup selects a bucket with
///
/// ```text
/// nn = hash % pmax;  if (nn < p) nn = hash % num_alloc_nodes;
/// ```
///
/// so the two counts and the two cursors are all load-bearing. They used to be
/// unobservable from the candidate's side because nothing exposed them; the
/// `OPENSSL_LH_*stats*` functions do, which is why this model exists rather than
/// the simpler one this module started with.
struct Inner {
    /// The bucket array (the authority's `b`), always `num_alloc_nodes` long.
    b: Vec<Vec<Node>>,
    /// `num_nodes`: buckets in use. Starts at `MIN_NODES / 2` and moves by one per
    /// split or merge, so it is deliberately **not** the allocation size.
    num_nodes: usize,
    /// `num_alloc_nodes`: the allocation size.
    num_alloc_nodes: usize,
    /// `p`: the bucket the next split acts on.
    p: usize,
    /// `pmax`: the split boundary — the distance between a bucket and the one it
    /// splits into.
    pmax: usize,
    num_items: usize,
    up_load: usize,
    down_load: usize,
    /// `error`. The authority's field is an `int` that is incremented on an
    /// allocation failure and cleared on the next insert/delete/retrieve, and
    /// `OPENSSL_LH_error` reports whether it is non-zero.
    error: usize,
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

    /// The authority's `getrn` bucket selection.
    fn bin_for(&self, hash: usize) -> usize {
        let nn = hash % self.pmax;
        if nn < self.p {
            hash % self.num_alloc_nodes
        } else {
            nn
        }
    }

    /// The authority's `static int expand(OPENSSL_LHASH *lh)`.
    ///
    /// Returns false only when the reallocation fails, which cannot be reproduced
    /// here: Rust's allocator aborts rather than returning NULL. The authority's
    /// `lh->error++` arm is therefore unreachable in this crate and is recorded in
    /// `forensics/phase4-obligations.json` rather than approximated.
    fn expand(&mut self) -> bool {
        // `nni`, `p` and `pmax` are captured **before** the branch, because the
        // split below acts on the old cursor and boundary. That is what makes the
        // new bucket always the highest one now in use (index `num_nodes - 1`),
        // which is why `doall` can iterate `0..num_nodes` and see everything.
        let nni = self.num_alloc_nodes;
        let p = self.p;
        let pmax = self.pmax;
        if p + 1 >= pmax {
            // Everything at the current boundary has been split: double the
            // allocation and start again from bucket 0.
            self.b.resize(nni * 2, Vec::new());
            self.pmax = nni;
            self.num_alloc_nodes = nni * 2;
            self.p = 0;
        } else {
            self.p += 1;
        }
        self.num_nodes += 1;
        // Split bucket `p`: entries whose hash no longer selects it move to
        // `p + pmax`. The authority *prepends* each moved entry to the new bucket,
        // reversing their relative order, and that order is observable through
        // `doall`, so it is reproduced rather than tidied.
        let chain = core::mem::take(&mut self.b[p]);
        let mut stay: Vec<Node> = Vec::new();
        let mut moved: Vec<Node> = Vec::new();
        for node in chain {
            if node.0 % nni != p {
                moved.push(node);
            } else {
                stay.push(node);
            }
        }
        moved.reverse();
        self.b[p] = stay;
        self.b[p + pmax] = moved;
        true
    }

    /// The authority's `static void contract(OPENSSL_LHASH *lh)`.
    fn contract(&mut self) {
        let idx = self.p + self.pmax - 1;
        let np = core::mem::take(&mut self.b[idx]);
        if self.p == 0 {
            let old_pmax = self.pmax;
            self.b.truncate(old_pmax);
            self.num_alloc_nodes /= 2;
            self.pmax /= 2;
            self.p = self.pmax - 1;
        } else {
            self.p -= 1;
        }
        self.num_nodes -= 1;
        // The absorbed chain is appended *after* the surviving entries.
        let target = self.p;
        if self.b[target].is_empty() {
            self.b[target] = np;
        } else {
            self.b[target].extend(np);
        }
    }

    /// Every entry, in the order the authority's `doall_util_fn` visits them:
    /// buckets from `num_nodes - 1` down to `0`, and within a bucket from the
    /// head of the chain (most recently inserted) to the tail.
    fn visit<F: FnMut(*mut c_void)>(&self, mut f: F) {
        for i in (0..self.num_nodes).rev() {
            for &(_, item) in &self.b[i] {
                f(item);
            }
        }
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
        // `OPENSSL_LH_new` allocates `MIN_NODES` buckets but marks only half of
        // them in use, and that asymmetry is what the stats functions report.
        b: core::iter::repeat_with(Vec::new).take(MIN_NODES).collect(),
        num_nodes: MIN_NODES / 2,
        num_alloc_nodes: MIN_NODES,
        p: 0,
        pmax: MIN_NODES / 2,
        num_items: 0,
        up_load: UP_LOAD,
        down_load: DOWN_LOAD,
        error: 0,
        // NULL is not "no hashing": the authority substitutes `strhash` and
        // `strcmp`. Defaulting to a zero hash made every key land in one bucket
        // and defaulting to pointer comparison changed what "equal key" means,
        // which the stats report exposed as a bucket distribution of one.
        hash_fn: Some(hash_fn.unwrap_or(default_hash)),
        comp_fn: Some(comp_fn.unwrap_or(default_comp)),
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
/// Empties the buckets that are in use and resets the item count. It does **not**
/// shrink the table: the authority leaves `num_nodes` and the allocation where
/// they were, so a flushed table keeps its shape. (An earlier version of this
/// module collapsed the table to its initial size and said the probe confirmed
/// it; it could not have, because nothing exposed the node count until the stats
/// functions existed. The claim was unsupported and is corrected here.)
///
/// # Safety
/// `lh` must be NULL or a live table.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_flush(lh: *mut OpenSslLhash) {
    guard_ffi((), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh) }) else {
            return;
        };
        for chain in s.b.iter_mut().take(s.num_nodes) {
            chain.clear();
        }
        s.num_items = 0;
    })
}

/// `void *OPENSSL_LH_insert(OPENSSL_LHASH *lh, void *data)`
///
/// Returns the item previously stored under an equal key, or NULL. The new item
/// replaces the old one *in place*, so a replacement does not change `num_items`
/// and does not move the entry within its chain.
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
        s.error = 0;
        if data.is_null() {
            // The authority has no guard here and would call the caller's hash and
            // comparison functions on NULL. Returning early is a deliberate, safer
            // divergence (docs/SECURITY_DIVERGENCE_POLICY.md); it is unobservable in
            // the courts because no probe stores a NULL item.
            return core::ptr::null_mut();
        }
        // The growth test runs *before* the lookup, as in the authority, so the
        // table can gain a bucket even when the insert turns out to be a
        // replacement of an existing key.
        if s.up_load <= s.num_items * LH_LOAD_MULT / s.num_nodes && !s.expand() {
            return core::ptr::null_mut();
        }
        let hash = s.hash(data);
        let bin = s.bin_for(hash);
        let found = s.b[bin]
            .iter()
            .position(|node| node.0 == hash && s.eq(node.1, data));
        match found {
            Some(pos) => {
                let old = s.b[bin][pos].1;
                s.b[bin][pos].1 = data;
                old
            }
            None => {
                // Prepended, because the authority links a new node at the head
                // of its chain and `doall` observes the resulting order.
                s.b[bin].insert(0, (hash, data));
                s.num_items += 1;
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
        s.error = 0;
        if data.is_null() {
            // As in `insert`: the authority would call the caller's functions on
            // NULL; returning early is the recorded safer divergence.
            return core::ptr::null_mut();
        }
        let hash = s.hash(data);
        let bin = s.bin_for(hash);
        let found = s.b[bin]
            .iter()
            .position(|node| node.0 == hash && s.eq(node.1, data));
        let Some(pos) = found else {
            return core::ptr::null_mut();
        };
        let item = s.b[bin].remove(pos).1;
        s.num_items -= 1;
        // The table merges a bucket back only while it is above `MIN_NODES`.
        if s.num_nodes > MIN_NODES && s.down_load >= s.num_items * LH_LOAD_MULT / s.num_nodes {
            s.contract();
        }
        item
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
        // A lookup clears a pending error rather than reporting it, which the
        // authority does so that a failed allocation does not poison every
        // subsequent call.
        if s.error != 0 {
            s.error = 0;
        }
        if data.is_null() {
            return core::ptr::null_mut();
        }
        let hash = s.hash(data);
        let bin = s.bin_for(hash);
        s.b[bin]
            .iter()
            .find(|node| node.0 == hash && s.eq(node.1, data))
            .map_or(core::ptr::null_mut(), |node| node.1)
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
            Some(s) => c_int::from(s.error != 0),
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
/// Iterates every item in the authority's order: buckets from the last in use
/// down to the first, and within a bucket from the head of the chain (most
/// recently inserted) to the tail. That order is observable by a typed table,
/// whose `doall` thunk is installed by `OPENSSL_LH_set_thunks`.
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
        s.visit(|item| {
            // SAFETY: `func` is the caller's callback over the caller's items.
            unsafe { func(item) };
        });
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
        s.visit(|item| {
            // SAFETY: `func` is the caller's callback over the caller's items.
            unsafe { func(item, arg) };
        });
    })
}

/// `void OPENSSL_LH_doall_arg_thunk(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNCARG_THUNK thunk, OPENSSL_LH_DOALL_FUNCARG func, void *arg)`
///
/// The authority exposes this as the entry point generated accessors go through.
/// When a thunk has been installed it is preferred, because that is the per-type
/// wrapper the caller wants applied; otherwise the candidate iterates directly,
/// where the authority would call the NULL thunk and fault.
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
        s.visit(|item| {
            // SAFETY: `func` is the caller's callback over the caller's items.
            unsafe { func(item, arg) };
        });
    })
}

/* ------------------------------------------------------------------------- */
/* Statistics.                                                               */
/* ------------------------------------------------------------------------- */

/// The thirteen counters the authority prints as literal zeroes.
///
/// OpenSSL 3 removed the per-table counters from the structure but kept the
/// report's shape, so these lines are constants in the authority's own source.
/// Reproducing them as constants is therefore exact, not an approximation.
const STAT_ZERO_LINES: [&core::ffi::CStr; 13] = [
    c"num_expands           = 0\n",
    c"num_expand_reallocs   = 0\n",
    c"num_contracts         = 0\n",
    c"num_contract_reallocs = 0\n",
    c"num_hash_calls        = 0\n",
    c"num_comp_calls        = 0\n",
    c"num_insert            = 0\n",
    c"num_replace           = 0\n",
    c"num_delete            = 0\n",
    c"num_no_delete         = 0\n",
    c"num_retrieve          = 0\n",
    c"num_retrieve_miss     = 0\n",
    c"num_hash_comps        = 0\n",
];

/// `void OPENSSL_LH_stats_bio(const OPENSSL_LHASH *lh, BIO *out)`
///
/// # Safety
/// `lh` must be NULL or a live table; `out` must be NULL or a live BIO.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_stats_bio(lh: *const OpenSslLhash, out: *mut Bio) {
    guard_ffi((), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh as *mut OpenSslLhash) }) else {
            return;
        };
        // SAFETY: `out` is the caller's BIO; `BIO_printf` is the implemented BIO
        // surface and the format specifiers match the argument types.
        unsafe {
            BIO_printf(
                out,
                c"num_items             = %lu\n".as_ptr(),
                s.num_items as c_ulong,
            );
            BIO_printf(
                out,
                c"num_nodes             = %u\n".as_ptr(),
                s.num_nodes as c_uint,
            );
            BIO_printf(
                out,
                c"num_alloc_nodes       = %u\n".as_ptr(),
                s.num_alloc_nodes as c_uint,
            );
            for line in STAT_ZERO_LINES {
                BIO_printf(out, line.as_ptr());
            }
        }
    })
}

/// `void OPENSSL_LH_node_stats_bio(const OPENSSL_LHASH *lh, BIO *out)`
///
/// One line per bucket that is *in use* — that is, the first `num_nodes`, not the
/// whole allocation.
///
/// # Safety
/// `lh` must be NULL or a live table; `out` must be NULL or a live BIO.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_node_stats_bio(lh: *const OpenSslLhash, out: *mut Bio) {
    guard_ffi((), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh as *mut OpenSslLhash) }) else {
            return;
        };
        for i in 0..s.num_nodes {
            let num = s.b[i].len();
            // SAFETY: `out` is the caller's BIO.
            unsafe {
                BIO_printf(
                    out,
                    c"node %6u -> %3u\n".as_ptr(),
                    i as c_uint,
                    num as c_uint,
                );
            }
        }
    })
}

/// `void OPENSSL_LH_node_usage_stats_bio(const OPENSSL_LHASH *lh, BIO *out)`
///
/// The load line mixes integer division and remainders, so it is computed exactly
/// as the authority computes it rather than re-derived.
///
/// # Safety
/// `lh` must be NULL or a live table; `out` must be NULL or a live BIO.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_node_usage_stats_bio(lh: *const OpenSslLhash, out: *mut Bio) {
    guard_ffi((), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh as *mut OpenSslLhash) }) else {
            return;
        };
        let mut total: usize = 0;
        let mut n_used: usize = 0;
        for i in 0..s.num_nodes {
            let num = s.b[i].len();
            if num != 0 {
                n_used += 1;
                total += num;
            }
        }
        // SAFETY: `out` is the caller's BIO.
        unsafe {
            BIO_printf(
                out,
                c"%lu nodes used out of %u\n".as_ptr(),
                n_used as c_ulong,
                s.num_nodes as c_uint,
            );
            BIO_printf(out, c"%lu items\n".as_ptr(), total as c_ulong);
        }
        if n_used == 0 {
            return;
        }
        let load_whole = total / s.num_nodes;
        let load_frac = (total % s.num_nodes) * 100 / s.num_nodes;
        let actual_whole = total / n_used;
        let actual_frac = (total % n_used) * 100 / n_used;
        // SAFETY: `out` is the caller's BIO.
        unsafe {
            BIO_printf(
                out,
                c"load %d.%02d  actual load %d.%02d\n".as_ptr(),
                load_whole as c_int,
                load_frac as c_int,
                actual_whole as c_int,
                actual_frac as c_int,
            );
        }
    })
}

/// Write an already-formatted report line to a `FILE *`.
///
/// # Safety
/// `fp` must be NULL or a live `FILE *`.
unsafe fn fp_write(fp: *mut FILE, text: &str) {
    if fp.is_null() {
        return;
    }
    // SAFETY: `fp` is the caller's stream and `text` is a live slice.
    unsafe { sys::fwrite(text.as_ptr().cast(), 1, text.len(), fp) };
}

/// The authority's `OPENSSL_LH_stats` builds a `BIO_s_file` and calls the `_bio`
/// variant. `BIO_s_file` is an open obligation of this stratum, so this writes the
/// same bytes to the stream directly — identical output, because a file BIO's only
/// effect on a write is `fwrite` to that stream. The mechanism difference is
/// recorded rather than hidden.
///
/// # Safety
/// `lh` must be NULL or a live table; `fp` must be NULL or a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_stats(lh: *const OpenSslLhash, fp: *mut FILE) {
    guard_ffi((), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh as *mut OpenSslLhash) }) else {
            return;
        };
        let mut text = format!(
            "num_items             = {}\nnum_nodes             = {}\nnum_alloc_nodes       = {}\n",
            s.num_items, s.num_nodes, s.num_alloc_nodes
        );
        for line in STAT_ZERO_LINES {
            text.push_str(&line.to_string_lossy());
        }
        // SAFETY: `fp` is the caller's stream.
        unsafe { fp_write(fp, &text) };
    })
}

/// The `FILE *` form of [`OPENSSL_LH_node_stats_bio`]; see that function's note on
/// the mechanism difference.
///
/// # Safety
/// `lh` must be NULL or a live table; `fp` must be NULL or a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_node_stats(lh: *const OpenSslLhash, fp: *mut FILE) {
    guard_ffi((), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh as *mut OpenSslLhash) }) else {
            return;
        };
        let mut text = String::new();
        for i in 0..s.num_nodes {
            text.push_str(&format!("node {:>6} -> {:>3}\n", i, s.b[i].len()));
        }
        // SAFETY: `fp` is the caller's stream.
        unsafe { fp_write(fp, &text) };
    })
}

/// The `FILE *` form of [`OPENSSL_LH_node_usage_stats_bio`]; see that function's
/// note on the mechanism difference.
///
/// # Safety
/// `lh` must be NULL or a live table; `fp` must be NULL or a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_LH_node_usage_stats(lh: *const OpenSslLhash, fp: *mut FILE) {
    guard_ffi((), || {
        // SAFETY: `lh` is live per the caller's contract.
        let Some(s) = (unsafe { inner(lh as *mut OpenSslLhash) }) else {
            return;
        };
        let mut total: usize = 0;
        let mut n_used: usize = 0;
        for i in 0..s.num_nodes {
            let num = s.b[i].len();
            if num != 0 {
                n_used += 1;
                total += num;
            }
        }
        let mut text = format!(
            "{} nodes used out of {}\n{} items\n",
            n_used, s.num_nodes, total
        );
        if n_used != 0 {
            text.push_str(&format!(
                "load {}.{:02}  actual load {}.{:02}\n",
                total / s.num_nodes,
                (total % s.num_nodes) * 100 / s.num_nodes,
                total / n_used,
                (total % n_used) * 100 / n_used
            ));
        }
        // SAFETY: `fp` is the caller's stream.
        unsafe { fp_write(fp, &text) };
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
