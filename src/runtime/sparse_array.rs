//! Phase 6.10a-i — `crypto/sparse_array.c`: the sparse array.
//!
//! A map from an arbitrary `uint64_t` to a `void *`, stored as a **sixteen-way tree** whose
//! depth grows with the largest index ever stored. That is the whole design: a dense array
//! would waste memory on the sparse indices OpenSSL uses (a `libctx` pointer cast to an
//! integer, a thread id, a padded slot number), and a hash table would not preserve the
//! iteration order `sa_doall` walks.
//!
//! ## The two settings that are the whole of the layout
//!
//! `OPENSSL_SA_BLOCK_BITS` is 4 — the library builder may redefine it in `[2, 63]`, and this
//! profile does not — so a node holds **16** pointers, the level mask is **15**, and the tree
//! can hold at most `(64 + 4 - 1) / 4 = 16` levels. `sa->levels` is the depth currently in use,
//! and the tree is grown **conservatively**: `ossl_sa_set` allocates a fresh root and pushes
//! the old one into slot 0, so growing by one level leaves fifteen sixteenths of the index
//! space empty. That is deliberate upstream and is reproduced: an index space of 2^60 cost the
//! same handful of nodes before and after the change, and the alternative — re-hashing the
//! whole tree on growth — is what a reader might "improve" it into.
//!
//! `sa->top` is the **largest index ever set**, not the largest currently present: it is
//! raised by `set` and never lowered, and `get` uses it as a short-circuit (`n <= sa->top`)
//! rather than as a bound. A caller that sets index 10^6 and then clears it still pays for
//! lookups up to it, and `nelem` is the count that *is* maintained both ways.
//!
//! ## `sa_doall` is one loop with an explicit stack, and the order is observable
//!
//! It walks depth-first in **increasing index order**, pushing a level's node on descent and
//! popping when a level is exhausted. The `idx` accumulation is the part to read carefully:
//! on descent it shifts left, and on ascent it shifts **right**, and the pop-branch reads `p`
//! after `l` is decremented. `ossl_sa_doall`'s order is what `CRYPTO_THREAD_clean_local`
//! relies on to release tables, and it is what a test can check.
//!
//! ## What is not a behaviour
//!
//! `struct trampoline_st` in C exists to launder a function-pointer cast past a compiler
//! warning: `ossl_sa_doall(sa, leaf)` wraps `leaf` in a struct so that `sa_doall` can call it
//! with an extra `arg`. This crate passes the leaf and a null argument straight through —
//! the same call sequence, without the warning workaround. That is the only place in this file
//! where the C is not transcribed literally, and it is a C-language constraint rather than a
//! contract.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_free, CRYPTO_zalloc};

/// `ossl_uintmax_t` — `uint64_t` in this profile.
pub(crate) type OsslUintMax = u64;

/// `OPENSSL_SA_BLOCK_BITS` — 4 in this profile, and the library builder may redefine it.
const SA_BLOCK_BITS: c_int = 4;
/// `SA_BLOCK_MAX` — the pointers in one node.
const SA_BLOCK_MAX: usize = 1 << SA_BLOCK_BITS;
/// `SA_BLOCK_MASK` — the level mask.
const SA_BLOCK_MASK: usize = SA_BLOCK_MAX - 1;
/// `SA_BLOCK_MAX_LEVELS` — `(sizeof(ossl_uintmax_t) * 8 + bits - 1) / bits`.
///
/// The ceiling division is written as the authority writes it rather than as `div_ceil`:
/// this constant is a transcription of a macro, and the arithmetic is the thing a reader
/// compares against `crypto/sparse_array.c`.
#[allow(clippy::manual_div_ceil)]
const SA_BLOCK_MAX_LEVELS: usize = (64 + SA_BLOCK_BITS as usize - 1) / SA_BLOCK_BITS as usize;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/sparse_array.c".as_ptr();

/// `OPENSSL_zalloc(sizeof(*res))` in `ossl_sa_new`.
const L_SA_NEW: c_int = 60;
/// `sa_free_node`'s `OPENSSL_free(p)`.
const L_SA_FREE_NODE: c_int = 102;
/// `sa_free_leaf`'s `OPENSSL_free(p)`.
const L_SA_FREE_LEAF: c_int = 107;
/// `ossl_sa_free`'s and `ossl_sa_free_leaves`' `OPENSSL_free(sa)`.
const L_SA_FREE: c_int = 114;
/// `alloc_node`'s `OPENSSL_calloc(SA_BLOCK_MAX, sizeof(void *))`.
const L_ALLOC_NODE: c_int = 176;

/// `struct sparse_array_st` — `crypto/sparse_array.c`.
#[repr(C)]
pub(crate) struct OpenSslSa {
    /// The depth currently in use.
    pub(crate) levels: c_int,
    /// The largest index ever set. Never lowered.
    pub(crate) top: OsslUintMax,
    /// The number of non-NULL leaves.
    pub(crate) nelem: usize,
    /// The root node, or NULL for an array that has never been set.
    pub(crate) nodes: *mut *mut c_void,
}

/// `OPENSSL_SA *ossl_sa_new(void)`.
///
/// Zeroed, so `levels` is 0, `top` is 0, `nelem` is 0 and `nodes` is NULL: an array with no
/// root, which `ossl_sa_get` short-circuits on and `ossl_sa_set` grows from.
#[allow(dead_code)] // unreachable until 6.10a-ii's `_ex` tables are built from it
pub(crate) fn ossl_sa_new() -> *mut OpenSslSa {
    // `CRYPTO_zalloc` is a SAFE function in this crate (D113), so this is unguarded.
    CRYPTO_zalloc(core::mem::size_of::<OpenSslSa>(), FILE, L_SA_NEW).cast::<OpenSslSa>()
}

/// `static ossl_inline void **alloc_node(void)`.
fn alloc_node() -> *mut *mut c_void {
    CRYPTO_calloc(
        SA_BLOCK_MAX,
        core::mem::size_of::<*mut c_void>(),
        FILE,
        L_ALLOC_NODE,
    )
    .cast::<*mut c_void>()
}

/// `static void sa_doall(const OPENSSL_SA *sa, void (*node)(void **),
/// void (*leaf)(ossl_uintmax_t, void *, void *), void *arg)`.
///
/// The walk, with its two explicit stacks. `node`, when given, is called on every node the
/// walk **leaves** — including the root — and `leaf` on every non-NULL value.
///
/// The `else` branch's `idx` accumulation is the part worth reading twice: on descent the
/// index of the child is `(idx & !MASK) | n`, then the whole thing shifts left; on ascent it
/// shifts **right**, which is what puts the parent's index back. A transcription that shifted
/// on only one side would visit the leaves in a different order and hit different addresses.
///
/// # Safety
/// `sa` must be live. `node` and `leaf` must be valid for the pointers they are handed.
unsafe fn sa_doall(
    sa: *const OpenSslSa,
    node: Option<unsafe fn(*mut *mut c_void)>,
    leaf: Option<unsafe fn(OsslUintMax, *mut c_void, *mut c_void)>,
    arg: *mut c_void,
) {
    let mut i = [0usize; SA_BLOCK_MAX_LEVELS];
    let mut nodes = [ptr::null_mut::<*mut c_void>(); SA_BLOCK_MAX_LEVELS];
    let mut idx: OsslUintMax = 0;
    let mut l: c_int = 0;

    i[0] = 0;
    // SAFETY: `sa` is live per this function's contract.
    nodes[0] = unsafe { (*sa).nodes };

    while l >= 0 {
        let li = l as usize;
        let n = i[li];
        let p = nodes[li];

        if n >= SA_BLOCK_MAX {
            if !p.is_null() {
                if let Some(f) = node {
                    // SAFETY: `p` is a node this structure allocated.
                    unsafe { f(p) };
                }
            }
            l -= 1;
            idx >>= SA_BLOCK_BITS;
        } else {
            i[li] = n + 1;
            if !p.is_null() {
                // SAFETY: `p` is a live node of `SA_BLOCK_MAX` pointers and the branch's own
                // test established `n < SA_BLOCK_MAX`, so the read is in bounds.
                let child = unsafe { *p.add(n) };
                if !child.is_null() {
                    idx = (idx & !(SA_BLOCK_MASK as OsslUintMax)) | n as OsslUintMax;
                    // SAFETY: the level is bounded by `sa->levels`, which `set` maintains and
                    // which cannot exceed `SA_BLOCK_MAX_LEVELS`.
                    if (l as usize) < unsafe { (*sa).levels } as usize - 1 {
                        l += 1;
                        i[l as usize] = 0;
                        nodes[l as usize] = child.cast::<*mut c_void>();
                        idx <<= SA_BLOCK_BITS;
                    } else if let Some(f) = leaf {
                        // SAFETY: `child` is a leaf value this structure holds, and `arg` is the
                        // caller's.
                        unsafe { f(idx, child, arg) };
                    }
                }
            }
        }
    }
}

/// `static void sa_free_node(void **p)`.
///
/// # Safety
/// `p` must be NULL or a node from this module.
unsafe fn sa_free_node(p: *mut *mut c_void) {
    // SAFETY: `p` is a node from this module, per the contract.
    unsafe { CRYPTO_free(p.cast::<c_void>(), FILE, L_SA_FREE_NODE) };
}

/// `static void sa_free_leaf(ossl_uintmax_t n, void *p, void *arg)`.
///
/// # Safety
/// `p` must be NULL or an owned leaf.
unsafe fn sa_free_leaf(_n: OsslUintMax, p: *mut c_void, _arg: *mut c_void) {
    // SAFETY: `p` is an owned leaf, per the contract. `ossl_sa_free_leaves` is documented as
    // releasing the values too, which is why a caller that does not own them must not use it.
    unsafe { CRYPTO_free(p, FILE, L_SA_FREE_LEAF) };
}

/// `void ossl_sa_free(OPENSSL_SA *sa)`.
///
/// Releases the tree's **nodes only**: the values are the caller's. A NULL `sa` is accepted and
/// ignored, which is why every caller in the authority can free unconditionally.
///
/// # Safety
/// `sa` must be NULL or a live array this module produced, and the caller must not use it after.
#[allow(dead_code)] // unreachable until 6.10a-ii's tables are released
pub(crate) unsafe fn ossl_sa_free(sa: *mut OpenSslSa) {
    if sa.is_null() {
        return;
    }
    // SAFETY: `sa` is live per the contract.
    unsafe {
        sa_doall(sa, Some(sa_free_node), None, ptr::null_mut());
        CRYPTO_free(sa.cast::<c_void>(), FILE, L_SA_FREE);
    }
}

/// `void ossl_sa_free_leaves(OPENSSL_SA *sa)`.
///
/// As `ossl_sa_free`, and releases each **value** first. The order is the walk's order, and the
/// leaves are released by `sa_free_leaf` which ignores its index — so a caller cannot depend on
/// anything about which value is released when.
///
/// # Safety
/// `sa` must be NULL or a live array whose values this caller owns.
#[allow(dead_code)] // unreachable until a caller that owns its values lands
pub(crate) unsafe fn ossl_sa_free_leaves(sa: *mut OpenSslSa) {
    if sa.is_null() {
        return;
    }
    // SAFETY: `sa` is live per the contract.
    unsafe {
        sa_doall(sa, Some(sa_free_node), Some(sa_free_leaf), ptr::null_mut());
        CRYPTO_free(sa.cast::<c_void>(), FILE, L_SA_FREE);
    }
}

/// `void ossl_sa_doall(const OPENSSL_SA *sa, void (*leaf)(ossl_uintmax_t, void *))`.
///
/// In C this wraps the caller's leaf in a `struct trampoline_st` so the extra `arg` parameter
/// can be discarded. Here the null argument is passed straight through; see the module note.
///
/// # Safety
/// `sa` must be NULL or live; `leaf` valid for each value.
#[allow(dead_code)] // unreachable until a caller walks without an argument
pub(crate) unsafe fn ossl_sa_doall(
    sa: *const OpenSslSa,
    leaf: Option<unsafe fn(OsslUintMax, *mut c_void)>,
) {
    if sa.is_null() {
        return;
    }
    // SAFETY: `sa` is live per the contract.
    unsafe {
        sa_doall(
            sa,
            None,
            leaf.map(|f| {
                // The trampoline, without the struct: a leaf of one argument is called with the
                // second as NULL. Written as a cast rather than a closure so the function
                // pointer type matches `sa_doall`'s.
                core::mem::transmute::<
                    unsafe fn(OsslUintMax, *mut c_void),
                    unsafe fn(OsslUintMax, *mut c_void, *mut c_void),
                >(f)
            }),
            ptr::null_mut(),
        )
    }
}

/// `void ossl_sa_doall_arg(const OPENSSL_SA *sa, void (*leaf)(ossl_uintmax_t, void *, void *),
/// void *arg)`.
///
/// # Safety
/// `sa` must be NULL or live; `leaf` valid for each value; `arg` the caller's.
pub(crate) unsafe fn ossl_sa_doall_arg(
    sa: *const OpenSslSa,
    leaf: Option<unsafe fn(OsslUintMax, *mut c_void, *mut c_void)>,
    arg: *mut c_void,
) {
    if sa.is_null() {
        return;
    }
    // SAFETY: `sa` is live per the contract.
    unsafe { sa_doall(sa, None, leaf, arg) }
}

/// `size_t ossl_sa_num(const OPENSSL_SA *sa)`.
///
/// A NULL array is **0**, not an error: the count of a structure that does not exist is zero.
///
/// # Safety
/// `sa` must be NULL or live.
pub(crate) unsafe fn ossl_sa_num(sa: *const OpenSslSa) -> usize {
    if sa.is_null() {
        return 0;
    }
    // SAFETY: `sa` is live per the contract.
    unsafe { (*sa).nelem }
}

/// `void *ossl_sa_get(const OPENSSL_SA *sa, ossl_uintmax_t n)`.
///
/// The `n <= sa->top` test is a **short-circuit on the largest index ever set**, not a bound on
/// what is present, and an index above it answers NULL without walking — which is the point of
/// tracking `top` at all. An index at or below it walks `levels - 1` nodes and then reads the
/// leaf; a NULL on the way answers NULL.
///
/// # Safety
/// `sa` must be NULL or live.
pub(crate) unsafe fn ossl_sa_get(sa: *const OpenSslSa, n: OsslUintMax) -> *mut c_void {
    if sa.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `sa` is live per the contract.
    unsafe {
        if (*sa).nelem == 0 {
            return ptr::null_mut();
        }
        if n > (*sa).top {
            return ptr::null_mut();
        }
        let mut p = (*sa).nodes;
        let mut level = (*sa).levels - 1;
        while !p.is_null() && level > 0 {
            let i = ((n >> (SA_BLOCK_BITS * level)) & SA_BLOCK_MASK as OsslUintMax) as usize;
            // SAFETY: `p` is a live node of `SA_BLOCK_MAX` pointers and `i < SA_BLOCK_MAX`.
            p = (*p.add(i)).cast::<*mut c_void>();
            level -= 1;
        }
        if p.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `p` is a live node and `n & MASK < SA_BLOCK_MAX`.
        *p.add((n & SA_BLOCK_MASK as OsslUintMax) as usize)
    }
}

/// `int ossl_sa_set(OPENSSL_SA *sa, ossl_uintmax_t posn, void *val)`.
///
/// Three steps, and the middle one is the design decision: the depth is computed from the
/// **position** by shifting until the index is exhausted, then the tree is grown to that depth
/// by allocating a fresh root and pushing the old one into slot 0 — so growth is O(1) nodes and
/// the new root's other fifteen slots are empty. Only then does the walk allocate the nodes on
/// the path, and the `nelem` bookkeeping distinguishes a value being *placed* from one being
/// *replaced*.
///
/// **`val == NULL` is a removal, not an insertion of NULL.** The `nelem` decrement happens only
/// when a non-NULL slot is being cleared, and the slot is written either way.
///
/// **A failure part-way leaves the array usable but changed.** If `alloc_node` fails while
/// growing, `sa->levels` has already been incremented — the `for` loop's increment runs after
/// the body — so a later `set` walks one level deeper than the tree has nodes for, and
/// `sa->nodes` is the LAST successful root. The authority has exactly that shape and it is
/// reproduced rather than repaired: an allocation failure here is not a fault, and "the tree
/// may be one level short of what `levels` says" is a property a caller could observe.
///
/// # Safety
/// `sa` must be live. `val` is borrowed, never copied, and the caller owns it.
pub(crate) unsafe fn ossl_sa_set(sa: *mut OpenSslSa, posn: OsslUintMax, val: *mut c_void) -> c_int {
    if sa.is_null() {
        return 0;
    }
    let mut n = posn;
    let mut level: usize = 1;

    // The depth the position needs: shift until the index is exhausted.
    while level < SA_BLOCK_MAX_LEVELS {
        n >>= SA_BLOCK_BITS;
        if n == 0 {
            break;
        }
        level += 1;
    }

    // SAFETY: `sa` is live per the contract, so every field access and every node write below
    // is to storage this structure owns.
    unsafe {
        let mut levels = (*sa).levels as usize;
        while levels < level {
            let p = alloc_node();
            if p.is_null() {
                // The authority increments `levels` in the loop's own step, so a failure here
                // still leaves it raised. Reproduced.
                (*sa).levels = levels as c_int + 1;
                return 0;
            }
            // C writes `p[0] = sa->nodes` with an implicit `void **` to `void *`
            // conversion; the cast is Rust's spelling of the same store.
            *p = (*sa).nodes.cast::<c_void>();
            (*sa).nodes = p;
            levels += 1;
            (*sa).levels = levels as c_int;
        }
        if (*sa).top < posn {
            (*sa).top = posn;
        }

        let mut p = (*sa).nodes;
        let mut level = (*sa).levels as usize;
        while level > 1 {
            level -= 1;
            let i = ((posn >> (SA_BLOCK_BITS * level as c_int)) & SA_BLOCK_MASK as OsslUintMax)
                as usize;
            if (*p.add(i)).is_null() {
                let fresh = alloc_node();
                if fresh.is_null() {
                    return 0;
                }
                *p.add(i) = fresh.cast::<c_void>();
            }
            p = (*p.add(i)).cast::<*mut c_void>();
        }
        let slot = p.add((posn & SA_BLOCK_MASK as OsslUintMax) as usize);
        if val.is_null() && !(*slot).is_null() {
            (*sa).nelem -= 1;
        } else if !val.is_null() && (*slot).is_null() {
            (*sa).nelem += 1;
        }
        *slot = val;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leaf value that is not dereferenced: the array stores pointers and this module never
    /// looks inside them.
    fn leaf(n: u64) -> *mut c_void {
        n as usize as *mut c_void
    }

    /// A fresh array is empty, its `top` is 0, and every lookup answers NULL — including one
    /// far above `top`.
    #[test]
    fn a_fresh_array_answers_null_everywhere() {
        let sa = ossl_sa_new();
        assert!(!sa.is_null());
        // SAFETY: `sa` is the array just created.
        unsafe {
            assert_eq!(ossl_sa_num(sa), 0);
            assert_eq!(ossl_sa_get(sa, 0), ptr::null_mut());
            assert_eq!(ossl_sa_get(sa, 1), ptr::null_mut());
            assert_eq!(ossl_sa_get(sa, u64::MAX), ptr::null_mut());
            ossl_sa_free(sa);
        }
    }

    /// NULL is accepted by every entry point and behaves as the empty case. `ossl_sa_set` is
    /// the exception and answers 0, because there is nowhere to write.
    #[test]
    fn null_is_answered_rather_than_dereferenced() {
        // SAFETY: every one of these accepts NULL by contract.
        unsafe {
            assert_eq!(ossl_sa_num(ptr::null()), 0);
            assert_eq!(ossl_sa_get(ptr::null(), 7), ptr::null_mut());
            assert_eq!(ossl_sa_set(ptr::null_mut(), 7, leaf(1)), 0);
            ossl_sa_free(ptr::null_mut());
            ossl_sa_free_leaves(ptr::null_mut());
            ossl_sa_doall(ptr::null(), None);
            ossl_sa_doall_arg(ptr::null(), None, ptr::null_mut());
        }
    }

    /// `set` then `get` round-trips, `num` counts only non-NULL slots, and clearing with NULL
    /// decrements the count while `top` stays where it was raised.
    #[test]
    fn set_get_and_the_count_are_maintained_in_both_directions() {
        let sa = ossl_sa_new();
        assert!(!sa.is_null());
        // SAFETY: `sa` is live.
        unsafe {
            assert_eq!(ossl_sa_set(sa, 3, leaf(33)), 1);
            assert_eq!(ossl_sa_num(sa), 1);
            assert_eq!(ossl_sa_get(sa, 3), leaf(33));
            assert_eq!(ossl_sa_get(sa, 2), ptr::null_mut());
            // SAFETY: `sa` is live, so `top` is readable.
            assert_eq!((*sa).top, 3, "top is the largest index ever set");
            assert_eq!((*sa).levels, 1, "index 3 needs one level of four bits");

            // The same slot twice is a replacement, not a second element.
            assert_eq!(ossl_sa_set(sa, 3, leaf(44)), 1);
            assert_eq!(ossl_sa_num(sa), 1);
            assert_eq!(ossl_sa_get(sa, 3), leaf(44));

            // NULL clears, and the count follows. `top` does not.
            assert_eq!(ossl_sa_set(sa, 3, ptr::null_mut()), 1);
            assert_eq!(ossl_sa_num(sa), 0);
            assert_eq!(ossl_sa_get(sa, 3), ptr::null_mut());
            assert_eq!(
                (*sa).top,
                3,
                "top is never lowered, so lookups below it still walk"
            );
            // A NULL into an already-NULL slot does not decrement past zero.
            assert_eq!(ossl_sa_set(sa, 3, ptr::null_mut()), 1);
            assert_eq!(ossl_sa_num(sa), 0);
            ossl_sa_free(sa);
        }
    }

    /// A large index forces the tree deeper than one level, and the depth is the position's
    /// rather than the previous maximum's.
    #[test]
    fn a_deep_index_grows_the_tree_by_one_level_per_four_bits() {
        let sa = ossl_sa_new();
        assert!(!sa.is_null());
        // SAFETY: `sa` is live.
        unsafe {
            // 0x10 is the first index that needs a second level: 4 bits overflow.
            assert_eq!(ossl_sa_set(sa, 0x10, leaf(0x10)), 1);
            assert_eq!((*sa).levels, 2);
            assert_eq!(ossl_sa_get(sa, 0x10), leaf(0x10));
            assert_eq!(ossl_sa_get(sa, 0x00), ptr::null_mut());
            // 0x100 needs three.
            assert_eq!(ossl_sa_set(sa, 0x100, leaf(0x100)), 1);
            assert_eq!((*sa).levels, 3);
            assert_eq!(ossl_sa_get(sa, 0x100), leaf(0x100));
            assert_eq!(
                ossl_sa_get(sa, 0x10),
                leaf(0x10),
                "the earlier entry survived"
            );
            // The deepest index this configuration can address is the one that needs all
            // sixteen levels: `1 << 60` is the first index whose four-bit digits fill the
            // tree, and `(1 << 60) - 1` needs one fewer. The depth is the position's, so
            // these two differ by one level and the test pins both.
            let almost = (1u64 << 60) - 1;
            assert_eq!(ossl_sa_set(sa, almost, leaf(almost)), 1);
            assert_eq!((*sa).levels as usize, SA_BLOCK_MAX_LEVELS - 1);
            assert_eq!(ossl_sa_get(sa, almost), leaf(almost));

            let deepest = 1u64 << 60;
            assert_eq!(ossl_sa_set(sa, deepest, leaf(deepest)), 1);
            assert_eq!((*sa).levels as usize, SA_BLOCK_MAX_LEVELS);
            assert_eq!(ossl_sa_get(sa, deepest), leaf(deepest));
            // Everything set is still reachable through the deeper tree.
            assert_eq!(ossl_sa_get(sa, 0x10), leaf(0x10));
            assert_eq!(ossl_sa_get(sa, 0x100), leaf(0x100));
            assert_eq!(ossl_sa_get(sa, almost), leaf(almost));
            assert_eq!(ossl_sa_num(sa), 4, "0x10, 0x100, almost and deepest");
            ossl_sa_free(sa);
        }
    }

    /// The walk visits the leaves in **increasing index order**, and the indices it reports are
    /// the ones they were set at. That order is what makes `sa_doall` usable for a deterministic
    /// release, and it is a property of the `idx` arithmetic on both descent and ascent.
    #[test]
    fn the_walk_visits_leaves_in_increasing_index_order() {
        static SEEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        static COUNT: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

        unsafe extern "C" fn note(idx: OsslUintMax, val: *mut c_void) {
            // The value is the index it was set at, so this checks both halves at once.
            assert_eq!(val, leaf(idx), "the walk reported a mismatched value");
            let prev = SEEN.load(core::sync::atomic::Ordering::SeqCst);
            assert!(idx > prev, "the walk went backwards: {idx} after {prev}");
            SEEN.store(idx, core::sync::atomic::Ordering::SeqCst);
            COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }

        SEEN.store(0, core::sync::atomic::Ordering::SeqCst);
        COUNT.store(0, core::sync::atomic::Ordering::SeqCst);
        let sa = ossl_sa_new();
        assert!(!sa.is_null());
        // SAFETY: `sa` is live; the callback is this test's own.
        unsafe {
            for n in [5u64, 1, 300, 0x11, 2, 0xFF] {
                assert_eq!(ossl_sa_set(sa, n, leaf(n)), 1);
            }
            // SAFETY: `note` takes the two-argument leaf form.
            let f = core::mem::transmute::<
                unsafe extern "C" fn(OsslUintMax, *mut c_void),
                unsafe fn(OsslUintMax, *mut c_void),
            >(note);
            ossl_sa_doall(sa, Some(f));
            assert_eq!(COUNT.load(core::sync::atomic::Ordering::SeqCst), 6);
            ossl_sa_free(sa);
        }
    }

    /// `ossl_sa_doall_arg` reaches the caller's argument, and `ossl_sa_free_leaves` releases
    /// the values — which is why a caller that does not own them must not use it. The release
    /// itself is not directly observable, so what is pinned is that the walk reaches every
    /// value and that the node count is what `nelem` says.
    #[test]
    fn the_argument_reaches_every_leaf_and_free_leaves_walks_them_all() {
        static SUM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

        unsafe extern "C" fn add(idx: OsslUintMax, _val: *mut c_void, arg: *mut c_void) {
            let acc = arg.cast::<core::sync::atomic::AtomicU64>();
            // SAFETY: `arg` is the atomic this test passes.
            unsafe { (*acc).fetch_add(idx, core::sync::atomic::Ordering::SeqCst) };
        }

        SUM.store(0, core::sync::atomic::Ordering::SeqCst);
        let sa = ossl_sa_new();
        assert!(!sa.is_null());
        // SAFETY: `sa` is live; the callback is this test's own.
        unsafe {
            for n in [4u64, 5, 6] {
                let owned = crate::runtime::mem::CRYPTO_malloc(8, FILE, 0);
                assert!(!owned.is_null());
                assert_eq!(ossl_sa_set(sa, n, owned), 1);
            }
            assert_eq!(ossl_sa_num(sa), 3);
            let f = core::mem::transmute::<
                unsafe extern "C" fn(OsslUintMax, *mut c_void, *mut c_void),
                unsafe fn(OsslUintMax, *mut c_void, *mut c_void),
            >(add);
            ossl_sa_doall_arg(sa, Some(f), ptr::addr_of!(SUM).cast_mut().cast::<c_void>());
            assert_eq!(SUM.load(core::sync::atomic::Ordering::SeqCst), 15);
            ossl_sa_free_leaves(sa);
        }
    }
}
