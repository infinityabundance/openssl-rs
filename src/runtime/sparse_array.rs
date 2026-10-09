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
//! ## The tree is an owned Rust value, not the authority's `void **`
//!
//! The authority keeps a heap tree of raw `void **` nodes and reaches a slot with pointer
//! arithmetic (`p[(n >> (bits * level)) & mask]`, `p.add(i)`). None of that is observable: the
//! type is opaque (`struct sparse_array_st`), it exports no symbol, and its only consumers
//! (`property/store.rs`, `rsa/ossl.rs`) hold the handle as a `*mut c_void` and never look
//! inside it. So the tree is modelled here as an **owned** value — a [`Node`] whose children are
//! `Box`es and whose deepest slots are the caller's raw values — and every descent is safe
//! indexing on that value. The node addresses, which C exposes only to its own `sa_free_node`,
//! are not part of any contract.
//!
//! The whole of the tree logic lives on the safe [`OpenSslSa`] methods below: the growth, the
//! descent, the leaf walk and the count are ordinary safe Rust with no raw pointer at all. Each
//! C entry point is then a thin **boundary** wrapper whose only unsafe operation is turning the
//! caller's opaque `*mut OpenSslSa` into a reference (and, for `doall`, calling the caller's own
//! leaf function pointer). The opaque handle and every entry point keep their signatures, so the
//! C-ABI-visible surface is unchanged.
//!
//! ## `sa_doall` visits in increasing index order
//!
//! It walks depth-first in **increasing index order**. The `idx` accumulation is the part to
//! read carefully: a node's slot `n` at depth `d` contributes nibble `n` at bit position
//! `4 * (d - 1)` from the bottom, so the top-level nibble is the high-order one — the same
//! selection `ossl_sa_get` makes. `ossl_sa_doall`'s order is what `CRYPTO_THREAD_clean_local`
//! relies on to release tables, and it is what a test can check.
//!
//! ## What is not a behaviour
//!
//! `struct trampoline_st` in C exists to launder a function-pointer cast past a compiler
//! warning: `ossl_sa_doall(sa, leaf)` wraps `leaf` in a struct so that `sa_doall` can call it
//! with an extra `arg`. This crate passes the leaf and a null argument straight through — the
//! same call sequence, without the warning workaround — so the two-argument walk is its own
//! function rather than a transmuted three-argument one. That is the only place in this file
//! where the C is not transcribed literally, and it is a C-language constraint rather than a
//! contract.
//!
//! ## The one recorded divergence
//!
//! The authority's `alloc_node` can return NULL, and `ossl_sa_set` reproduces the resulting
//! "one level short" tree. Here a node is a `Box`, so exhaustion aborts the process rather than
//! returning NULL, and that arm is unreachable — the same divergence `runtime/lhash.rs`
//! records for its own allocation-failure arm, and for the same reason: no test, court or
//! downstream workload installs a failing allocator, so nothing measures the path.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::runtime::mem::CRYPTO_free;

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

/// `sa_free_leaf`'s `OPENSSL_free(p)`.
const L_SA_FREE_LEAF: c_int = 107;

/// One node of the sixteen-way tree.
///
/// A node holds `SA_BLOCK_MAX` slots, and the slot type is fixed by the node's **depth**: the
/// deepest node's slots are the caller's values, and every node above it holds its children.
/// The authority spells both as one `void **` because C has no variant type; here the two
/// shapes are two variants of one owned type, so a child is an owned `Box` and a value is the
/// caller's pointer and nothing is reached by arithmetic.
enum Node {
    /// A node holding children (depth > 1).
    Branch([Option<Box<Node>>; SA_BLOCK_MAX]),
    /// The deepest node: its slots are the caller's values.
    Leaf([*mut c_void; SA_BLOCK_MAX]),
}

impl Node {
    /// The node shape for `depth`: a leaf array at depth 1, a branch above it. Slots start NULL,
    /// as the authority's `OPENSSL_calloc` leaves them.
    fn at_depth(depth: usize) -> Node {
        if depth <= 1 {
            Node::Leaf([ptr::null_mut(); SA_BLOCK_MAX])
        } else {
            Node::Branch(core::array::from_fn(|_| None))
        }
    }

    /// The leaf slot `posn` addresses, from a node whose depth is `level`, allocating the branch
    /// nodes on the path.
    ///
    /// This is the authority's `p = p[(posn >> (bits * (level - 1))) & mask]` descent, but as
    /// safe indexing on an owned tree: a missing child is created in place and no pointer is
    /// computed.
    fn leaf_slot(&mut self, level: usize, posn: OsslUintMax) -> &mut *mut c_void {
        if level <= 1 {
            return match self {
                Node::Leaf(slots) => &mut slots[(posn & SA_BLOCK_MASK as OsslUintMax) as usize],
                // A depth-1 node is always a leaf; the growth below keeps that invariant.
                Node::Branch(_) => unreachable!("a depth-1 node is a leaf array"),
            };
        }
        let i = ((posn >> (SA_BLOCK_BITS as usize * (level - 1))) & SA_BLOCK_MASK as OsslUintMax)
            as usize;
        match self {
            Node::Branch(children) => {
                let child = children[i].get_or_insert_with(|| Box::new(Node::at_depth(level - 1)));
                child.leaf_slot(level - 1, posn)
            }
            // A node above depth 1 is always a branch; the growth below keeps that invariant.
            Node::Leaf(_) => unreachable!("a node above depth 1 is a branch"),
        }
    }

    /// Call `f(idx, value)` for every non-NULL value under this node, whose subtree covers the
    /// indices sharing `prefix`'s high nibbles.
    ///
    /// The slots are visited `0..SA_BLOCK_MAX`, and a parent's nibble is the higher-order one, so
    /// the walk reports **increasing** indices — the order `doall_util_fn` establishes.
    fn walk(&self, prefix: OsslUintMax, f: &mut impl FnMut(OsslUintMax, *mut c_void)) {
        match self {
            Node::Leaf(slots) => {
                for (n, &val) in slots.iter().enumerate() {
                    if !val.is_null() {
                        f((prefix << SA_BLOCK_BITS) | n as OsslUintMax, val);
                    }
                }
            }
            Node::Branch(children) => {
                for (n, child) in children.iter().enumerate() {
                    if let Some(c) = child {
                        c.walk((prefix << SA_BLOCK_BITS) | n as OsslUintMax, f);
                    }
                }
            }
        }
    }
}

/// Release one leaf value an owner handed to `ossl_sa_set`.
///
/// # Safety
/// `val` must be NULL or an owned pointer from the crate's allocator.
unsafe fn free_value(val: *mut c_void) {
    // SAFETY: `val` is an owned block per the contract.
    unsafe { CRYPTO_free(val, FILE, L_SA_FREE_LEAF) };
}

/// `struct sparse_array_st` — `crypto/sparse_array.c`.
///
/// Not `#[repr(C)]`: the type is opaque and its layout is never read from C. The three counters
/// are the observable fields (`sa->levels`, `sa->top`, `sa->nelem`); `root` is the owned tree,
/// the counterpart of the authority's raw `nodes`.
pub(crate) struct OpenSslSa {
    /// The depth currently in use.
    pub(crate) levels: c_int,
    /// The largest index ever set. Never lowered.
    pub(crate) top: OsslUintMax,
    /// The number of non-NULL leaves.
    pub(crate) nelem: usize,
    /// The root node, or `None` for an array that has never been set (the authority's NULL
    /// `nodes`).
    root: Option<Box<Node>>,
}

impl OpenSslSa {
    /// `size_t ossl_sa_num(const OPENSSL_SA *sa)`.
    fn num(&self) -> usize {
        self.nelem
    }

    /// `void *ossl_sa_get(const OPENSSL_SA *sa, ossl_uintmax_t n)`.
    ///
    /// The `n <= sa->top` test is a **short-circuit on the largest index ever set**, not a bound
    /// on what is present, and an index above it answers NULL without walking — which is the
    /// point of tracking `top` at all. An index at or below it walks `levels - 1` nodes and then
    /// reads the leaf; a NULL on the way answers NULL.
    fn get(&self, n: OsslUintMax) -> *mut c_void {
        if self.nelem == 0 || n > self.top {
            return ptr::null_mut();
        }
        let Some(mut node) = self.root.as_deref() else {
            return ptr::null_mut();
        };
        let mut level = self.levels - 1;
        while level > 0 {
            let i = ((n >> (SA_BLOCK_BITS * level)) & SA_BLOCK_MASK as OsslUintMax) as usize;
            let Node::Branch(children) = node else {
                return ptr::null_mut();
            };
            match children[i].as_deref() {
                Some(child) => node = child,
                None => return ptr::null_mut(),
            }
            level -= 1;
        }
        match node {
            Node::Leaf(slots) => slots[(n & SA_BLOCK_MASK as OsslUintMax) as usize],
            // A node at the leaf level is always a leaf; unreachable by the growth invariant.
            Node::Branch(_) => ptr::null_mut(),
        }
    }

    /// `int ossl_sa_set(OPENSSL_SA *sa, ossl_uintmax_t posn, void *val)`.
    ///
    /// Three steps, and the middle one is the design decision: the depth is computed from the
    /// **position** by shifting until the index is exhausted, then the tree is grown to that
    /// depth by allocating a fresh root and pushing the old one into slot 0 — so growth is O(1)
    /// nodes and the new root's other fifteen slots are empty. Only then does the walk allocate
    /// the nodes on the path, and the `nelem` bookkeeping distinguishes a value being *placed*
    /// from one being *replaced*.
    ///
    /// **`val == NULL` is a removal, not an insertion of NULL.** The `nelem` decrement happens
    /// only when a non-NULL slot is being cleared, and the slot is written either way.
    fn set(&mut self, posn: OsslUintMax, val: *mut c_void) {
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

        // Grow conservatively: each new root pushes the old one into slot 0, and its depth
        // selects the node shape (a branch above depth 1, a leaf array at depth 1).
        while (self.levels as usize) < level {
            let depth = self.levels as usize + 1;
            if depth <= 1 {
                self.root = Some(Box::new(Node::at_depth(1)));
            } else {
                let old = self.root.take();
                let mut slots: [Option<Box<Node>>; SA_BLOCK_MAX] = core::array::from_fn(|_| None);
                slots[0] = old;
                self.root = Some(Box::new(Node::Branch(slots)));
            }
            self.levels = depth as c_int;
        }
        if self.top < posn {
            self.top = posn;
        }

        let levels = self.levels as usize;
        // `self.levels` is at least 1 after the growth above, so the root exists.
        let root = self.root.as_deref_mut().expect("a grown array has a root");
        let slot = root.leaf_slot(levels, posn);
        if val.is_null() {
            if !slot.is_null() {
                self.nelem -= 1;
            }
        } else if slot.is_null() {
            self.nelem += 1;
        }
        *slot = val;
    }

    /// The leaf walk of `sa_doall`/`sa_doall_arg`/`ossl_sa_free_leaves`, in increasing index
    /// order.
    fn for_each_leaf(&self, f: &mut impl FnMut(OsslUintMax, *mut c_void)) {
        if let Some(root) = self.root.as_deref() {
            root.walk(0, f);
        }
    }

    /// `void ossl_sa_free_leaves(OPENSSL_SA *sa)`: release each stored value, in walk order.
    fn free_leaves(&self) {
        self.for_each_leaf(&mut |_idx, val| {
            // SAFETY: every value was handed to `ossl_sa_set` by an owner, which is the contract
            // `ossl_sa_free_leaves` states.
            unsafe { free_value(val) };
        });
    }
}

/// `OPENSSL_SA *ossl_sa_new(void)`.
///
/// Zeroed, so `levels` is 0, `top` is 0, `nelem` is 0 and the root is `None`: an array with no
/// root, which `ossl_sa_get` short-circuits on and `ossl_sa_set` grows from.
#[allow(dead_code)] // unreachable until 6.10a-ii's `_ex` tables are built from it
pub(crate) fn ossl_sa_new() -> *mut OpenSslSa {
    // The authority `OPENSSL_zalloc`s the header; here it is a boxed Rust value, so no manual
    // initialisation is needed and the tree it owns needs no separate release.
    Box::into_raw(Box::new(OpenSslSa {
        levels: 0,
        top: 0,
        nelem: 0,
        root: None,
    }))
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
    // SAFETY: `sa` came from `ossl_sa_new`'s `Box::into_raw` and the caller releases it at most
    // once. Dropping the box drops `root`, which drops every node in the tree.
    drop(unsafe { Box::from_raw(sa) });
}

/// `void ossl_sa_free_leaves(OPENSSL_SA *sa)`.
///
/// As `ossl_sa_free`, and releases each **value** first. The order is the walk's order, and the
/// leaves are released here by a walk that ignores the index — so a caller cannot depend on
/// anything about which value is released when.
///
/// # Safety
/// `sa` must be NULL or a live array whose values this caller owns.
#[allow(dead_code)] // unreachable until a caller that owns its values lands
pub(crate) unsafe fn ossl_sa_free_leaves(sa: *mut OpenSslSa) {
    if sa.is_null() {
        return;
    }
    // SAFETY: `sa` is live per the contract, and the caller owns every value it holds.
    let s = unsafe { &*sa };
    s.free_leaves();
    // SAFETY: as `ossl_sa_free`; `s`'s borrow ends here.
    drop(unsafe { Box::from_raw(sa) });
}

/// `void ossl_sa_doall(const OPENSSL_SA *sa, void (*leaf)(ossl_uintmax_t, void *))`.
///
/// In C this wraps the caller's leaf in a `struct trampoline_st` so the extra `arg` parameter
/// can be discarded. Here the two-argument walk is passed straight through; see the module note.
///
/// # Safety
/// `sa` must be NULL or live; `leaf` valid for each value.
#[allow(dead_code)] // unreachable until a caller walks without an argument
pub(crate) unsafe fn ossl_sa_doall(
    sa: *const OpenSslSa,
    leaf: Option<unsafe fn(OsslUintMax, *mut c_void)>,
) {
    // SAFETY: `sa` is NULL or live per the contract.
    let Some(s) = (unsafe { sa.as_ref() }) else {
        return;
    };
    let Some(f) = leaf else {
        return;
    };
    s.for_each_leaf(&mut |idx, val| {
        // SAFETY: `f` is the caller's leaf, valid for every value it is handed.
        unsafe { f(idx, val) };
    });
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
    // SAFETY: `sa` is NULL or live per the contract.
    let Some(s) = (unsafe { sa.as_ref() }) else {
        return;
    };
    let Some(f) = leaf else {
        return;
    };
    s.for_each_leaf(&mut |idx, val| {
        // SAFETY: `f` is the caller's leaf, valid for every value it is handed, and `arg` is the
        // caller's.
        unsafe { f(idx, val, arg) };
    });
}

/// `size_t ossl_sa_num(const OPENSSL_SA *sa)`.
///
/// A NULL array is **0**, not an error: the count of a structure that does not exist is zero.
///
/// # Safety
/// `sa` must be NULL or live.
pub(crate) unsafe fn ossl_sa_num(sa: *const OpenSslSa) -> usize {
    // SAFETY: `sa` is NULL or live per the contract.
    match unsafe { sa.as_ref() } {
        Some(s) => s.num(),
        None => 0,
    }
}

/// `void *ossl_sa_get(const OPENSSL_SA *sa, ossl_uintmax_t n)`.
///
/// # Safety
/// `sa` must be NULL or live.
pub(crate) unsafe fn ossl_sa_get(sa: *const OpenSslSa, n: OsslUintMax) -> *mut c_void {
    // SAFETY: `sa` is NULL or live per the contract.
    match unsafe { sa.as_ref() } {
        Some(s) => s.get(n),
        None => ptr::null_mut(),
    }
}

/// `int ossl_sa_set(OPENSSL_SA *sa, ossl_uintmax_t posn, void *val)`.
///
/// # Safety
/// `sa` must be live. `val` is borrowed, never copied, and the caller owns it.
pub(crate) unsafe fn ossl_sa_set(sa: *mut OpenSslSa, posn: OsslUintMax, val: *mut c_void) -> c_int {
    // SAFETY: `sa` is NULL or live per the contract.
    match unsafe { sa.as_mut() } {
        Some(s) => {
            s.set(posn, val);
            1
        }
        None => 0,
    }
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
    /// release, and it is a property of the index arithmetic on descent.
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
