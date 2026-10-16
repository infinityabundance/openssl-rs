//! Phase 11.2 — `crypto/x509/pcy_node.c`: the policy-tree node operations.
//!
//! `crypto/x509/pcy_node.c` is 157 lines and now **lands whole**. Its six functions were withheld
//! in Phase 10.12 because nothing landed reached them (`pcy_node.rs`'s old module doc: *"the only
//! authority callers are `pcy_cache.c`/`pcy_data.c`/`pcy_tree.c` (all 10.14) and `x509_vfy.c`
//! (Phase 11); nothing landed reaches them"*). This slice is that caller arriving:
//! [`X509_policy_check`](crate::x509::pcy_tree::X509_policy_check)'s `tree_init`/`tree_evaluate`
//! closure reaches all six.
//!
//! * `node_cmp` (`:17-21`) — the file-local comparator, `OBJ_cmp` over the nodes' policy OIDs.
//! * `ossl_policy_node_cmp_new` (`:23-26`) — a node stack carrying `node_cmp`.
//! * `ossl_policy_tree_find_sk` (`:28-40`) — a node stack lookup by OID.
//! * `ossl_policy_level_find_node` (`:42-56`) — a level lookup by parent and OID.
//! * `ossl_policy_level_add_node` (`:58-125`) — the CVE-2023-0464 node cap, the anyPolicy slot,
//!   the sorted node stack and the extra-data stack.
//! * `ossl_policy_node_free` (`:127-130`) — `OPENSSL_free`; here the release of an [`OwnedNode`].
//! * `ossl_policy_node_match` (`:137-156`) — the valid-policy or expected-policy-set match.
//!
//! These are `ossl_*` internal symbols the authority's version script hides from `libcrypto.so`
//! (no court can name one); they are reached only through [`X509_policy_check`], which the Phase
//! 11.2 court drives. `ossl_policy_node_free` and `ossl_policy_data_free` (in `pcy_data.rs`) are
//! now the crate-canonical destructors of their units, and `pcy_tree.rs` calls them instead of its
//! former private copies.
//!
//! ## Ownership
//!
//! The node block is owned by an [`OwnedNode`]: `ossl_policy_level_add_node` allocates it through
//! the crate's allocator seam and links its stable address, and every release (the level stack's
//! `pop_free`, an anyPolicy, `exnode_free`, a prune, an error path) drops the handle. No caller
//! writes a `CRYPTO_free` for a node. The block itself stays a `CRYPTO_zalloc` at the node's exact
//! size rather than a Rust `Box`, because the failure-injection differential refuses the first
//! 24-byte allocation of the check window to prove `ossl_policy_level_add_node` propagates NULL —
//! a `Box` allocates on Rust's global allocator, which the caller-installed hook does not observe.
//!
//! ## The raise sites
//!
//! `crypto/x509/pcy_node.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its four
//! `ERR_raise` coordinates (`:85`, `:89`, `:99`, `:103`) are **declared locally** in the
//! `err_sites::ErrSite` shape, as `v3_cpols.rs` does. The reasons are read from
//! `include/openssl/err.h.in`: `ERR_R_X509_LIB` and `ERR_R_CRYPTO_LIB`.
//!
//! [`X509_policy_check`]: crate::x509::pcy_tree::X509_policy_check
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_void, CStr};
use core::ptr::NonNull;

use crate::runtime::bio::ERR_R_CRYPTO_LIB;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::{Asn1Object, NID_any_policy, OBJ_cmp, OBJ_obj2nid};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::pcy_lib::{X509PolicyData, X509PolicyLevel, X509PolicyNode, X509PolicyTree};

/// `OPENSSL_FILE` for this unit's allocator expansions.
const FILE: &CStr = c"crypto/x509/pcy_node.c";

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_X509_LIB` — `err.h`, `(ERR_LIB_X509 | ERR_RFLAG_COMMON)`.
const ERR_R_X509_LIB: c_int = 11 | (0x2 << 18);

/// `POLICY_DATA_FLAG_MAP_MASK` — `crypto/x509/pcy_local.h:49`, `MAPPED | MAPPED_ANY`.
const POLICY_DATA_FLAG_MAP_MASK: u32 = 0x3;
/// `X509_V_FLAG_INHIBIT_MAP` — `include/openssl/x509_vfy.h.in:359`, `0x400`.
const X509_V_FLAG_INHIBIT_MAP: u32 = 0x400;

/// One `pcy_node.c` raise coordinate, declared locally (see the module doc).
const fn pcy_node_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/pcy_node.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `ossl_policy_level_add_node`'s failed `ossl_policy_node_cmp_new` at `pcy_node.c:85`.
const PCY_NODE_85: ErrSite = pcy_node_site(85, c"ossl_policy_level_add_node", ERR_R_X509_LIB);
/// `ossl_policy_level_add_node`'s failed node push at `pcy_node.c:89`.
const PCY_NODE_89: ErrSite = pcy_node_site(89, c"ossl_policy_level_add_node", ERR_R_CRYPTO_LIB);
/// `ossl_policy_level_add_node`'s failed extra-data stack at `pcy_node.c:99`.
const PCY_NODE_99: ErrSite = pcy_node_site(99, c"ossl_policy_level_add_node", ERR_R_CRYPTO_LIB);
/// `ossl_policy_level_add_node`'s failed extra-data push at `pcy_node.c:103`.
const PCY_NODE_103: ErrSite = pcy_node_site(103, c"ossl_policy_level_add_node", ERR_R_CRYPTO_LIB);

/// A live policy node together with its datum — the walks' checked view of one node.
///
/// The graph reaches nodes as raw pointers: a level's sorted stack element (`OPENSSL_sk_value`'s
/// `void *`) and a node's `parent` edge. [`Node::of`] is the node's recorded raw boundary — the one
/// place a `*mut X509PolicyNode` becomes a borrow — and a walk then reads the relationship fields
/// through the borrow (`node.nchild`, `node.parent`, `data.flags`, `data.valid_policy`,
/// `data.expected_policy_set`) instead of dereferencing a raw pointer inline.
///
/// A node the graph links always refers to a live datum (`ossl_policy_level_add_node` links a
/// non-NULL `data`), so [`Node::of`] answers `None` only for a NULL node or the defensive
/// NULL-`data` case the authority's `exnode_free` guards.
#[derive(Clone, Copy)]
pub(crate) struct Node<'a> {
    /// The `X509_POLICY_NODE` block itself.
    pub(crate) node: &'a X509PolicyNode,
    /// The policy datum the node refers to.
    pub(crate) data: &'a X509PolicyData,
}

impl<'a> Node<'a> {
    /// Borrow the node `raw` and its datum.
    ///
    /// # Safety
    ///
    /// `raw` is NULL or a live node this crate owns and has not freed, and the borrow does not
    /// outlive it; its `data` is a live datum.
    pub(crate) unsafe fn of(raw: *mut X509PolicyNode) -> Option<Node<'a>> {
        // SAFETY: `raw` is NULL or a live node per the contract.
        let node = unsafe { raw.as_ref() }?;
        // SAFETY: the node's `data` is NULL or a live datum per the contract.
        let data = unsafe { node.data.as_ref() }?;
        Some(Node { node, data })
    }

    /// The node's parent, exclusively borrowed, for the `nchild` maintenance the walks perform
    /// (`node->parent->nchild--`).
    ///
    /// The borrow is **mutation-derived**: the receiver is `&mut self`, and the returned reference's
    /// lifetime is tied to that borrow, so the compiler enforces that this `Node` value is
    /// exclusively borrowed while the parent is written and that the borrow cannot outlive the
    /// value. One `Node` therefore cannot hand out two conflicting `&mut` to the same parent.
    ///
    /// # Safety
    ///
    /// The `parent` edge is NULL or a live node, and no other borrow of that parent node is live.
    /// `Node` is `Copy`, so two `Node` values built from the same raw node — or from distinct links
    /// to a shared parent — remain a caller obligation: the graph's own walks keep one `Node` per
    /// node, and this method cannot prove that from the shared `&X509PolicyNode` it holds.
    pub(crate) unsafe fn parent_mut(&mut self) -> Option<&mut X509PolicyNode> {
        // The pointer is copied out first so the returned reference does not borrow the shared
        // `self.node` field; the `&mut self` receiver ties the result to this `Node` value.
        let parent = self.node.parent;
        // SAFETY: the parent edge is NULL or a live node per the contract.
        unsafe { parent.as_mut() }
    }
}

/// An owned policy-node block — the owner of one [`X509PolicyNode`].
///
/// The node keeps the authority's `#[repr(C)]` layout (the graph's links and the `get0` accessors
/// see that same address), but its *ownership* is this type: `new` allocates the block through the
/// crate's allocator seam and `Drop` is its single release, so no caller writes a `CRYPTO_free` for
/// a node and the release can never be performed with the wrong size or allocator.
///
/// The allocation stays on the `CRYPTO_*` seam rather than moving to a Rust `Box` on purpose: the
/// failure-injection differential refuses the first **24-byte** allocation of the check window (the
/// root anyPolicy node) to prove `ossl_policy_level_add_node` propagates NULL. A `Box` allocates on
/// Rust's global allocator, which a caller-installed `CRYPTO_set_mem_functions` hook does not
/// observe, so the refusal would never fire and the return word would diverge. The seam is the
/// residual raw boundary the freeze records; the ownership above it is Rust's.
struct OwnedNode {
    ptr: NonNull<X509PolicyNode>,
}

impl OwnedNode {
    /// Allocate a fresh node datum/parent block through the installed allocator, or `None` if it
    /// answers NULL (the authority's `CRYPTO_zalloc` answer).
    fn new(data: *mut X509PolicyData, parent: *mut X509PolicyNode) -> Option<OwnedNode> {
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block of
        // the node's size, which is exactly `X509PolicyNode`'s layout.
        let raw = CRYPTO_zalloc(core::mem::size_of::<X509PolicyNode>(), FILE.as_ptr(), 0)
            .cast::<X509PolicyNode>();
        let ptr = NonNull::new(raw)?;
        // SAFETY: `ptr` is a fresh, uniquely-owned, `X509PolicyNode`-sized block, so writing the
        // value into it in place initialises it before any read.
        unsafe {
            ptr.as_ptr().write(X509PolicyNode {
                data,
                parent,
                nchild: 0,
            })
        };
        Some(OwnedNode { ptr })
    }

    /// The stable address the graph links and the accessors hand back.
    fn as_ptr(&self) -> *mut X509PolicyNode {
        self.ptr.as_ptr()
    }

    /// Give up ownership of the block to the graph, answering its address.
    fn into_raw(self) -> *mut X509PolicyNode {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }

    /// Reclaim a block that was handed to the graph, for release by `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` must be NULL or a live block a previous `into_raw` gave up and `Drop` has not yet
    /// released.
    unsafe fn from_raw(ptr: *mut X509PolicyNode) -> Option<OwnedNode> {
        NonNull::new(ptr).map(|ptr| OwnedNode { ptr })
    }
}

impl Drop for OwnedNode {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block `new` allocated (or `from_raw` reclaimed), and this is its
        // single release; `Drop` runs once.
        unsafe { CRYPTO_free(self.ptr.as_ptr().cast(), FILE.as_ptr(), 0) };
    }
}

/// `static int node_cmp(const X509_POLICY_NODE *const *a, const X509_POLICY_NODE *const *b)` —
/// `crypto/x509/pcy_node.c:17-21`.
///
/// # Safety
///
/// The stack comparator contract: `a` and `b` point at element slots holding live
/// `X509_POLICY_NODE *`.
unsafe extern "C" fn node_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the comparator contract above; both element slots hold live node pointers.
    let (na, nb) = unsafe {
        (
            *(a.cast::<*const X509PolicyNode>()),
            *(b.cast::<*const X509PolicyNode>()),
        )
    };
    // SAFETY: both elements are live nodes; the graph links a live datum to each.
    match (unsafe { Node::of(na.cast_mut()) }, unsafe {
        Node::of(nb.cast_mut())
    }) {
        // SAFETY: each node's `data` is a live datum; `OBJ_cmp` reads only the two OIDs.
        (Some(x), Some(y)) => unsafe { OBJ_cmp(x.data.valid_policy, y.data.valid_policy) },
        // A NULL element or datum is outside the comparator contract (the graph links a live datum
        // to every node it sorts), so this arm is unreachable; it exists only to keep the Rust
        // total where the authority would fault.
        _ => 0,
    }
}

/// `STACK_OF(X509_POLICY_NODE) *ossl_policy_node_cmp_new(void)` — `crypto/x509/pcy_node.c:23-26`.
///
/// # Safety
///
/// The returned stack is owned by the caller and must be freed with `OPENSSL_sk_free`.
pub(crate) unsafe fn ossl_policy_node_cmp_new() -> *mut OpenSslStack {
    OPENSSL_sk_new(Some(node_cmp))
}

/// `X509_POLICY_NODE *ossl_policy_tree_find_sk(STACK_OF(X509_POLICY_NODE) *nodes, const ASN1_OBJECT *id)`
/// — `crypto/x509/pcy_node.c:28-40`.
///
/// A miss answers NULL (the stack's `find` returns -1, whose `value` is NULL).
///
/// # Safety
///
/// `nodes` is NULL or a live node stack; `id` is NULL or a live `ASN1_OBJECT`.
pub(crate) unsafe fn ossl_policy_tree_find_sk(
    nodes: *mut OpenSslStack,
    id: *const Asn1Object,
) -> *mut X509PolicyNode {
    let n = X509PolicyData {
        flags: 0,
        valid_policy: id as *mut Asn1Object,
        qualifier_set: core::ptr::null_mut(),
        expected_policy_set: core::ptr::null_mut(),
    };
    let l = X509PolicyNode {
        data: &raw const n,
        parent: core::ptr::null_mut(),
        nchild: 0,
    };
    // SAFETY: `nodes` is live per the contract; `&l` is the comparator's key element.
    let idx = unsafe { OPENSSL_sk_find(nodes, (&raw const l).cast::<c_void>()) };
    // SAFETY: `nodes` is live; a miss (`idx < 0`) answers NULL.
    unsafe { OPENSSL_sk_value(nodes, idx) }.cast::<X509PolicyNode>()
}

/// `X509_POLICY_NODE *ossl_policy_level_find_node(const X509_POLICY_LEVEL *level, const X509_POLICY_NODE *parent, const ASN1_OBJECT *id)`
/// — `crypto/x509/pcy_node.c:42-56`.
///
/// # Safety
///
/// `level` is live; `parent` is NULL or a live node; `id` is NULL or a live `ASN1_OBJECT`.
pub(crate) unsafe fn ossl_policy_level_find_node(
    level: *const X509PolicyLevel,
    parent: *const X509PolicyNode,
    id: *const Asn1Object,
) -> *mut X509PolicyNode {
    // SAFETY: `level` is live per the contract.
    let level = unsafe { &*level };
    // SAFETY: `level.nodes` is NULL or a live node stack.
    let num = unsafe { OPENSSL_sk_num(level.nodes) };
    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live node.
        let raw = unsafe { OPENSSL_sk_value(level.nodes, i) }.cast::<X509PolicyNode>();
        // SAFETY: `raw` is a live node; the graph links a live datum to it.
        let Some(node) = (unsafe { Node::of(raw) }) else {
            continue;
        };
        if node.node.parent.cast_const() == parent
            // SAFETY: `node`'s datum and `id` are live `ASN1_OBJECT`s.
            && unsafe { OBJ_cmp(node.data.valid_policy, id) } == 0
        {
            return raw;
        }
    }
    core::ptr::null_mut()
}

/// `X509_POLICY_NODE *ossl_policy_level_add_node(X509_POLICY_LEVEL *level, X509_POLICY_DATA *data, X509_POLICY_NODE *parent, X509_POLICY_TREE *tree, int extra_data)`
/// — `crypto/x509/pcy_node.c:58-125`.
///
/// The CVE-2023-0464 cap: once `tree->node_count` reaches `tree->node_maximum` the call fails.
/// A non-NULL `level` links the node either as the level's anyPolicy or into its sorted node
/// stack; `extra_data` also records the datum on the tree.
///
/// # Safety
///
/// `level` is NULL or a live level; `data` is a live datum; `parent` is NULL or a live node;
/// `tree` is live. The node is owned by the tree on success.
pub(crate) unsafe fn ossl_policy_level_add_node(
    level: *mut X509PolicyLevel,
    data: *mut X509PolicyData,
    parent: *mut X509PolicyNode,
    tree: *mut X509PolicyTree,
    extra_data: c_int,
) -> *mut X509PolicyNode {
    // SAFETY: `tree` is live per the contract.
    let tree = unsafe { &mut *tree };
    if tree.node_maximum > 0 && tree.node_count >= tree.node_maximum {
        return core::ptr::null_mut();
    }
    // SAFETY: `data` is a live datum per the contract.
    let data_ref = unsafe { &*data };

    // The node block, allocated through the crate's allocator seam and owned by this handle until
    // it is linked into the tree below. A refused allocation answers NULL, unchanged.
    let Some(node) = OwnedNode::new(data, parent) else {
        return core::ptr::null_mut();
    };
    let node_ptr = node.as_ptr();

    let mut extra_data_error = false;
    if !level.is_null() {
        // SAFETY: `level` is a live, writable level per the contract.
        let level = unsafe { &mut *level };
        // SAFETY: `data_ref`'s OID is a live `ASN1_OBJECT`.
        if unsafe { OBJ_obj2nid(data_ref.valid_policy) } == NID_any_policy {
            if !level.anyPolicy.is_null() {
                // The level already has an anyPolicy; `node` drops here, releasing the block.
                return core::ptr::null_mut();
            }
            level.anyPolicy = node_ptr;
        } else {
            if level.nodes.is_null() {
                // SAFETY: the new node stack is owned here.
                level.nodes = unsafe { ossl_policy_node_cmp_new() };
            }
            if level.nodes.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&PCY_NODE_85) };
                // `node` drops here, releasing the block.
                return core::ptr::null_mut();
            }
            // SAFETY: `level.nodes` is a live node stack; `node_ptr` is a live node.
            if unsafe { OPENSSL_sk_push(level.nodes, node_ptr.cast::<c_void>()) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&PCY_NODE_89) };
                // `node` drops here, releasing the block.
                return core::ptr::null_mut();
            }
        }
    }

    if extra_data != 0 {
        if tree.extra_data.is_null() {
            tree.extra_data = OPENSSL_sk_new_null();
        }
        if tree.extra_data.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&PCY_NODE_99) };
            extra_data_error = true;
        } else {
            // SAFETY: `tree.extra_data` is a live stack; `data` is the live datum.
            if unsafe { OPENSSL_sk_push(tree.extra_data, data.cast::<c_void>()) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&PCY_NODE_103) };
                extra_data_error = true;
            }
        }
        if extra_data_error {
            // SAFETY: `level` is NULL or a live level per the contract; unlink the node `node_ptr`
            // just linked.
            if !level.is_null() {
                // SAFETY: `level` is live and writable per the contract.
                let level = unsafe { &mut *level };
                if level.anyPolicy == node_ptr {
                    level.anyPolicy = core::ptr::null_mut();
                } else {
                    // SAFETY: `level.nodes` is the live stack `node_ptr` was pushed onto.
                    let _ = unsafe { OPENSSL_sk_pop(level.nodes) };
                }
            }
            // `node` drops here, releasing the block, the authority's `goto err`.
            return core::ptr::null_mut();
        }
    }

    tree.node_count += 1;
    // SAFETY: `parent` is NULL or a live node per the contract.
    if let Some(parent) = unsafe { parent.as_mut() } {
        parent.nchild += 1;
    }
    // Ownership transfers to the graph: the level stack and the `get0` accessors hold `node_ptr`, and
    // `ossl_policy_node_free` reclaims it through `OwnedNode`.
    node.into_raw()
}

/// `void ossl_policy_node_free(X509_POLICY_NODE *node)` — `crypto/x509/pcy_node.c:127-130`.
///
/// A NULL node is a no-op; otherwise the block is reclaimed through [`OwnedNode`], whose `Drop` is
/// the single release.
///
/// # Safety
///
/// `node` must be NULL or a node this crate owns and has not already freed.
pub(crate) unsafe fn ossl_policy_node_free(node: *mut X509PolicyNode) {
    // SAFETY: `node` is NULL or an owned block per the contract; `OwnedNode`'s `Drop` releases it.
    drop(unsafe { OwnedNode::from_raw(node) });
}

/// `int ossl_policy_node_match(const X509_POLICY_LEVEL *lvl, const X509_POLICY_NODE *node, const ASN1_OBJECT *oid)`
/// — `crypto/x509/pcy_node.c:137-156`.
///
/// With mapping inhibited or the node unmapped, the valid policy is compared; otherwise the
/// expected-policy set is searched.
///
/// # Safety
///
/// `lvl` is live; `node` is live; `oid` is NULL or a live `ASN1_OBJECT`.
pub(crate) unsafe fn ossl_policy_node_match(
    lvl: *const X509PolicyLevel,
    node: *const X509PolicyNode,
    oid: *const Asn1Object,
) -> c_int {
    // SAFETY: `lvl` is live per the contract.
    let lvl = unsafe { &*lvl };
    // SAFETY: `node` is a live node; the graph links a live datum to it.
    let Some(node) = (unsafe { Node::of(node.cast_mut()) }) else {
        return 0;
    };
    let x = node.data;
    if (lvl.flags & X509_V_FLAG_INHIBIT_MAP) != 0 || (x.flags & POLICY_DATA_FLAG_MAP_MASK) == 0 {
        // SAFETY: `x`'s valid policy and `oid` are live `ASN1_OBJECT`s.
        return c_int::from(unsafe { OBJ_cmp(x.valid_policy, oid) } == 0);
    }
    // SAFETY: `x.expected_policy_set` is NULL or a live stack.
    let num = unsafe { OPENSSL_sk_num(x.expected_policy_set) };
    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live `ASN1_OBJECT`.
        let policy_oid = unsafe { OPENSSL_sk_value(x.expected_policy_set, i) }.cast::<Asn1Object>();
        // SAFETY: `policy_oid` and `oid` are live.
        if unsafe { OBJ_cmp(policy_oid, oid) } == 0 {
            return 1;
        }
    }
    0
}
