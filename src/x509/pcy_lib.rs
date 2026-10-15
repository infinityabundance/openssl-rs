//! `crypto/x509/pcy_lib.c` — the policy-tree accessors. Phase 10.12.
//!
//! `crypto/x509/pcy_lib.c` is 105 lines and **lands whole**. It is the read-only face of the
//! policy graph section 6 names: nine exported accessors over the four `pcy_local.h` structures
//! that `pcy_tree.c`/`pcy_cache.c`/`pcy_data.c` build (all 10.14's). Nothing in the unit is
//! withheld — every field it reads is a plain member of a structure this module is the canonical
//! definition for, and the only callee is `OPENSSL_sk_num`/`OPENSSL_sk_value`.
//!
//! `pcy_lib.c` itself never reads the fifth `pcy_local.h` structure, `X509_POLICY_CACHE` (the
//! cache `pcy_cache.c`'s `ossl_policy_cache_set` hangs off the certificate), but this module is
//! where the crate keeps the `pcy_local.h` layouts, so [`X509PolicyCache`] is defined here beside
//! the other four. Phase 11.2 added it: it is the layout `pcy_tree.rs`'s `X509_policy_check`
//! closure reads and writes through the `X509::policy_cache` `*mut c_void` slot.
//!
//! ## The structures
//!
//! `struct X509_POLICY_DATA_st`, `struct X509_POLICY_NODE_st`, `struct X509_POLICY_LEVEL_st` and
//! `struct X509_POLICY_TREE_st` are declared in `crypto/x509/pcy_local.h`; `X509_POLICY_DATA`'s
//! comment records why it holds no parent/child pointers (the main data can be cached with the
//! certificate) and `X509_POLICY_NODE` is what carries the relationship. Their offsets are the
//! `#[repr(C)]` ones the asserts below carry.
//!
//! ## The court
//!
//! None of the accessors can be handed a live tree — building one needs `X509_policy_check`
//! (`pcy_tree.c`, 10.14) — but every one has a NULL-input arm, and the authority's own guards make
//! those observable: `X509_policy_tree_level_count(NULL)` is 0, the three `get0` tree/level/node
//! readers answer NULL, and `X509_policy_level_node_count(NULL)` is 0. `RT-STORE`'s 10.12 arms
//! print all nine, so the functions are driven even though no tree exists.
//!
//! ## No raise, and the court
//!
//! The unit raises nothing, so it is deliberately not an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uint};

use crate::runtime::obj::Asn1Object;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::pcy_node::Node;
use crate::x509::x_x509::X509;

/// `#define POLICY_FLAG_ANY_POLICY 0x2` — `pcy_local.h`.
const POLICY_FLAG_ANY_POLICY: c_uint = 0x2;

/// `struct X509_POLICY_DATA_st` — `X509_POLICY_DATA`, from `crypto/x509/pcy_local.h:24-30`.
///
/// The Policy "node" of RFC 3280: the OID, its qualifiers and the expected policy set. It holds
/// no parent or child data, which is what lets the authority cache it with the certificate.
#[repr(C)]
pub struct X509PolicyData {
    /// `unsigned int flags` — the `POLICY_DATA_FLAG_*` word.
    pub(crate) flags: c_uint,
    /// `ASN1_OBJECT *valid_policy` — the policy OID.
    pub(crate) valid_policy: *mut Asn1Object,
    /// `STACK_OF(POLICYQUALINFO) *qualifier_set` — the qualifiers, or null.
    pub(crate) qualifier_set: *mut OpenSslStack,
    /// `STACK_OF(ASN1_OBJECT) *expected_policy_set` — the mapped set, or null.
    pub(crate) expected_policy_set: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<X509PolicyData>() == 32);
    assert!(core::mem::offset_of!(X509PolicyData, flags) == 0);
    assert!(core::mem::offset_of!(X509PolicyData, valid_policy) == 8);
    assert!(core::mem::offset_of!(X509PolicyData, qualifier_set) == 16);
    assert!(core::mem::offset_of!(X509PolicyData, expected_policy_set) == 24);
};

/// `struct X509_POLICY_NODE_st` — `X509_POLICY_NODE`, from `crypto/x509/pcy_local.h:82-90`.
///
/// The relationship between policy data: the data it refers to, its parent, and its child count.
#[repr(C)]
pub struct X509PolicyNode {
    /// `const X509_POLICY_DATA *data` — the data this node refers to.
    pub(crate) data: *const X509PolicyData,
    /// `X509_POLICY_NODE *parent` — the parent node, or null at a level's root.
    pub(crate) parent: *mut X509PolicyNode,
    /// `int nchild` — the number of child nodes.
    pub(crate) nchild: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<X509PolicyNode>() == 24);
    assert!(core::mem::offset_of!(X509PolicyNode, data) == 0);
    assert!(core::mem::offset_of!(X509PolicyNode, parent) == 8);
    assert!(core::mem::offset_of!(X509PolicyNode, nchild) == 16);
};

/// `struct X509_POLICY_LEVEL_st` — `X509_POLICY_LEVEL`, from `crypto/x509/pcy_local.h:92-104`.
#[repr(C)]
pub struct X509PolicyLevel {
    /// `X509 *cert` — the certificate for this level, or null for an extra level.
    pub(crate) cert: *mut X509,
    /// `STACK_OF(X509_POLICY_NODE) *nodes` — the non-anyPolicy nodes.
    pub(crate) nodes: *mut OpenSslStack,
    /// `X509_POLICY_NODE *anyPolicy` — the anyPolicy node, or null.
    pub(crate) anyPolicy: *mut X509PolicyNode,
    /// `unsigned int flags` — the level's flags.
    pub(crate) flags: c_uint,
}

const _: () = {
    assert!(core::mem::size_of::<X509PolicyLevel>() == 32);
    assert!(core::mem::offset_of!(X509PolicyLevel, cert) == 0);
    assert!(core::mem::offset_of!(X509PolicyLevel, nodes) == 8);
    assert!(core::mem::offset_of!(X509PolicyLevel, anyPolicy) == 16);
    assert!(core::mem::offset_of!(X509PolicyLevel, flags) == 24);
};

/// `struct X509_POLICY_TREE_st` — `X509_POLICY_TREE`, from `crypto/x509/pcy_local.h:106-124`.
#[repr(C)]
pub struct X509PolicyTree {
    /// `size_t node_count` — the number of nodes built.
    pub(crate) node_count: usize,
    /// `size_t node_maximum` — the CVE-2023-0464 node cap, or 0 for unlimited.
    pub(crate) node_maximum: usize,
    /// `X509_POLICY_LEVEL *levels` — the array of levels.
    pub(crate) levels: *mut X509PolicyLevel,
    /// `int nlevel` — the number of levels.
    pub(crate) nlevel: c_int,
    /// `STACK_OF(X509_POLICY_DATA) *extra_data` — extra policy data, or null.
    pub(crate) extra_data: *mut OpenSslStack,
    /// `STACK_OF(X509_POLICY_NODE) *auth_policies` — the authority-constrained set.
    pub(crate) auth_policies: *mut OpenSslStack,
    /// `STACK_OF(X509_POLICY_NODE) *user_policies` — the user-constrained set.
    pub(crate) user_policies: *mut OpenSslStack,
    /// `unsigned int flags` — the `POLICY_FLAG_*` word.
    pub(crate) flags: c_uint,
}

const _: () = {
    assert!(core::mem::size_of::<X509PolicyTree>() == 64);
    assert!(core::mem::offset_of!(X509PolicyTree, node_count) == 0);
    assert!(core::mem::offset_of!(X509PolicyTree, node_maximum) == 8);
    assert!(core::mem::offset_of!(X509PolicyTree, levels) == 16);
    assert!(core::mem::offset_of!(X509PolicyTree, nlevel) == 24);
    assert!(core::mem::offset_of!(X509PolicyTree, extra_data) == 32);
    assert!(core::mem::offset_of!(X509PolicyTree, auth_policies) == 40);
    assert!(core::mem::offset_of!(X509PolicyTree, user_policies) == 48);
    assert!(core::mem::offset_of!(X509PolicyTree, flags) == 56);
};

/// `struct X509_POLICY_CACHE_st` — `X509_POLICY_CACHE`, from `crypto/x509/pcy_local.h:65-82`.
///
/// The policy data cached with a certificate: its anyPolicy datum, the remaining data, and the
/// three extension skip counters (`-1` when the extension is absent). The certificate's
/// `policy_cache` member is a `*mut c_void` (`x_x509.rs`) because no landed unit needed the layout
/// until now; `pcy_cache.rs` casts it to this type.
#[repr(C)]
pub struct X509PolicyCache {
    /// `X509_POLICY_DATA *anyPolicy` — the anyPolicy data, or null.
    pub(crate) anyPolicy: *mut X509PolicyData,
    /// `STACK_OF(X509_POLICY_DATA) *data` — the other policy data.
    pub(crate) data: *mut OpenSslStack,
    /// `long any_skip` — inhibitAnyPolicy's value, or -1.
    pub(crate) any_skip: c_long,
    /// `long explicit_skip` — requireExplicitPolicy's value, or -1.
    pub(crate) explicit_skip: c_long,
    /// `long map_skip` — inhibitPolicyMapping's value, or -1.
    pub(crate) map_skip: c_long,
}

const _: () = {
    assert!(core::mem::size_of::<X509PolicyCache>() == 40);
    assert!(core::mem::offset_of!(X509PolicyCache, anyPolicy) == 0);
    assert!(core::mem::offset_of!(X509PolicyCache, data) == 8);
    assert!(core::mem::offset_of!(X509PolicyCache, any_skip) == 16);
    assert!(core::mem::offset_of!(X509PolicyCache, explicit_skip) == 24);
    assert!(core::mem::offset_of!(X509PolicyCache, map_skip) == 32);
};

// ---------------------------------------------------------------------------------------------
// The level array: the graph's one raw level-address boundary
// ---------------------------------------------------------------------------------------------

/// The level array a live policy tree owns, as a mutable slice — the walks' checked view.
///
/// The levels are one `CRYPTO_calloc` block ([`OwnedLevels`](crate::x509::pcy_tree)) whose element
/// addresses `X509_policy_tree_get0_level` hands out and the graph compares by value, so the block
/// itself stays raw and every level keeps a stable address for the tree's lifetime. This function
/// and [`level_ptr`] are the graph's **only** level-address arithmetic: a walk takes the slice once
/// and then indexes or iterates it (`levels[i]`, `split_at_mut`, `iter`), so no walk carries a
/// `*mut X509PolicyLevel` or steps one with `add`/`sub`.
///
/// # Safety
///
/// `tree` is a live policy tree, and no other borrow of its level array is live for the returned
/// slice's use.
pub(crate) unsafe fn tree_levels<'a>(tree: *const X509PolicyTree) -> &'a mut [X509PolicyLevel] {
    // SAFETY: `tree` is NULL or live per the contract; the borrow reads only the header's plain
    // `levels`/`nlevel` members.
    let Some(tree) = (unsafe { tree.as_ref() }) else {
        return &mut [];
    };
    // `levels`/`nlevel` describe the block `OwnedLevels` allocated and `tree_init` linked —
    // `nlevel` contiguous `X509PolicyLevel`s.
    let (base, nlevel) = (tree.levels, tree.nlevel);
    if base.is_null() || nlevel <= 0 {
        return &mut [];
    }
    // SAFETY: `base` is the live block of `nlevel` levels; the caller keeps it unaliased for the
    // slice's use.
    unsafe { core::slice::from_raw_parts_mut(base, nlevel as usize) }
}

/// The address of level `i`, checked against the tree's level count — the `get0` accessor's form.
///
/// Answers NULL when `tree` is NULL, `i` is out of range, or the array is absent. Unlike
/// [`tree_levels`] it forms no reference: the accessor's contract is a borrowed address, not an
/// exclusive borrow of the array.
///
/// # Safety
///
/// `tree` is NULL or a live policy tree.
pub(crate) unsafe fn level_ptr(tree: *const X509PolicyTree, i: c_int) -> *mut X509PolicyLevel {
    if i < 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: `tree` is NULL or live per the contract; the borrow reads only the header's plain
    // `levels`/`nlevel` members.
    let Some(tree) = (unsafe { tree.as_ref() }) else {
        return core::ptr::null_mut();
    };
    let (base, nlevel) = (tree.levels, tree.nlevel);
    if base.is_null() || i >= nlevel {
        return core::ptr::null_mut();
    }
    // SAFETY: `i` is in `0..nlevel`, the block's own range; this is the one element-address
    // computation the graph performs, kept here so no caller does it.
    unsafe { base.add(i as usize) }
}

// ---------------------------------------------------------------------------------------------
// `X509_POLICY_TREE` accessors — `crypto/x509/pcy_lib.c:20-52`
// ---------------------------------------------------------------------------------------------

/// `int X509_policy_tree_level_count(const X509_POLICY_TREE *tree)` —
/// `crypto/x509/pcy_lib.c:20-25`.
///
/// # Safety
///
/// `tree` is NULL or a live tree.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_tree_level_count(tree: *const X509PolicyTree) -> c_int {
    // SAFETY: `tree` is NULL or a live tree per the contract; the borrow reads the header's plain
    // `nlevel` member, and a NULL tree answers the authority's 0.
    match unsafe { tree.as_ref() } {
        Some(tree) => tree.nlevel,
        None => 0,
    }
}

/// `X509_POLICY_LEVEL *X509_policy_tree_get0_level(const X509_POLICY_TREE *tree, int i)` —
/// `crypto/x509/pcy_lib.c:27-33`.
///
/// # Safety
///
/// `tree` is NULL or a live tree.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_tree_get0_level(
    tree: *const X509PolicyTree,
    i: c_int,
) -> *mut X509PolicyLevel {
    // SAFETY: `tree` is NULL or live per the contract; the boundary checks `i` against `nlevel`.
    unsafe { level_ptr(tree, i) }
}

/// `STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_policies(const X509_POLICY_TREE *tree)` —
/// `crypto/x509/pcy_lib.c:35-41`.
///
/// # Safety
///
/// `tree` is NULL or a live tree.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_tree_get0_policies(
    tree: *const X509PolicyTree,
) -> *mut OpenSslStack {
    // SAFETY: `tree` is NULL or a live tree per the contract; the borrow reads the header's plain
    // `auth_policies` member — the borrowed set the accessor returns.
    match unsafe { tree.as_ref() } {
        Some(tree) => tree.auth_policies,
        None => core::ptr::null_mut(),
    }
}

/// `STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_user_policies(const X509_POLICY_TREE *tree)`
/// — `crypto/x509/pcy_lib.c:43-52`.
///
/// # Safety
///
/// `tree` is NULL or a live tree.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_tree_get0_user_policies(
    tree: *const X509PolicyTree,
) -> *mut OpenSslStack {
    // SAFETY: `tree` is NULL or a live tree per the contract.
    let Some(tree) = (unsafe { tree.as_ref() }) else {
        return core::ptr::null_mut();
    };
    if tree.flags & POLICY_FLAG_ANY_POLICY != 0 {
        tree.auth_policies
    } else {
        tree.user_policies
    }
}

// ---------------------------------------------------------------------------------------------
// `X509_POLICY_LEVEL` accessors — `crypto/x509/pcy_lib.c:56-80`
// ---------------------------------------------------------------------------------------------

/// `int X509_policy_level_node_count(X509_POLICY_LEVEL *level)` —
/// `crypto/x509/pcy_lib.c:56-68`.
///
/// The level is borrowed once and its fields read through the borrow, so the node-stack walk uses
/// no inline raw dereference.
///
/// # Safety
///
/// `level` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_level_node_count(level: *mut X509PolicyLevel) -> c_int {
    // SAFETY: `level` is NULL or live per the contract.
    let Some(level) = (unsafe { level.as_ref() }) else {
        return 0;
    };
    let mut n = if level.anyPolicy.is_null() { 0 } else { 1 };
    if !level.nodes.is_null() {
        // SAFETY: `level.nodes` is a live node stack.
        n += unsafe { OPENSSL_sk_num(level.nodes) };
    }
    n
}

/// `X509_POLICY_NODE *X509_policy_level_get0_node(const X509_POLICY_LEVEL *level, int i)` —
/// `crypto/x509/pcy_lib.c:70-80`.
///
/// The anyPolicy node, when present, is index 0; the remaining indices are offset by one into
/// `nodes`. The level is borrowed once, so the stack walk uses no inline raw dereference.
///
/// # Safety
///
/// `level` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_level_get0_node(
    level: *const X509PolicyLevel,
    mut i: c_int,
) -> *mut X509PolicyNode {
    // SAFETY: `level` is NULL or live per the contract.
    let Some(level) = (unsafe { level.as_ref() }) else {
        return core::ptr::null_mut();
    };
    if !level.anyPolicy.is_null() {
        if i == 0 {
            return level.anyPolicy;
        }
        i -= 1;
    }
    // SAFETY: `level.nodes` is a live node stack; an in-range `i` answers the node, an out-of-range
    // one NULL.
    unsafe { OPENSSL_sk_value(level.nodes, i) }.cast::<X509PolicyNode>()
}

// ---------------------------------------------------------------------------------------------
// `X509_POLICY_NODE` accessors — `crypto/x509/pcy_lib.c:84-105`
// ---------------------------------------------------------------------------------------------

/// `const ASN1_OBJECT *X509_policy_node_get0_policy(const X509_POLICY_NODE *node)` —
/// `crypto/x509/pcy_lib.c:84-89`.
///
/// # Safety
///
/// `node` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_node_get0_policy(
    node: *const X509PolicyNode,
) -> *const Asn1Object {
    // SAFETY: `node` is NULL or live per the contract; [`Node::of`] is this module's recorded raw
    // boundary — the one place the node pointer becomes a borrow — and the borrow does not outlive
    // the call. A NULL node answers the authority's NULL.
    let Some(node) = (unsafe { Node::of(node.cast_mut()) }) else {
        return core::ptr::null();
    };
    node.data.valid_policy
}

/// `STACK_OF(POLICYQUALINFO) *X509_policy_node_get0_qualifiers(const X509_POLICY_NODE *node)` —
/// `crypto/x509/pcy_lib.c:91-97`.
///
/// # Safety
///
/// `node` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_node_get0_qualifiers(
    node: *const X509PolicyNode,
) -> *mut OpenSslStack {
    // SAFETY: `node` is NULL or live per the contract; [`Node::of`] borrows the node and its datum
    // once, and the borrow does not outlive the call.
    let Some(node) = (unsafe { Node::of(node.cast_mut()) }) else {
        return core::ptr::null_mut();
    };
    node.data.qualifier_set
}

/// `const X509_POLICY_NODE *X509_policy_node_get0_parent(const X509_POLICY_NODE *node)` —
/// `crypto/x509/pcy_lib.c:99-105`.
///
/// # Safety
///
/// `node` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_node_get0_parent(
    node: *const X509PolicyNode,
) -> *const X509PolicyNode {
    // SAFETY: `node` is NULL or live per the contract; the borrow reads the node's plain `parent`
    // member (it needs no datum), so a NULL node answers the authority's NULL.
    let Some(node) = (unsafe { node.as_ref() }) else {
        return core::ptr::null();
    };
    node.parent
}
