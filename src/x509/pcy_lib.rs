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
    if tree.is_null() {
        return 0;
    }
    // SAFETY: `tree` is live per the contract.
    unsafe { (*tree).nlevel }
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
    // SAFETY: `tree` is NULL or live per the contract.
    unsafe {
        if tree.is_null() || i < 0 || i >= (*tree).nlevel {
            return core::ptr::null_mut();
        }
        (*tree).levels.add(i as usize)
    }
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
    if tree.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `tree` is live per the contract.
    unsafe { (*tree).auth_policies }
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
    // SAFETY: `tree` is NULL or live per the contract.
    unsafe {
        if tree.is_null() {
            return core::ptr::null_mut();
        }
        if (*tree).flags & POLICY_FLAG_ANY_POLICY != 0 {
            (*tree).auth_policies
        } else {
            (*tree).user_policies
        }
    }
}

// ---------------------------------------------------------------------------------------------
// `X509_POLICY_LEVEL` accessors — `crypto/x509/pcy_lib.c:56-80`
// ---------------------------------------------------------------------------------------------

/// `int X509_policy_level_node_count(X509_POLICY_LEVEL *level)` —
/// `crypto/x509/pcy_lib.c:56-68`.
///
/// # Safety
///
/// `level` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_level_node_count(level: *mut X509PolicyLevel) -> c_int {
    if level.is_null() {
        return 0;
    }
    // SAFETY: `level` is live per the contract.
    unsafe {
        let mut n = if (*level).anyPolicy.is_null() { 0 } else { 1 };
        if !(*level).nodes.is_null() {
            n += OPENSSL_sk_num((*level).nodes);
        }
        n
    }
}

/// `X509_POLICY_NODE *X509_policy_level_get0_node(const X509_POLICY_LEVEL *level, int i)` —
/// `crypto/x509/pcy_lib.c:70-80`.
///
/// The anyPolicy node, when present, is index 0; the remaining indices are offset by one into
/// `nodes`.
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
    unsafe {
        if level.is_null() {
            return core::ptr::null_mut();
        }
        if !(*level).anyPolicy.is_null() {
            if i == 0 {
                return (*level).anyPolicy;
            }
            i -= 1;
        }
        OPENSSL_sk_value((*level).nodes, i).cast::<X509PolicyNode>()
    }
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
    if node.is_null() {
        return core::ptr::null();
    }
    // SAFETY: `node` is live per the contract.
    unsafe { (*(*node).data).valid_policy }
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
    if node.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `node` is live per the contract.
    unsafe { (*(*node).data).qualifier_set }
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
    if node.is_null() {
        return core::ptr::null();
    }
    // SAFETY: `node` is live per the contract.
    unsafe { (*node).parent }
}
