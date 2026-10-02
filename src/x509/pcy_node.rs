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
//! * `ossl_policy_node_free` (`:127-130`) — `OPENSSL_free`.
//! * `ossl_policy_node_match` (`:137-156`) — the valid-policy or expected-policy-set match.
//!
//! These are `ossl_*` internal symbols the authority's version script hides from `libcrypto.so`
//! (no court can name one); they are reached only through [`X509_policy_check`], which the Phase
//! 11.2 court drives. `ossl_policy_node_free` and `ossl_policy_data_free` (in `pcy_data.rs`) are
//! now the crate-canonical destructors of their units, and `pcy_tree.rs` calls them instead of its
//! former private copies.
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

/// `static int node_cmp(const X509_POLICY_NODE *const *a, const X509_POLICY_NODE *const *b)` —
/// `crypto/x509/pcy_node.c:17-21`.
///
/// # Safety
///
/// The stack comparator contract: `a` and `b` point at element slots holding live
/// `X509_POLICY_NODE *`.
unsafe extern "C" fn node_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the comparator contract above; both elements are live node pointers.
    unsafe {
        let na = *(a.cast::<*const X509PolicyNode>());
        let nb = *(b.cast::<*const X509PolicyNode>());
        OBJ_cmp((*(*na).data).valid_policy, (*(*nb).data).valid_policy)
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
    let num = unsafe { OPENSSL_sk_num((*level).nodes) };
    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live node.
        let node = unsafe { OPENSSL_sk_value((*level).nodes, i) }.cast::<X509PolicyNode>();
        // SAFETY: `node` is live.
        if unsafe { (*node).parent }.cast_const() == parent {
            // SAFETY: `node` is live; its data is a live policy datum.
            if unsafe { OBJ_cmp((*(*node).data).valid_policy, id) } == 0 {
                return node;
            }
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
    if unsafe { (*tree).node_maximum > 0 && (*tree).node_count >= (*tree).node_maximum } {
        return core::ptr::null_mut();
    }

    // A fresh block of the node's own size, written below before it is read.
    let node = CRYPTO_zalloc(core::mem::size_of::<X509PolicyNode>(), FILE.as_ptr(), 0)
        .cast::<X509PolicyNode>();
    if node.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `node` is live and writable.
    unsafe {
        (*node).data = data;
        (*node).parent = parent;
    }

    let mut extra_data_error = false;
    if !level.is_null() {
        // SAFETY: `data` is live per the contract.
        if unsafe { OBJ_obj2nid((*data).valid_policy) } == NID_any_policy {
            // SAFETY: `level` is live.
            if !unsafe { (*level).anyPolicy }.is_null() {
                // SAFETY: `node` is owned here.
                unsafe { ossl_policy_node_free(node) };
                return core::ptr::null_mut();
            }
            // SAFETY: `level` is live and writable.
            unsafe { (*level).anyPolicy = node };
        } else {
            // SAFETY: `level` is live and writable.
            unsafe {
                if (*level).nodes.is_null() {
                    (*level).nodes = ossl_policy_node_cmp_new();
                }
                if (*level).nodes.is_null() {
                    raise_site(&PCY_NODE_85);
                    ossl_policy_node_free(node);
                    return core::ptr::null_mut();
                }
                if OPENSSL_sk_push((*level).nodes, node.cast::<c_void>()) == 0 {
                    raise_site(&PCY_NODE_89);
                    ossl_policy_node_free(node);
                    return core::ptr::null_mut();
                }
            }
        }
    }

    if extra_data != 0 {
        // SAFETY: `tree` is live and writable.
        unsafe {
            if (*tree).extra_data.is_null() {
                (*tree).extra_data = OPENSSL_sk_new_null();
            }
            if (*tree).extra_data.is_null() {
                raise_site(&PCY_NODE_99);
                extra_data_error = true;
            } else if OPENSSL_sk_push((*tree).extra_data, data.cast::<c_void>()) == 0 {
                raise_site(&PCY_NODE_103);
                extra_data_error = true;
            }
        }
        if extra_data_error {
            // SAFETY: `level` is NULL or live; `node` is owned here.
            unsafe {
                if !level.is_null() {
                    if (*level).anyPolicy == node {
                        (*level).anyPolicy = core::ptr::null_mut();
                    } else {
                        let _ = OPENSSL_sk_pop((*level).nodes);
                    }
                }
                ossl_policy_node_free(node);
            }
            return core::ptr::null_mut();
        }
    }

    // SAFETY: `tree` and `parent` are live here.
    unsafe {
        (*tree).node_count += 1;
        if !parent.is_null() {
            (*parent).nchild += 1;
        }
    }
    node
}

/// `void ossl_policy_node_free(X509_POLICY_NODE *node)` — `crypto/x509/pcy_node.c:127-130`.
///
/// # Safety
///
/// `node` must be NULL or a node this crate owns and has not already freed.
pub(crate) unsafe fn ossl_policy_node_free(node: *mut X509PolicyNode) {
    // SAFETY: `node` is NULL or an owned block per the contract.
    unsafe { CRYPTO_free(node.cast(), FILE.as_ptr(), 0) };
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
    // SAFETY: `node` is live per the contract.
    let x = unsafe { (*node).data };
    // SAFETY: `lvl` and `x` are live.
    if unsafe {
        ((*lvl).flags & X509_V_FLAG_INHIBIT_MAP) != 0
            || ((*x).flags & POLICY_DATA_FLAG_MAP_MASK) == 0
    } {
        // SAFETY: `x` is live.
        return c_int::from(unsafe { OBJ_cmp((*x).valid_policy, oid) } == 0);
    }
    // SAFETY: `x` is live.
    let num = unsafe { OPENSSL_sk_num((*x).expected_policy_set) };
    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live `ASN1_OBJECT`.
        let policy_oid =
            unsafe { OPENSSL_sk_value((*x).expected_policy_set, i) }.cast::<Asn1Object>();
        // SAFETY: `policy_oid` is live.
        if unsafe { OBJ_cmp(policy_oid, oid) } == 0 {
            return 1;
        }
    }
    0
}
