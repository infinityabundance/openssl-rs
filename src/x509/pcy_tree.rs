//! `crypto/x509/pcy_tree.c` — the RFC 5280 policy tree. Phase 11.2's third unit. **This slice now
//! lands [`X509_policy_tree_free`] and [`X509_policy_check`] with the whole graph between them.**
//!
//! `crypto/x509/pcy_tree.c` is 726 lines and publishes two exports plus the file-local graph that
//! [`X509_policy_check`] drives.
//!
//! ## The graph lands
//!
//! * `tree_init` (`:98-255`) — sets up the policy cache in every non-trust-anchor certificate,
//!   counts `explicit_policy` down, decides empty/invalid, then allocates the tree and its levels
//!   with the anyPolicy root and the per-level inhibit flags.
//! * `tree_link_matching_nodes` (`:260-282`), `tree_link_nodes` (`:290-304`),
//!   `tree_add_unmatched` (`:312-336`), `tree_link_unmatched` (`:341-371`) and
//!   `tree_link_any` (`:376-394`) — RFC 5280 6.1.3(d), the level-linking pass.
//! * `tree_prune` (`:406-449`) — RFC 5280 6.1.4, the prune pass.
//! * `tree_add_auth_node` (`:454-462`), `tree_calculate_authority_set` (`:480-524`) and
//!   `tree_calculate_user_set` (`:529-592`) — RFC 5280 6.1.5, the two output sets.
//! * `tree_evaluate` (`:600-620`) — the linking/pruning driver.
//! * `exnode_free` (`:622-626`) and [`X509_policy_tree_free`] (`:628-648`) — the destructors.
//! * [`X509_policy_check`] (`:658-726`) — the entry point, returning the `X509_PCY_TREE_*` word.
//!
//! Its closure is now met: the two destructors it names moved to their authority units
//! (`ossl_policy_node_free` in `pcy_node.rs`, `ossl_policy_data_free` in `pcy_data.rs`), the cache
//! it reads is `pcy_cache.rs`'s, and the six node operations are `pcy_node.rs`'s. `X509_self_signed`
//! is not involved here; `X509_check_purpose`/`X509_get_extension_flags`/`X509_up_ref`/`X509_free`
//! are landed. The one authority callee **not** transcribed is the trace macro `TREE_PRINT`
//! (`:84-89`) and its `tree_print`/`expected_print` bodies (`:30-82`): the admitted build defines
//! `OPENSSL_NO_TRACE` (`configuration.h:134-135`), so `OSSL_TRACE_BEGIN*` expands to nothing and the
//! two bodies are unreachable dead code with no caller but the macro. They are omitted with this
//! sentence as their record (the same treatment `evp_cnf.rs`/`rand_lib.rs` give their traces); no
//! runtime behaviour differs.
//!
//! ## No raise
//!
//! The landed unit raises nothing of its own, so it is not an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`. The `ERR_raise` sites are in `pcy_cache.c`,
//! `pcy_data.c` and `pcy_node.c`, declared locally in those units.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_uint, c_void, CStr};

use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::{Asn1Object, NID_any_policy, OBJ_nid2obj, OBJ_obj2nid};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::pcy_cache::ossl_policy_cache_set;
use crate::x509::pcy_data::{ossl_policy_data_free, ossl_policy_data_new, policy_data_free_void};
use crate::x509::pcy_lib::{
    X509PolicyCache, X509PolicyData, X509PolicyLevel, X509PolicyNode, X509PolicyTree,
};
use crate::x509::pcy_node::{
    ossl_policy_level_add_node, ossl_policy_level_find_node, ossl_policy_node_cmp_new,
    ossl_policy_node_free, ossl_policy_node_match, ossl_policy_tree_find_sk,
};
use crate::x509::v3_purp::{X509_check_purpose, X509_get_extension_flags};
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_x509::{X509_free, X509};

/// `OPENSSL_FILE` for this unit's allocator expansions.
const FILE: &CStr = c"crypto/x509/pcy_tree.c";

/// `OPENSSL_POLICY_TREE_NODES_MAX` — `crypto/x509/pcy_tree.c:25`, the CVE-2023-0464 cap.
const OPENSSL_POLICY_TREE_NODES_MAX: usize = 1000;

/// `POLICY_DATA_FLAG_MAPPED` — `crypto/x509/pcy_local.h:38`.
const POLICY_DATA_FLAG_MAPPED: u32 = 0x1;
/// `POLICY_DATA_FLAG_MAP_MASK` — `crypto/x509/pcy_local.h:49`, `MAPPED | MAPPED_ANY`.
const POLICY_DATA_FLAG_MAP_MASK: u32 = 0x3;
/// `POLICY_DATA_FLAG_SHARED_QUALIFIERS` — `crypto/x509/pcy_local.h:53`, `0x4`.
const POLICY_DATA_FLAG_SHARED_QUALIFIERS: u32 = 0x4;
/// `POLICY_DATA_FLAG_EXTRA_NODE` — `crypto/x509/pcy_local.h:57`, `0x8`.
const POLICY_DATA_FLAG_EXTRA_NODE: u32 = 0x8;
/// `POLICY_DATA_FLAG_CRITICAL` — `crypto/x509/pcy_local.h:61`, `0x10`.
const POLICY_DATA_FLAG_CRITICAL: u32 = 0x10;
/// `POLICY_FLAG_ANY_POLICY` — `crypto/x509/pcy_local.h:134`, `0x2`.
const POLICY_FLAG_ANY_POLICY: u32 = 0x2;

/// `EXFLAG_SI` — `include/openssl/x509v3.h:434`, self-issued.
const EXFLAG_SI: u32 = 0x20;
/// `EXFLAG_INVALID_POLICY` — `include/openssl/x509v3.h:442`, `0x800`.
const EXFLAG_INVALID_POLICY: u32 = 0x800;

/// `X509_V_FLAG_EXPLICIT_POLICY` — `include/openssl/x509_vfy.h.in:355`, `0x100`.
const X509_V_FLAG_EXPLICIT_POLICY: c_uint = 0x100;
/// `X509_V_FLAG_INHIBIT_ANY` — `include/openssl/x509_vfy.h.in:357`, `0x200`.
const X509_V_FLAG_INHIBIT_ANY: c_uint = 0x200;
/// `X509_V_FLAG_INHIBIT_MAP` — `include/openssl/x509_vfy.h.in:359`, `0x400`.
const X509_V_FLAG_INHIBIT_MAP: c_uint = 0x400;

/// `X509_PCY_TREE_FAILURE` — `include/openssl/x509_vfy.h.in:783`.
const X509_PCY_TREE_FAILURE: c_int = -2;
/// `X509_PCY_TREE_INVALID` — `include/openssl/x509_vfy.h.in:784`.
const X509_PCY_TREE_INVALID: c_int = -1;
/// `X509_PCY_TREE_INTERNAL` — `include/openssl/x509_vfy.h.in:785`.
const X509_PCY_TREE_INTERNAL: c_int = 0;
/// `X509_PCY_TREE_VALID` — `include/openssl/x509_vfy.h.in:791`.
const X509_PCY_TREE_VALID: c_int = 1;
/// `X509_PCY_TREE_EMPTY` — `include/openssl/x509_vfy.h.in:792`.
const X509_PCY_TREE_EMPTY: c_int = 2;
/// `X509_PCY_TREE_EXPLICIT` — `include/openssl/x509_vfy.h.in:793`.
const X509_PCY_TREE_EXPLICIT: c_int = 4;

/// `TREE_CALC_FAILURE` — `crypto/x509/pcy_tree.c:464`.
const TREE_CALC_FAILURE: c_int = 0;
/// `TREE_CALC_OK_NOFREE` — `crypto/x509/pcy_tree.c:465`.
const TREE_CALC_OK_NOFREE: c_int = 1;
/// `TREE_CALC_OK_DOFREE` — `crypto/x509/pcy_tree.c:466`.
const TREE_CALC_OK_DOFREE: c_int = 2;

/// `node_critical(node)` — `crypto/x509/pcy_local.h:139`, the node datum's critical flag.
///
/// # Safety
///
/// `node` must be a live node with live data.
unsafe fn node_critical(node: *const X509PolicyNode) -> c_int {
    // SAFETY: `node` is live per the contract; its data is a live datum.
    (unsafe { (*(*node).data).flags } & POLICY_DATA_FLAG_CRITICAL) as c_int
}

/// `static void exnode_free(X509_POLICY_NODE *node)` — `crypto/x509/pcy_tree.c:622-626`.
///
/// Frees a node only when its data carries `POLICY_DATA_FLAG_EXTRA_NODE`.
///
/// # Safety
///
/// `node` must be a live node owned by the user-policy set.
unsafe fn exnode_free(node: *mut X509PolicyNode) {
    // SAFETY: `node` is live per the contract.
    unsafe {
        if !(*node).data.is_null() && ((*(*node).data).flags & POLICY_DATA_FLAG_EXTRA_NODE) != 0 {
            CRYPTO_free(node.cast(), FILE.as_ptr(), 0);
        }
    }
}

/// The `exnode_free` element thunk for `sk_X509_POLICY_NODE_pop_free`.
///
/// # Safety
///
/// `n` must be a live node owned by the user-policy set.
unsafe extern "C" fn exnode_free_void(n: *mut c_void) {
    // SAFETY: `n` is live per the contract.
    unsafe { exnode_free(n.cast()) };
}

/// The `ossl_policy_node_free` element thunk for `sk_X509_POLICY_NODE_pop_free`.
///
/// # Safety
///
/// `n` must be NULL or a node this tree owned.
unsafe extern "C" fn policy_node_free_void(n: *mut c_void) {
    // SAFETY: `n` is NULL or owned per the contract.
    unsafe { ossl_policy_node_free(n.cast()) };
}

/// `static int tree_init(X509_POLICY_TREE **ptree, STACK_OF(X509) *certs, unsigned int flags)` —
/// `crypto/x509/pcy_tree.c:98-255`.
///
/// Answers the `X509_PCY_TREE_*` word (a bitmask: `VALID`/`EMPTY`/`EXPLICIT`, or `INVALID`).
///
/// # Safety
///
/// `ptree` is writable; `certs` is NULL or a live `STACK_OF(X509)`.
unsafe fn tree_init(
    ptree: *mut *mut X509PolicyTree,
    certs: *mut OpenSslStack,
    flags: c_uint,
) -> c_int {
    let mut ret = X509_PCY_TREE_VALID;
    // SAFETY: `certs` is NULL or live per the contract.
    let n = unsafe { OPENSSL_sk_num(certs) } - 1; // RFC 5280 paths omit the TA
    let mut explicit_policy = if (flags & X509_V_FLAG_EXPLICIT_POLICY) != 0 {
        0
    } else {
        n + 1
    };
    let mut any_skip = if (flags & X509_V_FLAG_INHIBIT_ANY) != 0 {
        0
    } else {
        n + 1
    };
    let mut map_skip = if (flags & X509_V_FLAG_INHIBIT_MAP) != 0 {
        0
    } else {
        n + 1
    };

    // SAFETY: `ptree` is writable per the contract.
    unsafe { *ptree = core::ptr::null_mut() };

    if n < 0 {
        return X509_PCY_TREE_INTERNAL;
    }
    // Can't do anything with just a trust anchor.
    if n == 0 {
        return X509_PCY_TREE_EMPTY;
    }

    // First, set up the policy cache in all n non-TA certificates.
    for i in (0..n).rev() {
        // SAFETY: `i` is in range; the element is a live `X509`.
        let x = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // Call for side-effect of computing hash and caching extensions.
        // SAFETY: `x` is live.
        unsafe { X509_check_purpose(x, -1, 0) };
        // SAFETY: `x` is live.
        if unsafe { ossl_policy_cache_set(x) }.is_null() {
            return X509_PCY_TREE_INTERNAL;
        }
    }

    let mut i = n - 1;
    while i >= 0 && (explicit_policy > 0 || (ret & X509_PCY_TREE_EMPTY) == 0) {
        // SAFETY: `i` is in range; the element is a live `X509`.
        let x = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // SAFETY: `x` is live.
        let ex_flags = unsafe { X509_get_extension_flags(x) };
        if (ex_flags & EXFLAG_INVALID_POLICY) != 0 {
            return X509_PCY_TREE_INVALID;
        }
        // The policies are already cached, so the cache now exists.
        // SAFETY: `x` is live.
        let cache = unsafe { ossl_policy_cache_set(x) };
        // SAFETY: `cache` is non-null here.
        if (ret & X509_PCY_TREE_VALID) != 0 && unsafe { (*cache).data }.is_null() {
            ret = X509_PCY_TREE_EMPTY;
        }
        if explicit_policy > 0 {
            if (ex_flags & EXFLAG_SI) == 0 {
                explicit_policy -= 1;
            }
            // SAFETY: `cache` is non-null here.
            let explicit_skip = unsafe { (*cache).explicit_skip };
            if explicit_skip >= 0 && explicit_skip < explicit_policy as i64 {
                explicit_policy = explicit_skip as c_int;
            }
        }
        i -= 1;
    }

    if explicit_policy == 0 {
        ret |= X509_PCY_TREE_EXPLICIT;
    }
    if (ret & X509_PCY_TREE_VALID) == 0 {
        return ret;
    }

    // If we get this far, initialize the tree.
    // A fresh, zeroed block of the tree's own size.
    let tree = CRYPTO_zalloc(core::mem::size_of::<X509PolicyTree>(), FILE.as_ptr(), 0)
        .cast::<X509PolicyTree>();
    if tree.is_null() {
        return X509_PCY_TREE_INTERNAL;
    }
    // Limit the growth of the tree to mitigate CVE-2023-0464.
    // SAFETY: `tree` is live and writable.
    unsafe { (*tree).node_maximum = OPENSSL_POLICY_TREE_NODES_MAX };

    // A fresh, zeroed array of `n + 1` levels.
    let levels = CRYPTO_calloc(
        (n + 1) as usize,
        core::mem::size_of::<X509PolicyLevel>(),
        FILE.as_ptr(),
        0,
    )
    .cast::<X509PolicyLevel>();
    if levels.is_null() {
        // SAFETY: `tree` is owned here.
        unsafe { CRYPTO_free(tree.cast(), FILE.as_ptr(), 0) };
        return X509_PCY_TREE_INTERNAL;
    }
    // SAFETY: `tree` is live and writable.
    unsafe {
        (*tree).levels = levels;
        (*tree).nlevel = n + 1;
    }
    let mut level = levels;
    // SAFETY: `OBJ_nid2obj(NID_any_policy)` is a static object.
    let data =
        unsafe { ossl_policy_data_new(core::ptr::null_mut(), OBJ_nid2obj(NID_any_policy), 0) };
    if data.is_null() {
        // SAFETY: `tree` is owned here.
        unsafe { X509_policy_tree_free(tree) };
        return X509_PCY_TREE_INTERNAL;
    }
    // SAFETY: `level`, `data` and `tree` are live.
    if unsafe { ossl_policy_level_add_node(level, data, core::ptr::null_mut(), tree, 1) }.is_null()
    {
        // SAFETY: `data` is owned here; `tree` is owned here.
        unsafe {
            ossl_policy_data_free(data);
            X509_policy_tree_free(tree);
        }
        return X509_PCY_TREE_INTERNAL;
    }

    let mut i = n - 1;
    while i >= 0 {
        // SAFETY: `i` is in range; the element is a live `X509`.
        let x = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // SAFETY: `x` is live.
        let ex_flags = unsafe { X509_get_extension_flags(x) };
        // SAFETY: `x` is live.
        let cache = unsafe { ossl_policy_cache_set(x) };

        // SAFETY: `x` is live.
        if unsafe { X509_up_ref(x) } == 0 {
            // SAFETY: `tree` is owned here.
            unsafe { X509_policy_tree_free(tree) };
            return X509_PCY_TREE_INTERNAL;
        }

        // SAFETY: `level.add(1)` stays inside the `n + 1` levels array.
        level = unsafe { level.add(1) };
        // SAFETY: `level` is live and writable.
        unsafe { (*level).cert = x };

        // SAFETY: `cache` is non-null here.
        if unsafe { (*cache).anyPolicy }.is_null() {
            // SAFETY: `level` is live and writable.
            unsafe { (*level).flags |= X509_V_FLAG_INHIBIT_ANY };
        }

        // Determine inhibit any and inhibit map flags.
        if any_skip == 0 {
            if (ex_flags & EXFLAG_SI) == 0 || i == 0 {
                // SAFETY: `level` is live and writable.
                unsafe { (*level).flags |= X509_V_FLAG_INHIBIT_ANY };
            }
        } else {
            if (ex_flags & EXFLAG_SI) == 0 {
                any_skip -= 1;
            }
            // SAFETY: `cache` is non-null here.
            let cache_any_skip = unsafe { (*cache).any_skip };
            if cache_any_skip >= 0 && cache_any_skip < any_skip as i64 {
                any_skip = cache_any_skip as c_int;
            }
        }

        if map_skip == 0 {
            // SAFETY: `level` is live and writable.
            unsafe { (*level).flags |= X509_V_FLAG_INHIBIT_MAP };
        } else {
            if (ex_flags & EXFLAG_SI) == 0 {
                map_skip -= 1;
            }
            // SAFETY: `cache` is non-null here.
            let cache_map_skip = unsafe { (*cache).map_skip };
            if cache_map_skip >= 0 && cache_map_skip < map_skip as i64 {
                map_skip = cache_map_skip as c_int;
            }
        }
        i -= 1;
    }

    // SAFETY: `ptree` is writable per the contract.
    unsafe { *ptree = tree };
    ret
}

/// `static int tree_link_matching_nodes(X509_POLICY_LEVEL *curr, X509_POLICY_DATA *data, X509_POLICY_TREE *tree)`
/// — `crypto/x509/pcy_tree.c:260-282`.
///
/// # Safety
///
/// `curr` (and `curr - 1`) are live levels; `data` is a live datum; `tree` is live.
unsafe fn tree_link_matching_nodes(
    curr: *mut X509PolicyLevel,
    data: *mut X509PolicyData,
    tree: *mut X509PolicyTree,
) -> c_int {
    // SAFETY: `curr` is the second-or-later level, so `curr - 1` is in range.
    let last = unsafe { curr.sub(1) };
    let mut matched = 0;

    // SAFETY: `last` is live.
    let num = unsafe { OPENSSL_sk_num((*last).nodes) };
    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live node.
        let node = unsafe { OPENSSL_sk_value((*last).nodes, i) }.cast::<X509PolicyNode>();
        // SAFETY: `last`, `node` and `data` are live.
        if unsafe { ossl_policy_node_match(last, node, (*data).valid_policy) } != 0 {
            // SAFETY: `curr`, `data`, `node` and `tree` are live.
            if unsafe { ossl_policy_level_add_node(curr, data, node, tree, 0) }.is_null() {
                return 0;
            }
            matched = 1;
        }
    }
    // SAFETY: `last` is live.
    if matched == 0 && !unsafe { (*last).anyPolicy }.is_null() {
        // SAFETY: `curr`, `data`, `last` and `tree` are live.
        if unsafe { ossl_policy_level_add_node(curr, data, (*last).anyPolicy, tree, 0) }.is_null() {
            return 0;
        }
    }
    1
}

/// `static int tree_link_nodes(X509_POLICY_LEVEL *curr, const X509_POLICY_CACHE *cache, X509_POLICY_TREE *tree)`
/// — `crypto/x509/pcy_tree.c:290-304`.
///
/// # Safety
///
/// `curr` is a live level; `cache` is a live policy cache; `tree` is live.
unsafe fn tree_link_nodes(
    curr: *mut X509PolicyLevel,
    cache: *const X509PolicyCache,
    tree: *mut X509PolicyTree,
) -> c_int {
    // SAFETY: `cache` is live per the contract.
    let num = unsafe { OPENSSL_sk_num((*cache).data) };
    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live datum.
        let data = unsafe { OPENSSL_sk_value((*cache).data, i) }.cast::<X509PolicyData>();
        // SAFETY: `curr`, `data` and `tree` are live.
        if unsafe { tree_link_matching_nodes(curr, data, tree) } == 0 {
            return 0;
        }
    }
    1
}

/// `static int tree_add_unmatched(X509_POLICY_LEVEL *curr, const X509_POLICY_CACHE *cache, const ASN1_OBJECT *id, X509_POLICY_NODE *node, X509_POLICY_TREE *tree)`
/// — `crypto/x509/pcy_tree.c:312-336`.
///
/// # Safety
///
/// `curr` is a live level; `cache` is a live cache with an anyPolicy; `id` is NULL or a live
/// `ASN1_OBJECT`; `node` is a live node; `tree` is live.
unsafe fn tree_add_unmatched(
    curr: *mut X509PolicyLevel,
    cache: *const X509PolicyCache,
    id: *const Asn1Object,
    node: *mut X509PolicyNode,
    tree: *mut X509PolicyTree,
) -> c_int {
    // `node` is live per the contract.
    let id = if id.is_null() {
        // SAFETY: `node` is live under this branch.
        unsafe { (*(*node).data).valid_policy }
    } else {
        id as *mut Asn1Object
    };
    // SAFETY: `node` is live.
    let crit = unsafe { node_critical(node) };
    // SAFETY: `id` is live.
    let data = unsafe { ossl_policy_data_new(core::ptr::null_mut(), id, crit) };
    if data.is_null() {
        return 0;
    }
    // SAFETY: `data` is live and writable; `cache` is live with an anyPolicy.
    unsafe {
        (*data).qualifier_set = (*(*cache).anyPolicy).qualifier_set;
        (*data).flags |= POLICY_DATA_FLAG_SHARED_QUALIFIERS;
    }
    // SAFETY: `curr`, `data`, `node` and `tree` are live.
    if unsafe { ossl_policy_level_add_node(curr, data, node, tree, 1) }.is_null() {
        // SAFETY: `data` is owned here.
        unsafe { ossl_policy_data_free(data) };
        return 0;
    }
    1
}

/// `static int tree_link_unmatched(X509_POLICY_LEVEL *curr, const X509_POLICY_CACHE *cache, X509_POLICY_NODE *node, X509_POLICY_TREE *tree)`
/// — `crypto/x509/pcy_tree.c:341-371`.
///
/// # Safety
///
/// `curr` (and `curr - 1`) are live levels; `cache` is a live cache; `node` is a live node;
/// `tree` is live.
unsafe fn tree_link_unmatched(
    curr: *mut X509PolicyLevel,
    cache: *const X509PolicyCache,
    node: *mut X509PolicyNode,
    tree: *mut X509PolicyTree,
) -> c_int {
    // SAFETY: `curr` is the second-or-later level, so `curr - 1` is in range.
    let last = unsafe { curr.sub(1) };

    // SAFETY: `last` and `node` are live.
    if unsafe {
        ((*last).flags & X509_V_FLAG_INHIBIT_MAP) != 0
            || ((*(*node).data).flags & POLICY_DATA_FLAG_MAPPED) == 0
    } {
        // If no policy mapping: matched if one child present.
        // SAFETY: `node` is live.
        if unsafe { (*node).nchild } != 0 {
            return 1;
        }
        // SAFETY: `curr`, `cache`, `node` and `tree` are live.
        return unsafe { tree_add_unmatched(curr, cache, core::ptr::null(), node, tree) };
    }

    // If mapping: matched if one child per expected policy set.
    // SAFETY: `node` is live.
    let expset = unsafe { (*(*node).data).expected_policy_set };
    // SAFETY: `expset` is live; `node` is live.
    if unsafe { (*node).nchild } == unsafe { OPENSSL_sk_num(expset) } {
        return 1;
    }
    // Locate unmatched nodes.
    // SAFETY: `expset` is live.
    let num = unsafe { OPENSSL_sk_num(expset) };
    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live `ASN1_OBJECT`.
        let oid = unsafe { OPENSSL_sk_value(expset, i) }.cast::<Asn1Object>();
        // SAFETY: `curr`, `node` and `oid` are live.
        if !unsafe { ossl_policy_level_find_node(curr, node, oid) }.is_null() {
            continue;
        }
        // SAFETY: `curr`, `cache`, `oid`, `node` and `tree` are live.
        if unsafe { tree_add_unmatched(curr, cache, oid, node, tree) } == 0 {
            return 0;
        }
    }
    1
}

/// `static int tree_link_any(X509_POLICY_LEVEL *curr, const X509_POLICY_CACHE *cache, X509_POLICY_TREE *tree)`
/// — `crypto/x509/pcy_tree.c:376-394`.
///
/// # Safety
///
/// `curr` (and `curr - 1`) are live levels; `cache` is a live cache; `tree` is live.
unsafe fn tree_link_any(
    curr: *mut X509PolicyLevel,
    cache: *const X509PolicyCache,
    tree: *mut X509PolicyTree,
) -> c_int {
    // SAFETY: `curr` is the second-or-later level, so `curr - 1` is in range.
    let last = unsafe { curr.sub(1) };
    // SAFETY: `last` is live.
    let num = unsafe { OPENSSL_sk_num((*last).nodes) };
    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live node.
        let node = unsafe { OPENSSL_sk_value((*last).nodes, i) }.cast::<X509PolicyNode>();
        // SAFETY: `curr`, `cache`, `node` and `tree` are live.
        if unsafe { tree_link_unmatched(curr, cache, node, tree) } == 0 {
            return 0;
        }
    }
    // Finally add link to anyPolicy.
    // SAFETY: `last` and `cache` are live.
    if !unsafe { (*last).anyPolicy }.is_null() {
        // SAFETY: `curr`, `cache`, `last` and `tree` are live.
        if unsafe {
            ossl_policy_level_add_node(curr, (*cache).anyPolicy, (*last).anyPolicy, tree, 0)
        }
        .is_null()
        {
            return 0;
        }
    }
    1
}

/// `static int tree_prune(X509_POLICY_TREE *tree, X509_POLICY_LEVEL *curr)` —
/// `crypto/x509/pcy_tree.c:406-449`.
///
/// # Safety
///
/// `tree` is live; `curr` is a live level at index >= 1.
unsafe fn tree_prune(tree: *mut X509PolicyTree, mut curr: *mut X509PolicyLevel) -> c_int {
    // SAFETY: `curr` is live.
    let mut nodes = unsafe { (*curr).nodes };
    // SAFETY: `curr` is live.
    if (unsafe { (*curr).flags } & X509_V_FLAG_INHIBIT_MAP) != 0 {
        // SAFETY: `nodes` is live.
        let mut i = unsafe { OPENSSL_sk_num(nodes) } - 1;
        while i >= 0 {
            // SAFETY: `i` is in range; the element is a live node.
            let node = unsafe { OPENSSL_sk_value(nodes, i) }.cast::<X509PolicyNode>();
            // SAFETY: `node` is live.
            if (unsafe { (*(*node).data).flags } & POLICY_DATA_FLAG_MAP_MASK) != 0 {
                // SAFETY: `node` is live; its parent is live.
                unsafe {
                    (*(*node).parent).nchild -= 1;
                    CRYPTO_free(node.cast(), FILE.as_ptr(), 0);
                    OPENSSL_sk_delete(nodes, i);
                }
            }
            i -= 1;
        }
    }

    loop {
        // SAFETY: `curr` is at index >= 1, so `curr - 1` is in range.
        curr = unsafe { curr.sub(1) };
        // SAFETY: `curr` is live.
        nodes = unsafe { (*curr).nodes };
        // SAFETY: `nodes` is NULL or live.
        let mut i = unsafe { OPENSSL_sk_num(nodes) } - 1;
        while i >= 0 {
            // SAFETY: `i` is in range; the element is a live node.
            let node = unsafe { OPENSSL_sk_value(nodes, i) }.cast::<X509PolicyNode>();
            // SAFETY: `node` is live.
            if unsafe { (*node).nchild } == 0 {
                // SAFETY: `node` is live; its parent is live.
                unsafe {
                    (*(*node).parent).nchild -= 1;
                    CRYPTO_free(node.cast(), FILE.as_ptr(), 0);
                    OPENSSL_sk_delete(nodes, i);
                }
            }
            i -= 1;
        }
        // SAFETY: `curr` is live.
        if !unsafe { (*curr).anyPolicy }.is_null() && unsafe { (*(*curr).anyPolicy).nchild } == 0 {
            // SAFETY: `curr` is live.
            if !unsafe { (*(*curr).anyPolicy).parent }.is_null() {
                // SAFETY: the anyPolicy's parent is live.
                unsafe { (*(*(*curr).anyPolicy).parent).nchild -= 1 };
            }
            // SAFETY: the anyPolicy node is owned here.
            unsafe {
                CRYPTO_free((*curr).anyPolicy.cast(), FILE.as_ptr(), 0);
                (*curr).anyPolicy = core::ptr::null_mut();
            }
        }
        // SAFETY: `curr` and `tree` are live.
        if curr == unsafe { (*tree).levels } {
            // If we zapped anyPolicy at top then the tree is empty.
            // SAFETY: `curr` is live.
            if unsafe { (*curr).anyPolicy }.is_null() {
                return X509_PCY_TREE_EMPTY;
            }
            break;
        }
    }
    X509_PCY_TREE_VALID
}

/// `static int tree_add_auth_node(STACK_OF(X509_POLICY_NODE) **pnodes, X509_POLICY_NODE *pcy)` —
/// `crypto/x509/pcy_tree.c:454-462`.
///
/// # Safety
///
/// `pnodes` is writable; `pcy` is a live node.
unsafe fn tree_add_auth_node(pnodes: *mut *mut OpenSslStack, pcy: *mut X509PolicyNode) -> c_int {
    // SAFETY: `pnodes` is writable; the allocation is owned here.
    unsafe {
        if (*pnodes).is_null() {
            *pnodes = ossl_policy_node_cmp_new();
            if (*pnodes).is_null() {
                return 0;
            }
        }
        if OPENSSL_sk_find(*pnodes, pcy.cast::<c_void>()) >= 0 {
            return 1;
        }
        c_int::from(OPENSSL_sk_push(*pnodes, pcy.cast::<c_void>()) != 0)
    }
}

/// `static int tree_calculate_authority_set(X509_POLICY_TREE *tree, STACK_OF(X509_POLICY_NODE) **pnodes)`
/// — `crypto/x509/pcy_tree.c:480-524`.
///
/// # Safety
///
/// `tree` is live; `pnodes` is writable.
unsafe fn tree_calculate_authority_set(
    tree: *mut X509PolicyTree,
    pnodes: *mut *mut OpenSslStack,
) -> c_int {
    // SAFETY: `tree` is live.
    let mut curr = unsafe { (*tree).levels.add(((*tree).nlevel - 1) as usize) };

    // SAFETY: `curr` is live.
    let addnodes = if !unsafe { (*curr).anyPolicy }.is_null() {
        // SAFETY: `tree.auth_policies` is writable; `curr.anyPolicy` is live.
        if unsafe { tree_add_auth_node(&raw mut (*tree).auth_policies, (*curr).anyPolicy) } == 0 {
            return TREE_CALC_FAILURE;
        }
        pnodes
    } else {
        // SAFETY: `tree` is live and its auth_policies slot is writable.
        unsafe { &raw mut (*tree).auth_policies }
    };

    // SAFETY: `tree` is live.
    curr = unsafe { (*tree).levels };
    // SAFETY: `tree` is live.
    let nlevel = unsafe { (*tree).nlevel };
    for _ in 1..nlevel {
        // SAFETY: `curr` is live.
        let anyptr = unsafe { (*curr).anyPolicy };
        if anyptr.is_null() {
            break;
        }
        // SAFETY: `curr` is inside the levels array.
        curr = unsafe { curr.add(1) };
        // SAFETY: `curr` is live.
        let num = unsafe { OPENSSL_sk_num((*curr).nodes) };
        for j in 0..num {
            // SAFETY: `j` is in range; the element is a live node.
            let node = unsafe { OPENSSL_sk_value((*curr).nodes, j) }.cast::<X509PolicyNode>();
            // SAFETY: `node` and `anyptr` are live.
            let parent_match = unsafe { (*node).parent } == anyptr;
            // SAFETY: `addnodes` and `node` are live.
            if parent_match && unsafe { tree_add_auth_node(addnodes, node) } == 0 {
                if addnodes == pnodes {
                    // SAFETY: `pnodes` is writable; the stack is owned here.
                    unsafe {
                        OPENSSL_sk_free(*pnodes);
                        *pnodes = core::ptr::null_mut();
                    }
                }
                return TREE_CALC_FAILURE;
            }
        }
    }
    if addnodes == pnodes {
        return TREE_CALC_OK_DOFREE;
    }
    // SAFETY: `pnodes` is writable.
    unsafe { *pnodes = (*tree).auth_policies };
    TREE_CALC_OK_NOFREE
}

/// `static int tree_calculate_user_set(X509_POLICY_TREE *tree, STACK_OF(ASN1_OBJECT) *policy_oids, STACK_OF(X509_POLICY_NODE) *auth_nodes)`
/// — `crypto/x509/pcy_tree.c:529-592`.
///
/// # Safety
///
/// `tree` is live; `policy_oids` is NULL or a live `STACK_OF(ASN1_OBJECT)`; `auth_nodes` is NULL
/// or a live node stack.
unsafe fn tree_calculate_user_set(
    tree: *mut X509PolicyTree,
    policy_oids: *mut OpenSslStack,
    auth_nodes: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `policy_oids` is NULL or live per the contract.
    if unsafe { OPENSSL_sk_num(policy_oids) } <= 0 {
        return 1;
    }

    // SAFETY: `tree` is live.
    let any_policy = unsafe { (*(*tree).levels.add(((*tree).nlevel - 1) as usize)).anyPolicy };

    // SAFETY: `policy_oids` is live.
    let num = unsafe { OPENSSL_sk_num(policy_oids) };
    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live `ASN1_OBJECT`.
        let oid = unsafe { OPENSSL_sk_value(policy_oids, i) }.cast::<Asn1Object>();
        // SAFETY: `oid` is live.
        if unsafe { OBJ_obj2nid(oid) } == NID_any_policy {
            // SAFETY: `tree` is live and writable.
            unsafe { (*tree).flags |= POLICY_FLAG_ANY_POLICY };
            return 1;
        }
    }

    for i in 0..num {
        // SAFETY: `i` is in range; the element is a live `ASN1_OBJECT`.
        let oid = unsafe { OPENSSL_sk_value(policy_oids, i) }.cast::<Asn1Object>();
        // SAFETY: `auth_nodes` and `oid` are live.
        let mut node = unsafe { ossl_policy_tree_find_sk(auth_nodes, oid) };
        if node.is_null() {
            if any_policy.is_null() {
                continue;
            }
            // SAFETY: `oid` is live; `any_policy` is live.
            let extra = unsafe {
                ossl_policy_data_new(core::ptr::null_mut(), oid, node_critical(any_policy))
            };
            if extra.is_null() {
                return 0;
            }
            // SAFETY: `extra` and `any_policy` are live.
            unsafe {
                (*extra).qualifier_set = (*(*any_policy).data).qualifier_set;
                (*extra).flags = POLICY_DATA_FLAG_SHARED_QUALIFIERS | POLICY_DATA_FLAG_EXTRA_NODE;
            }
            // SAFETY: `extra`, `any_policy` and `tree` are live.
            node = unsafe {
                ossl_policy_level_add_node(
                    core::ptr::null_mut(),
                    extra,
                    (*any_policy).parent,
                    tree,
                    1,
                )
            };
            if node.is_null() {
                // SAFETY: `extra` is owned here.
                unsafe { ossl_policy_data_free(extra) };
                return 0;
            }
        }
        // SAFETY: `tree` is live and writable.
        if unsafe { (*tree).user_policies }.is_null() {
            // SAFETY: `tree` is live and writable.
            unsafe { (*tree).user_policies = OPENSSL_sk_new_null() };
            // SAFETY: `tree` is live.
            if unsafe { (*tree).user_policies }.is_null() {
                // SAFETY: `node` is owned here.
                unsafe { exnode_free(node) };
                return 0;
            }
        }
        // SAFETY: `tree` is live; `node` is live.
        if unsafe { OPENSSL_sk_push((*tree).user_policies, node.cast::<c_void>()) } == 0 {
            // SAFETY: `node` is owned here.
            unsafe { exnode_free(node) };
            return 0;
        }
    }
    1
}

/// `static int tree_evaluate(X509_POLICY_TREE *tree)` — `crypto/x509/pcy_tree.c:600-620`.
///
/// # Safety
///
/// `tree` is live with at least two levels.
unsafe fn tree_evaluate(tree: *mut X509PolicyTree) -> c_int {
    // SAFETY: `tree` is live with at least two levels.
    let mut curr = unsafe { (*tree).levels.add(1) };
    // SAFETY: `tree` is live.
    let nlevel = unsafe { (*tree).nlevel };
    for _ in 1..nlevel {
        // SAFETY: `curr` is live.
        let cert = unsafe { (*curr).cert };
        // SAFETY: `cert` is live.
        let cache = unsafe { ossl_policy_cache_set(cert) };
        // SAFETY: `curr`, `cache` and `tree` are live.
        if unsafe { tree_link_nodes(curr, cache, tree) } == 0 {
            return X509_PCY_TREE_INTERNAL;
        }
        // SAFETY: `curr` is live.
        let inhibit_any = (unsafe { (*curr).flags } & X509_V_FLAG_INHIBIT_ANY) != 0;
        // SAFETY: `curr`, `cache` and `tree` are live.
        if !inhibit_any && unsafe { tree_link_any(curr, cache, tree) } == 0 {
            return X509_PCY_TREE_INTERNAL;
        }
        // SAFETY: `tree` and `curr` are live.
        let ret = unsafe { tree_prune(tree, curr) };
        if ret != X509_PCY_TREE_VALID {
            return ret;
        }
        // SAFETY: `curr` stays inside the levels array.
        curr = unsafe { curr.add(1) };
    }
    X509_PCY_TREE_VALID
}

/// `void X509_policy_tree_free(X509_POLICY_TREE *tree)` — `crypto/x509/pcy_tree.c:628-648`.
///
/// Releases the authority- and user-constrained policy sets, then every level's borrowed
/// certificate, node set and anyPolicy node, then the extra data, the level array and the tree.
/// A NULL tree is a no-op, matching the authority's first guard.
///
/// # Safety
///
/// `tree` must be NULL or a live tree not already freed.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_tree_free(tree: *mut X509PolicyTree) {
    if tree.is_null() {
        return;
    }
    // SAFETY: `tree` is live per the contract; each pointer member is NULL or owned by it.
    unsafe {
        OPENSSL_sk_free((*tree).auth_policies);
        OPENSSL_sk_pop_free((*tree).user_policies, Some(exnode_free_void));

        let mut curr: *mut X509PolicyLevel = (*tree).levels;
        for _ in 0..(*tree).nlevel {
            // SAFETY: `curr` walks the live `levels` array.
            X509_free((*curr).cert);
            // SAFETY: the same contract.
            OPENSSL_sk_pop_free((*curr).nodes, Some(policy_node_free_void));
            // SAFETY: the same contract.
            ossl_policy_node_free((*curr).anyPolicy);
            curr = curr.add(1);
        }

        OPENSSL_sk_pop_free((*tree).extra_data, Some(policy_data_free_void));
        CRYPTO_free((*tree).levels.cast(), FILE.as_ptr(), 0);
        CRYPTO_free(tree.cast(), FILE.as_ptr(), 0);
    }
}

/// `int X509_policy_check(X509_POLICY_TREE **ptree, int *pexplicit_policy, STACK_OF(X509) *certs, STACK_OF(ASN1_OBJECT) *policy_oids, unsigned int flags)`
/// — `crypto/x509/pcy_tree.c:658-726`.
///
/// The application policy-checking entry point. Answers an `X509_PCY_TREE_*` word: `VALID` (-2
/// `FAILURE` for an unmet explicit policy, `INVALID` for inconsistent extensions, `INTERNAL` for
/// an allocation failure). On `VALID` with a non-empty tree, `*ptree` receives the tree and
/// `*pexplicit_policy` is 1 when the explicit policy was required.
///
/// # Safety
///
/// `ptree` and `pexplicit_policy` are writable; `certs` is NULL or a live `STACK_OF(X509)`;
/// `policy_oids` is NULL or a live `STACK_OF(ASN1_OBJECT)`.
#[no_mangle]
pub unsafe extern "C" fn X509_policy_check(
    ptree: *mut *mut X509PolicyTree,
    pexplicit_policy: *mut c_int,
    certs: *mut OpenSslStack,
    policy_oids: *mut OpenSslStack,
    flags: c_uint,
) -> c_int {
    // SAFETY: the out-parameters are writable per the contract.
    unsafe {
        *ptree = core::ptr::null_mut();
        *pexplicit_policy = 0;
    }
    let mut tree: *mut X509PolicyTree = core::ptr::null_mut();

    // SAFETY: `&raw mut tree` is writable; `certs` is as contracted.
    let init_ret = unsafe { tree_init(&raw mut tree, certs, flags) };
    if init_ret <= 0 {
        return init_ret;
    }

    if (init_ret & X509_PCY_TREE_EXPLICIT) == 0 {
        if (init_ret & X509_PCY_TREE_EMPTY) != 0 {
            // SAFETY: `tree` is NULL or owned here.
            unsafe { X509_policy_tree_free(tree) };
            return X509_PCY_TREE_VALID;
        }
    } else {
        // SAFETY: `pexplicit_policy` is writable per the contract.
        unsafe { *pexplicit_policy = 1 };
        // Tree empty and requireExplicit True: error.
        if (init_ret & X509_PCY_TREE_EMPTY) != 0 {
            // SAFETY: `tree` is NULL or owned here.
            unsafe { X509_policy_tree_free(tree) };
            return X509_PCY_TREE_FAILURE;
        }
    }

    // SAFETY: `tree` is live here.
    let ret = unsafe { tree_evaluate(tree) };
    if ret <= 0 {
        // SAFETY: `tree` is owned here.
        unsafe { X509_policy_tree_free(tree) };
        return X509_PCY_TREE_INTERNAL;
    }

    if ret == X509_PCY_TREE_EMPTY {
        // SAFETY: `tree` is owned here.
        unsafe { X509_policy_tree_free(tree) };
        if (init_ret & X509_PCY_TREE_EXPLICIT) != 0 {
            return X509_PCY_TREE_FAILURE;
        }
        return X509_PCY_TREE_VALID;
    }

    // Tree is not empty: continue.
    let mut auth_nodes: *mut OpenSslStack = core::ptr::null_mut();
    // SAFETY: `tree` and `&raw mut auth_nodes` are live/writable.
    let calc_ret = unsafe { tree_calculate_authority_set(tree, &raw mut auth_nodes) };
    if calc_ret == TREE_CALC_FAILURE {
        // SAFETY: `tree` is owned here.
        unsafe { X509_policy_tree_free(tree) };
        return X509_PCY_TREE_INTERNAL;
    }
    // SAFETY: `auth_nodes` came from `tree_calculate_authority_set`.
    unsafe { OPENSSL_sk_sort(auth_nodes) };
    // SAFETY: `tree`, `policy_oids` and `auth_nodes` are live.
    let ret = unsafe { tree_calculate_user_set(tree, policy_oids, auth_nodes) };
    if calc_ret == TREE_CALC_OK_DOFREE {
        // SAFETY: `auth_nodes` is owned here.
        unsafe { OPENSSL_sk_free(auth_nodes) };
    }
    if ret == 0 {
        // SAFETY: `tree` is owned here.
        unsafe { X509_policy_tree_free(tree) };
        return X509_PCY_TREE_INTERNAL;
    }

    if (init_ret & X509_PCY_TREE_EXPLICIT) != 0 {
        // SAFETY: `tree` is live.
        let nodes = unsafe { crate::x509::pcy_lib::X509_policy_tree_get0_user_policies(tree) };
        // SAFETY: `nodes` is NULL or live.
        if unsafe { OPENSSL_sk_num(nodes) } <= 0 {
            // SAFETY: `tree` is owned here.
            unsafe { X509_policy_tree_free(tree) };
            return X509_PCY_TREE_FAILURE;
        }
    }

    // SAFETY: `ptree` is writable per the contract.
    unsafe { *ptree = tree };
    X509_PCY_TREE_VALID
}
