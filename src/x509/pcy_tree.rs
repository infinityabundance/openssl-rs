//! `crypto/x509/pcy_tree.c` — the RFC 5280 policy tree. Phase 11.2's third unit. **This slice
//! lands [`X509_policy_tree_free`] and withholds [`X509_policy_check`] by name**, whose blocker
//! is recorded below.
//!
//! `crypto/x509/pcy_tree.c` is 726 lines and publishes two exports.
//!
//! ## [`X509_policy_tree_free`] lands
//!
//! `X509_policy_tree_free` (`:628-648`) is the destructor the verification engine's
//! `X509_STORE_CTX_cleanup` calls (`x509_vfy.c:2902`), so landing it is what lets the store
//! context's own lifecycle land. It walks `tree->levels[0..nlevel]`, releasing each level's
//! borrowed `cert`, its `nodes` and its `anyPolicy`; then `extra_data`, `auth_policies`,
//! `user_policies` and the `levels` array. Nothing in it waits on a later stratum.
//!
//! **The two node/data destructors it calls are landed privately here.** The authority defines
//! `ossl_policy_node_free` (`pcy_node.c:127-130`) and `ossl_policy_data_free`
//! (`pcy_data.c:18-28`), both of which `pcy_node.rs`/`pcy_data.c` withhold because *"the only
//! authority callers are ... `pcy_tree.c` (all 10.14) and `x509_vfy.c` (Phase 11); nothing landed
//! reaches them"* (`pcy_node.rs` module doc). This slice is that caller arriving, so the two
//! destructors land here as private helpers, transcribed from their own lines, rather than
//! leaving the only reached caller of a landed export blocked. They are **internal** symbols the
//! authority's version script hides (`nm -D` shows no `ossl_policy_*`), so no court can name
//! them and none is claimed; they are exactly the two the free path needs, not the two units.
//!
//! ## [`X509_policy_check`] is withheld by name, with its blocker
//!
//! `X509_policy_check` (`:658-726`) is **not** transcribed. Its closure is the whole of the policy
//! graph the crate has not landed: `tree_init`/`tree_evaluate`/`tree_prune`/`tree_calculate_*`
//! (this same unit, `:98-620`) reach `ossl_policy_cache_set` (`pcy_cache.c`, withheld in no module
//! yet), `ossl_policy_data_new` (`pcy_data.c`, withheld), `ossl_policy_level_add_node`/
//! `ossl_policy_tree_find_sk`/`ossl_policy_level_find_node`/`ossl_policy_node_match`
//! (`pcy_node.c`, all six withheld by name in `pcy_node.rs`), and `X509_POLICY_NODE_print`
//! (`pcy_print.c`, not landed). Landing the entry point without the graph would be a stub, which
//! `docs/CUSTODIAN_CONTRACT.md` section 5 forbids; the name is named, not declared.
//!
//! ## No raise
//!
//! The landed destructor raises nothing, so this unit is not an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`. The withheld `X509_policy_check` would contribute
//! `ERR_R_INTERNAL_ERROR`/`ERR_R_CRYPTO_LIB` sites when its graph lands.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_uint, c_void};

use crate::asn1::prim::ASN1_OBJECT_free;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::stack::{OPENSSL_sk_free, OPENSSL_sk_pop_free};
use crate::x509::pcy_lib::{X509PolicyData, X509PolicyLevel, X509PolicyNode, X509PolicyTree};
use crate::x509::v3_cpols::{POLICYQUALINFO_free, PolicyQualInfo};
use crate::x509::x_x509::X509_free;

/// `POLICY_DATA_FLAG_SHARED_QUALIFIERS` — `crypto/x509/pcy_local.h:60`, `0x4`.
const POLICY_DATA_FLAG_SHARED_QUALIFIERS: c_uint = 0x4;
/// `POLICY_DATA_FLAG_EXTRA_NODE` — `crypto/x509/pcy_local.h:63`, `0x8`.
const POLICY_DATA_FLAG_EXTRA_NODE: c_uint = 0x8;

/// `OPENSSL_FILE` for this unit's `OPENSSL_free` expansion.
const FILE: &core::ffi::CStr = c"crypto/x509/pcy_tree.c";

/// `ossl_policy_node_free` — `crypto/x509/pcy_node.c:127-130`, `OPENSSL_free(node)`.
///
/// Landed privately because [`X509_policy_tree_free`] is now its only reached caller (see the
/// module doc).
///
/// # Safety
///
/// `node` must be NULL or a node this tree owned.
unsafe fn ossl_policy_node_free(node: *mut X509PolicyNode) {
    // SAFETY: `node` is NULL or an owned block per the contract.
    unsafe { CRYPTO_free(node.cast(), FILE.as_ptr(), 0) };
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

/// `ossl_policy_data_free` — `crypto/x509/pcy_data.c:18-28`.
///
/// Releases the policy OID, the qualifier set (unless it is shared) and the expected-policy set,
/// then the data. Landed privately for the same reason as [`ossl_policy_node_free`].
///
/// # Safety
///
/// `data` must be NULL or policy data this tree owned.
unsafe fn ossl_policy_data_free(data: *mut X509PolicyData) {
    if data.is_null() {
        return;
    }
    // SAFETY: `data` is live per the contract; each member is NULL or owned by it.
    unsafe {
        ASN1_OBJECT_free((*data).valid_policy);
        // Don't free qualifiers if shared (`:24`).
        if ((*data).flags & POLICY_DATA_FLAG_SHARED_QUALIFIERS) == 0 {
            OPENSSL_sk_pop_free((*data).qualifier_set, Some(policy_qualinfo_free_void));
        }
        OPENSSL_sk_pop_free((*data).expected_policy_set, Some(asn1_object_free_void));
        CRYPTO_free(data.cast(), FILE.as_ptr(), 0);
    }
}

/// The `POLICYQUALINFO_free` element thunk for `sk_POLICYQUALINFO_pop_free`.
///
/// # Safety
///
/// `q` must be NULL or a live `POLICYQUALINFO`.
unsafe extern "C" fn policy_qualinfo_free_void(q: *mut c_void) {
    // SAFETY: `q` is NULL or live per the contract.
    unsafe { POLICYQUALINFO_free(q.cast::<PolicyQualInfo>()) };
}

/// The `ASN1_OBJECT_free` element thunk for `sk_ASN1_OBJECT_pop_free`.
///
/// # Safety
///
/// `a` must be NULL or a live `ASN1_OBJECT`.
unsafe extern "C" fn asn1_object_free_void(a: *mut c_void) {
    // SAFETY: `a` is NULL or live per the contract.
    unsafe { ASN1_OBJECT_free(a.cast()) };
}

/// The `ossl_policy_data_free` element thunk for `sk_X509_POLICY_DATA_pop_free`.
///
/// # Safety
///
/// `d` must be NULL or policy data this tree owned.
unsafe extern "C" fn policy_data_free_void(d: *mut c_void) {
    // SAFETY: `d` is NULL or owned per the contract.
    unsafe { ossl_policy_data_free(d.cast()) };
}

/// `static void exnode_free(X509_POLICY_NODE *node)` — `crypto/x509/pcy_tree.c:622-626`.
///
/// Frees a node only when its data carries `POLICY_DATA_FLAG_EXTRA_NODE`, i.e. when the node was
/// an "extra" node not cached with a certificate.
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
