//! Phase 10.12 — `crypto/x509/pcy_node.c`: the policy-tree node operations, **withheld whole**.
//!
//! `crypto/x509/pcy_node.c` is 157 lines, and **all six functions are withheld by name** for two
//! reasons that hold for every one of them:
//!
//! * every name is `ossl_policy_*`, an **internal** symbol the authority's version script hides
//!   from `libcrypto.so`'s dynamic table (`nm -D` on the admitted prefix shows no `ossl_policy_*`).
//!   The differential plane links its probes against the shared object, so no probe on either side
//!   can name one, let alone drive it: the evidence rule (D442/D451) calls that a `pending` with a
//!   blocker, not a landing.
//! * the only authority callers are `pcy_cache.c`/`pcy_data.c`/`pcy_tree.c` (all 10.14) and
//!   `x509_vfy.c` (Phase 11); nothing landed reaches them, so a transcription now would be dead
//!   code with no court — exactly the shape D453 withheld `ossl_sk_ASN1_UTF8STRING2text` in.
//!
//! The withhold by name, with the closure each would need:
//!
//! * `ossl_policy_node_cmp_new` (`crypto/x509/pcy_node.c:23-26`) — allocates a node stack whose
//!   comparator is the file-local `node_cmp` (`:17-21`), which calls `OBJ_cmp`. Both callees are
//!   landed; the blocker is the absent caller.
//! * `ossl_policy_tree_find_sk` (`:28-40`) — searches a node stack by policy OID using
//!   `sk_X509_POLICY_NODE_find`, which needs the `X509_POLICY_DATA`/`X509_POLICY_NODE` layouts the
//!   landed `pcy_lib.rs` already defines. The blocker is the absent caller.
//! * `ossl_policy_level_find_node` (`:42-56`) — `OBJ_cmp` over a level's nodes. Same blocker.
//! * `ossl_policy_level_add_node` (`:58-125`) — the CVE-2023-0464 node cap, `OPENSSL_zalloc`,
//!   `OBJ_obj2nid`, the two stacks, `ossl_policy_node_free` and four `ERR_raise` sites
//!   (`ERR_LIB_X509V3` with `ERR_R_X509_LIB`/`ERR_R_CRYPTO_LIB` at `:85`, `:89`, `:99`, `:103`).
//!   Same blocker; its coordinates would come from `gen_err_raise_sites.py` once it lands.
//! * `ossl_policy_node_free` (`:127-130`) — `OPENSSL_free`. Same blocker.
//! * `ossl_policy_node_match` (`:137-156`) — `OBJ_cmp` and the expected-policy set. Same blocker.
//!
//! When 10.14 lands `pcy_cache.c`/`pcy_tree.c` and `X509_policy_check`, the whole unit can be
//! transcribed directly, because every callee it names is either landed or is another function in
//! this same unit. Nothing is stubbed and no symbol is declared, so the crate's surface is
//! unchanged by this module's existence.
//!
//! SPDX-License-Identifier: Apache-2.0

// No items: see the module documentation. The six authority functions are withheld by name.
