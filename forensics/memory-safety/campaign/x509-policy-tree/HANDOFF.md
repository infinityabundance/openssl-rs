# P25-X509-001 — X.509 policy-tree safe-core: reconnaissance + ownership/invariant freeze

Task id: `P25-X509-001` · branch `stage/p25/x509-policy-tree` · base `b5bbb457e` (main)
Scope: `src/x509/pcy_tree.rs`, `pcy_node.rs`, `pcy_cache.rs`, `pcy_data.rs`, `pcy_lib.rs`
Authority: `forensics/authorities/src/openssl-3.6.4/crypto/x509/pcy_*.c`, `pcy_local.h`
This unit is reconnaissance and a freeze only. It builds nothing, converts nothing, and
changes no gate. Later conversion units build on it.

---

## 1. Ownership / unsafe inventory

### Representation: raw heap blocks, not an arena and not a `Vec`

The graph is raw `*mut`/`*const` with `#[repr(C)]` layouts (all in `pcy_lib.rs`) and
const-asserted size/offset. Five structures:

| struct | file:line (def) | size | fields (offset) |
|---|---|---|---|
| `X509PolicyData` | `pcy_lib.rs:53-63` | 32 | `flags` u32(0), `valid_policy *mut Asn1Object`(8), `qualifier_set *mut OpenSslStack`(16), `expected_policy_set *mut OpenSslStack`(24) |
| `X509PolicyNode` | `pcy_lib.rs:76-84` | 24 | `data *const X509PolicyData`(0), `parent *mut X509PolicyNode`(8), `nchild c_int`(16) |
| `X509PolicyLevel` | `pcy_lib.rs:94-104` | 32 | `cert *mut X509`(0), `nodes *mut OpenSslStack`(8), `anyPolicy *mut X509PolicyNode`(16), `flags`(24) |
| `X509PolicyTree` | `pcy_lib.rs:115-133` | 64 | `node_count`(0), `node_maximum`(8), `levels *mut X509PolicyLevel`(16), `nlevel`(24), `extra_data`(32), `auth_policies`(40), `user_policies`(48), `flags`(56) |
| `X509PolicyCache` | `pcy_lib.rs:153-165` | 40 | `anyPolicy`(0), `data`(8), `any_skip`(16), `explicit_skip`(24), `map_skip`(32) |

Graph shape:
- `tree.levels` is a **`CRYPTO_calloc`'d array** of `nlevel` levels; levels are reached by
  **pointer arithmetic** `levels.add(i)` (`pcy_tree.rs:674,689,699,746,826,850`;
  `pcy_lib.rs:211`; `curr.sub(1)` `pcy_tree.rs:379,486,539,596`).
- Each level's `nodes` is an `OPENSSL_sk_new(node_cmp)` **sorted stack**; `anyPolicy` is a
  single node. Child/parent is implicit: a `parent` back-pointer plus an `nchild` counter
  (`pcy_node.rs:197-199,266-268`), never a child list.
- Each node is a `CRYPTO_zalloc`'d block (`pcy_node.rs:190`); each datum a `CRYPTO_zalloc`'d
  block (`pcy_data.rs:154`); `extra_data`/`auth_policies`/`user_policies` and the per-datum
  qualifier/expected sets are `OPENSSL_sk_*` stacks.
- The **cache** is a separate `CRYPTO_malloc`'d block hung off `X509::policy_cache`
  (`x_x509.rs:176-177`, offset assert `x_x509.rs:220`).

### Allocation sites (`file:line`)
- data `pcy_data.rs:154`; expected set `:162`; free-on-error `:167`
- node `pcy_node.rs:190`; node stack `:107`; `extra_data` stack `:237`
- cache `pcy_cache.rs:268`; cache data stack `:190`
- tree `pcy_tree.rs:255`; levels array `:265-271`; `user_policies` stack `:801`
- stacks (generic): `OPENSSL_sk_new`/`OPENSSL_sk_new_null`
All block sizes are **observable** through `CRYPTO_set_mem_functions` (see §2.4).

### Free sites (`file:line`)
- `ossl_policy_node_free` `pcy_node.rs:278-281` → `CRYPTO_free`
- `ossl_policy_data_free` `pcy_data.rs:97-111` (OID; qualifiers **unless**
  `POLICY_DATA_FLAG_SHARED_QUALIFIERS`; expected set; block)
- inline node frees: `pcy_tree.rs:136` (`exnode_free`), `:586`, `:609`, `:624`
- `X509_policy_tree_free` `pcy_tree.rs:865-889`
- `ossl_policy_cache_free` `pcy_cache.rs:419-429` — **`#[allow(dead_code)]`, no caller in the
  crate**; consequently the per-cert cache is never released and leaks on `X509_free`. This is
  a recorded authoring gap (`pcy_cache.rs:407-418`), not a bug to fix in conversion.

### `#[repr(C)]` / stable-address assertions
`pcy_lib.rs:65-71`, `:86-91`, `:106-112`, `:135-145`, `:167-174` (`size_of` + `offset_of!` for
all five). Plus `X509::policy_cache` offset assert `x_x509.rs:220`.

### Pointer exposure through the public API
11 `#[no_mangle]` C exports: 9 accessors (`pcy_lib.rs`) + 2 (`pcy_tree.rs`). Seven return an
**interior pointer** into the graph:
- `X509_policy_tree_get0_level` `pcy_lib.rs:202-213` → `&tree.levels[i]`
- `X509_policy_tree_get0_policies` `:222-230` → `tree.auth_policies`
- `X509_policy_tree_get0_user_policies` `:239-253` → `auth_policies` or `user_policies`
- `X509_policy_level_get0_node` `:290-307` → `level.anyPolicy` or a stack element
- `X509_policy_node_get0_policy` `:320-328` → `node.data.valid_policy`
- `X509_policy_node_get0_qualifiers` `:337-345` → `node.data.qualifier_set`
- `X509_policy_node_get0_parent` `:354-362` → `node.parent`
The other two answer ints. Internally, `ossl_policy_cache_set` returns `*const X509PolicyCache`
(`pcy_cache.rs:439`).

### Operation counts
Campaign census (`forensics/memory-safety/unsafe-reconstruction.json`, `next_targets`):
**649 interior operations** — `FFI_EXPORT` 11, `RAW_POINTER_DEREFERENCE` 246,
`UNSAFE_FUNCTION_CALL` 268, `UNSAFE_METHOD_CALL` 124. Cross-check by this unit: 11
`#[no_mangle]` exactly. Per-file `(*`-deref heuristic: `pcy_tree` 108, `pcy_cache` 56,
`pcy_node` 36, `pcy_lib` 18, `pcy_data` 14 (Σ232; census 246 counts `(*`-forms the heuristic
misses).

---

## 2. Invariant freeze (observables the conversion must conserve)

1. **Public C ABI.** The 11 exported symbols' names and signatures are fixed
   (`x509_vfy.h.in:800-823`). `X509_policy_check` return word ∈ {FAILURE −2, INVALID −1,
   INTERNAL 0, VALID 1, EMPTY 2, EXPLICIT 4} (`x509_vfy.h.in:783-793`); on VALID it sets
   `*ptree` and `*pexplicit_policy`; on error it leaves `*ptree` NULL and `*pexplicit_policy` 0
   (`pcy_tree.rs:911-915,924-994`). `X509_policy_tree_free(NULL)` is a no-op
   (`pcy_tree.rs:866-868`). The nine accessors keep their NULL arms.
2. **Pointer identity / stable address (mandatory).** The accessors are `get0` — the OpenSSL
   *borrow* convention: the returned pointer is owned by the tree, must not be freed, and is
   valid **until `X509_policy_tree_free`** (`x509_vfy.h.in:800-823`). It must also be the
   *same* pointer the graph carries: `X509_policy_node_get0_parent` must equal the node that
   `X509_policy_level_get0_node` returns for that parent, and a node pushed into a level stack
   must be the identical pointer the accessor returns. Therefore the **levels array and every
   node must keep a stable address for the tree's lifetime** (a `Vec`/`Box`-by-value that
   reallocates or moves after linking breaks this). `X509_policy_node_get0_policy` must return
   the same `ASN1_OBJECT` that qualifier/parent relationships expose.
3. **Traversal ordering.** Node stacks are sorted by `OBJ_cmp` over `valid_policy`
   (`node_cmp` `pcy_node.rs:92-99`; `OPENSSL_sk_sort` `pcy_cache.rs:229`, `pcy_tree.rs:968`).
   `X509_policy_level_get0_node` yields anyPolicy at index 0 then the stack order
   (`pcy_lib.rs:299-305`). The authority set is written in level/parent order
   (`pcy_tree.rs:669-726`), the user set in `policy_oids` order (`pcy_tree.rs:750-815`).
4. **Allocator contract.** The authority builds the graph through `OPENSSL_malloc/zalloc/calloc/
   free` (crate: `runtime::mem::{CRYPTO_malloc,zalloc,calloc,free}`), routed through the
   installable `CRYPTO_set_mem_functions` hooks — so block **sizes are observable** (tree 64,
   level 32, node 24, data 32, cache 40, plus `OPENSSL_sk_*` blocks) as are the call
   sequences. A representation allocating via Rust's global allocator would be invisible to the
   hooks and abort on exhaustion instead of returning NULL — exactly the divergence the
   sparse-array court measured (`forensics/memory-safety/sparse-array-differential.json`).
   Either keep the `CRYPTO_*` blocks/`OPENSSL_sk_*` stacks, or prove conservation by
   differential. **Failure semantics** (NULL on exhaustion → `INTERNAL`/error) are behaviour.
5. **Error/raise semantics.** `pcy_tree.rs` raises nothing (`:33-37`); the `ERR_raise` sites are
   in `pcy_cache`/`pcy_data`/`pcy_node` (declared locally). Error-queue behaviour is unchanged.
6. **Cleanup / destruction.** `X509_policy_tree_free` (`pcy_tree.rs:865-889`) frees exactly:
   `auth_policies` (`sk_free`); `user_policies` (`pop_free` with `exnode_free` — frees **only**
   `EXTRA_NODE` data); each level's `cert` via `X509_free` (refcount decrement of the ref taken
   by `X509_up_ref` at `pcy_tree.rs:312`); each level's `nodes` (`pop_free` `node_free`);
   `anyPolicy` (`node_free`); `extra_data` (`pop_free` `data_free`); the levels array; the tree.
   Datum sharing (`SHARED_QUALIFIERS`, qualifier set aliased from anyPolicy, `pcy_tree.rs:460-461`,
   `778-780`; `pcy_cache.rs:531-535`) means qualifiers are freed **once** — `data_free` checks
   the flag (`pcy_data.rs:104-107`). The pre-existing cache leak (§1) is recorded, not fixed.
7. **CVE-2023-0464 cap.** `node_maximum = 1000` (`pcy_tree.rs:68,262`); exceeding it makes
   `ossl_policy_level_add_node` answer NULL (`pcy_node.rs:185-187`) → `INTERNAL`. This cap and
   its failure answer are behaviour.
8. **Cert refcounts.** Each level holds a counted reference to its cert (`X509_up_ref`
   `pcy_tree.rs:312`), released by `X509_free` in the destructor.

**Authority guarantees to cite:** the `get0` lifetime/borrow contract (`x509_vfy.h.in:800-823`);
the layouts (`pcy_local.h:24-30,65-82,82-90,92-104,106-124`); the *data is static/cached and
aliased* guarantee — "this structure contains no pointers to parent or child data …
the main policy data can be kept static and cached with the certificate" (`pcy_local.h:16-22`);
`node_critical` (`pcy_local.h:135-139`).

---

## 3. Baseline

- **Phase 11.2 court** `courts/phase11/rt_x509_verify_probe.c` — `policy_surface()` (`:736-878`)
  drives `X509_policy_check` over NULL / empty / one-TA / policy-free / explicit / real
  `CertificatePolicies` stacks and prints the return word, the explicit flag, and the tree
  shape via the accessors (`out_tree`, `:709-730`).
- **Phase 10.12 court** `courts/phase10/rt_store_probe.c` (`:1070-1079`) drives the nine
  accessors **only through their NULL arms** (no live tree).
- **No dedicated policy-tree differential exists.** Neither court installs allocator hooks or
  injects allocation failure.
- The nearest model: `courts/phase25/rt_sparse_array_differential.c` +
  `forensics/tools/ms_sparse_array_court.py` + `forensics/memory-safety/sparse-array-differential.json`
  (compiles the C probe against the authority, installs a counting/failure-injecting allocator
  via `CRYPTO_set_mem_functions`, runs a crate Rust harness, compares JSON transcripts
  field-by-field).

**What a minimal policy-tree differential must drive** (mirror the sparse-array court; do **not**
build it in this unit):
1. the `X509_policy_check` return word + explicit flag for {NULL, empty, one-TA, policy-free,
   explicit-policy, single-policy, mapped-policy, 2-level chain};
2. the built tree's shape (level count, per-level node count, authority/user set sizes);
3. **traversal order** of `X509_policy_level_get0_node` and the sorted node stacks;
4. **pointer identity/lifetime**: `get0_parent`/`get0_node` return the same nodes as the stack
   elements and stay stable across repeated calls until free;
5. **allocator observability**: `CRYPTO_*` call counts and block sizes for the graph and the
   `OPENSSL_sk_*` blocks, success and under injected failure (proving NULL→`INTERNAL`);
6. **cleanup**: free counts after `X509_policy_tree_free` (no leak / no double-free) and cert
   refcount decrements;
7. the CVE-2023-0464 cap: a stack exceeding `node_maximum` answers the capped failure;
8. optionally the authority's own fixtures
   `test/recipes/80-test_policy_tree_data/{small,large}_policy_tree.pem` (+ leaf PEMs) via
   `openssl verify -policy_check` (`test/recipes/80-test_policy_tree.t`).
Link the authority's internal `pcy_*.o` (they are global in `libcrypto.a`) as the sparse-array
probe does; build `clang -std=c11 -O1 -I <authority>/include -o probe probe.c -L <authority>/lib
-lcrypto -Wl,-rpath,<authority>/lib -lpthread -ldl -lm`.

---

## 4. Worklist (independently recoverable units)

| id | objective | files touched | invariants to preserve | stopping condition |
|---|---|---|---|---|
| **P25-X509-001** | recon + ownership/invariant freeze (this) | this record only | — | record committed; no source changed |
| **P25-X509-002** | stable-address + allocator requirements: fix the representation that keeps stable node/level addresses and observable `CRYPTO_*`/`sk_*` allocation; stand up the differential harness | `courts/phase25/x509_policy_differential.c`, `forensics/tools/ms_x509_policy_court.py`, probe harness | §2.2, §2.4 | harness runs green on the **unconverted** crate (baseline parity) and records exact block sizes + hook counts |
| **P25-X509-003** | safe node/data ownership: replace raw `X509PolicyData`/`X509PolicyNode` blocks with an owning type at stable addresses | `pcy_data.rs`, `pcy_node.rs` | §2.2, §2.4, §2.7 | no raw block alloc/free left in the two files; existing courts + differential green |
| **P25-X509-004** | traversal: convert `tree_init`/`tree_evaluate`/link/prune/calculate to safe traversal | `pcy_tree.rs` | §2.2, §2.3 | traversal contains no raw deref/unsafe method call; ordering transcript identical |
| **P25-X509-005** | destruction / ownership transfer: safe `Drop` for tree/cache/data/node, `exnode_free` | `pcy_tree.rs`, `pcy_cache.rs`, `pcy_data.rs`, `pcy_node.rs` | §2.6, §2.8 | free-count transcript matches authority; no leak/double-free; cache-leak recorded |
| **P25-X509-006** | public accessors / pointer lifetimes: re-express the 9 `get0` accessors over the owned graph | `pcy_lib.rs` | §2.1, §2.2 | ABI check unchanged; accessor transcript identical (identity + stability) |
| **P25-X509-007** | hostile cases + Miri/sanitizers/differential | probes, `ms_miri/ms_asan`, differential tool | all of §2 | miri/asan green; cap + failure-injection green; HIDDEN=0 |
| **P25-X509-008** | reconcile + promote: `ms_reduction.py` adjudication; update `unsafe-reconstruction.json` | `forensics/memory-safety/*` | — | reduction accepted, or recorded `REVERTED_NOT_A_REDUCTION` |

Recovery rule: each unit stops at its stopping condition, leaves the tree buildable and the
existing courts green, and writes its own compact state so a fresh session resumes from it.

---

## 5. Handoff pointers
- Machine state: `forensics/memory-safety/campaign/x509-policy-tree/state.json`
- Prior campaign record naming this target: `forensics/memory-safety/unsafe-reconstruction.json`
  (`next_targets[0].id == "x509-policy-tree"`, `interior_operations: 649`)
- Model differential: `forensics/tools/ms_sparse_array_court.py`,
  `courts/phase25/rt_sparse_array_differential.c`,
  `forensics/memory-safety/sparse-array-differential.json`
