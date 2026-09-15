# Phase 6 — `OSSL_LIB_CTX` and the provider core, as subphases

Phase 6 is the stratum that makes providers **real**. `docs/PROVIDER_MODEL.md` is the
constitution for it and is a hard gate: OpenSSL 3.x routes modern cryptographic
operations through providers, library contexts, `OSSL_PARAM` descriptors, operation
dispatch tables, algorithm fetches and property queries, so a compatibility layer
that mapped `EVP_*` onto bespoke functions while faking the provider APIs would
collapse the moment a third-party provider, an alternate `OSSL_LIB_CTX` or a
property query appeared.

This document exists before any code for the same reason `docs/PHASE-5-SUBPHASES.md`
did: D73 established that a section is not closed by writing code for it. A subphase
closes only when its exports are implemented **and** a differential court observes
them, in the same commit. Source that no build compiles and no CI checks is invisible
to every gate.

Every count below is read from the generated artifacts at the revision this document
was written at — `forensics/atlas/symbol-ownership.json`,
`forensics/phase{3,4,5}-obligations.json`, `forensics/atlas/ownership-audit.json` —
and never typed by hand. Where a count is expected to change as a subphase lands, the
table says so rather than asserting a number it cannot hold.

## 1. The universe, before anything moves

The global ownership atlas (`forensics/tools/ownership_rules.py`, D72) assigns every
one of the authority's **6,499** DSO exports to exactly one stratum. Phase 6's share:

| declaring header | rule | exports |
|---|---|---|
| `params.h` | declaring-header | 61 |
| `provider.h` | declaring-header | 22 |
| `param_build.h` | declaring-header | 20 |
| `self_test.h` | declaring-header | 7 |
| `indicator.h` | declaring-header | 2 |
| — (no installed header) | abi-only | 15 |
| `crypto.h` | reassigned by 6.0 | 10 |
| **total** | | **137** |

The `crypto.h` row is the one place in the atlas where a declaring header is too
coarse to decide: `crypto.h` declares both the core runtime and the library context,
so 6.0 reassigned the ten `OSSL_LIB_CTX_*` exports to this stratum explicitly (D97).
The first draft of this table listed 127 and then added the ten a second time in the
prose, which made the total read as 156; the derived count is **137**
atlas-owned, and the table is now read from
`forensics/atlas/symbol-ownership.json` rather than summed by hand.

Three further sets arrive as recorded hand-offs and are Phase 6's obligations even
though their declaring headers belong to other strata:

* **18 from Phase 4** (`forensics/phase4-obligations.json`, `deferred` rows with
  `owning_phase == 6`): `BIO_s_core`, `BIO_new_from_core_bio`,
  `CONF_module_add`, `CONF_module_get_usr_data`, `CONF_module_set_usr_data`,
  `CONF_imodule_get_flags`, `CONF_imodule_get_module`, `CONF_imodule_get_name`,
  `CONF_imodule_get_usr_data`, `CONF_imodule_get_value`,
  `CONF_imodule_set_flags`, `CONF_imodule_set_usr_data`, `CONF_modules_finish`,
  `CONF_modules_load`, `CONF_modules_load_file`, `CONF_modules_load_file_ex`,
  `CONF_modules_unload`, and `OPENSSL_load_builtin_modules`, which is
  `crypto/conf/conf_mall.c`'s registration loop over the built-in `CONF_MODULE`s and
  therefore cannot exist before the module registry does. The first draft listed the
  last of those separately, which is how the same 18 came to be counted as 19.
* **1 from Phase 5**: `ASN1_add_oid_module`.
* **5 from Phase 3**, deferred by 6.0: `OPENSSL_atexit`, `OPENSSL_thread_stop`,
  `OPENSSL_thread_stop_ex`, `OSSL_get_max_threads`, `OSSL_set_max_threads`.

Phase 6's working set is therefore **161** exports: 137 the atlas assigns it and 24
received by hand-off. Both numbers are in the ledger's `counts` block, and
`ownership_audit.py` reconciles the hand-off edges in both directions.

## 2. The subphases

| # | Subphase | Owns | Depends on | Court | Exit criterion |
|---|---|---|---|---|---|
| 6.0 | Ledger reconciliation | nothing — evidence | — | — | **COMPLETE**: `ownership_audit.py` fails when a stratum's ledger has no row for a symbol the atlas gives it; the four atlas overrides and the forty-odd ledger rows are recorded; phases 3, 4 and 5 re-derive without a single unaccounted export (D97) |
| 6.1 | Prototype gap closure (item 4 of the review) | nothing — evidence | — | `ABI-PROTOTYPE`, generated declaration plane | **COMPLETE** (D98): of 932 implemented exports, 921 are checked as Rust declarations, 8 as C definitions, 0 unreadable, 0 unfound, 0 mismatches on either plane; the 3 remaining are declared in headers the authority does not install and say so; three sensitivity controls prove the court can fail |
| 6.2 | Core-runtime addendum | 24 of the 29 Phase 3 exports 6.0 recorded `open`: `OSSL_trace_*` (10), `OSSL_ERR_STATE_*` (5), `OPENSSL_die`, `OPENSSL_fork_prepare/_parent/_child`, `OPENSSL_isservice`, `OPENSSL_issetugid`, `err_free_strings_int`, `OSSL_sleep`, `OSSL_get_thread_support_flags` | 6.0 | `RT-RUNTIME-EXT` | **COMPLETE** (D99): Phase 3's ledger is at zero open, its seal gains an appended §11, and the court observes all 24 in 94 observations. The other 5 — `OSSL_get/set_max_threads`, `OPENSSL_thread_stop(_ex)`, `OPENSSL_atexit` — are handed to Phase 6 with the dependency named, because each reads an `OSSL_LIB_CTX` or needs `DSO_dsobyaddr`, so 6.6 and 6.9 discharge them |
| 6.3 | BIO/CONF addendum | the 18 Phase 4 exports 6.0 recorded `open` (`COMP_*` fourteen, `conf_ssl_*` three, `OPENSSL_config`) | 6.0 | `RT-COMP` | **COMPLETE** (D99, D100): the reopened Phase 4 ledger is at zero open, the stratum re-closes, and `RT-COMP` observes 27. Six of the fourteen `COMP_*` and one of the three `conf_ssl_*` are unreachable by any consumer in this profile and the seal says so rather than implying coverage; the court also found an unrecorded `OPENSSL_info` divergence (D100) |
| 6.4 | Core-runtime addendum II — the allocator dispatch | nothing owed; this addendum adds no export. It corrects `src/runtime/mem.rs`, which Phase 3 owns | 6.3 | `RT-MEM-DEFAULT`, `RT-MEM-INSTALL` | **COMPLETE** (D102): the *default* branch of the allocation family is measured for the first time. Thirteen zero-length divergences, a release `CRYPTO_realloc(addr, 0)` was hiding behind its own NULL return, a candidate-only out-of-bounds read in `CRYPTO_memdup`, two `CRYPTO_set/get_mem_functions` dispatch gaps, one invented constant name, and one divergence recorded rather than fixed. Phase 3's seal gains §12; its courts go 8 → 10 and its observations 4,358 → 4,410 |
| 6.5 | `OSSL_PARAM` | `params.c` 61 and `param_build.c` 20 — the descriptor substrate every provider call is made of | 6.3, 6.4 | `RT-PARAM` | **COMPLETE** (D103, D104): all 81 exports implemented across `src/params/{mod,dup,from_text,build}.rs`, and `RT-PARAM` observes 1,161 behaviours on each side with zero residuals — the descriptor matrix of accessor × width × signedness × type, the setters' NULL-buffer size queries, the string and pointer forms, `BN`, dup/merge/free, text allocation and the builder. The court found two defects in the new code (a terminator written through the wrong pointer, and an exactness test using Rust's saturating cast where the authority uses the platform's) and one in **Phase 5**, whose `BN_signed_bn2native` fit rule accepted five destinations the authority refuses; that stratum's seal gains §10 and `RT-BN` gains 860 observations. Every export is also checked by both prototype planes |
| 6.6 | `OSSL_LIB_CTX` + the core dispatch table | `crypto/context.c` (658 lines), `crypto/core_algorithm.c`, `crypto/core_namemap.c`, the ten reassigned `OSSL_LIB_CTX_*` | 6.5 | `RT-LIBCTX` | **split into 6.6a–6.6g** on the dependencies 6.6a's reconnaissance found: two of the ten exports cannot be written before the core BIO (`new_from_dispatch`), the provider-child path (`new_child`) and `CONF_modules_load_file_ex` (`load_config`) exist, and those belong to 6.6c, 6.6d and 6.10. The index-slot table below is part of this subphase's closure |
| 6.6a | the context itself | the seven of the ten exports that need nothing else: `new`, `free`, `get0_global_default`, `set0_default`, `get_data`, `get_conf_diagnostics`, `set_conf_diagnostics`; `src/context/mod.rs` | 6.5 | `RT-LIBCTX` | **COMPLETE** (D106): the identity contract — the default chain, the three `free` cases of which two are no-ops, `conf_diagnostics` as per-context state, and the index registry's shape. 73 observations, zero residuals, first run. The three remaining exports are 6.6c/d/g, and the seventeen unfilled index slots are named below |
| 6.6b | the namemap | `crypto/core_namemap.c` — `src/context/namemap.rs`; fills slot 4 | 6.6a | `RT-LIBCTX` | **COMPLETE** (D109): all ten internal functions over a real `STACK_OF(NAMES)`, the bit-5-mask key comparison at the authority's 63-byte bound, the two split refusals and their order-dependence, and the `stored` flag's effect on the releaser. It adds no export, so the slot is what the court can see (RT-LIBCTX 79 → 81). The legacy pre-population is deferred **whole** to Phase 13, with the reason — running the RSA-PSS block alone would make the emptiness guard false and hide a later phase's legacy load |
| 6.6c | the core BIO | `crypto/bio/bss_core.c` — `src/context/core_bio.rs`; `src/context/dispatch.rs`; fills slot 17; adds `OSSL_LIB_CTX_new_from_dispatch` | 6.6a | `RT-LIBCTX`, `RT-BIO-CORE` | **COMPLETE** (D110): `BIO_s_core`, `BIO_new_from_core_bio` and `OSSL_LIB_CTX_new_from_dispatch` implemented, and `RT-BIO-CORE` observes 108 behaviours on each side with zero residuals — the method's identity and stable address, the constructor's refusal without a table and its acceptance of a table carrying only one of `read_ex`/`write_ex`, the five-way answer to a missing callback (`read_ex`/`write_ex` answer 0, `ctrl`/`gets`/`puts` answer −1, `destroy` answers 0) over two deliberately incomplete tables, the handle compared against the constructor's argument and against NULL, two contexts holding two tables named by the answers their callbacks produce, an up-ref that refuses, and a BIO built with a NULL context whose `libctx` is stored as given and resolved at *use* time. The court found no defect; it found that slot 17 is filled **eagerly** by `context_init`, which is why the constructor's NULL answer comes from the absent callbacks rather than from an absent globals block |
| 6.6d | the child context | `OSSL_LIB_CTX_new_child` and the `ischild` flag, which needs `ossl_provider_init_as_child` | 6.6c, 6.8 | `RT-LIBCTX` | a context whose default properties and provider set come from its parent, and the `free` child-provider deinit that 6.6a leaves a named line for |
| 6.6e | the thread slot and the counter accessors | `crypto/thread/internal.c`'s `ossl_threads_ctx_new`/`_free` and `crypto/thread/api.c`'s `OSSL_get_max_threads`/`OSSL_set_max_threads`; `src/context/thread_data.rs`; fills slot 19 | 6.6a | `RT-THREADDATA` | **COMPLETE** (D107): the slot and the two accessors, 39 observations, zero residuals, first run. The counter is per **context**, a NULL context follows the thread default, and the value is stored verbatim with no range check. The condition variable the slot owns is created and released here because `ossl_threads_ctx_new` fails without it; nothing waits on it until the thread pool exists |
| 6.6e-ii | the thread-stop pair and `OPENSSL_atexit` | `crypto/initthread.c` — the per-thread event-handler table, `OSS_get_avail_threads`, `ossl_ctx_thread_stop`; and `crypto/init.c`'s `OPENSSL_atexit` | 6.6e, 6.9 | `RT-THREADDATA` | `OPENSSL_thread_stop` and `OPENSSL_thread_stop_ex`, which need the handler table that `ossl_init_thread_deregister` walks; and `OPENSSL_atexit`, which pins the handler's object with `DSO_dsobyaddr` and so waits for the loader. These three are the remainder of the five Phase 3 hand-offs, and 6.6a's `context_deinit` names the `ossl_ctx_thread_stop` line it is waiting for |
| 6.6f | the algorithm dispatch walk | `crypto/core_algorithm.c` | 6.6b, 6.8 | `RT-LIBCTX` | `ossl_algorithm_do_all` — the walk over a provider's algorithms that the legacy method enumerations are built on |
| 6.6g | `OSSL_LIB_CTX_load_config` | the tenth export | 6.10 | `RT-LIBCTX` | a one-line forward to `CONF_modules_load_file_ex`, which is why it waits for the module registry rather than being written against a stub |
| 6.7 | Property engine | `crypto/property/property.c`, `property_parse.c`, `property_string.c`, `property_query.c`, `defn_cache.c`, `property_err.c`; fills slots 2, 3 and 14 | 6.6b | `RT-LIBCTX` | **split into 6.7a–6.7c, and its stated exit criterion is corrected here.** The subsystem is **entirely internal** — every entry point is `ossl_property_*`, `ossl_ctx_global_properties*` or `ossl_prop_defn_*`, and nothing in `libcrypto.so.3`'s export list names it — so a probe compiled against *installed headers* cannot reach one function of the grammar. The criterion this row previously carried ("definition, parse, string round-trip, matching, query parse and negative selection") was therefore **not observable through any export**, and `RT-PROPERTY` cannot be a differential court. What a consumer reaches is `OSSL_LIB_CTX_get_data`, so the three slots are observed where slot 4 and slot 17 were, by `RT-LIBCTX`; the *behaviour* the old criterion named is real and required, and it becomes observable at 6.8 (a provider fetch, which is `docs/PROVIDER_MODEL.md` §5's gate item 4) and at 6.12. Claiming it was courted here would be claiming an observation no probe can make |
| 6.7a | the string table and the three slots | `crypto/property/property_string.c`; `defn_cache.c`'s constructor and releaser; `property.c`'s two global-property functions — `src/property/` | 6.6b | `RT-LIBCTX` | **COMPLETE** (D111): slots 2, 3 and 14 filled eagerly by `context_init`, `ossl_property_parse_init` called as its last step, and the name/value indices assigned in the authority's order — which the authority itself asserts at every context construction, since `OSS_PROPERTY_TRUE` is 1 and `OSSL_PROPERTY_FALSE` is 2 and the two counters are separate. `RT-LIBCTX` goes 83 → 89. The definition cache and the global-properties holder are filled **and empty**, which is what their own constructors produce; nothing is asserted about a list nobody can yet parse |
| 6.7b | the grammars | `crypto/property/property_parse.c` (763), `property_query.c` (80), and all of `defn_cache.c` | 6.7a | the fetch at 6.8 | **COMPLETE** (D112, D113): the leaf parsers for names, decimal/hex/octal numbers and quoted and unquoted values, the dispatch on the first character, `stack_to_property_list` with its sort and its duplicate-name refusal, `ossl_parse_property`, `ossl_parse_query`, `ossl_property_match_count`, `ossl_property_merge`, `ossl_property_list_to_string` with its `put_*` helpers, and the cache's `ossl_prop_defn_get`/`set`. Twelve unit tests over the refusal cases, the merge join, the backwards printer's round trip and the cache's four shapes. Every symbol carries an `allow(dead_code)` naming 6.8, because the whole subsystem is the interface the provider fetch is written against |
| 6.7c | the store and the fetch | `property.c`'s remainder (949 lines) | 6.8 | `RT-PROVIDER` | `ossl_method_store_*` and the fetch cache, which take an `OSSL_PROVIDER *` and therefore cannot precede providers |
| 6.8 | Provider registry and dispatch | `crypto/provider.c` (158), `provider_core.c` (2,679), `provider_child.c` (317), `provider_predefined.c` (32), `provider_conf.c` (430); `src/provider/`; fills slot 1 | 6.6g, 6.9, 6.7b | `RT-PROVIDER` | the twenty-two `OSSL_PROVIDER_*` exports: the provider object and its refcount, the per-context store in slot 1, `add_builtin` and the predefined providers, `load`/`try_load`/`load_ex` over **both** the builtin and the `DSO_load` path, `unload`, `available`, `do_all`, the dispatch tables (`get0_dispatch`, `query_operation`, `unquery_operation`, `get0_provider_ctx`), the parameter and capability surfaces (`gettable_params`, `get_params`, `get_capabilities`, `self_test`), and the CONF layer (`add_conf_parameter`, `conf_get_bool`, `get_conf_parameters`, `get0_default_search_path`/`set_default_search_path`). This is the stratum that makes 6.7's grammar observable, so `RT-PROVIDER` is where `PROVIDER_MODEL.md` §5 gate item 4 — property-based fetch selection including negative selection — is discharged |
| 6.9 | DSO | the fifteen `DSO_*` — `dso_lib.c` (329), `dso_dlfcn.c` (445), `dso_err.c`, `dso_openssl.c`; `src/dso/` | 6.6a | `RT-DSO` | **MOVED BEFORE 6.8** (D114): `OSSL_PROVIDER_load`'s dynamic branch *is* a `DSO_load` call, and DSO depends on nothing in the provider registry, so the dependency only runs one way. Landing DSO first also unblocks `6.6e-ii`, whose `OPENSSL_atexit` needs `DSO_dsobyaddr`. It is much the smaller of the two (1,131 lines against 3,649) and — unlike the property engine — **all fifteen symbols are exported**, so `RT-DSO` can be a differential court rather than a slot sweep. Note that `dso.h` is exported but **not installed**: the probe must take its declarations from the authority's committed source tree, exactly as the error-coordinate resolver takes `internal/propertyerr.h` |
| 6.10 | CONF module registry | the 18 hand-offs from Phase 4 and Phase 5 — `crypto/conf/conf_mod.c` | 6.8, 6.9 | `RT-CONF-MOD` | module activation through configuration, `CONF_modules_load*`, the imodule/module accessors, and the diagnostics flag interaction D50 recorded |
| 6.11 | Self-test and indicator | `self_test.h` 7, `indicator.h` 2 — `crypto/self_test_core.c`, `crypto/indicator_core.c`; `src/selftest/{mod,indicator}.rs`; fills slots 12 and 22 | 6.6a | `RT-SELFTEST` | **COMPLETE** (D108): all nine exports, 71 observations, zero residuals, first run. The probe *is* the callback, so what it observes is what the library passes it: the array's entries alias the object's own fields (the same array reports `Pass` inside `onend`'s callback and `None` afterwards), `onend` treats anything but 1 as failure, and `oncorrupt_byte`'s answer is the callback's inverted. The indicator callback is stored and read back; nothing invokes it in this stratum, because the code that reports an indicator is provider-side |
| 6.12 | **Third-party provider court** | nothing new — the crown-jewel test | 6.5–6.11 | `RT-PROVIDER-3P` | an **independently written C provider**, compiled separately from this project and loaded **unchanged** into both the authority and the candidate, yields matching init dispatch, core upcalls, parameter flow, algorithm enumeration, property selection, operation calls, teardown and failure behaviour |
| 6.13 | Inventory generation and closure | nothing — evidence | all | — | the provider/algorithm/property inventory is generated from the authority rather than handwritten; every court passes; FRF receipts compile into a claim; the seal is written from the ledgers; a Gemel checkpoint closes the stratum |

### The index-slot table, and why it is a closure criterion

`OSSL_LIB_CTX_get_data(ctx, index)` answers a pointer for **eighteen** index numbers.
Each number names a sub-object that a different stratum owns, and the index space is not
in any installed header — it is `OSSL_LIB_CTX_*_INDEX` in
`include/internal/cryptlib.h`. A caller therefore cannot *name* a slot, but it can pass
an integer, so "which numbers answer a pointer" is observable through an exported
function alone.

That makes each slot an obligation of the same kind as an unimplemented export, and it
is easy for one to disappear between layers just as `a2d_ASN1_OBJECT` did: nothing in the
symbol ledgers can see a *field* that was never filled. The table is the record.

| index | slot | filled by |
|---|---|---|
| 0 | `evp_method_store` | Phase 7 |
| 1 | `provider_store` | 6.8 |
| 2 | `property_defns` | **filled by 6.7a** |
| 3 | `property_string_data` | **filled by 6.7a** |
| 4 | `namemap` | **filled by 6.6b** |
| 5 | `drbg` | Phase 9 |
| 6 | `drbg_nonce` | Phase 9 |
| 10 | `encoder_store` | Phase 7 |
| 11 | `decoder_store` | Phase 7 |
| 12 | `self_test_cb` | **filled by 6.11** |
| 14 | `global_properties` | **filled by 6.7a** |
| 15 | `store_loader_store` | Phase 10 |
| 16 | `provider_conf` | 6.8 |
| 17 | `bio_core` | **filled by 6.6c** |
| 18 | `child_provider` | 6.8 |
| 19 | `threads` | **filled by 6.6e** |
| 20 | `decoder_cache` | Phase 7 |
| 21 | `comp_methods` | **filled by 6.6a** |
| 22 | `indicator_cb` | **filled by 6.11** |

**Phase 6 cannot be called complete while any row above is unfilled.** The slot's owner
is the subphase named, not this stratum, and the same rule applies to those: a subphase
that closes with a slot it owns still set to NULL is not closed.

Two things about the table are worth stating explicitly.

**Why a slot is not filled with a placeholder.** The value is a live object of a type a
later stratum owns — a method store, a property definition table, a DRBG. A one-byte
allocation that merely makes the pointer non-NULL would satisfy the *observation* while
saying something false about the object, which is what this project calls a fake-success
stub. The arms in `src/context/mod.rs` answer NULL until their owner lands.

**Why the probe does not simply observe all eighteen.** A slot whose owner has not landed
can only be observed as a *missing subsystem* rather than as a divergence, and that is the
obligation ledger's business, not a court's — the same rule that keeps the phase-4 and
phase-5 probes on the implemented surface. `RT-LIBCTX` therefore observes the **dead**
indices (which answer NULL in the authority because its `switch` has no arm for them, and
must answer NULL here for the same reason), plus the slots this stratum has filled, and it
prints `libctx.slots.live`, `.filled` and `.deferred` so the transcript states the scope
of its own table rather than leaving it to be inferred. The three counts are derived from
the probe's own `filled_slots` array and the authority's index space, never typed, so a
subphase that lands adds its slot there and the counts move with it. The table above
carries the same state in the other direction — a row is `**filled by <subphase>**` or it
names the stratum still owed — so the document cannot drift from the probe without one of
the two being wrong in a way a reader can see.

### Why 6.0 comes before any implementation

The review that preceded this document found that **Phase 5's discovery was still
prefix-derived** even though its ownership was header-derived, which is how
`a2d_ASN1_OBJECT` had been invisible to every ledger at once. The global ownership
atlas fixed that.

Looking at the atlas from the *other* end exposed a second, symmetric defect that no
one had checked: the atlas assigns a stratum an export and **the stratum's ledger has
no row for it at all**. Phase 5's apparent gap of 91 turned out to be an artifact of
`ownership_audit.py` not reading the `deferred` list; phases 3 and 4 had *real* gaps —
69 and 19 exports respectively — that had been invisible because each ledger's
`FAMILIES` was a prefix list and a prefix that matches nothing reports nothing.

That is the same defect class a fourth time, and it is the thing this project exists
to remove: **an obligation that disappears between classification layers**. A phase
whose ledger has no row for an export the atlas gives it cannot be complete, and
nothing was failing when that was true. 6.0 makes it fail, then disposes of every
row honestly, then re-derives.

### Why 6.2 and 6.3 reopen phases that were sealed

Because 6.0 found that they were not, in a checkable way, complete. `docs/DECISIONS.md`
D97 records the correction, the seals gain an appended correction section rather than
being rewritten, and `phase_state.py` returns the two strata to `in-progress` from the
ledger's `open` count rather than from a typed string. Phase 6 cannot itself become
`complete` while Phase 3 or Phase 4 is not, which is the dependency-order invariant
doing exactly what it was written for.

### Why `ASYNC_*` is deferred to Phase 13 rather than implemented in 6.2

Twenty-two of the 69 exports Phase 3's ledger had no row for are `async.h`'s. They
are *not* deferred for difficulty: the authority's own tree shows every in-tree
caller is either an asynchronous engine (`engines/e_dasync.c`, `engines/e_afalg.c`,
Phase 13) or the SSL async API (`ssl/ssl_lib.c`, Phase 14), so the earliest stratum
whose own obligations require the async job framework is Phase 13. Phase 3's ledger
records the hand-off with that reason and `implemented_by_owner: false`; Phase 6.2
does not touch it. `OPENSSL_NO_ASYNC` is **not** defined in the pinned profile, so
this is real functionality waiting for a real dependent, not a stub.

### The hand-offs, which leave the stratum by disposition and not by implementation

Phase 6's own hand-offs are recorded per symbol with the dependency named, in
`forensics/phase6-obligations.json`, and each names the stratum that will absorb it.
Nothing is handed on merely because it is large.

## 3. What each subphase must honour — authority facts already established

Recorded here so they are not re-derived per subphase. Every one was read from the
authority's source at `forensics/authorities/src/openssl-3.6.4`, or measured by a
probe run in the court, and every one is a behaviour a court can compare.

### The pinned build profile (`forensics/authorities/captures/openssl-3.6.4-production/configdata.pm`)

```
enable-shared enable-legacy no-tests
no-brotli no-brotli-dynamic no-fips no-fips-jitter no-fips-post
no-ssl3 no-ssl3-method no-weak-ssl-ciphers no-trace no-zlib no-zlib-dynamic
no-zstd no-zstd-dynamic no-ktls no-sctp no-tfo no-async(absent) ...
```

`no-trace` defines `OPENSSL_NO_TRACE`; `no-zlib`, `no-zstd` and `no-brotli` define
`OPENSSL_NO_ZLIB`, `OPENSSL_NO_ZSTD` and `OPENSSL_NO_BROTLI`. Measured in the court:
`OPENSSL_NO_TRACE=1`, `OPENSSL_NO_ASYNC=0`. Phase 6 is where these stop being trivia:
the property and provider inventories are *per-profile*, and a claim that does not
name the profile is not a claim.

### `COMP_*` in this profile (`courts/phase4/discover_comp.c`, run against the authority)

All six factories answer `NULL`:

```
COMP_zlib=(nil)           COMP_zlib_oneshot=(nil)
COMP_zstd=(nil)           COMP_zstd_oneshot=(nil)
COMP_brotli=(nil)         COMP_brotli_oneshot=(nil)
```

and the accessors follow from that: `COMP_get_type(NULL)=0` (`NID_undef`),
`COMP_get_name(NULL)=NULL`, `COMP_CTX_new(NULL)=NULL`, `COMP_CTX_free(NULL)` is
harmless. `COMP_CTX_get_type(NULL)` **faults** — `comp_lib.c` dereferences
`comp->meth` with no NULL check — and that fault is recorded in
`docs/SECURITY_DIVERGENCE_POLICY.md` rather than reproduced. The consequence for 6.3
is that fourteen `COMP_*` exports need no compression library at all in this profile.

### The provider core's shape

```
crypto/params.c              1723   crypto/provider_core.c      2679
crypto/param_build.c          489   crypto/provider_conf.c       430
crypto/context.c              658   crypto/provider_child.c      317
crypto/provider.c             158   crypto/provider_predefined.c  32
crypto/self_test_core.c       160   crypto/indicator_core.c       54
crypto/property/property.c    949   crypto/property/property_parse.c 763
crypto/property/defn_cache.c  137   crypto/property/property_string.c 273
crypto/property/property_query.c 80  crypto/property/property_err.c  46
crypto/dso/dso_lib.c          329   crypto/dso/dso_dlfcn.c       445
crypto/dso/dso_dl.c           279   crypto/dso/dso_err.c          56
crypto/dso/dso_openssl.c       22
```

`dso_vms.c` and `dso_win32.c` are not this profile. Line counts are a *scope* signal,
not a plan: the plan is the inventory, and the inventory is generated.

### The gate

`docs/PROVIDER_MODEL.md` §5, unchanged and not negotiable:

1. the provider/algorithm/property inventory is generated from the authority;
2. built-in and dynamic providers load, dispatch and tear down compatibly;
3. **the third-party provider court passes** (6.12);
4. property-based fetch selection matches, **including negative selection**;
5. the FRF receipts for the above compile into a claim.

> Until then, EVP work may proceed only against genuinely provider-backed
> implementations.

## 4. Order of work, and why

1. **6.0 first, and blocking.** Every later subphase's ledger is a projection of the
   ownership atlas. Building on a projection that can silently drop a symbol would
   reproduce the defect one level up.
2. **6.1 next**, because the prototype court's blind spot grows with the stratum
   being worked on and Phase 6's `OSSL_PARAM_*` surface is 81 functions of pointer
   depth that a runtime court would only catch if it happened to call the wrong one.
   Closing it while the crate has 932 exports is materially cheaper than closing it
   at 2,000.
3. **6.2 and 6.3** discharge the reopened obligations before Phase 6 proper begins,
   so the dependency-order invariant is satisfied by work rather than by a waiver.
   **6.4** is the same kind of item found one stratum later: while preparing to build
   the descriptor substrate, reading `crypto/params.c`'s `OSSL_PARAM_set_int` against
   `src/runtime/mem.rs` exposed that the allocation family's *default* branch had
   never been measured, and a defect in the substrate every later subphase allocates
   through is not something to carry forward. It adds no export, so it is a
   correction to a sealed stratum rather than work in this one — but it is ordered
   here because it had to be, and because 6.0's rule is that an earlier stratum's
   gap is closed before a later stratum depends on it.
4. **6.5 then 6.6 then 6.7**, because that is the dependency order of the substrate:
   a descriptor is what a dispatch function is called with, a library context owns
   the property definitions, and a fetch is a property query against a registered
   algorithm.
5. **6.8, 6.9, 6.10, 6.11** in that order, for the same reason: the registry needs
   property selection, the loader is what a dynamic provider is loaded through, the
   module registry is what activates a provider from configuration, and self-test is
   the provider/context callback plumbing.
6. **6.12 only after 6.5–6.11 pass**, because a third-party provider exercises all of
   them at once. Its first green run is the stratum's real beginning.
7. **6.13 last**, and it is the only subphase allowed to say anything about the
   stratum as a whole.

### What 6.0 discovered about generator sequencing

`forensics/tools/regression_guard.py` compares a candidate against a baseline read
from the pre-change ref, so it is already fail-closed. `ownership_audit.py` is not:
it read `implemented | open` and silently ignored `deferred`, which produced an
apparent 91-symbol Phase 5 gap that did not exist. Both directions of that mistake —
reading a field that is absent as if it were empty, and not reading a field that
exists — are the same defect: **absence of an evidence plane resembling a satisfied
one**. 6.0 fixes the reader and adds the missing invariant, and D97 records the
reasoning so the next stratum does not have to rediscover it.
