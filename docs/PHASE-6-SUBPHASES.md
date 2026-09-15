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
| **total** | | **127** |

Three further sets arrive as recorded hand-offs and are Phase 6's obligations even
though their declaring headers belong to other strata:

* **17 from Phase 4** (`forensics/phase4-obligations.json`, `deferred` rows with
  `owning_phase == 6`): `BIO_s_core`, `BIO_new_from_core_bio`,
  `CONF_module_add`, `CONF_module_get_usr_data`, `CONF_module_set_usr_data`,
  `CONF_imodule_get_flags`, `CONF_imodule_get_module`, `CONF_imodule_get_name`,
  `CONF_imodule_get_usr_data`, `CONF_imodule_get_value`,
  `CONF_imodule_set_flags`, `CONF_imodule_set_usr_data`, `CONF_modules_finish`,
  `CONF_modules_load`, `CONF_modules_load_file`, `CONF_modules_load_file_ex`,
  `CONF_modules_unload`.
* **1 from Phase 5**: `ASN1_add_oid_module`.
* **1 from Phase 4** recorded by 6.0: `OPENSSL_load_builtin_modules`, which is
  `crypto/conf/conf_mall.c`'s registration loop over the built-in `CONF_MODULE`s
  and therefore cannot exist before the module registry does.

And **10 reassigned** from Phase 3 by 6.0: `OSSL_LIB_CTX_*`. `crypto.h` declares both
the core runtime and the library context, so the declaring-header rule alone cannot
separate them; the library context is Phase 6's subject matter and is the one place
in the atlas where a header is genuinely too coarse to decide. See D97.

Phase 6's working set is therefore **156** exports: 127 owned by the atlas, 28
received by hand-off, 10 reassigned into it.

## 2. The subphases

| # | Subphase | Owns | Depends on | Court | Exit criterion |
|---|---|---|---|---|---|
| 6.0 | Ledger reconciliation | nothing — evidence | — | — | **COMPLETE**: `ownership_audit.py` fails when a stratum's ledger has no row for a symbol the atlas gives it; the four atlas overrides and the forty-odd ledger rows are recorded; phases 3, 4 and 5 re-derive without a single unaccounted export (D97) |
| 6.1 | Prototype gap closure (item 4 of the review) | nothing — evidence | — | `ABI-PROTOTYPE`, generated declaration plane | **COMPLETE** (D98): of 932 implemented exports, 921 are checked as Rust declarations, 8 as C definitions, 0 unreadable, 0 unfound, 0 mismatches on either plane; the 3 remaining are declared in headers the authority does not install and say so; three sensitivity controls prove the court can fail |
| 6.2 | Core-runtime addendum | 24 of the 29 Phase 3 exports 6.0 recorded `open`: `OSSL_trace_*` (10), `OSSL_ERR_STATE_*` (5), `OPENSSL_die`, `OPENSSL_fork_prepare/_parent/_child`, `OPENSSL_isservice`, `OPENSSL_issetugid`, `err_free_strings_int`, `OSSL_sleep`, `OSSL_get_thread_support_flags` | 6.0 | `RT-RUNTIME-EXT` | **COMPLETE** (D99): Phase 3's ledger is at zero open, its seal gains an appended §11, and the court observes all 24 in 94 observations. The other 5 — `OSSL_get/set_max_threads`, `OPENSSL_thread_stop(_ex)`, `OPENSSL_atexit` — are handed to Phase 6 with the dependency named, because each reads an `OSSL_LIB_CTX` or needs `DSO_dsobyaddr`, so 6.5 and 6.8 discharge them |
| 6.3 | BIO/CONF addendum | the 18 Phase 4 exports 6.0 recorded `open` (`COMP_*` fourteen, `conf_ssl_*` three, `OPENSSL_config`) | 6.0 | `RT-COMP` | the reopened Phase 4 ledger is at zero open and the stratum re-closes |
| 6.4 | `OSSL_PARAM` | `params.c` 61 and `param_build.c` 20 — the descriptor substrate every provider call is made of | 6.3 | `RT-PARAM` | all 81 exports implemented; the court covers construct/get/set/locate/merge/dup/free/print, `OSSL_PARAM_BLD_*`, and the `modified` bitmap |
| 6.5 | `OSSL_LIB_CTX` + the core dispatch table | `crypto/context.c` (658 lines), `crypto/core_algorithm.c`, `crypto/core_namemap.c`, the ten reassigned `OSSL_LIB_CTX_*` | 6.4 | `RT-LIBCTX` | default and child contexts, `OSSL_LIB_CTX_new_child`/`_new_from_dispatch`, `get_data`/`set0_default`/`load_config`, diagnostics flags |
| 6.6 | Property engine | `crypto/property/property.c`, `property_parse.c`, `property_string.c`, `property_query.c`, `defn_cache.c`, `property_err.c` | 6.5 | `RT-PROPERTY` | definition, parse, string round-trip, matching, query parse **and negative selection** — a query that must *exclude* a definition is as much an observation as one that includes it |
| 6.7 | Provider registry and dispatch | `crypto/provider.c`, `provider_core.c` (2,679 lines), `provider_child.c`, `provider_predefined.c`, `provider_conf.c` | 6.5, 6.6 | `RT-PROVIDER` | load/unload/try_load, reference ownership, builtin and dynamic providers, `OSSL_DISPATCH` walking, core→provider and provider→core upcalls, algorithm registration, name map, gettable params, capabilities, `do_all`, operation query, fetch and the fetch cache |
| 6.8 | DSO | the fifteen abi-only `DSO_*` — `dso_lib.c`, `dso_dlfcn.c`, `dso_dl.c`, `dso_openssl.c` | 6.7 | `RT-DSO` | the dynamic loader that `DSO_load` needs to make a provider module a module |
| 6.9 | CONF module registry | the 18 hand-offs from Phase 4 and Phase 5 — `crypto/conf/conf_mod.c` | 6.7, 6.8 | `RT-CONF-MOD` | module activation through configuration, `CONF_modules_load*`, the imodule/module accessors, and the diagnostics flag interaction D50 recorded |
| 6.10 | Self-test and indicator | `self_test.h` 7, `indicator.h` 2 — `crypto/self_test_core.c`, `crypto/indicator_core.c` | 6.7 | `RT-SELFTEST` | the callback plumbing and the corrupt/begin/end transitions, which the FIPS provider's *behavioural* parity will later stand on |
| 6.11 | **Third-party provider court** | nothing new — the crown-jewel test | 6.4–6.10 | `RT-PROVIDER-3P` | an **independently written C provider**, compiled separately from this project and loaded **unchanged** into both the authority and the candidate, yields matching init dispatch, core upcalls, parameter flow, algorithm enumeration, property selection, operation calls, teardown and failure behaviour |
| 6.12 | Inventory generation and closure | nothing — evidence | all | — | the provider/algorithm/property inventory is generated from the authority rather than handwritten; every court passes; FRF receipts compile into a claim; the seal is written from the ledgers; a Gemel checkpoint closes the stratum |

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
3. **the third-party provider court passes** (6.11);
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
4. **6.4 then 6.5 then 6.6**, because that is the dependency order of the substrate:
   a descriptor is what a dispatch function is called with, a library context owns
   the property definitions, and a fetch is a property query against a registered
   algorithm.
5. **6.7, 6.8, 6.9, 6.10** in that order, for the same reason: the registry needs
   property selection, the loader is what a dynamic provider is loaded through, the
   module registry is what activates a provider from configuration, and self-test is
   the provider/context callback plumbing.
6. **6.11 only after 6.4–6.10 pass**, because a third-party provider exercises all of
   them at once. Its first green run is the stratum's real beginning.
7. **6.12 last**, and it is the only subphase allowed to say anything about the
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
