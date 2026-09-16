# Phase 6 — `OSSL_LIB_CTX`, the provider core and CONF: seal

**STATUS: complete.** Every export this stratum owns is either implemented and observed by a
differential court, or handed to a named later stratum with the dependency it is waiting on:
`open_in_this_stratum` in `forensics/phase6-obligations.json` is **zero**, and
`forensics/phase-state.json` derives `complete` only because every earlier stratum is complete
and this one's obligations are closed.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which is generated from the
ledgers and the court results by `forensics/tools/render_seal_census.py`. This seal cites that
document rather than restating its arithmetic, because a number typed here is a number that can
drift from the evidence it summarises (D97).

This is **not** a claim that openssl-rs is a usable OpenSSL. `docs/SEAL-CENSUS.md` carries the
current figures, and all 603 `libssl` exports remain `SCAFFOLDED` and abort when called.

- Authority: `openssl-3.6.4-production` (with `openssl-3.6.3-historical` admitted for the
  oracle-versus-oracle trajectory in `docs/SECURITY_DIVERGENCE_POLICY.md`)
- Court results: `artifacts/phase6/COURTS.json` — 8 courts, all pass, zero residuals
- Obligation ledger: `forensics/phase6-obligations.json` — **0 open in this stratum**
- Derived state: `forensics/phase-state.json`
- Deciding record: `docs/DECISIONS.md` D106–D131, and `docs/PHASE-6-SUBPHASES.md` for the
  subphase plan this seal closes

## 1. What this phase owns, and how that was decided

Phase 6 owns the **library context** — the object the whole of OpenSSL 3 is parameterised by —
and the **provider core** that lives inside it. The scope was not chosen; it was derived:

- **the export set** is the projection of `forensics/atlas/symbol-ownership.json` for phase 6.
  The atlas assigns every one of the authority's 6,499 exports to exactly one owner by the
  header that declares it, with `unknown = 0`, `multiply_owned = 0` and `unassigned_headers =
  0` (D127's predecessor). The five `OSSL_LIB_CTX_*` symbols Phase 3 could not write are
  discharged hand-offs recorded on both sides; so are Phase 4's eighteen and Phase 5's one.
- **the internal surface** is `provider_core.c`'s ninety-odd functions, `context.c`,
  `core_namemap.c`, `core_algorithm.c`, `provider_child.c`, `provider_conf.c`,
  `provider_predefined.c`, `crypto/conf/conf_mod.c`, `conf_sap.c`, `conf_ssl.c`,
  `crypto/property/*` and `crypto/sparse_array.c`. The prerequisite gate answers whether each
  is built or owed to a stratum, and its `blocking_dependencies` list is now **Phase 7 and 16
  only**.
- **the index-slot table** is this stratum's closure criterion. 10 of the authority's 18 live
  slots were filled when the subphase plan was written; the table in
  `docs/PHASE-6-SUBPHASES.md` §3 names the subphase that fills each of the rest, and this
  phase filled 16 and 18.

## 2. What has been built

| subphase | what it is |
|---|---|
| 6.0 | ledger reconciliation: `ownership_audit.py` fails when a stratum's ledger has no row for a symbol the atlas gives it |
| 6.1 | the generated-declaration prototype plane — `ABI-PROTOTYPE` over 932 exports |
| 6.2 | the 24 Phase-3 exports 6.0 recorded open, in `RT-RUNTIME-EXT` |
| 6.3 | the 18 Phase-4 exports 6.0 recorded open, and `RT-COMP` |
| 6.4 | the allocator dispatch, measured for the first time |
| 6.5 | `OSSL_PARAM` — all 81 exports, `RT-PARAM` |
| 6.6a–g | the context itself, the namemap, the core BIO, the thread slot, the thread-stop pair and `OPENSSL_atexit`, the child context, and `OSSL_LIB_CTX_load_config` |
| 6.7a–c | the property engine: the three slots, the two grammars, and the method store |
| 6.8a–e | the provider object and its store, `add_builtin` and the predefined table, init/activate/deactivate and the operation tables, the CONF layer, and the child provider |
| 6.9 | DSO — the fifteen `DSO_*` exports, reassigned from Phase 2 by D95 |
| 6.10a–e | RCU, the per-context thread-local family, the sparse array, the CONF module registry, the automatic configuration loader, the OID module and the `ssl_conf` module |
| 6.11 | the self-test and indicator callback pairs |
| 6.12 | the third-party provider court — `RT-PROVIDER-3P`, the only probe that compiles an `OSSL_provider_init` into itself and therefore the only one that can see the core's provider-facing table |
| 6.13 | this seal, and the closure reconciliation |

## 3. The evidence

Each court is a C probe compiled twice — once against the admitted authority's headers and
library, once against the candidate's generated headers and `artifacts/phase2` — run on the
same machine, and diffed line by line on `key=value` so one divergence produces exactly one
residual instead of shifting every following line.

| court | what it covers |
|---|---|
| `RT-LIBCTX` | the context: identity and lifetime, the default chain, the index registry's shape, `conf_diagnostics` as per-context state, `OSSL_LIB_CTX_load_config`'s three contract details, and `OSSL_LIB_CTX_new_child` with the probe playing the parent |
| `RT-PARAM` | the descriptor matrix of accessor × width × signedness × type, the string and pointer forms, `BN`, dup/merge/free, text allocation and the builder |
| `RT-SELFTEST` | the two callback pairs, the array's aliasing of the object's own fields, and the corrupt-byte answer |
| `RT-THREADDATA` | the thread slot, the two counter accessors, the thread-stop pair, `OPENSSL_atexit` and the handler table |
| `RT-BIO-CORE` | `BIO_s_core`, `BIO_new_from_core_bio` and `OSSL_LIB_CTX_new_from_dispatch` |
| `RT-DSO` | the loader: the filename conversion rules, the bind/unbind contract, and the error paths |
| `RT-PROVIDER` | the registry, the dispatch-table walk inside `provider_init`, activation and refcounts, the enumeration, and the `providers` configuration module |
| `RT-PROVIDER-3P` | the core *serving* a provider: the provider-facing dispatch table (its length outside the one deferred family, a digest of its id sequence, and the id it starts with), `CORE_GET_LIBCTX`, `CORE_GET_PARAMS` with the configuration-parameter merge and an absent key left alone, the `CRYPTO_*` trio, `CORE_THREAD_START` with the handler's having run, `OSSL_LIB_CTX_new_child` from inside `init`, the child-callback pair, and the teardown freeing the child |
| `RT-CONF-MOD` | the CONF module registry, the automatic configuration loader, and the two modules this stratum registers |

`RT-CONF-MOD` is also the differential court **RCU** could not have: `D-RCU-4` recorded that
RCU has no C-visible entry point and that no probe can reach it, and `conf_mod.c` is its only
consumer in this build — so the court that exercises the registry exercises RCU's read and
write locks, its quiescent-point accounting and its callbacks through the one path a
configuration file drives.

## 4. What the courts found

Every subphase was corrected by its own court, and the corrections are the reason the courts
exist rather than a by-product of them.

| decision | what the court found |
|---|---|
| D99 | `RT-COMP` found an unrecorded `OPENSSL_info` divergence while covering `conf_ssl_*` |
| D100 | the `COMP_*` surface's unreachable members, stated rather than implied |
| D102 | a release-only `CRYPTO_realloc(addr, 0)` hiding behind its own NULL return, and a candidate-only out-of-bounds read in `CRYPTO_memdup` |
| D103/D104 | a terminator written through the wrong pointer in the builder; and a fit rule in **Phase 5**'s `BN_signed_bn2native` that accepted five destinations the authority refuses |
| D105 | the lhash insertion-order mistake that had survived four phases |
| D106/D109 | the identity contract of the default chain, and the namemap's bit-5-mask key comparison at the authority's 63-byte bound |
| D110 | slot 17 filled **eagerly** by `context_init`, which is why the core BIO's NULL answer comes from the absent callbacks rather than an absent globals block |
| D111/D112/D113 | the property engine's name/value indices asserted by the authority itself at every context construction; and the grammars' refusal cases |
| D116/D117 | an arm on the wrong side of `if (ref == 0)`; a nullable entry point the court caught |
| D120 | a probe that called the wrong dispatch entry: `OSSL_FUNC_core_thread_start(x)` is a **cast of the entry it is handed**, not a search |
| D123 | the prerequisite gate's first run found `CRYPTO_THREAD_clean_local` defined and called from nowhere — the class a scan of the crate alone cannot see |
| D124 | RCU's four divergences, and the defect its own tests found on their first run |
| D127 | `ossl_ctx_thread_stop` written against the wrong helper, which left a freed head in the global register and made `OPENSSL_cleanup` dereference released memory. Found by running the full unit-test binary once the exit-time cleanup was reachable |
| D130 | the language census's invariant could not tell a legitimate growth from a hidden omission; it is now per authority unit |

## 5. Fault boundaries — recorded, not reproduced

Each of these is a place the authority faults, and the candidate does something defined. All
are in `docs/SECURITY_DIVERGENCE_POLICY.md`, and each names the phase or the condition that
would make the authority's behaviour reachable.

| divergence | what the authority does |
|---|---|
| `D-RCU-1`, `D-RCU-2`, `D-RCU-3`, `D-RCU-4` | an out-of-range quiescent-point index; an unlock with no thread data; an over-unlock whose `OPENSSL_assert` is active |
| `D-TEVENT-REENTRANT-1` | a handler that registers another handler deadlocks, because the walk holds the register's write lock across the call |
| `D-TEVENT-CTX-STOP-LEAK-1` | **withdrawn.** The entry described the candidate's own defect as the authority's; the correction is written out in place |
| `D-CHILD-DEREGISTER-NULL-1` | `ossl_provider_init_as_child` validates seven of its eight pointers, and `ossl_provider_deinit_child` calls the eighth unguarded |
| `D-CHILD-REGISTER-PROPS-1`, `D-CHILD-PROPS-CB-1` | the child's global-property path is Phase 7's `evp_fetch.c`, so the candidate omits it and says so |
| `D106`'s crash, and the sparse array's failure path | recorded where they were found, with what the candidate answers instead |

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable OpenSSL.** `implemented` in the ledgers means a symbol with
   that name is defined. `docs/PARITY_MODEL.md` states what each label means.
2. **`libssl` is untouched.** All 603 exports abort when called.
3. **The fallback walk is courted only in its disabled state.** The three predefined providers'
   `init` pointers are NULL in this crate because `ossl_default_provider_init`,
   `ossl_base_provider_init` and `ossl_null_provider_init` are Phases 7 and 8's. From the first
   `OSSL_PROVIDER_load` the walk takes its early return on both sides, so `available`, `do_all`
   and the enumeration *are* compared — and the day 7/8 lands them this exclusion must be
   revisited, which `RT-PROVIDER`'s header says.
4. **The `OPENSSL_load_builtin_modules` fan-out is six of seven short.** `ASN1_add_stable_module`
   (11), `ENGINE_add_conf_module` (13), `EVP_add_alg_module` (7), `ossl_random_add_conf_module`
   (9) are absent; `ssl_conf` and `providers` are registered and `oid_section` is. A
   configuration naming one of the four observes the difference, which is why `RT-CONF-MOD`
   names `oid_section` and `ssl_conf` and nothing else.
5. **`CONF_get1_default_config_file`'s fallback is divergent.** It answers the authority's own
   `OPENSSLDIR` and this crate's empty string, so a NULL filename with `OPENSSL_CONF` unset is
   not observed by any court — stated in `RT-LIBCTX`'s header rather than left to be discovered.
6. **The namemap's legacy pre-population is deferred whole to Phase 13**, with the reason.
7. **Provider-side property handling is Phase 7's**, so the child's global-property path
   (`D-CHILD-REGISTER-PROPS-1`) and the method store's fetch are written *against*
   `evp_fetch.c`, not by it.
8. **The index-slot table is incomplete by design.** The slots Phase 7, 9 and 10 fill are named
   in `docs/PHASE-6-SUBPHASES.md` §3 with the subphase that fills each, and `RT-LIBCTX` prints
   its own scope so a reader of the transcript can see the gap without reading the probe.
9. **The algorithm dispatch walk (6.8f/6.6f) is not built, and is Phase 7's prerequisite
   rather than this stratum's obligation.** `crypto/core_algorithm.c`'s `ossl_algorithm_do_all`
   has exactly **one** authority caller — `crypto/core_fetch.c`'s `ossl_method_construct`, the
   fetch path — and nothing in this crate references it, so it was invisible to the
   prerequisite gate, whose rule is about names a crate module *references*. It is now a
   recorded deferral owned by Phase 7 (`forensics/prerequisites.json`, D132), which is where a
   name that nothing can yet call belongs. The alternative — leaving it unnamed because nothing
   names it — is the `a2d_ASN1_OBJECT` failure class arriving from the other direction, and it
   is the reason this seal says so instead of staying silent.
10. **Every count is `docs/SEAL-CENSUS.md`'s.** This document types none of them.

## 7. Exit criteria

| criterion | evidence |
|---|---|
| every export the stratum owns is implemented or handed to a named later stratum | `forensics/phase6-obligations.json`: `open_in_this_stratum` = 0 |
| every implemented export is observed by a differential court | `artifacts/phase6/COURTS.json`, 8 courts, `all_pass` |
| every internal function a transcribed unit calls is built or owed to a stratum | `forensics/atlas/prerequisite-gate.json`: `findings` = 0 |
| every implemented export's Rust declaration matches the authority's C prototype | `forensics/atlas/prototype-court.json` |
| the three earlier strata are complete, which the rule requires | `forensics/phase-state.json` |
| the stratum's own structure is reconciled against its ledger | `forensics/atlas/ownership-audit.json`, cross-ledger double counts = 0 |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the merge base's baseline |

## 8. FRF and Gemel

### FRF

Phase 6's behavioural corrections are recorded through the FRF chain — Authority → Court →
Capture → Residual → Endoduction → Route → Disposition → Receipt → Claim — under the FRF
court's own store, which is recreated from clean on every run in which the candidate's
behaviour changed. The receipts and claims for this stratum are the ones the FRF court
generated for the corrections listed in §4; their identities are read back from the store
rather than quoted here, because a quoted identity goes stale the moment the store is rebuilt.

### Gemel

The stratum's trajectory — the plan, what the reconnaissance measured, the discards, and the
checkpoints — is projected into `forensics/GEMEL_TRAJECTORY.md`, and the native Gemel store's
`exchange/` namespace is what carries the machine-readable half. As elsewhere, the native store
itself is not Git-tracked; the projections are, and the checkpoint identities in the trajectory
file are the ones the store answered.

## 9. What happens next

Phase 6 is the last stratum whose completion is a *precondition* for everything after it: the
library context and the provider core are what every fetch, every method and every algorithm
is reached through. Phase 7 (`EVP`) is therefore the first stratum that can be written *into*
an existing registry rather than beside a missing one, and the defers this stratum recorded are
its first work items:

- `evp_generic_fetch`, `evp_generic_fetch_from_prov`, `evp_generic_do_all`, `evp_is_a`,
  `evp_names_do_all`, `evp_get_global_properties_str`, `evp_set_default_properties_int`,
  `evp_default_properties_enable_fips_int` — the eight names the gate lists as blocking, all
  `crypto/evp/evp_fetch.c`'s;
- the three predefined providers' `init` functions, which close §6's item 3;
- slot 0 (`EVP_METHOD_STORE`), slot 10 (`ENCODER_STORE`), slot 11 (`DECODER_STORE`), slot 15
  (`STORE_LOADER_STORE`) and slot 20 (`DECODER_CACHE`), which are the five slots named in the
  index table as Phases 7 and 10's.
