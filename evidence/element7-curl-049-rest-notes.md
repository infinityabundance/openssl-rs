# E7 untouched-family batch — checkpoint notes

Branch `staging`, HEAD `230d2a13e` (clean at start). No commit/push.
`src/`, `Cargo.toml`, `Cargo.lock` untouched. Tool under change:
`forensics/tools/consumer_closure.py`.

Scope: the ~30 sites in families no earlier batch touched — ssl_mcnf,
provider/rand, confmod, evp_pbe, encoder_meth, dh/check, rand_lib,
pem_lib/pem_pk8, obj, stack, ui_read, x509_vfy/check_crl, cmp_vfy,
passphrase, store_result, SSL_CTX_new_ex.  Court `openssl-rs-court`
(16 GiB) reused, not recreated; `OPENSSL_RS_COURT_DATA=12582912`;
no full closure run.

(Entries appended per family below; this header is written first so a
transport failure cannot lose the index.)

Artifacts: `court/tmp/rest/{probe_shapes,probe_ctx,probe_dso,probe_sf,
probe_gates,probe_why,reresolve}.py`, `probe-shapes.json`, `reresolve.json`,
`reresolve-baseline.log`, `reresolve.log`, `selftest.log`.

## Family ssl_mcnf (3 sites) — BOUND, contract

`ssl_do_config` dispatches `CONF_SSL_NAME_FIND`, `CONF_SSL_GET`,
`CONF_SSL_GET_CMD`.  Each is a `dso_shared::LazySymbol` cell: the inlined
`resolve` calls `dlsym(RTLD_DEFAULT, "<export>")`, stores `%rax` into the
cell, stores the PRESENT state at cell+8, then the site NULL-guards the load
and calls it.  Those are the documented libcrypto exports `conf_ssl_name_find`,
`conf_ssl_get`, `conf_ssl_get_cmd`; the in-image fallback arm calls the local
copy.  The E7-DSO shape already proves this exactly; the batch adds the four
cells to `E7DSO_CELLS` (an enumeration extension, same witness, same
writer/defect rules).  Writer set per cell: two inlined publications (one in
`ssl_do_config`, one in the `dso_shared` helper); no other reference is a store.

## Family SSL_CTX_new_ex (1 site) — BOUND, contract

The site's only defs are the inlined `dlsym(OPENSSL_init_crypto)` publication
(store at 0x483b1b) and the cell load at 0x483b53; NULL-guarded, with the
in-image `runtime::init::OPENSSL_init_crypto` fallback.  Bound by the same
E7-DSO witness with the `OPENSSL_INIT_CRYPTO` cell.

**Correction, not a withdrawal.**  The batch-2 note called this operand a
"two-definition `SSL_METHOD` table slot".  The two defs are the dlsym cell
load and the inlined dlsym publication.  Batch-2 *refused* the site (it was
never bound), so nothing is withdrawn; the new result supersedes a refusal
only.  The earlier `CRYPTO_128_wrap_pad` withdrawal is untouched and is not
resurrected.

## Family cmp_vfy (1 site) — BOUND, proved-empty (E7-SF)

`check_msg_all_certs` contains the inlined `sk_pop_free` thunk arm: it loads
`Inner.free_thunk` at the installer's compiled offset `0x20`, NULL-tests it,
and calls `thunk(freefn, elem)` with `%rdi` materialised as the in-image
`x509_free_void`.  Same field, same installer (`OPENSSL_sk_set_thunks`, local,
no reference of any kind), same `from_boxes { free_thunk: None }` constructor
and copy-only propagators, so the empty set is the field's proof, not a new
claim.  Added as the fourth `E7SF_SITES` pin (`check_msg_all_certs`+0x1D6).

The separate `OPENSSL_sk_pop_free` site in the `stack` family is the `func`
*parameter*, not this field, and stays refused below.

## Families refused (23 sites)

| family | sites | reason |
|---|---|---|
| provider/rand | 3 | parent-provider `OSSL_FUNC_RAND_*` slots in `ProvDrbg` are loaded from the caller's `OSSL_DISPATCH` via inlined `find_call`/`entry_function`; no existing witness handles that inlined extraction shape |
| confmod | 2 | local copy; `CONF_module_add` is not exported by this DSO, so the `init`/`finish` targets are an in-image closed set that no existing witness enumerates |
| evp_pbe | 2 | plain `keygen` is a libssl-local registry dispatch; the `keygen_ex` site's supplying `EVP_PBE_find_ex` call is not identifiable in this copy (`pbe-find-ex-call-is-not-unique`) |
| encoder_meth | 2 | `do_all` callback parameter of a local copy with no in-image direct caller (address-materialised only); no finite call-site set to close |
| dh/check | 2 | inlined `OSSL_SELF_TEST_onbegin/onend` call of `OsslSelfTest.cb` (application `OSSL_CALLBACK`); `OSSL_SELF_TEST_set_callback` is exported only by libcrypto, so the exported route is not proved in this DSO (same rule as the libssl `ui_read`/`check_crl` twins) |
| rand_lib | 2 | local copies; slot is the in-image RAND method's `bytes` field reached from the context; the method-table writer set is not enumerated and `RAND_set_rand_method` is not exported here |
| pem_lib `PEM_do_header` | 1 | callback is the local copy's parameter 3; no in-image direct caller (address-only), no closed caller set |
| pem_lib `PEM_ASN1_write_bio_internal` | 2 | 89 in-image callers; the chain passes a non-parameter value (`caller-chain-passes-a-non-parameter-value`) |
| pem_pk8 `do_pk8pkey` | 1 | private; the NULL arm's `PEM_def_callback` is a local copy, not this DSO's exported entry point, so the exported-callback-default contract does not apply |
| obj | 1 | `OBJ_NAME_do_all` callback parameter; local copy, address-materialised, no in-image direct caller |
| stack | 1 | `OPENSSL_sk_pop_free`'s `func` parameter; local copy, address-materialised, no closed caller set |
| ui_read (libssl) | 1 | `UI_UTIL_wrap_read_pem_callback` is local to this DSO (`wrapper-is-local-to-this-dso`); libcrypto 0x28a500 was already bound (PEM_PASSWORD_CB) |
| x509_vfy `check_crl` (libssl) | 1 | `X509_STORE_set_cleanup` is not exported by this DSO; libcrypto 0x421cb2 was already bound (X509_CTX_CALLBACK) |
| passphrase | 1 | `OsslPassphraseData` callback is installed by `ossl_pw_set_ossl_passphrase_cb` (refuses NULL); the setter is not an exported entry point of this DSO |
| store_result | 1 | guarded field load from the store-load-result data; no exported writer/entry point of this DSO establishes the writer set |

Counts: 5 newly bound, 2 already bound (the libcrypto `ui_read` and
`check_crl` twins), 23 refused.  5 + 2 + 23 = 30.

## Controls added (each fires)

- `E7DSO_CELLS` four new cells.  Self-test per new site: baseline resolves
  (`ABI_CONTRACT_DSO_EXPORT`, `writer_set_closed`); `e7dso-second-writer`
  refuses `cell-has-a-writer-outside-the-enumerated-seam`; removing the
  site's cell from the enumeration refuses (no target admitted).  Independent
  evidence: the pre-edit baseline re-resolution refused all four with
  `dlsym-result-is-not-stored-into-a-cell` (cells not enumerated).
- `E7SF_SITES` fourth pin.  Self-test: baseline resolves to `[]` with
  `proved_empty`; the load offset equals the installer's compiled store
  offset; a synthetic graph with one new direct call to
  `OPENSSL_sk_set_thunks` flips that exact site to
  `installer-has-in-image-caller`.  Independent evidence: the pre-pin
  baseline left the site `unmatched` (target-bounded).
- No existing witness or refusal was weakened; no class was widened.  The
  only behavioural change is the enumeration/pin extension.

## Validation

- `python3 forensics/tools/consumer_closure.py --self-test` → **rc=0**,
  `self-test ok`, no `FAIL` line, no new `PREMISE_UNAVAILABLE` (the one
  occurrence is the pre-existing e7core summary sentence).
- Targeted re-resolution (no closure run): 30 rows seeded; 4 contract-bounded
  (`E7DSO_contract_bounded=4`), 1 proved-empty resolved (`E7SF=1`), 2 already
  bound, 23 refused by name.
- Full closure: **NOT_RUN** (per the brief).

## Queue after

56 → **51** by the running count (5 bound).  The triage's own arithmetic gives
55 → 50: 82 rows − 27 already resolved (13 witnesses + 2 comparator + 3
batch-2 + 9 closedset) = 55.  The ±1 between 56 and 55 is the accounting
discrepancy already recorded in the batch-2 notes; it is reported, not
smoothed.  Remaining known groups: modes 21, http 4, p12 1, plus this batch's
23 refusals = 49 named rows; the residual ±2 is carried from the earlier
receipts.

## Residuals

1. The E7-DSO claim remains the in-image `LazySymbol` writer set plus the
   documented export name; a runtime `LD_PRELOAD`/GOT interposer is outside it
   (unchanged residual).
2. The E7-SF empty set remains a claim about stacks this image constructs; the
   installer is local and unreferenced, and the exported-entry-point account is
   unchanged from the prior batch.
3. `confmod`, `rand_lib` and `provider/rand` are plausible closed-target-set
   proofs (in-image method/module tables) that this batch did not attempt;
   each would be a new witness needing its own mutation control.
4. `dh/check` is a genuine application-callback ABI; binding it would need a
   self-test-callback contract class, which is a new boundary, not an existing
   shape.  Refused deliberately.
5. element 7 remains **FAIL**; `safe_compatible_curl` is **NOT ESTABLISHED**.
   No consumer graduates.  No earlier result is withdrawn.
