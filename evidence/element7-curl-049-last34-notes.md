# E7 last-34 batch — checkpoint notes

Branch `staging`, HEAD `c0e8bcddf` (clean at start). No commit/push.
`src/`, `Cargo.toml`, `Cargo.lock` untouched. Tool under change:
`forensics/tools/consumer_closure.py`.

Scope: the 34 remaining element-7 rows — modes 4 (ofb x3, cfb1 x1),
http 4, p12 1, and the 23 named refusals from the untouched-family batch.

Court `openssl-rs-court` (16 GiB) reused; `OPENSSL_RS_COURT_DATA=8388608`;
one DSO graph at a time; no full closure run.

(Entries appended per family below; this header is written first so a
transport failure cannot lose the index.)

## Family modes (4 remaining) — BOUND, same composition gap

**Decision: the remaining ofb/cfb1 refusal is the same composition gap, not a
genuinely open caller set.**  The field writer set and the caller set were
already enumerated by E7-CLS; only the guard/frame-slot edge of that same proof
was missing.  No new contract and no widened target set.

- **ofb128_encrypt x3** (0x2a282b, 0x2a294b, 0x2a2a78) — bound, 19 targets
each.  The only open caller was `ossl_cipher_hw_chunked_ofb128` at 0x20e13d,
which passes `ProvCipherCtx.block` loaded at 0x20e0e7 (`test 0x20e0eb` /
`je 0x20e0ee`) and reloaded at 0x20e161 (`test 0x20e170` / `jne 0x20e173`).
`_e7cls_guard_cover` now proves the back-edge test dominates the next
iteration's call and its zero edge cannot reach it, instead of requiring the
test to precede the site in linear order.  The old linear rule is restored by
`e7cls-no-loop-guard`, which refuses these three again.
- **cfb128_1_encrypt x1** (0x2a07d0) — bound, 15 targets.  The later callers
reload the spilled `cipher_data` pointer from `0x8(%rsp)` after a balanced
`push`/`push`/`add $0x10,%rsp` sequence.  `_e7cls_ctx_loads` now tracks the
net `%rsp` delta (0 at the spill and the reload) and refuses an access at any
shifted displacement that aliases the slot.  `e7cls-no-frame-stability`
restores the old any-`%rsp`-write refusal and refuses the site again.

Controls (all in `_e7cls_self_test`, real candidate image):
`e7cls-second-writer` refuses both ofb and cfb1 with
`field-writer-set-not-enumerated`; `e7cls-new-target` moves each set by exactly
the pinned function start and loses none; `e7cls-field-base-any` still flips
the wrong-base refusal; `e7cls-no-loop-guard` and `e7cls-no-frame-stability`
are load-bearing and each restores exactly.

## Family p12 (1 remaining) — BOUND, proved-empty with a deferred frame-slot guard

- **PKCS12_create_ex2 +0x3E8** (0x2686e8) — bound.  The other two p12 sites
(0x268526, 0x268b2c) already proved the caller set empty: all three in-image
callers pass a zeroed `%xmm` as parameter 12.  This site's operand is the
frame slot `0x110(%rsp)`, so `_e7lcp_guard` cannot test it as a register.  The
witness now defers the `Option` guard: if the caller set contains any non-NULL
target the site refuses `slot-not-null-guarded`; if the set is empty the call
site is unreachable and the guard is vacuous.  The result records
`guard_deferred: true`, `null_guard: null`, `proved_empty: true`; it is **not**
a claim that the frame slot was NULL-guarded.  Control: `e7lcp-new-target`
flips exactly this site to `slot-not-null-guarded`.

## Family http (4) — REFUSED: the documented ABI is libcrypto's exported copy

**Decision: refusal, not a contract.**  `OSSL_HTTP_open`/`OSSL_HTTP_get` are
local `t` symbols in libssl (0x326080/0x325a00); libcrypto exports the actual
ABI (`T OSSL_HTTP_open@@OPENSSL_3.0.0`, `T OSSL_HTTP_get@@OPENSSL_3.0.0`).
The four rows are the libssl local copies, so the documented
`OSSL_HTTP_bio_cb_t` contract names a different function in a different
module.  The installer `http_req_ctx_new` is reachable (inlined at
`http_client.rs:1347`, called at 2362), so E7-LEW's empty-writer proof does not
apply, and the in-image caller set is not closed.

A dedicated witness `http_bio_update_cb_witness` now records the exact refusal
`entry-point-is-not-exported-in-this-image` for all four sites (0x325d8d,
0x325ec5, 0x325fbe, 0x3261d8).  It still proves the field shape (single
`.upd_fn` source writer, compiled store at 0x326510 of the
`OSSL_HTTP_open` parameter, NULL-guarded loads), so a future candidate that
exports this copy can be re-evaluated without a new proof idea.  The
`ABI_CONTRACT_HTTP_BIO_CB` registry entry documents the contract considered;
**no site is bound to it**.  The self-test asserts the refusal reason on the
candidate.

## Families still refused (23) — no new binding

| family | sites | one-line reason |
|---|---|---|
| provider/rand | 3 | parent `OSSL_FUNC_RAND_*` slots extracted from the caller's `OSSL_DISPATCH` by inlined `find_call`/`entry_function`; no existing witness handles that extraction shape |
| confmod | 2 | local copy; `CONF_module_add` is not exported here, so the `init`/`finish` target set is an in-image closed set no existing witness enumerates |
| evp_pbe | 2 | local registry dispatch; the `keygen_ex` site's supplying `EVP_PBE_find_ex` call is not identifiable (`pbe-find-ex-call-is-not-unique`) |
| encoder_meth | 2 | `do_all` callback parameter of a local copy with no in-image direct caller (address-materialised only) |
| dh/check | 2 | inlined `OSSL_SELF_TEST_*` call of `OsslSelfTest.cb`; the setter is exported only by libcrypto, not this DSO |
| rand_lib | 2 | local copies; the in-image RAND method's `bytes` field writer set is not enumerated and `RAND_set_rand_method` is not exported here |
| pem_lib `PEM_do_header` | 1 | local copy's parameter 3; no in-image direct caller (address-only), no closed caller set |
| pem_lib `PEM_ASN1_write_bio_internal` | 2 | 89 in-image callers; the chain passes a non-parameter value |
| pem_pk8 `do_pk8pkey` | 1 | private; the NULL arm's `PEM_def_callback` is a local copy, not this DSO's exported entry point |
| obj | 1 | `OBJ_NAME_do_all` callback parameter; local copy, address-materialised, no in-image direct caller |
| stack | 1 | `OPENSSL_sk_pop_free`'s `func` parameter; local copy, address-materialised, no closed caller set |
| ui_read (libssl) | 1 | `UI_UTIL_wrap_read_pem_callback` is local to this DSO; the exported route is not proved |
| x509_vfy `check_crl` (libssl) | 1 | `X509_STORE_set_cleanup` is not exported by this DSO |
| passphrase | 1 | the `OsslPassphraseData` setter is not an exported entry point of this DSO |
| store_result | 1 | guarded field load with no exported writer/entry point establishing the writer set |

Counts: the 30 untouched-family rows re-resolve to the same 5 new + 2
already-bound + 23 refused.  No witness was weakened and no class widened.

## Validation (this candidate)

- `python3 forensics/tools/consumer_closure.py --self-test` -> **rc=0**,
  `self-test ok`, 0 `FAIL` lines, no new `PREMISE_UNAVAILABLE` (the one in the
  e7core summary is pre-existing).  The E7CLS line reports the ofb/cfb1,
  p12 and http results; the E7LCP matrix still has all six switches
  load-bearing.
- Targeted re-resolution (no closure): modes 4/4 bound (19/19/19/15 targets),
  p12 3/3 (one new), http 0/4 refused, untouched families 5 new + 2
  already-bound + 23 refused.  **Newly bound in this batch: 5** (modes 4,
  p12 1).
- Court peak `memory.current` 2,107,981,824 B (~1.96 GiB); `memory.max`
  16 GiB; no OOM.  `free -g` available 29-32 GiB before each heavy step;
  `OPENSSL_RS_COURT_DATA=8388608`; one DSO graph at a time.
- No Rust change, so no `fmt`/`clippy`/`cargo test` gate was run.

## Queue after

27 named rows remain refused: http 4 + the 23 untouched-family rows.  The
`±2` accounting discrepancy carried from the earlier receipts is unchanged
(34 by the commit's running count; 32 named rows here plus the 2 pre-bound
libcrypto rows).  Element 7 remains **FAIL**; `safe_compatible_curl` is
**NOT ESTABLISHED**; no consumer graduates.

## Residuals (plainly)

1. The loop-aware guard cover is a CFG dominance proof; it does not model an
   indirect jump into the middle of the loop.  None is present in this image.
2. The frame-slot stability proof walks the instructions between the spill
   and the reload linearly; it is bound to this candidate's pinned sites and
   the unique reload definition, not a path-sensitive `%rsp`-delta dataflow.
   It also admits calls between the spill and the reload under the existing
   call residual; it does not prove the callee cannot write the caller's frame.
3. The p12 result is a proved-empty target set with a deferred guard, not a
   NULL-guard proof; a non-NULL caller target refuses the site.
4. The http contract is unavailable for this DSO's local copy; libcrypto's
   exported copy is a different function and is not bound by this batch.
5. The 23 untouched-family reasons are unchanged; no new witness was
   attempted for them.
6. `ABI_CONTRACT_HTTP_BIO_CB` is a documented contract class with no bound
   site on this candidate; it is not counted as a closed or bound target set.
7. The new controls are candidate-bound; a re-freeze must re-run the E7CLS and
   E7LCP self-tests.
8. The withdrawn `CRYPTO_128_wrap_pad` result (the old closed-set proof) is not
   resurrected; the current E7CLS binding stands on the `aes_wrap_init`
   store-provenance proof and this batch leaves it untouched.
