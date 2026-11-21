# Earned Trust Protocol — work queue

Single tracked queue for the assurance programme. Nothing in this file is a
claim: `DONE` means the artefact exists in Git at the named commit, `PARTIAL`
means a bounded piece exists with named residues, everything else is open.

Status vocabulary for each item: `TODO`, `IN_PROGRESS`, `PARTIAL`, `DONE`,
`BLOCKED` (with the blocker), `NOT_APPLICABLE` (with the reason).

Rules that bind this queue (from AGENTS.md, extended by the ETP mandate):

- a claim may never exceed its evidence; an implementation is not a specification;
- a test is not a proof; source-level verification is not binary-level verification;
- compatibility is not security; memory safety is not constant-time execution;
- a reproducible build is not a correct build; a signature establishes provenance,
  not truth;
- an independent agent is not an independent organisation;
- absence of observed failure is not universal absence;
- an undocumented assumption is an unresolved obligation;
- a counterexample outranks a thousand successes within its scope;
- an instrument must demonstrate sensitivity to the defect it claims to detect;
- historical evidence is never fresh evidence;
- no authority, including the project principal, may promote a contradicted claim
  by declaration;
- **do not omit, do not stop, push often.**

---

## A. Already landed (this programme)

| item | commit | scope, honestly stated |
|---|---|---|
| Timing toolchain installed and validated | `32a4b7828` | valgrind 3.19, ctgrind technique (stock valgrind + client requests), dudect @ `dc269651`, BINSEC 0.11.3 + `unisim_archisec`, TIMECOP method; controls fire. perf BLOCKED on capability at that commit. |
| perf unblocked + toolchain persisted | `18d12e1d5` | `--cap-add=CAP_PERFMON` (seccomp untouched, CapEff delta exactly bit 38); derived image `openssl-rs-court-tools:1`; all instruments re-validated; capability negative control reproduces the old `EPERM`. |
| BN separations have a measured mechanism | `20ee9dc90` | ctgrind: 771 errors/9 contexts (branches on secret exponent bits); inverse 620/209 incl. 38 secret-derived address uses; dudect t 3855/2464/3262/3698. Reachability: both symbols may-bound only; DH reaches the same core via `BN_mod_exp_mont`. |
| Constant-pattern exponentiation | `968fa281a` | fixed-width ladder, Montgomery REDC, masked select; ctgrind 771 → 4; dudect → 1.59–2.37; 2344 tests, RT-BN 1510/0. |
| Public loop width + constant normalise | `d3c6d4210` | width from modulus limb count; `normalise_consttime`/`store_consttime`; ctgrind 0/0; EC secret base recorded open. |
| Public geometry + length-taint control | `b7d5ff745` | loop reads only `exponent[i>>6]`; length-taint control fires with 19 errors, none in the ladder; allocations 14 365 → 31. |
| Timing receipt bound to binary | `0c5f10f1e` | `revision_3` in `evidence/timing-bn-repair.json`; earlier fields marked `superseded`, not deleted. |
| `SecretBuf` cleanses on all exit paths | `8e6c539ae` | volatile zeroise in `Drop`; no `Copy`/`Clone`/`into_inner`; wired into the consttime ladder only. |
| Destructor proven by mutation; boundary copy cleansed | `3f9369878` | removing the `Drop` body → 1 passed/3 failed; exponent adopted via `SecretBuf::from_vec`; full DSO digest recorded. |
| Timing harnesses tracked | `53ad82779` | `courts/phase18/timing/` with README, geometry, result vocabulary. |
| Campaign baseline | `0433aa40c` | identity, Phase-18 reproduction, 9.9p1 vs 10.5p1 reconciliation, absent-tool inventory. |
| Curl closure | `07f9f1bb9` | ACCEPTED, 0 BLOCKED, 0 UNKNOWN, 644 files, 7/7 discharged. |
| Curl element-7 queue | `2e74a2ec0` | 219 → 27 named refusals; every reduction mutation-controlled; element-7 still **FAIL**. |

---

## B. Timing safety — open work

| id | item | status |
|---|---|---|
| T1 | Infallible allocations in `limbs::rem`/`limbs::mul`; `base_plain`, `rr`, `one_mont`, `product` still plain `Vec`s (`OBL-BN-ALLOCATOR`) | PARTIAL: `limbs::{rem,mul,shl,shr,div_rem,div_rem_small,from_u64}_fallible`; the consttime ladder (`base_plain`/`rr`/`one_mont` in `SecretBuf`, `product` fallible) returns `None`/0 on failure, with a forced-failure test. Residual: C-ABI `bignum::parts` clones and the variable-time `limbs::{rem,mul}` wrappers still allocate infallibly; `OBL-BN-ALLOCATOR` stays open. |
| T2 | `SecretBuf::from_vec` cleanses initialised length only; spare capacity may retain secret bytes — establish a storage invariant or cleanse the whole allocation | DONE: `Drop` cleanses the whole allocation (`capacity * size_of`), writes only; invariant documented in `bn/secret.rs`; capacity test fails when disabled |
| T3 | Destructor cleansing is proportional to normalised (secret) length; representation-level fix needed, not a normalisation tweak | DONE for the protected buffer: the exponent is staged by `fixed_width_exponent` into an allocation sized by the declared **public** width (modulus limb count) before any secret limb is copied, so the ladder's long-lived `SecretBuf` cleanse extent is public. The earlier residual (a secret-sized `parts()` clone cleansed over `capacity() * 8` bytes) was removed by T9: the C entry points borrow the caller's magnitude instead of cloning it, so no secret-sized allocation exists on the constant-time path. The one remaining length read is the staging transfer's presence test, tracked with T9. |
| T4 | Mutate only `cleanse_now()` while keeping the observer, to prove the tests detect uncleansed bytes rather than only the absence of the destructor | DONE: cleanse-only mutation re-observed at `ce86f2aab` → **0 passed / 5 failed**; restored → 5 passed. The implementation arrived inside commit `d9fa09689` whose message describes only documentation; that provenance defect is recorded here rather than rewritten. |
| T5 | EC secret-base reduction: `ecdsa_sign_setup` inverts nonce `k` via `ec_field_inverse_mod_ord`; `ossl_ec_GFp_mont_field_inv` takes field elements; initial `limbs::rem` is variable-time | DONE for the ladder path: nonce `k` (secret) and EC field elements (conditionally secret) are classified per call site; `mod_exp_core_consttime_staged` replaces the initial `rem_fallible` with zero-extension plus `mont_mul_fallible(base, rr)` when `ad.len() <= n`, relying on the documented precondition `base < R = 2^(64n)`, which both EC callers satisfy. The first taint run exposed 24 overflow-check branches in `mont_mul_into`, fixed by `mul_add_carry` with `wrapping_*` under a proven `< 2^128` bound. ctgrind: real 0 errors, control fires. **Open:** `ossl_ec_GFp_simple_field_inv`'s `BN_mod_inverse` (T7), bases wider than `n`, `mod_exp_core` on public inputs, and RT-BN was NOT RUN in this batch. |
| T6 | RSA CRT moduli are secret (only the width is public); Montgomery precomputation runs on them — taint CRT modulus contents, not just exponents | PARTIAL: tainted CRT moduli took the error count from 185 contexts / 113 694 to 114 / 97 152, classified (a) 109, (b) 5, (c) 0. Repaired `mont_set`'s `ri`/`rr`, the ladder's `R`/`R²`, `mont_reduce`, `BN_to_montgomery`/`BN_mod_mul_montgomery` and the smooth-arm decision (branchless `bn_num_bits_consttime`). **Also repaired a correctness defect found on the way: the smooth CRT arm's result was overwritten because a `goto tail` was missing, so every private operation silently fell back to the unblinded `d` exponentiation.** Open: recombination still reads `p`/`q` (`BN_mul(r1,q)`, `BN_add(r1,p)`), revealing zero limbs of the first multiply operand, carry propagation ≤ n+1 limbs and one carry bit; result-length contexts reveal `floor(bitlen/64)`; RT-RSA NOT RUN. |
| T7 | `BN_mod_inverse`: 171 branches + 38 secret-derived addresses + 28 allocator branches; needs a domain-correct constant-time inversion, with a separate variable-time public path | PARTIAL: fixed-iteration binary extended GCD for odd moduli (`limbs::mod_inverse_consttime_with_mask`), with `BN_FLG_CONSTTIME` dispatch on `a`/`n` and a fail-closed internal entry; secret callers routed (EC simple field inverse, DSA blind/nonce via base-flag dispatch, RSA blinding, RSA CRT `iqmp`, RSA `(p-1)⁻¹ mod e`, RSA validation, X9.31/FIPS odd-modulus inversions). ctgrind on the secret inversion: **0 errors**, control **4/1 context**; old same-input VT core 18 935/125. Gates: fmt 0, clippy 0, 2365 passed/0 failed/54 ignored. **Open:** even-modulus RSA keygen `e⁻¹ mod φ/λ` and FIPS `r₂⁻¹ mod 2r₁` remain variable-time (binary EEA needs odd modulus; `p-2` invalid on composites); limb-count metadata (T8/T9); one authorised no-inverse declassification branch; authority differential/RT-BN/BOUNDARY/SEAL NOT RUN. Evidence: `court/tmp/t7/NOTES.md`. | **Also open, found by review:** the new inversion still builds secret intermediates with plain fallible-less `vec!` at a secret-derived width — tracked as T24.
| T8 | Observable result bit length survives in the returned `BIGNUM` (`store_consttime`) | DONE (option (b), normalised output retained): `store_consttime`/`new_owned_consttime` take the **public** limb width and `limbs::normalise_consttime` scans exactly that width with masked selects, so the trim's cost is bounded by public geometry even if a pre-trimmed (variable-time) magnitude arrives. Option (a) (a flagged fixed-width output) was rejected: it would make `BN_num_bits`/word accessors report a width OpenSSL's normalised `BIGNUM` does not, changing exported behaviour. **Remaining visible to a caller by design:** the returned magnitude stays normalised, so `BN_num_bits`, `BN_bn2bin`, `d.len()` and downstream readers (e.g. `BN_bn2binpad`'s fit check) can still observe the result's bit length — a declassification at the `BIGNUM` API, recorded rather than hidden (T9 covers the downstream length-dependent copies). ctgrind on the store: **0 errors**, control fires. Evidence: `court/tmp/t8/NOTES.md`. |
| T9 | Secret-length-dependent boundary copy and admission checks (the 19 length-taint sites) | PARTIAL: the boundary no longer clones the exponent at its own length. `bignum::magnitude` borrows the caller's storage; `stage_fixed_width_exponent` allocates exactly the **public** width and writes exactly `width` destination limbs with a masked extension (`limb & constant_time_lt_s(i, len)`), so the allocation, the destination write count, the ladder's `64 * width` loop and the cleanse extent are public geometry. Length-taint (`modexp_len`) on the release DSO: current-HEAD baseline **24 errors / 21 contexts** (12 memmove, 2 allocator-size, 7 direct — the recorded 19/19 predates the T3 split by two commits) → **5 errors / 5 contexts**: 1 **admission** (`len > width` refusal, kept and stated) + 4 unrolled instances of the single presence/bounds test in the transfer. That test is **open**, not hidden: the caller's `BIGNUM` stores only `len` limbs (DH's 256-bit private exponent under a 2048-bit modulus is the normal case), so a public-width read would be out of bounds or read uninitialised spare storage. `modexp` (contents) **0/0**; controls 0 and 4096/1. Mutation: restoring `min`+`copy_from_slice` raises `modexp_len` to **7/7 (6 memmove)** and fails the new staging-width test (2 vs 4). Gates: fmt 0, clippy 0, **2369 passed / 0 failed / 54 ignored**. Evidence: `court/tmp/t9/NOTES.md`. |
| T10 | Unify `CleansedScratch<const N>` and `SecretBuf<T>` into one secret-storage policy (`SecretArray<N>`, `SecretBuf<T>`, `SecretLimbs`, `SecretRef`) | DONE: `src/runtime/secret.rs` states the policy (`SecretArray<N>`, `SecretBuf<T>`, `SecretLimbs`, `SecretRef`); every `CleansedScratch`/`CleansedBlock`/`CleansedHeap`/`SecretScratch` call site and BN limb storage migrated; allocator/C-owned seams and 516 ad-hoc cleanses deliberately unmigrated with reasons. Mutation re-check after the refactor: 0 passed / 11 failed with the wipes disabled, green when restored. Residual: `runtime::secret` re-exports `SecretBuf` from `bn::secret`, so the runtime layer depends on BN for a runtime-wide abstraction — to be moved (T26). |
| T11 | RSA blinding lifecycle and CRT recombination review; padding implicit-rejection consistency; error paths not disclosing secret validation state | PARTIAL: lifecycle established (lazy setup, convert/invert per private op, refresh every 32 uses, release in finish/free; setup failure raises ERR_R_INTERNAL_ERROR, no silent unblinded fallback). New end-to-end test with blinding on: the CRT tail fallback counter stays 0 and a negative control (dmp1+1) fires it. CRT arms shown to agree with blinding cancelling; padding implicit rejection verified per scheme with no divergence. Residuals: blinding factor released with BN_free rather than cleansed (authority parity, recorded), no runtime timing evidence, and mid-operation-failure reuse is control-flow evidence only. |
| T12 | ECDSA nonce generation, inversion and scalar arithmetic reviewed end to end | PARTIAL: path traced through `ecdsa_sign_setup` → `EC_POINT_mul` → `BN_nnmod` → `ossl_ec_group_do_inverse_ord` → Montgomery s-computation → encoding, with each step classified. **Defect found and fixed:** `store`/`store_consttime` released the replaced limb vector uncleansed, so the nonce was freed uncleansed whenever it was overwritten by k⁻¹ (every successful signature) and a rejected candidate was freed uncleansed on redraw; `cleanse_replaced` now wipes a `BN_FLG_SECURE` destination's capacity first. Inversion uses the T7 fixed window; scalar multiplication is the branchless ladder with a public bound. ctgrind on a fully tainted sign: 821 982–822 904 errors / 128 contexts, broken down as ~39 trim, 14 compare, 9 division, ~38 secret-length→copy/alloc, 5 bit-length, 6 ladder/field, 1 T7 declassification; the control adds exactly one context. Open: no constant-time mod-add (the `bn_mod_add_fixed_top`→`BN_mod_add` substitution accounts for most of the 128), fixed-width secret store, `limbs::cmp`/`normalise`/`bit_len` value dependence, uncleansed `BN_CTX` scratch, and no authority differential. |
| T13 | `core::hint::black_box` audit — it guarantees nothing; audit every use and every secret-bearing caller of `constant_time.rs` | DONE: 17 uses inventoried (12 production, 5 test-only); contracts that implied a guarantee corrected to a best-effort barrier; per-helper guarantees stated; a -O3 test disassembles the select family and rejects conditional jumps, loops and calls. Residuals: binds to rustc 1.98.1 / x86-64 / no LTO / overflow-checks on; post-LTO callers and the curve448 and bn/limbs barriers unchecked; branchless is not fixed-latency. |
| T14 | Optimised-code review: LTO/inlining/cmov-vs-branch, division latency, CPU feature dispatch; automated binary inspection rather than assembly snapshots | DONE for the audit, with a finding: profile recorded (release, opt-level 3, cgu 16, no LTO, overflow checks on, cc -shared over the archive); `courts/phase18/timing/binary_branch_audit.py` reports per-function jcc/div/cmov and is now fail-closed (exact unique symbol match, non-empty disassembly, explicit expected-coverage count, non-zero exit on missing or ambiguous). Auditing a fresh DSO (f092d095) resolves all 7 and exits 0; the stale tracked DSO correctly exits 1 naming four missing. BN_div ignoring BN_FLG_CONSTTIME is T28. Residual: secret-dependence is not established; review aid until T16 is validated. |
| T15 | Compiler-upgrade policy that invalidates code-generation assurance until rechecked | DONE: `docs/CODE-GENERATION-ASSURANCE.md` binds each result to rustc/LLVM, target, the exact release profile, linker and DSO digest; any change to that set invalidates automatically, and re-checking means machine-code test + branch audit + the affected dudect/ctgrind cases. |
| T16 | BINSEC `-checkct` with a validated `-sse-script`; previously exited 0 with no output | PARTIAL: the non-result is explained (`-checkct` alone starts no engine; with `-sse` but no script it says `Nothing to reach`). The working invocation is `-sse -checkct -sse-script <cfg> -smt-solver z3`, taken from BINSEC's own `examples/relse/quickstart`. Validated on a known-answer pair: the leaky fixture reports `control flow leak` / `insecure`, the constant-time fixture reports `secure`, with no SMT `unknown` in either. One real crate target, `CRYPTO_memcmp`, is **secure** with 11/11 control-flow and 11/11 memory checks over a 16-byte secret/public split. The ladder and inversion reach the engine but return **unknown** — std's allocator vtable `call *%rax`, the `rust_oom` GOT, and 2 unsolved 64-bit queries — so no verdict is claimed for them. Persisted as `courts/phase18/timing/binsec_checkct.sh`, which exits 0 only for secure/insecure, 4 for unknown, 3 for silence. |
| T17 | Hardware PMU counters absent in this environment (`cpu-cycles` ENOENT; `/sys/bus/event_source/devices` has no `cpu`) | BLOCKED (environment) |
| T18 | TIMECOP SUPERCOP harness (dormant, pinned to 2018–2019 trees); client-request method available | BLOCKED (unmaintained) |
| T19 | Fresh binary-bound measurement of the **final** candidate | DONE for this candidate: measured DSO `aaa32f21` (build-id `97ebf329`, clean build from `36fae14be`), which matches no earlier receipt digest. ctgrind modexp 0/0 with controls 0 and 4096; length-taint 5/5, all boundary; **inverse 856 errors / 274 contexts, up from 620 / 209** as the new constant-time path is exercised (215 jumps, 59 address uses, top frame `div_rem_fallible`); dudect printed 60000 measurements with max t 2.18, state 1; allocations 18/18/18/36 from 31/31/31/62; 2048-bit 5623 µs (+3.7%), 3072 +1.9%, 8192 within noise, RSA CRT 1498 µs. Recorded in `revision_4` of the receipt. Residual: the inverse regression is unresolved and needs its own analysis. |
| T20 | Byte-reproducible instrumentation build (D255 `.symtab` difference); preserve measured binaries as content-addressed artefacts | TODO |
| T21 | Benchmark against reference OpenSSL for RSA/DH/EC workloads; 8192-bit at ~370 ms is a throughput concern | TODO |
| T22 | Allocation-failure behaviour for the whole secret-bearing operation, not just ladder scratch | PARTIAL |
| T23 | Secret ownership does not propagate through the arithmetic itself: the final allocation is protected but the intermediate is not (e.g. `pad_to(&limbs::rem_fallible(ad, md)?, n)?` — the `rem_fallible` result is ordinary; likewise the Montgomery constant intermediates and `div_rem_fallible` temporaries). For secret EC inputs and RSA CRT moduli these hold confidential values. Fallible allocation establishes neither value-independence nor erasure. | TODO |
| T24 | The constant-time inversion's intermediates are ordinary `vec!` allocations at a secret-dependent width (`w.max(a.len())`), so they are infallible, uncleansed on drop, and their geometry may follow secret metadata. Use the same public-width, fallible, auto-cleansed storage as the ladder. | TODO |
| T25 | The `runtime::secure` init-order instability: one run showed 17 failures and an identical rerun was clean. A release gate must be deterministic; establish whether this is a genuine race or a test-isolation defect. | TODO |
| T26 | Move the `SecretBuf` implementation from `bn::secret` into `runtime::secret` so the runtime-wide abstraction does not depend on the BN subsystem; keep the BN alias and re-run the mutation controls. | TODO |
| T27 | Constant-time modular addition and a fixed-width secret store: the `bn_mod_add_fixed_top`→`BN_mod_add` substitution is the largest single residue in the ECDSA taint result (~90 of 128 contexts). | TODO |
| T28 | `BN_div` ignores `BN_FLG_CONSTTIME`: the RSA CRT path has 10 indirect `BN_div` callsites on flagged (secret) operands, and the crate's `div_rem_fallible` branches on a value comparison. Measured at DSO `5d0f9098` with `courts/phase18/timing/binary_branch_audit.py`. Non-smooth and tail error paths, so narrow — but it is a variable-time path on secret operands. | TODO |

---

## C. OpenSSH interoperability — open work

| id | item | status |
|---|---|---|
| O1 | Choose and justify the primary version (9.9p1 backs closures/L7; 10.5p1 backs probe/unit probe); keep the other as a separate cohort | TODO |
| O2 | Hermetic environment: pin and verify OpenSSL source, OpenSSH tarball, PuTTY, Dropbear by digest | TODO |
| O3 | Install plink/puttygen/dropbear/dbclient/dropbearkey/dropbearconvert **before** configure; verify detection from the generated Makefile and `regress/test-exec.sh` rather than assuming | TODO |
| O4 | Build A (reference OpenSSL) and Build B (OpenSSL-RS) from the same unmodified source in isolated trees, no shared `LD_LIBRARY_PATH` | TODO |
| O5 | Per-executable runtime identity (`ssh`, `sshd`, `sshd-session`, `ssh-keygen`, `ssh-agent`, `sftp-server`): `readelf -d`, resolved `ldd`, live `/proc/<pid>/maps`; fail closed on mixed linkage | TODO |
| O6 | Full upstream `make tests` on both builds; classify every failure as upstream-common / candidate-specific / harness; keep upstream-common failures as failures | TODO |
| O7 | Four-cell matrix (A-A, B-B, B-A, A-B) using the upstream harness and `TEST_SSH_SSH`, with isolated ports/config/keys per cell | TODO |
| O8 | PuTTY client → OpenSSH server and Dropbear client → OpenSSH server; OpenSSH client → Dropbear server where the harness supports it; record negotiated algorithms from transcripts; distinguish unsupported from failed | TODO |
| O9 | Coverage: Ed25519/RSA/ECDSA auth, X25519 and NIST ECDH, FFDH, PQ hybrid, AES-CTR/GCM, ChaCha20-Poly1305, HMAC integrity failures, host-key rejection, certificates, rekeying, agent, concurrent sessions | TODO |
| O10 | Harness negative controls: wrong client binary, wrong crypto library, failed auth, dead server, unsupported algorithm, missing third-party tool, timeout/signal kill; harness must fail if a control does not trigger | TODO |
| O11 | Machine-readable manifests, exact executed/skipped/blocked counts, reproduction commands; no hand-authored totals | TODO |
| O12 | Reconcile the historical 9.9p1/10.5p1 populations in one receipt so their results are never treated as interchangeable | TODO |

---

## D. ETP — assurance constitution and claim integrity

| id | item | status |
|---|---|---|
| ETP-0 | Baseline and trust-gap inventory: freeze the staging identity; inventory claims, evidence, assumptions, contradictions, missing reconstruction inputs; initial threat model; inspect binary reproducibility | PARTIAL (`evidence/baseline-20261120.json` covers identity and timing; trust-gap inventory outstanding) |
| ETP-1 | Claim algebra: typed claims with property, interpretation, quantification, scope, threat/leakage model, source/build identities, artefact digests, authority, target, assumptions, evidence, TCB, obligations, invalidation deps. Modalities (`DOCUMENTED`…`BINARY_REFINEMENT_VERIFIED`), reproduction status, verdicts — orthogonal, never a scalar score | TODO |
| ETP-2 | Artefact reproduction: pristine offline builds; two independently initialised clean builds; variation matrix; resolve every byte difference or record it; no byte-normalisation to manufacture a PASS | TODO |
| ETP-3 | Instrument qualification (DO-330-inspired): intended use, failure modes, soundness limits, version validation, sensitivity controls; fail closed on truncation, missing artefacts, timeouts, unsupported instructions | TODO |
| ETP-4 | Foundational verification pilot on production code: start with `SecretBuf`/cleansing and fixed-width Montgomery arithmetic; bind proof to source; record the missing binary bridge | TODO |
| ETP-5 | Consumer validation under the new machinery: reconstruct OpenSSH and curl identities, re-execute closures, reconcile the historical adjudications; the machinery must refuse the known unresolved conditions | TODO |
| ETP-6 | External reproduction readiness: frozen self-contained package, replay from an environment with no private state, documented external procedure; report `EXTERNAL_REVIEW_PENDING` until it actually happens | TODO |
| ETP-7 | Continuous enforcement in CI and release tooling | TODO |
| ETP-T1 | Requirements traceability: threat/hazard → requirement → spec → implementation → artefact → obligation → evidence → adjudication → release claim; orphan detection; MC/DC where appropriate | TODO |
| ETP-T2 | Security hazard register: fault trees, FMEA, STPA-Sec, attack graphs; distinguish legal API input from adversarial input from ABI-contract violation; never claim arbitrary invalid C pointers are safe | TODO |
| ETP-T3 | Refinement architecture: abstract spec vs executable reference vs Rust vs ABI contracts vs machine code vs consumer composition; avoid implementation-shaped specifications | TODO |
| ETP-T4 | Foundational Rust verification: classify unsafe sites by obligation and impact, not keyword count; inventory every axiom and admitted result; refuse vacuous proofs | TODO |
| ETP-T5 | Cryptographic correctness independent of OpenSSL: normative specs, independent reference implementations, differential observations; classify authority disagreements | TODO |
| ETP-T6 | Binary-level assurance: TCB includes compiler, linker, assembler, runtime, CPU dispatch, loader; per-architecture and per-profile claims; no inheritance across targets | TODO |
| ETP-T7 | Side-channel and erasure verification: define secret classification incl. lengths/capacities/allocation sizes; pre-register geometry, controls, exclusion rules, stopping conditions; never claim constant-time from a low t | IN_PROGRESS |
| ETP-T8 | Independence: role separation (author, proof producer, instrument author, evidence producer, adjudicator, reproducer, release authority); never fabricate external reviewers; preserve dissent | TODO |
| ETP-T9 | Evidence freshness and automatic revocation: dependency-aware invalidation; car-forward only as explicit history or with a verified preservation argument | TODO |
| ETP-T10 | Consumer closure discipline: every omitted edge needs an independently checkable exclusion argument; every opaque external op needs a scoped contract; no aggregation hiding a blocked row | PARTIAL (mechanism exists; curl queue open) |
| ETP-T11 | Scheduling: FAST/BATCH/BOUNDARY/SEAL/EXTERNAL, content-addressed caching by full applicability identity; resource exhaustion is BLOCKED, never PASS | PARTIAL |
| ETP-T12 | Public verification interface (`verify manifest|rebuild|proofs|instruments|controls|receipts|consumer-*|claims|all`) from a clean checkout with no private state | TODO |
| ETP-T13 | Long-term preservation: open formats, schema migration, digest agility, archival of source/recipes/proofs/checkers; the proof must outlive the agent | TODO |
| ETP-T14 | `EARNED-TRUST.md` constitution + integrate the rules into `AGENTS.md` and release policy | TODO |
| ETP-T15 | Reconciliation of the OpenSSH b85c graduation and the `NOT ESTABLISHED` adjudication, as distinct records with their actual provenance | TODO |

---

## E. ETP Addendum A — SARIF / DSSE / in-toto / SLSA / Sigstore

| id | item | status |
|---|---|---|
| A0 | Evidence and trust audit: inventory formats, receipts, identities, adjudications, release tooling; find every truncation, silent suppression, summary-without-reconstruction and wrong-candidate application | TODO |
| A1 | SARIF 2.1.0 (+ Errata 01) interoperability profile; deterministic adapter for representative real findings (BN timing, unsafe-boundary obligations, curl element-7 refusals, OpenSSH adjudication) | TODO |
| A2 | Lossless evidence preservation: original output, args, instrument identity, candidate identity, population, counts, unsupported ops, timeouts; content-addressed; reconciliation of native vs exported populations | TODO |
| A3 | Identity model: rule identity / logical finding identity / exact occurrence identity; fingerprints never authorise reuse across artefacts; conservative on collisions and code movement | TODO |
| A4 | Rust/FFI/binary location fidelity: macro expansion, monomorphisation, C ABI, indirect dispatch, optimised code; no fabricated line precision for machine-code findings | TODO |
| A5 | Completeness and execution admission: expected vs examined population, unsupported constructs, skips, timeouts, truncation; an absent population is not an empty population; exit code is not completeness | TODO |
| A6 | Suppression governance: a suppressed finding remains a finding; justification, scope, evidence, reviewer, independence, expiry, consequences; auto-invalidate on change | TODO |
| A7 | Baselines and honest regression tracking: distinguish root-cause elimination and proved unreachable from tool-stopped-reporting; no artificial monotonicity | TODO |
| A8 | GitHub code-scanning integration without GitHub dependency: full local artefacts authoritative; shard manifest when export limits truncate (5 000-result limit) | TODO |
| A9 | in-toto Statement v1 typed attestations; SLSA provenance predicate only for genuine SLSA statements; versioned project predicate types for everything else | TODO |
| A10 | DSSE authentication with the exact PAE over the received bytes; never reparse/reserialise before verification; `keyid` is an unauthenticated hint only | TODO |
| A11 | DSSE parser hardening: duplicate JSON keys, invalid encodings, oversized payloads, signature-count bounds, algorithm downgrade refusal, forward-extension discipline | TODO |
| A12 | Independent cryptographic verification of envelopes: the root of trust must not be the unverified candidate; keep verification deps out of `libcrypto`/`libssl` | TODO |
| A13 | Signature reproducibility vs artefact reproducibility kept separate; never seed production randomness for reproducible signatures | TODO |
| A14 | Role-bound authorisation: maintainer, source/build/analysis/proof producer, instrument reviewer, adjudicator, external reproducer, release authority, revocation authority; wrong-role signature insufficient | TODO |
| A15 | Thresholds over distinct authorised keys and distinct trust domains; repeated signatures and aliases cannot satisfy independence | TODO |
| A16 | Sigstore bundle profile with certificates, transparency entries, inclusion proofs, timestamps; offline verification with stated trust-root/freshness assumptions | TODO |
| A17 | Transparency and omission resistance: freeze an expected evidence manifest before execution; close with a signed reconciliation manifest; a producer cannot PASS by omitting a failed result | TODO |
| A18 | Survivable key compromise (TUF principles): rotation, delegation, expiry, revocation, anti-rollback, anti-freeze; old signatures never authorise a stale release | TODO |
| A19 | Authenticated corrections and retractions: append-only, bound to the original attestation, propagating invalidation; preserve what was believed and what was disproved | TODO |
| A20 | Deterministic policy engine: conjunction of obligations, not a score; denial-by-default; a candidate may not choose a permissive policy for itself | TODO |
| A21 | Verification-summary attestations after policy evaluation; a summary never replaces the evidence for independent reconstruction | TODO |
| A22 | Adversarial qualification: the eight mandatory experiments (stripped results, wrong-binary proof, self-signed independence, crashed-but-empty report, one-person-two-credentials, withdrawn claim, reproducible-but-defective binary, complete-and-independent evidence) | TODO |
| A23 | Formal verification of the verifier: the smallest evidence-processing core; verify that required evidence cannot be omitted, signatures cannot imply semantic correctness, substitution cannot preserve acceptance | TODO |
| A24 | External verification package: frozen manifest, provenance, full SARIF, native evidence, reconciliation, envelopes, statements, bundles, policy, controls, rebuild instructions; treat remote evidence as hostile | TODO |
| A25 | Extended public verifier surface (`verify sarif|sarif-completeness|evidence-manifest|envelopes|attestations|signer-roles|provenance|transparency|freshness|revocations|policy|controls|release|all`) | TODO |
| A26 | Verification economics: FAST/BATCH/BOUNDARY/SEAL/EXTERNAL; sign immutable manifests rather than every report; never trade completeness for cost | TODO |
| A27 | Vertical slice first: real frozen finding → native evidence → SARIF → content-addressed manifest → in-toto statement → DSSE → independent verification → policy adjudication → reproducible result; then the deliberately corrupted counterpart | TODO |

---

## F. Curl consumer — open work

| id | item | status |
|---|---|---|
| C1 | Close or honestly hold the 27 named element-7 refusals (`http` 4 local-copy sites; `provider/rand`, `confmod`, `evp_pbe`, `encoder_meth`, `rand_lib`, PEM pair, `passphrase`, `store_result`, `obj`, `stack`, `ui_read`, `check_crl`, `dh/check`) | IN_PROGRESS |
| C2 | Reconcile the running site count against the named rows (the ±1/±2 discrepancies recorded in the batch notes) | TODO |
| C3 | One frozen census → freeze → closure run at a single identity after the tool changes | TODO |
| C4 | Independent adversarial review of the ~9,600 new lines in `consumer_closure.py` (CFG dominance, frame-slot scans, DSO-local copies, callback writers) | TODO |
| C5 | Curl L7 replay at the final candidate; element-7 PASS; graduation record; counter 2/33 only if the safety argument survives independent review | TODO |

---

## G. Execution sequence (fixed)

Work proceeds strictly in item order. No choosing, no reordering, no skipping an
item to take a convenient one. Each item is finished (proof, controls, gates,
receipt) before the next begins, and each is pushed before the next starts.

| order | section | items |
|---|---|---|
| 1 | B — timing safety | `T1`, `T2`, `T3`, `T4`, `T5`, … `T22` |
| 2 | C — OpenSSH interoperability | `O1`, `O2`, … `O12` |
| 3 | D — ETP constitution and claim integrity | `ETP-0`, `ETP-1`, … `ETP-T15` |
| 4 | E — SARIF / DSSE addendum | `A0`, `A1`, … `A27` |
| 5 | F — curl consumer | `C1` … `C5`, **last** |

An item that is `BLOCKED` is recorded with its blocker and the next item in the
same section begins; it is revisited when the blocker changes. Nothing is
declared complete without the evidence named in its row.

## H. Non-claims that bind this queue

SARIF compliance does not prove absence of vulnerabilities. A clean scanner
output is not memory safety. A signed report is not necessarily true. DSSE does
not establish independence. A transparency entry does not establish
completeness. SLSA provenance alone does not establish a reproducible build. A
reproducible build is not a correct build. Two signatures are not necessarily
two independent verifications. A cryptographically valid historical signature
does not establish present authorisation. A signed summary does not replace the
underlying proof. A successful CI workflow is not regulatory certification.
