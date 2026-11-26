# PFP-31 — ML-KEM implicit rejection, end to end

**State: the rejection path is now inside the branch audit and the audit
**fails**. One `jcc` in `key::decap` is controlled by the ciphertext-comparison
result — the implicit-rejection decision — in the release codegen of the
candidate DSO. The mutation control proves the instrument fires on a
deliberately introduced branch on the same result. The three parameter sets and
the malformed-ciphertext failure surface are measured separately. A
compatibility result is not a constant-time result, and no clean claim is made.

---

## 1. Artefacts and venue

| item | value |
|---|---|
| candidate `src` | `4b71a2a96` (`staging`); `git diff --stat e49d34d8f..HEAD -- src Cargo.toml Cargo.lock build.rs` is empty, so the reused DSO's build-relevant source is this tree's |
| candidate DSO **A** | **`5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae`**, 17,094,080 B (PFP-29's artefact, reused) |
| canary DSO **K** | **`7a039deed0565a1c1507bbe584f75c54c9f59a434dd855937da2e556ab16da60`**, 17,095,632 B |
| authority | `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` (3.6.4 production) |
| audit tool | `courts/phase18/timing/binary_branch_audit.py`, sha256 `5d54f3a1995263032fbdd23f9ccd533b50fa53b283199b2e1f43a3002cd1dfd4`, 1,692 lines |
| objdump | GNU objdump (GNU Binutils for Debian) 2.40 |
| venue | court `openssl-rs-court-tools:1`, cgroup `Memory=8,589,934,592`; `available` 25 GiB before every heavy command, `cap = min(8 GiB, 25 − 16 GiB) = 8 GiB`; `CARGO_BUILD_JOBS=4`; one heavy command at a time |

The canary is built from a **copy** of `HEAD` (`git archive HEAD` extracted under
`court/tmp/pfp31/canary-src`). The working `src/` is never edited: its
fingerprint is byte-identical before and after the canary build
(`court/tmp/pfp31/src.before-canary.sha256` vs `…after…`). K is never the
candidate and is not shipped.

---

## 2. The witness that admits the LLVM-suffixed copies

The audit's exact-identifier rule is unchanged. A suffixed local copy is
admitted only through a re-derived witness, and only when the exact identifier
has no out-of-line body:

1. the **whole symbol** must have the v0 structural form
   `<len(module)><module><len(identifier)><identifier>.llvm.<digits>` with
   nothing after the digits; both length prefixes are parsed and compared. A
   longer identifier that merely ends with the name, or a name followed by other
   text, does not match. It is not a prefix or substring test;
2. exactly one symbol matches, and exactly one symbol entry starts at its
   address (no alias);
3. the copy has a non-zero extent and byte-complete disassembly;
4. the recorded **producer** string occurs in the DSO's bytes;
5. a declared **caller** resolves uniquely, disassembles completely, and
   contains a direct `call` to the copy's entry. The call site is the evidence
   that the reviewed path reaches this copy; every site is recorded with its
   offset.

The witness is re-derived per artefact: K's suffix hash differs from A's
(`.llvm.15622672340991759178` vs `.llvm.15287269651090981652`), and the audit
resolves K without any inventory change.

| target | observed suffix | extent | caller | direct call sites |
|---|---|---|---:|---|
| `key::decap` | `3key5decap.llvm.15287269651090981652` | 1,522 B @ `0x2c8cc0` | `ossl_ml_kem_decap` | `+0x108`, `+0x216`, `+0x300` |
| `arith::scalar_ntt` | `5arith10scalar_ntt.llvm.3800245403269729001` | 1,030 B @ `0x396a00` | `gencbd_vector_ntt` | `+0x65` |

`scalar_ntt` has two further direct calls to the same entry at `0x397063` and
`0x397a4f` (inside the K-PKE decrypt/encrypt carriers, verified against the same
address in `raw/audit-real.md`'s target row). The recorded `check` fields in
`targets-pfp31.json` state these source-level facts; the audit re-establishes
only items 1–5.

The inventory is `targets-pfp31.json` = PFP-29's 29 targets + these two = **31**.
The tool's *default* inventory and `targets-pfp29.json` are untouched; re-running
the PFP-29 inventory at `5e75b694` still resolves **29/29, exit 0**
(`raw/audit-pfp29-recheck.*`), and the default inventory still refuses
`mont_mul_into` with exit 1.

---

## 3. Conditional-transfer classification for the rejection select

From `raw/audit-real.md` (generated, not hand-typed). `key::decap` carries 17
`jcc`, 0 `setcc`, 0 `cmovcc`. Classes follow PFP-27: **public-bound** = no
tracked comparison register reaches the condition (loop bound, length, return
code); **secret-derived** = the comparison accumulator reaches the condition.

| addr | insn | condition source | class | depends on |
|---|---|---|---|---|
| `0x2c8d60` | `je` | `test %eax,%eax` | public-bound | kdf/digest return code |
| `0x2c8d79` | `je` | `test %eax,%eax` | public-bound | digest update return code |
| `0x2c8d90` | `je` | `test %eax,%eax` | public-bound | digest update return code |
| `0x2c8dab` | `je` | `test %eax,%eax` | public-bound | digest final return code |
| `0x2c8e15` | `je` | `test %eax,%eax` | public-bound | `hash_g` return code |
| `0x2c8e38` | `je` | `test %eax,%eax` | public-bound | `encrypt_cpa` return code |
| `0x2c8e45` | `je` | `test %rax,%rax` | public-bound | `ctext_bytes == 0` |
| `0x2c8e4e` | `je` | `test %r14,%r14` | public-bound | compiler guard on an operand (null/geometry check) |
| `0x2c8e58` | `jae` | `cmp $0x4,%rax` | public-bound | `ctext_bytes >= 4` |
| `0x2c8f6a` | `jae` | `cmp $0x20,%rax` | public-bound | `ctext_bytes >= 32` (vector path) |
| `0x2c8fb2` | `jne` | `cmp %rdx,%rcx` | public-bound | vector accumulation loop bound |
| `0x2c8feb` | `je` | `cmp %rcx,%rax` | public-bound | no 4-byte tail |
| `0x2c8fef` | `je` | `test $0x1c,%al` | public-bound | tail length low bits |
| `0x2c9026` | `jne` | `cmp %rsi,%rcx` | public-bound | 4-byte accumulation loop bound |
| `0x2c9063` | `jne` | `cmp %rcx,%rax` | public-bound | byte accumulation loop bound |
| **`0x2c9067`** | **`jne 0x2c904e`** | **`test %dl,%dl`** | **secret-derived** | **XOR/OR ciphertext comparison accumulator** |
| `0x2c90c7` | `jne` | `cmp $0x20,%rsi` | public-bound | `constant_time_select_8` store loop bound |

Addressing the two required components separately:

* **`CRYPTO_memcmp` accumulation.** It is inlined; the XOR/OR loops are at
  `0x2c8f83..0x2c8fb2` (vector), `0x2c9010..0x2c9026` (4-byte) and
  `0x2c9052..0x2c9063` (byte). Every conditional transfer in those regions is a
  length/alignment bound. The accumulation itself is **branch-free on the
  compared bytes**; its only exit transfers are public-bound.
* **`constant_time_select_8`.** The store loop is `0x2c9090..0x2c90c7`; the only
  conditional transfer is its back edge, classified public-bound. The mask is
  applied with `and`/`and`/`or` at `0x2c90a2`–`0x2c90b9`; the selection of the
  secret bytes is **branch-free**.
* **The eq-mask derivation between them is not.** The compiler lowered
  `constant_time_eq_int_8(0, CRYPTO_memcmp(..))` (source:
  `src/runtime/constant_time.rs:211`, `constant_time_is_zero_u32`) to
  `test %dl,%dl; jne`, selecting the constant `0xff`/`0` mask register at
  `0x2c904e`/`0x2c9069`. The claimed "select is branch-free on the comparison
  result" is therefore **false in release codegen**: the comparison result is a
  branch condition, even though the bytes it eventually selects are chosen
  without a branch. The audit reports this as its one violation.

Dynamic confirmation at the same instruction: ctgrind reports
`Conditional jump or move depends on uninitialised value(s)` at
`key::decap` twice per run (import pairwise test and the operation), for every
parameter set (§5). This is the same function region; Memcheck cannot say which
outcome was taken, which is why the static classification above is the finding
and the dynamic count is corroboration, not the proof.

---

## 4. Canary versus real, side by side

The canary replaces the mask select with a branch on the comparison result:

```diff
-        for i in 0..ML_KEM_SHARED_SECRET_BYTES {
-            *secret.add(i) = constant_time_select_8(mask, kr[i], failure_key[i]);
-        }
+        // CANARY (PFP-31 negative control): a branch on the comparison result
+        // instead of the constant-time select. Two distinct `#[inline(never)]`
+        // sinks keep the optimiser from if-converting it into a data select.
+        if mask != 0 {
+            canary_take_kr(secret, kr.as_ptr());
+        } else {
+            canary_take_failure_key(secret, failure_key.as_ptr());
+        }
```

Full diff: `raw/canary-difference.diff` (the two sinks plus this one site).

| | real A `5e75b694` | canary K `7a039dee` |
|---|---|---|
| PFP-31 inventory | 31/31 resolved | 31/31 resolved |
| audit exit | **1** | **1** |
| named violation | `secret-derived-conditional-jump` | `secret-derived-conditional-jump` |
| offending jump | **`0x2c9067` `jne 0x2c904e`**, `test %dl,%dl` | **`0x300613` `je 0x300629`**, `test %dl,%dl` |
| what the branch controls | the `0xff`/`0x00` mask register | the two copy arms (`canary_take_kr` / `canary_take_failure_key`) |
| secret-derived `jcc` count | 1 | 1 |
| select store loop | branchless (public back edge) | absent; replaced by the branch |

The canary branch is on the comparison result and selects the shared secret, so
the instrument is sensitive to exactly the defect class PFP-31 is about. The
real artefact independently contains a branch of the same class: this is a
finding, not a passing clean result. The audit is *not* insensitive (the
canary fires), and it is *not* trigger-happy on the select loop (that loop
passes); it fires once, at the mask derivation.

The previous PFP-29 audit is unchanged by the tool extension: 29/29, exit 0, and
the default inventory still exits 1 on its named `mont_mul_into` refusal
(§2). The tool digest is recorded above so a later reader can tell which
instrument produced which result.

---

## 5. Three parameter sets, tainted

Seed marked undefined at the documented `EVP_PKEY_fromdata` boundary; defined
ciphertext from a separately imported defined key; three repetitions each.
`raw/taint-summary.tsv`, `attrib/*.summary.json`.

| param | runs | errors med | contexts | contexts in `key::decap` | other origins |
|---|---:|---:|---:|---:|---|
| 512 | 3 | 1,273 | 5 | **2** | `matrix_expand` 2, `ml_kem_pairwise_test` 1 |
| 768 | 3 | 2,897 | 5 | **2** | `matrix_expand` 2, `ml_kem_pairwise_test` 1 |
| 1024 | 3 | 4,992 | 5 | **2** | `matrix_expand` 2, `ml_kem_pairwise_test` 1 |
| 512 / 768 / 1024, authority | 1 each | 1,272 / 2,896 / 4,991 | 4 | **0** | `matrix_expand` 2, `ml_kem_pairwise_test` 2 |

Negative control (nothing tainted, valid ciphertext): **0 errors from 0
contexts** for all three sets. All five candidate contexts are in the `driver`
bucket (ML-KEM/provider); `engine_on_path = 0`.

The candidate/authority difference is measured at the same instruction:
the candidate reports two undefined conditional transfers inside
`ml_kem::key::decap`; the authority reports none in decapsulation (its four
contexts are the import's `matrix_expand` and `ml_kem_pairwise_test`). This is
the conversion-introduced control-flow dependence described in §3. It is
reported as an observation at the artefact digest, not as a claim about every
build.

`matrix_expand` is inside the import of the tainted seed (keygen), not the
decapsulation kernel; it is reported rather than excluded, as in PFP-29.

---

## 6. Malformed ciphertexts: population and failure surface

Population per parameter set, identical for both subjects and verified equal
before comparison (`BASE` line carries the full ciphertext and encapsulated
secret):

| class | count |
|---|---:|
| valid | 1 |
| wrong length (`len-1`, `len+1`) | 2 |
| one-bit flips spread over the ciphertext body | 64 |
| all-zero | 1 |
| all-ones | 1 |
| seeded random | 8 |
| **total** | **77** |

Candidate vs authority, `raw/indistinguishability.tsv` and
`raw/malformed-{cand,auth}-<param>.txt`:

| param | cases | differing rows | rc mismatches | outlen mismatches | ss mismatches |
|---|---:|---:|---:|---:|---:|
| 512 | 77 | 0 | 0 | 0 | 0 |
| 768 | 77 | 0 | 0 | 0 | 0 |
| 1024 | 77 | 0 | 0 | 0 | 0 |

So on 231 rows (77 × 3): the return code, the output length and the 32-byte
output agree byte for byte. Wrong lengths return `0`; every in-range malformed
ciphertext returns `1` with a 32-byte implicit-rejection secret identical to the
authority's. There is **no compatibility finding**.

### The three verdicts, kept separate

1. **Correctness on valid inputs — PASS.** The valid case returns
   `rc=1, outlen=32`, and its shared secret equals the authority's for all three
   sets (inside verdict 2's rows).
2. **Compatibility of the failure surface — PASS.** 231/231 case rows identical
   in return code, output length and output bytes; no distinguishable *output*
   surface.
3. **Constant-time behaviour of the failure path — FINDING.** A conditional
   transfer at `0x2c9067` reads the ciphertext-comparison accumulator, so the
   *control flow* depends on whether implicit rejection occurred. The exact
   observable is the branch outcome on the validity bit; there is no output
   difference. Supporting measurements: the static audit (§3), and the dynamic
   fact that the candidate reports the undefined conditional in `key::decap`
   while the authority reports none. It is **not** established dynamically:
   valid and one-bit-flipped runs produce identical Memcheck counts and site
   sets (delta 0, identical sites for all three sets), because Memcheck reports
   the conditional as undefined in both and does not observe which way it went.

The output surface is indistinguishable; the control-flow surface is not. The
finding is the latter, and it is not smoothed into the compatibility row.

---

## 7. What this establishes, and what it does not

Established, at the stated digests:

* both suffixed symbols are inside the audit with a per-call-site witness that
  is re-derived per artefact and is not a substring match (§2);
* the rejection select is audited in the release DSO, and **the audit fails** at
  one named `jcc` (§3);
* the mutation control fires, naming its own introduced `jcc` (§4);
* ML-KEM-512, -768 and -1024 are each exercised under ctgrind, three times, with
  a 0-error negative control (§5);
* the malformed failure surface is byte-identical to the authority on 231 rows
  (§6).

Not established:

* **Branch-freeness of the rejection decision.** The opposite is measured. The
  row cannot be a clean `DONE`.
* **Exploitability.** No timing distribution, PMU counter or statistical test
  (dudect) was run on the branch; both arms do essentially equal work and the
  compiler may have created the branch only to materialise a constant mask.
  "Control flow depends on the rejection outcome" is the measured claim; "a
  practical oracle exists" is not.
* **A whole-function constant-time verdict for `decap`.** The taint analysis is
  a within-function may-taint over registers; it does not model memory, implicit
  flow through an earlier conditional, or interprocedural effects. Other
  contexts (`matrix_expand`, `ml_kem_pairwise_test`) are reported, not
  classified.
* **That the authority's silence is a clean authority result.** The authority's
  four contexts are its own import/test conditionals; no authority-side claim
  beyond "no decapsulation context under this taint" is made.
* **ML-KEM-512/-768/-1024 on the canary.** The canary is only a control for the
  audit; its parameter sets were not separately run.
* **A source fix.** None was attempted: the task forbids editing `src/` for the
  real artefact. The natural follow-up is a mask materialisation barrier for
  `constant_time_eq_int_8` (or a `black_box` around the comparison result) with
  its own machine-code test, then a re-audit at a new digest.

---

## 8. Reproduce

```
# 1. canary from a copy of HEAD (never edits the working src/)
OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g CARGO_BUILD_JOBS=4 \
  bash docker/openssl-rs-court.sh exec sh \
    evidence/performance-frontier/campaigns/PFP-31/build_canary.sh

# 2. ctgrind per parameter set, valid-vs-invalid, authority comparison
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-31/run_taint.sh

# 3. malformed population, candidate vs authority (uses the harness from 2)
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-31/run_indistinguishability.sh

# 4. audit: real (expect exit 1), canary (expect exit 1), PFP-29 re-check (exit 0)
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-31/run_audit.sh
```

## 9. Files

| file | role |
|---|---|
| `targets-pfp31.json` | 31-target inventory: PFP-29's 29 + `key::decap` and `arith::scalar_ntt`, each with an LLVM-suffix witness; `decap` also carries the comparison contract |
| `build_canary.sh` | canary DSO from a `git archive HEAD` copy; records the one-site diff; re-checks the working `src` fingerprint |
| `pfp31_mlkem.c` | 512/768/1024 harness: control, taint, malformed population (77 cases), full BASE ciphertext/secret |
| `run_taint.sh` | controls, three taint repetitions per set, valid-vs-invalid, authority; summary TSVs |
| `run_indistinguishability.sh` | candidate vs authority on the malformed population; rc/outlen/ss verdict |
| `run_audit.sh` | real and canary audits, named refusal, PFP-29 regression re-check |
| `raw/` | audit reports and stderr, valgrind logs, attribution TSVs, summary TSVs |
| `courts/phase18/timing/binary_branch_audit.py` | extended: LLVM-suffix witness and the comparison-result contract (exact-identifier rule unchanged) |
