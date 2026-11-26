# PFP-31 repair — ML-KEM implicit-rejection mask is branch-free in the release DSO

**State: the audited region has zero secret-derived conditional transfers and
zero secret-derived memory addresses, and every acceptance block passes.** The
release DSO rebuilt from the repaired source is `43a23e9b…`; the PFP-31 audit
inventory resolves 31/31 and exits **0**; the deliberately branchy canary still
exits **1** at its own site. The residual is one **branchless** `cmovcc` reached
from the comparison result (register-to-register, fixed-address compare), which
the instrument reports but does not treat as a failure and which is not a
secret-conditional transfer. This is a control-flow result, not a timing claim:
no dudect/PMU measurement is made here.

## Committed-source identity supplement (added 2026-11-26, PFP-28)

The identity statement in §1 is superseded on one point: the repair described here **is
committed**. It landed in `c34cfe62f107f6f28f2939772485e7d5ac1fcd5a` — "PFP-31 repair: the
implicit-rejection mask is branch-free in the release artefact" (2026-11-26) — whose parent is
`5c29d5e71`, the base the repaired DSO was built from.

The committed source is the measured source. At `c34cfe62f` the `src` tree fingerprint (886
`.rs` files, `find src -name '*.rs' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum`) is
`1587dcca275eb2f54d53398a9f5250ec9653092a2264bc9871ca3cf9754e3553`, byte-for-byte the value in
`repair-raw/build-inputs.txt`; `src/runtime/constant_time.rs` is
`503f0a7dfbc5f219f75170327f772df5caffff1e23d3d41596dca64f6c6e0403`, `Cargo.lock` is
`95e8fd837792b69a69798c3884dfc4000bee28d87c58fd3bf4cd5f597e62c2d9`, and the `src` diff against
`5c29d5e71` is `d0fa299ed196081a61ca49f93694193eff2fad1c4dbe33b86190ec0975ec6bfc` — the other
digests the build record carries. (`LC_ALL=C` is load-bearing: the manifest sha256 depends on
path collation, and the host's default locale yields a different, equally well-formed digest
from the same bytes.)

The artefact measured for PFP-31 is therefore DSO
`43a23e9b7b4628cb236d75bb8bc4b73583a035f3335bd0244f1771e81b773557` (build-id
`e4025832eb16152a4697680391b0c4be6297d967`, 17,102,040 B) from source `c34cfe62f`. The
artefact-audit tool is `courts/phase18/timing/binary_branch_audit.py` at sha256
`5d54f3a1995263032fbdd23f9ccd533b50fa53b283199b2e1f43a3002cd1dfd4` (1,692 lines), unchanged
between the audit and `c34cfe62f`.

**Not transferred.** Nothing measured on the PFP-31 finding DSO `5e75b694…` is cited for
`43a23e9b`; the audit and taint runs in `repair-raw/` were executed with
`--expect-sha256 43a23e9b…` against the repaired DSO. A source, compiler or target change
requires the audit to be re-run.

---

## 1. Artefacts and venue

| item | value |
|---|---|
| source HEAD (uncommitted repair) | `5c29d5e71` (`staging`) plus the diff in `repair-raw/build-inputs.txt` |
| source fingerprint (886 `.rs` files) | `1587dcca275eb2f54d53398a9f5250ec9653092a2264bc9871ca3cf9754e3553` |
| `src/diff` sha256 | `d0fa299ed196081a61ca49f93694193eff2fad1c4dbe33b86190ec0975ec6bfc` |
| `src/runtime/constant_time.rs` | `503f0a7dfbc5f219f75170327f772df5caffff1e23d3d41596dca64f6c6e0403` |
| `src/ml_kem/key.rs` (**unchanged**) | `d6ddf75902b1fb7d7716e96e676cd51ccc82b039178f2748c238ea1c1fc27389` |
| **repaired DSO** | **`43a23e9b7b4628cb236d75bb8bc4b73583a035f3335bd0244f1771e81b773557`**, 17,102,040 B, build-id `e4025832…`, `r2_matches_r=yes` |
| original DSO (PFP-31 finding) | `5e75b694…` |
| branchy canary DSO | `7a039dee…` |
| authority | `611e511d…` (3.6.4 production) |
| audit tool | `courts/phase18/timing/binary_branch_audit.py`, sha256 `5d54f3a1…`, 1,692 lines |
| objdump | GNU objdump (GNU Binutils for Debian) 2.40 |
| venue | court `openssl-rs-court-tools:1`, `Memory=8g`; `available ≥ 24 GiB` before each heavy command, `cap = min(8g, available−16g) = 8g`; `CARGO_BUILD_JOBS=4`; `--test-threads=4`; one heavy command at a time |

Reproducibility: `build_repair.sh` builds the repaired tree twice, into two
fresh `CARGO_TARGET_DIR`s; both produce byte-identical archives and DSOs
(`build-inputs.txt`). The DSO digest above is the clean-build digest; an earlier
incremental build produced a different digest from the same source, which is why
the recorded digest is bound to the two clean builds.

---

## 2. The mechanism the branch came from

The source is a pure-arithmetic is-zero mask, so the branch is **not** the
authority's `constant_time_eq_int_8` arithmetic by itself. It is a
**fusion** performed by InstCombine across two inlined functions:

1. `CRYPTO_memcmp` (`src/runtime/mem.rs:1105-1113`) normalises its byte OR to a
   boolean: `if r == 0 { 0 } else { 1 }`.
2. `constant_time_eq_int_8(0, v)` (`src/runtime/constant_time.rs`) computes the
   authority's `constant_time_msb(is_zero(v ^ 0))`, which InstCombine canonicalises
   to `select(v == 0, -1, 0)`.
3. Because `v` is exactly the `{0,1}` that step 1 produced, InstCombine folds
   steps 1 and 2 into a single `select(r == 0, 0xFF, 0)`.
4. The x86 instruction selector materialises that constant select as a
   **conditional branch** — `test %dl,%dl; jne` at `0x2c9067` in DSO `5e75b694`,
   selecting the `0xFF`/`0` mask register — rather than `setcc`/`neg` or `cmov`.

The `value_barrier` in `constant_time_select` protects the *byte select* (which
was already branchless); there was **no barrier on the mask derivation**, and the
authority places none there either. So the comparison result became a branch
condition even though the bytes it eventually selects are chosen without one.

---

## 3. The change

`src/runtime/constant_time.rs`, `constant_time_eq_int_8` only (no caller change;
`src/ml_kem/key.rs` is untouched):

```rust
#[inline(always)]
pub(crate) fn constant_time_eq_int_8(a: i32, b: i32) -> u8 {
    let x = value_barrier_u32((a as u32) ^ (b as u32));
    // Bit 31 of `(x - 1) & !x` is set exactly when `x == 0` …
    (((x.wrapping_sub(1) & !x) as i32) >> 31) as u8
}
```

Two properties, and only the first is load-bearing for branch-freeness:

* **`value_barrier_u32` on the compared word** stops the fusion in §2: the
  caller's normalisation must be materialised in a register (`setne`), so it
  cannot be folded into the mask select. Without the barrier, every arithmetic
  spelling tested folds back to the same `jne`.
* **An arithmetic zero-bit spelling** (`((x−1) & !x) >> 31`) expresses the mask
  without a comparison. LLVM still canonicalises it to `select(x == 0, 0xFF, 0)`;
  the point is that the select is no longer fused with the normalisation and is
  lowered as a **`cmov`**, not a branch.

Why this is branch-free **after inlining into `key::decap`**, not only in
isolation: the barrier is inside the helper, so it survives inlining; the
inlined region (§5) shows `setne` + `cmpl $0x0,0xa0(%rsp); cmovne`, with no
`jcc` on the comparison result. Testing the helper in isolation is explicitly
insufficient — an isolated probe of the *pre-repair* arithmetic produced
`cmovne`, while the real inlined `decap` produced `jne`; the acceptance here is
the inlined carrier, not a standalone wrapper.

---

## 4. Classification before and after

Classes follow PFP-27: **public-bound** = no tracked comparison register reaches
the condition; **secret-derived** = the comparison accumulator reaches it.
Counts are from `repair-raw/audit-repaired.md` (after) and `raw/audit-real.md`
(before), same inventory `targets-pfp31.json`.

| | before `5e75b694` | after `43a23e9b` |
|---|---:|---:|
| `jcc` | 17 | 16 |
| `setcc` | 0 | 1 |
| `cmovcc` | 0 | 1 |
| **secret-derived `jcc`** | **1** (`0x2c9067` `test %dl,%dl; jne`) | **0** |
| secret-derived `setcc` | 0 | 1 (`0x1d3675` `setne %al`, branchless) |
| secret-derived `cmovcc` | 0 | 0 classified; see note |

After, the 16 `jcc` are all public-bound: four digest-update return codes, two
`hash_g`/`encrypt_cpa` return codes, `ctext_bytes == 0`, an operand geometry
guard, `ctext_bytes >= 4`, `ctext_bytes >= 32`, and the vector/4-byte/byte/select
loop bounds. The two non-`jcc` flag readers are:

| addr | insn | condition source | class | note |
|---|---|---|---|---|
| `0x1d3675` | `setne %al` | `test %dl,%dl` | **secret-derived** | branchless data write; the accumulator's `r != 0` normalisation |
| `0x1d3696` | `cmovne %rcx,%rdx` | `cmpl $0x0,0xa0(%rsp)` | public-bound *per the register-taint analysis* | the compared word was spilled to a **fixed** stack slot; the tool models registers only, so this reads the taint as absent |

**On the `cmov`.** The tool's own text says its may-taint is over registers and
does not model memory, so the `public-bound` label on the `cmov` is a limit of
the instrument, not a claim that the condition is secret-independent — the
condition really is the comparison result, recovered from a fixed stack slot.
The claim made here is narrower and measured: it is a `cmovcc` with
**register operands** (`%rcx`, `%rdx`) reading a **constant address**
(`0xa0(%rsp)`), i.e. a conditional *move*, not a conditional *transfer* and not a
data-dependent address. On x86-64 `cmovcc` between registers has no
data-dependent timing and the compare's load is from an address independent of
the secret, so this is not a timing signal on this target. Eliminating the
`cmov` entirely was attempted (two further arithmetic spellings, including a
signed-neg form); LLVM canonicalises every is-zero spelling to the same select
and the branchless lowering is `cmov`, so the dependence is retained as a
branchless move and is recorded, not hidden.

---

## 5. The inlined region, exactly as the audit reads it

From the repaired DSO `43a23e9b`, `key::decap` at `.llvm.8141794212082648356`
(`0x1d32b0`, 1,554 B, 341 insns):

```
1d366c: cmp    %rcx,%rax
1d366f: jne    1d365e            ; byte-accumulation loop (public bound)
1d3671: xor    %eax,%eax
1d3673: test   %dl,%dl
1d3675: setne  %al               ; normalised {0,1}, branchless
1d3678: mov    %eax,0xa0(%rsp)   ; value barrier: fixed stack slot
1d367f: lea    0xa0(%rsp),%rax
1d3687: xor    %ecx,%ecx
1d3689: cmpl   $0x0,0xa0(%rsp)   ; compare the fixed slot (constant address)
1d3691: mov    $0xff,%edx
1d3696: cmovne %rcx,%rdx         ; mask = 0xff (equal) / 0 (unequal), branchless
1d369a: mov    %rdx,%rsi
1d369d: not    %rsi
1d36a0: …                        ; constant_time_select_8 store loop, public back edge
```

There is no `jcc` on the comparison result; the store loop's only conditional
transfer is its `cmp $0x20` back edge.

---

## 6. Canary control

The branchy canary (`7a039dee`, built by `build_canary.sh` from a `git archive`
copy of the then-HEAD) is unchanged. Re-run against the repaired tool on the
repaired engine:

```
REFUSED target="…key::decap" reason=secret-derived-conditional-jump
        detail=0x300613 je 300629 … condition from 0x300611: test %dl,%dl
binary_branch_audit: FAIL-CLOSED: 1 of 31 expected targets were refused … exit 1
```

The canary fails at **its own** site (`0x300613`, `je`), not the repaired
`decap`'s remapped address, so the audit did not merely stop looking. Verified
in `repair-raw/audit-canary.stderr`; the repaired audit is
`repair-raw/audit-repaired.stderr` (exit 0).

---

## 7. Verification

### 7.1 Mask semantics and direct decapsulation

`src/runtime/constant_time.rs::tests::the_eq_int_8_mask_is_all_ones_or_all_zeros_across_the_domain`
— exhaustive over every byte pair (`256²`), the signed boundaries
(`i32::MIN` … `i32::MAX`), the length-zero row (`eq_int_8(0,0) == 0xff`) and
all-zero-versus-nonzero; asserts `0xff` iff equal and that the result is never a
boolean. `src/ml_kem/tests.rs::the_decap_returns_the_encapsulated_secret_or_the_implicit_rejection_secret`
— for all three parameter sets: a valid ciphertext's decapsulation equals the
encapsulation's shared secret (`kr`); a one-bit-flipped ciphertext returns a
secret that is **not** `kr`, is deterministic for that ciphertext, and changes
with the ciphertext. Both pass (ml_kem-filtered run and the full suite).

### 7.2 Malformed differential — 231 rows, 0 differences

`run_indistinguishability_repair.sh`: 77 cases per set (valid, len−1, len+1, 64
one-bit flips, all-zero, all-ones, 8 seeded random), candidate `43a23e9b` vs
authority `611e511d`, comparing return code, output length and shared-secret
bytes (`repair-raw/indistinguishability.tsv`):

| param | cases | differing rows | rc | outlen | ss |
|---|---:|---:|---:|---:|---:|
| 512 | 77 | 0 | 0 | 0 | 0 |
| 768 | 77 | 0 | 0 | 0 | 0 |
| 1024 | 77 | 0 | 0 | 0 | 0 |

### 7.3 Taint — `key::decap` contexts 2 → 0

`run_taint_repair.sh`, seed undefined at the `EVP_PKEY_fromdata` boundary,
three repetitions per set, negative control 0 errors for all three sets
(`repair-raw/taint-summary.tsv`):

| param | errors before → after | contexts before → after | contexts in `key::decap` before → after |
|---|---:|---:|---:|
| 512 | 1,273 → **1,271** | 5 → **3** | **2 → 0** |
| 768 | 2,897 → **2,895** | 5 → **3** | **2 → 0** |
| 1024 | 4,992 → **4,990** | 5 → **3** | **2 → 0** |

Remaining origins are the same as before and not in decapsulation:
`matrix_expand` ×2 (keygen import) and `ml_kem_pairwise_test` ×1. The authority
stays at 4 contexts (`matrix_expand` ×2, `ml_kem_pairwise_test` ×2). Valid-vs-
invalid remains delta 0 / sites identical for all three sets (Memcheck cannot
say which way the undefined conditional went), as in PFP-31; the absolute count
drop and the removal of the two `decap` contexts are the observed change.

### 7.4 No regression elsewhere

* `cargo test --lib -- ml_kem`: **9 passed, 0 failed**.
* full library suite: **2,474 passed, 0 failed, 54 ignored** (2,528 tests;
  +2 versus the pre-repair tree for the two new tests, no new ignores).
* PFP-29 cross-path `emit` differential against the authority on the repaired
  DSO: `ECDSA_R`, `ECDSA_S`, `ECDH_SS`, `RSA_PT`, `DH_SS`, `MLKEM_CT`,
  `MLKEM_ENCAP_SS`, `MLKEM_DECAP_SS` all **MATCH** (`repair-raw/pfp29-emit-compare.txt`).
  The full per-path PFP-29 checkpoint (timing loops, 3×9 memcheck paths) was not
  re-run: it hardcodes DSO `5e75b694` and is not cheap; its ML-KEM path is
  covered by §7.2 and the suite.
* `cargo fmt --all -- --check`: clean.
* `cargo clippy --all-targets -- -D warnings`: clean.

---

## 8. Reproduce

```
# repaired DSO, two clean builds, digest + agreement
OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g CARGO_BUILD_JOBS=4 \
  bash docker/openssl-rs-court.sh exec sh \
    evidence/performance-frontier/campaigns/PFP-31/build_repair.sh

# audit: repaired (expect 0), canary (expect 1)
python3 courts/phase18/timing/binary_branch_audit.py \
  --expect-sha256 43a23e9b7b4628cb236d75bb8bc4b73583a035f3335bd0244f1771e81b773557 \
  --targets-file evidence/performance-frontier/campaigns/PFP-31/targets-pfp31.json \
  court/tmp/pfp31/repair/r/distribution/libcrypto.so.3

# taint (builds the harness), then the 231-row differential
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-31/run_taint_repair.sh
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-31/run_indistinguishability_repair.sh
```

## 9. Files

| file | role |
|---|---|
| `src/runtime/constant_time.rs` | the repair (`constant_time_eq_int_8`) + its mask-semantics test |
| `src/ml_kem/tests.rs` | the direct valid-vs-rejection decapsulation test |
| `build_repair.sh` | two clean builds, digest + `r2_matches_r`, source/diff fingerprint |
| `run_taint_repair.sh`, `run_indistinguishability_repair.sh` | the §7.3 / §7.2 runs retargeted at `43a23e9b`, writing `repair-raw/` (original `raw/` untouched) |
| `repair-raw/` | build inputs, audit reports + stderr, taint logs + summary, differential rows, `pfp29-emit-*` |
| `repair-attrib/` | five-way attribution of the repaired taint logs |

## 10. What this establishes, and what it does not

Established, at `43a23e9b`: the audited `key::decap` region has **0
secret-derived conditional jumps**, the mutation control still fires, the mask
is all-ones/all-zeros over the full domain, the 231-row failure surface is
byte-identical to the authority, and the two `key::decap` taint contexts are
gone.

Not established: a whole-function constant-time proof (the taint analysis is a
register may-taint, not memory/implicit-flow), any timing distribution or
practical oracle (no dudect/PMU run), and elimination of the residual branchless
`cmov`. The barrier is best-effort; the claim is bound to rustc 1.98.1, x86-64,
this profile, and DSO `43a23e9b` — a compiler or target change requires the
audit to be re-run.
