# PFP-7 — the bound, the profile, and the decision

**Item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-7 (RSA CRT dual engine).
**Decision:** **REFUSE** — the measured bound does not support interleaving the two
CRT halves. No source change was made, so the digest is unchanged.
**Claim class:** `SCOPED_OBSERVATION` on the court venue (no PMU; `perf stat`
reports `<not supported>` for every hardware event).

## 0. Identity at which every number below was taken

| item | value |
|---|---|
| source | `staging` `05ee177a3d0d6e7ef7a80e466a1cba5b6ea765c2`, build-relevant tree **clean** |
| DSO | **`6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39`** (17,118,904 B, build-id `05a6b994`) |
| archive | `c01b2b1f4070ce4fbca329f2ca1057c51ca352f18e5c93879839d9f05027f489` |
| rebuild | two independent clean builds (`build`, `build-b`) agree byte for byte on archive *and* DSO (`raw/identity/two-builds.txt`) |
| authority | OpenSSL 3.6.4 production `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| machine | i9-13900K; flags `adx avx2 bmi2 vaes vpclmulqdq`; **no `avx512f`, no `avx512ifma`** |
| effective clock | **5.470 GHz** from a dependent `add` chain (182.8 ps per 1-cycle add; `raw/ilp/probe.txt`) |

The DSO is the PFP-6 CIOS-admitted digest, now reproduced from a **clean commit**
rather than a worktree: `staging` `05ee177a3` builds `6d002db2` with an empty
build-relevant status. PFP-7 therefore makes no change to the artefact PFP-6
admitted.

## 1. The profile: where an RSA-2048 private operation spends its time

Two instruments, one digest.

**(a) Instruction split** — callgrind, one process, 60 `RSA_private_encrypt`
(`RSA_NO_PADDING`) operations, so the one-time blinding construction is amortised
(2 re-creations in 60 calls, i.e. 1 per 32 — see §3):

| component | instructions/op | share |
|---|---:|---:|
| two CRT halves, CIOS ladder kernel (`mont_mul_ladder_into`) | 16,297,811 | **89.4 %** of the refresh-free total |
| result check (`BN_mod_exp_mont`, `e = 65537`, 2048-bit) | ≈ 1.03 M | 5.7 % |
| blinding re-creation, amortised (`mod_inverse_consttime`) | 2,153,924 | 10.6 % of the 20.37 M/op total |
| recombination, conversions, padding, `BN_CTX`, allocator | remainder | ≈ 4 % |

Refresh-free total: **18.22 M instructions/op**; with the amortised re-creation
**20.37 M/op**. Sources: `raw/profile/cg-priv.annotate` (inclusive and exclusive).

**(b) Wall split** — measured with per-call timestamps in one process; anchors
are independent measurements, the split is the attribution (`Stage` harness,
`harness/pfp7_rsa.c`):

| component | wall | share of the latency op |
|---|---:|---:|
| two CRT exponentiations | 577 µs (2 × ≈ 289 µs) | **89.4 %** |
| result check (`vrfy` mode, measured standalone) | 35.7 µs | 5.5 % |
| recombination + conversions + padding + `BN_CTX` | ≈ 26 µs | 4.0 % |
| blinding convert + invert per op (`blinded − unblinded` medians) | 6.5 µs | 1.0 % |
| **latency op** (refresh-free, min/median over 205 calls) | **639.7–645.7 µs** | |
| blinding re-creation, **periodic** (5.2 ms every 32 calls) | 162 µs per sustained op | +20 % of throughput |

**Padding and conversion.** The operation profiled above is
`RSA_private_encrypt(RSA_NO_PADDING)`, whose tail is `BN_bn2binpad` plus a copy.
The padding checks are measured in the same harness: PKCS#1 signing is
645,438 ns against 645,730 ns for no padding (inside the run-to-run spread), and
`RSA_private_decrypt` is 657,034 ns (PKCS#1) / 655,191 ns (OAEP) — about 11 µs
(1.7 %) for the conversion, the unpad and, on the PKCS#1 path with `d`, the KDK
derivation. Padding is therefore not part of what an interleave could move.

The re-creation is measured, not inferred: the per-call times have outliers at
**call indices 0, 32, 64, 96, 128** of 5.19–5.32 ms each, and `BN_BLINDING_COUNTER`
is 32 (`src/bn/blinding.rs:67`). The authority has no such outlier (its
mean − median gap is 8–11 µs/op). This is a PFP-1/blinding-substrate property,
not PFP-7's; it is why the row's `2.484×` is a throughput ratio and the
exponentiation-only ratio is 1.88× (§`TIMING.md`).

**Independence of the two halves in the current code.** They are fully
independent: different moduli (`q`, `p`), different exponents (`dmq1`, `dmp1`),
different output buffers (`m1`, `r1`), separate `BN_MONT_CTX`s. The only shared
object is the `BN_CTX`, whose buffers are used per call. `BN_mod_exp_mont_consttime_x2`
(`src/bn/mont.rs:1030-1037`) is **two sequential calls** — there is no
interleaving in this build.

## 2. The ILP bound

### 2.1 The kernel's dependency structure, as compiled

`mont_mul_cios_into` at n = 16 limbs (a 1024-bit half) compiles to (rustc 1.98.1,
baseline x86-64, no ADX/BMI2: `mul`, `add`, `setb`, `adc` only — verified in
`raw/audit/ladder-mont_mul_ladder_into.dis`):

```
mov rax,rcx ; mul [a+j] ; xor r10d,r10d ; add rsi,[acc+j] ; setb r10b
            ; add rsi,rax ; adc r10,rdx ; mov [acc+j],rsi
```

* 1,262 Montgomery multiplications per half = 205 windows × (5 squarings + 1
  multiplication) + 30 table rows + 1 base conversion + 1 output conversion;
  2,524 per private operation.
* **6,457 instructions per Montgomery multiplication** in situ
  (16,297,811 / 2,524) ≈ 12.6 per limb-op, unrolled two limbs at a time.
* In-situ cost **255.8 ns per multiplication** (645.7 µs / 2,524) = **1,399 cycles**
  at 5.470 GHz → **IPC 4.62**.
* Loop-carried carry chain: 2 rows × 16 limbs × 16 outer iterations = **512
  one-cycle `adc` steps ≈ 512 cycles**, i.e. **36.6 %** of the measured 1,399.

So the kernel is neither cleanly latency-bound nor cleanly width-bound: the
carry chain is 37 % of the time and the issue width is the rest.

### 2.2 What interleaving could buy, arithmetically

Interleaving two full exponentiations does not change the instruction count: it
re-runs the same kernel on a second operand set. With `U = 6,457` instructions
per multiplication and `W` the sustained issue width:

* **Ceiling** — `U / 6 = 1,076` cycles per multiplication if the core could
  retire exactly 6 instructions/cycle → **1.30× on the kernel** → with the 89.4 %
  share, **1.26× on the operation (20.6 % wall)**. This is the only positive
  bound and it requires IPC 6.0.
* **Retained** — the two chains share the same 6-wide issue, the same single
  integer-multiply port and the same ALU ports, and the fused loop doubles the
  live state (two accumulators, two `t`, two `diff`). Nothing is added to the
  machine; only latency stalls could be filled, and there is at most 37 % of
  the time that is *not* issue-bound.

### 2.3 What it actually buys — measured

A transcription of this kernel (u128 arithmetic, same row structure, n = 16) run
three ways over identical operands: one multiplication, two back to back, and
two **advanced in one loop, limb of A then limb of B** (`harness/pfp7_ilp.c`;
`raw/ilp/probe.txt`). The transcription is representative, not assumed:
**255.1–256.4 ns per multiplication vs 255.8 ns in situ (≤ 0.5 % across
campaigns)**. Its fused output is bit-identical to its sequential output
(`CHECK fused_equals_sequential=1`).

The saved campaign (`raw/ilp/probe.txt`) is 7 invocations per build, each
reporting the best of 7 repetitions per shape, so the ratio is a median over
invocations. An earlier campaign (not saved) read 1.1436 (baseline) and 1.0559
(native); the campaign values below bracket that one.

| build | single (ns) | two sequential (ns/mul) | fused (ns/mul) | fused / sequential |
|---|---:|---:|---:|---:|
| baseline x86-64 (what ships) | 255.1 | 254.7 | 283.3 | **1.1132** [1.1102, 1.1151] |
| `-march=native` (ADX/BMI2: independent carry chains) | 269.5 | 272.9 | 276.9 | **1.0183** [1.0111, 1.0341] |

Interleaving the two independent chains is **slower in every run** — 1.1 % to
14 % depending on the campaign — and faster in none. With independent carry
chains (ADX) the fused penalty shrinks (1.02–1.06×) but never reverses, and the
single-operation cost does not move. The wall extrapolation at the saved
campaign's baseline ratio is `0.894 × 1.1132 + 0.106 = 1.101` → **0.91×**; at the
earlier campaign's ratio, `0.894 × 1.1436 + 0.106 = 1.128` → **0.89×**. Neither
is a gain.

### 2.4 IFMA

The radix-2^52 AVX512IFMA pairing (Drucker–Gueron) requires `avx512ifma`. This
machine reports no `avx512f` and no `avx512ifma`, so the vector arm cannot be
built, executed or measured here. Recorded **NOT_APPLICABLE_HARDWARE**, not
"absent by choice"; it must not be reported as a negative result.

## 3. Decision

**REFUSE.** The arithmetic:

* the only positive bound is `U/6 = 1,076` cycles/multiplication → 1.30× kernel,
  1.26× operation (20.6 % wall) — and it is conditional on IPC 6.0;
* the measured IPC is **4.62**, and the measured fused loop is **1.02–1.14×
  slower** in every run (never faster), i.e. the attainable wall change is
  **0.89–0.91×**;
* filling latency stalls cannot help because the deficit to the issue-width
  floor is 23 % (`1 − 1,076/1,399`) while the interleaved shape adds more
  per-limb work than it fills (two chains × 12.6 instructions per limb against a
  6-wide issue).

A bound that is positive only at an unattainable IPC and negative at the
achievable one does not support a change, so the sequential path stays as it is.
Nothing was weakened, nothing was traded: blinding, the result check and the
padding surface are untouched because no code changed (§`FAULT-INJECTION.md`,
§`DIFFERENTIAL.md`).

Hand-scheduled ADX assembly (the shape OpenSSL's `rsaz` uses) is a *different*
change class — it would need its own bound, its own per-kernel differential and
its own branch audit, and the ADX compiler build here shows no headroom for it.
Recorded as a possible follow-up, not as a PFP-7 deliverable.
