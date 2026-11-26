# PFP-27 — artefact audit of the integrated CIOS kernel

**State: DONE for the classification, the taint at the artefact and the DSO
benchmark; the residuals in §9 are stated, not deferred silently.** The
production default stays `Sos` (§8).

This record answers PFP-27's question at the artefact, not at source level:
`overflowing_add`/`overflowing_sub` booleans do not by themselves guarantee
branchless release code, so every conditional transfer and every `setcc` in the
CIOS carrier is classified **from the disassembly of the release DSO**.

## 1. Identity

| item | value |
|---|---|
| source commit (`S`) | `8f771620bba5739fcc830dc23236dd003802c0ec` (`staging`) |
| `src` tree | `8c8deea0835897ee365c3d994686968425935585`, 886 `.rs` files, fingerprint `1946bd86…0b4` |
| `src/bn/arith.rs` | blob `1ea1965` (sha256 `06005795…9a1c`), introduced by **`20972901d`**; **identical** to HEAD (`git diff 20972901d HEAD -- src/bn/arith.rs` is empty) |
| toolchain | rustc 1.98.1 (48a229cea 2026-09-01), cargo 1.98.1, cc 12.2.0, x86_64-unknown-linux-gnu |
| profile | `cargo build --release --lib --offline`, `CARGO_BUILD_JOBS=4` |
| shell / version script | `libcrypto.shell.rs` sha256 `efa0fbc…5606`; `libcrypto.ld` sha256 `75fb6ef…1275` |

| DSO | sha256 | bytes | build id | role |
|---|---|---|---|---|
| **A** | `5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae` | 17,094,080 | `73d0772b…2b69` | production default: `LADDER_SCHEDULE = Sos` |
| **A2** | `5e75b694…` (identical) | 17,094,080 | identical | second clean build, fresh `CARGO_TARGET_DIR` |
| **B** | `12023efec3e40444f579c9e88a78653c891448b2ffd2abf9c9c0ee89e0b9f9e8` | 17,092,448 | `511acbda…2263` | the same source with one line changed: `MontSchedule::Cios` |
| **K** | `97e960f31e8d345bd0ad529f8f5f84df7bebb4b731ce41e0e72a3aa392420309` | 17,040,568 | — | **negative-control canary** (§4.2): B + a deliberate branch on the CIOS `keep` flag |

A/A2 agreement is byte-for-byte (static archive `3d082ac…be63`, DSO digest, size
and build id all equal), so the digest is reproducible with PFP-23's discipline
applied to a new candidate. The only input difference between A and B is
`raw/schedule-difference.diff`; the source fingerprint is re-checked after
every patched build (`restore: src fingerprint identical`, 886 files).

Venue: court `openssl-rs-court-tools:1`, 8 GiB cgroup; host `available` was
25 GiB before every heavy command, so `cap = min(8 GiB, 25 − 16 GiB) = 8 GiB`
held; one heavy command at a time, `CARGO_BUILD_JOBS=4`. The court cgroup
reports `oom 0` and `oom_kill 0`; its cumulative `max 18438` reclaim counter
spans the container's longer history and is not an OOM (no process was killed).
No release test rebuild was attempted.

**Cross-check.** `5e75b694` is the candidate digest named by
`dso-differential/pfp24-domain-5e75b694`; this build reproduces it
independently, which is why that campaign's record is the same artefact (§5).

## 2. The carrier, and what is actually in the artefact

Selection is a **compile-time `const`** (`LADDER_SCHEDULE`), so the CIOS kernel
is unreachable in A by construction and is dead-code-eliminated:

| query | DSO A | DSO B |
|---|---|---|
| `mont_mul_cios_into` symbol | absent | absent (inlined) |
| `mont_mul_ladder_into` symbol | absent (inlined into `run_mont_ladder`) | `0x544000`, size `0x36c` (`t`) |
| `mont_mul_sos_into` symbol | `0x543950`, `0x3f5` | `0x5438e0`, `0x3f5` |
| `mont_sqr_into` (dedicated squaring) | **absent** | **absent** |

**Carrier = `mont_mul_ladder_into`, DSO B, `0x544000`–`0x54436b`.** Proof that it
contains the body, not a forwarding stub:

* its only call target is `memset` (`0x544086`, the `acc.fill(0)`); there is no
  call to any Montgomery function inside the extent;
* the body has the CIOS shape: outer loop over `b`'s `n` limbs
  (`0x54410e`), `acc[j] += a[j]*b[i]` (`mulq` rows at `0x544130`), the
  `u = acc[0]*n0` word (`imul 0x70(%rsp)` at `0x5441aa`), the reduction row
  starting at `j = 1` and storing to `acc[j-1]` (`0x5441d0`), the borrow chain
  (`0x5442b0`), then the mask-select loop (`0x544330`);
* callers: `run_mont_ladder` at `0x542f24` (per-iteration) and `0x54306a`
  (post-loop), plus `mont_mul_sos_into` at `0x542fc7` for the fixed squaring;
* producer strings in the DSO: `GCC: (Debian 12.2.0…) 12.2.0`,
  `rustc version 1.98.1 (48a229cea 2026-09-01)`, `clang version 22.1.0-rc2`.

In A the same function body is inlined into `run_mont_ladder`, which calls
`mont_mul_sos_into` at `0x542f89`, `0x54302b` (the two ladder multiplies) and
`0x5430ce` (the squaring) — the production path.

**The squaring counterpart is not in either artefact.** `LADDER_DEDICATED_SQUARING = false`
and `mont_sqr_into` has no symbol and no body in both DSOs, so there is nothing
to audit at artefact level; the ladder's squaring in both builds is the SOS
kernel (`mont_mul_into` → `mont_mul_sos_into`). A source-level audit of
`mont_sqr_into` exists in PFP-6's differential, but that is not an artefact
claim, and none is made here.

## 3. Conditional-jump and `setcc` classification (the deliverable)

Generated by `classify_sites.py` from the objdump extents; the script **fails**
if a site in the listing is unclassified or a mapped site is absent. Full
per-site tables: `raw/disasm/classification.md`; raw extents and listings in
`raw/disasm/`.

Classes: **(a)** public loop bound, length/geometry check, or a compiler-provable
invariant; **(b)** a branch or flag derived from secret limb data.

### 3.1 CIOS carrier (`mont_mul_ladder_into`, DSO B) — 14 jcc, 18 setcc, 0 cmovcc

| addr | insn | depends on | class |
|---|---|---|---|
| `0x544033` | `jne` | `mont_geometry_ok`: xor/or of the five length words | (a) geometry |
| `0x544057` | `jne` | `!(geometry) \|\| n == 0` (early return) | (a) geometry |
| `0x544097` | `jb` | `n < 2` specialisation | (a) loop |
| `0x54410e` | `je` | outer loop over `b`'s `n` limbs | (a) loop |
| `0x544123` | `je` | `n == 1` (no inner iteration) | (a) loop |
| `0x544171` | `jne` | product loop `j < n & ~1` | (a) loop |
| `0x544177` | `je` | `n` odd: remaining limb | (a) loop |
| `0x5441ca` | `je` | `n == 2` reduction specialisation | (a) loop |
| `0x544216` | `jne` | reduction-loop count from `n` | (a) loop |
| `0x54421e` | `jne` | `n - 1` odd: remaining limb | (a) loop |
| `0x544293` | `jne` | `n == 1` subtraction specialisation | (a) loop |
| `0x5442e8` | `jne` | subtraction loop `j < n & ~1` | (a) loop |
| `0x5442ee` | `je` | `n` odd: remaining limb | (a) loop |
| `0x544359` | `jne` | mask-select loop `j < n` | (a) loop |

| addr | insn | depends on | class |
|---|---|---|---|
| `0x544049` `sete`, `0x54404c` `setne`, `0x544052` `sete` | geometry flags (`t.len == 2n+1`, `n == 0`) | (a) geometry |
| `0x5440dd` | `setb` | carry of `acc[j] + a[j]*b[i]` | (b) flag → `adc` |
| `0x54413e`, `0x54415b` | `setb` | carries of the product row | (b) flag → `adc`/`or` |
| `0x544186` | `setb` | carry of the tail product limb | (b) flag → `adc` |
| `0x54419c` | `setb` | carry into `acc[n+1]` | (b) flag → stored |
| `0x5441de`, `0x5441fc` | `setb` | carries of the reduction row | (b) flag → `adc`/`or` |
| `0x544245`, `0x544249` | `setb` | carry of `acc[n] += carry` (read twice) | (b) flag → `adc`/store |
| `0x54426b` | `setb` | carry of `u*m[0] + acc[0]` | (b) flag → `adc` |
| `0x5442b8`, `0x5442bf` | `setb` | borrows of `acc[j] - m[j]`, `- borrow` | (b) flag → `or`/`adc` |
| `0x5442df` | `setb` | borrow of the `sbb` pair | (b) flag → `movzbl` |
| `0x5442f8`, `0x5442ff` | `setb` | borrows of the tail limb | (b) flag → `or`/`movzbl` |

**Counts: 14 conditional jumps, 14 class (a), 0 class (b). 18 `setcc`: 3 class
(a) geometry flags, 15 class (b) carry/borrow flags. Zero `cmovcc`.**

Dataflow of every class-(b) `setcc`: the byte written is read only by `adc`,
`add`, `or`, `mov` or `movzbl` in the same carrier; none is read by any `jcc`.
The conditional subtraction is arithmetic (`xor $1` / `or` / `neg` / `dec` at
`0x54430c`–`0x544324`) producing two masks consumed by `and`/`or` — the PFP-20
mask barrier is present in the machine code, not just in source.

### 3.2 SOS carrier (`mont_mul_sos_into`) — 19 jcc, 10 setcc, 0 cmovcc

Same function in A (`0x543950`) and B (`0x5438e0`); the site sequences are
asserted identical by `classify_sites.py`.

* 19 conditional jumps, **all class (a)**: geometry (`0x543983`, `0x54399c`,
  `0x5439cd`), product loops (`0x543a31`, `0x543a44`, `0x543a92`, `0x543a98`),
  REDC loops (`0x543b0d`, `0x543b1b`, `0x543b7f`, `0x543b8d`, `0x543bb3`),
  subtraction (`0x543bd2`, `0x543c38`, `0x543c3e`), three public
  bounds-check panic paths (`0x543b53`, `0x543cb7`, `0x543cbc`) and the final
  mask-select loop (`0x543ce8`).
* 10 `setcc`, **all class (b) carry/borrow flags**, all consumed arithmetically
  (`0x543a12`, `0x543a5f`, `0x543a7d`, `0x543b67`, `0x543ba6` carries;
  `0x543c09`, `0x543c10`, `0x543c2f`, `0x543c6a`, `0x543c71` borrows).
* No secret-derived control transfer.

### 3.3 Before/after

| carrier | jcc (a) | jcc (b) | setcc (a) | setcc (b, flag only) | setcc reaching control |
|---|---|---|---|---|---|
| A · CIOS? | absent from A | — | — | — | — |
| A/B · SOS (production) | 19 | **0** | 0 | 10 | 0 |
| B · CIOS | 14 | **0** | 3 | 15 | 0 |

The classification finds **no (b) branch**, so Task 3's repair condition is not
met: nothing was removed, no arithmetic changed, and there is no before/after
delta to report beyond the table above.

## 4. ctgrind, at the artefact, with the PFP-21 harness unchanged

`ctgrind/pfp27-2026-11-26/run_ctgrind.sh`; harness source
`…/PFP-2/ctgrind/pfp21-2026-11-26/pfp21_dso_ct.c`, **unmodified**
(sha256 `ef137412…3c51`), modes and repetitions as in PFP-21
(`control`, `mul-g`, `mul-p`, `mul-g-bytes`, `sign`, `sign-ex`, `sign-ex-k`;
3 reps each, 1 for `control`). Every process proves its mapping
(realpath/dev/ino/size + `/proc/self/maps`), and no foreign libcrypto is mapped.

| mode | A: contexts (3 reps) | B: contexts (3 reps) |
|---|---|---|
| `control` | **0** | **0** |
| `sign` | 271 / 232 / 232 | 232 / 274 / 247 |
| `sign-ex` | 24 / 24 / 24 | 24 / 24 / 24 |
| `sign-ex-k` | 461 / 442 / 452 | 427 / 461 / 450 |
| `mul-g` | 235 / 217 / 227 | 186 / 186 / 235 |
| `mul-p` | 196 / 227 / 185 | 224 / 236 / 217 |
| `mul-g-bytes` | 233 / 201 / 200 | 235 / 197 / 186 |

* **Engine-origin contexts: 0** in both artefacts (`origin_in_engine = 0`,
  `engine_on_path = 0`). This matches PFP-21's post-fix result for the engine.
* **Kernel-origin contexts: 0** — and not because the kernel is silent, but
  because **no tainted value reaches it** in this population: across all 1,488
  `sign` contexts (735 in A, 753 in B over three repetitions) there is **no
  stack containing `run_mont_ladder`, `mont_mul_ladder_into` or
  `mont_mul_sos_into`** (281/306 contexts have some `bn::` frame, none of them
  the ladder); the same is true of every other mode's contexts.
* **Sensitivity control (engine):** the pre-PFP-20 DSO `83f67826…` still
  produces `engine_on_path = 4` on all three `mul-g` repetitions, as PFP-21
  recorded. The instrument is sensitive to the engine path.

### 4.1 Reachability: did the CIOS path actually run?

Selection is compile-time, so B is the only artefact in which CIOS is reachable.
Callgrind, same harness, same population (`raw/callgrind.tsv`):

| mode | iters | A Ir | B Ir | Δ |
|---|---|---|---|---|
| `sign` | 64 | 372,813,421 | 368,399,897 | **4,413,524** (68,961/sign) |
| `mul-g` | 64 | 341,684,888 | 341,683,153 | 1,735 (0.0005 %) |
| `sign-ex-k` | 64 | 34,482,562 | 34,479,107 | 3,455 (0.01 %, noise) |

Only `sign` — ECDSA `sign` → `ecdsa_sign_setup` → `ec_field_inverse_mod_ord`
(Fermat) → `BN_mod_exp_mont_consttime` → `run_mont_ladder` — changes executed
instructions between the two DSOs, and it changes them by 16,448 kernel calls'
worth. So the CIOS branch **was** taken. The other modes are the same code in
both artefacts, which is why their difference is layout noise.

### 4.2 The taint that the harness cannot supply (and why a probe was added)

`sign` generates its nonce inside the library, `sign-ex` takes `kinv` from the
caller, and `sign-ex-k`'s `BN_mod_inverse` is the variable-time EEA, not the
ladder (confirmed by the flat `sign-ex-k` instruction count above). Consequently
**no exported entry point in the PFP-21 mode set routes a tainted secret into
the ladder**, and its silence there is a coverage limit, not a result.

`artefact-audit/pfp27_ladder_probe.c` supplies the missing population: it
taints the **base** of `BN_mod_exp_mont_consttime` (validating the BIGNUM limb
layout against its own big-endian export first), so the CIOS kernel multiplies a
tainted operand on every one of the 257 calls. The result is discarded without
inspection, exactly as the PFP-21 harness treats secret results.

`artefact-audit/run_probe.sh` (probe sha256 `ddc48b3d…cee8`):

| subject | mode | contexts (3 reps) | in a kernel carrier |
|---|---|---|---|
| A (SOS) | `control` / `ladder` | 0 / **0, 0, 0** | 0 |
| B (CIOS) | `control` / `ladder` | 0 / **0, 0, 0** | 0 |
| K (canary) | `control` / `ladder` | 0 / **2, 2, 2** (257 errors) | **2, inside `mont_mul_ladder_into`** |

**Sensitivity control (kernel):** the canary K is B with the final masked
subtraction replaced by a real branch on `keep` (the two arms call distinct
`#[inline(never)]` sinks so the optimiser cannot if-convert it; the site is a
`je` at `0x35c824`). Memcheck fires twice per run, at
`mont_mul_ladder_into`, with stack
`mont_mul_ladder_into ← run_mont_ladder ← mod_exp_core_consttime_from_parts_prepared ← BN_mod_exp_mont_consttime`.
The instrument can therefore see a secret-flag control transfer in **this**
kernel; its silence on A and B is the negative result, not blindness.

## 5. Correctness at the same source

* `cargo test --lib -- pfp6` (court, 4/4 pass, counts printed under `--nocapture`):
  kernel congruence `sos=7890 cios=7890 sqr=254`, mismatches 0;
  CIOS differential `exhaustive=3018 sampled=7890`, mismatches 0;
  squaring differential `exhaustive=144 sampled=254`, mismatches 0.
* PFP-22/PFP-24 domain court re-run against this artefact A
  (`artefact-audit/run_domain_court.sh`, runner and harness unchanged except the
  output directory): **16,434 cases, 0 mismatches, PASS**, candidate
  `5e75b694…`, authority `611e511d…`. The PFP-24 record was not overwritten.

No repair was made (§3.3), so these are the unchanged kernels; the gate is
recorded because PFP-27's acceptance asks for the differential at this head.

Repository gate at this head, in the court: `cargo fmt --all -- --check` clean;
`cargo clippy --all-targets -- -D warnings` clean; `cargo test --lib --
--test-threads=4` **2,472 passed, 0 failed, 54 ignored** (the ignored count is
the pre-existing set; no test was added, removed, weakened or newly ignored).
`src/` is byte-identical to HEAD (`git hash-object src/bn/arith.rs` =
`1ea1965…`), the three unsafe lints, the `CRYPTO_*` seam and every `#[repr(C)]`
layout are untouched, and no Rust `unsafe` was added.

## 6. Timing, through the DSO

`artefact-audit/run_timing.sh`: same probe, same population, `taskset -c 1`,
15 interleaved repetitions × 2,000 operations per DSO, order alternated,
i9-13900K, 8 GiB court.

| | ns/operation |
|---|---|
| A (`Sos`) | 19,644.9 (median) |
| B (`Cios`) | 18,369.1 (median) |
| **CIOS / SOS** | **0.93997** [0.9117, 0.97355] (median of 15 paired ratios, 20,000-resample bootstrap, seed fixed) |
| ratio of medians | 0.93506 |

The measured operation is `BN_mod_exp_mont_consttime` (P-256 order), i.e. the
fixed ladder: 257 schedule multiplies + 256 SOS squarings. Exact work, from the
artefacts' own callgrind runs (`kernel_ir.py`):

| quantity | A | B |
|---|---|---|
| schedule multiply Ir/call | 844 (SOS) | **572 (CIOS)** |
| ladder Ir per sign (513 calls vs 257+256) | 432,972 | 363,068 |
| exp-operation Ir/operation | 534,365 | 465,476 |

The multiply kernel executes **0.678×** the instructions of SOS; the ladder
operation **0.839×**; the whole exponentiation **0.871×**; wall time **0.940×**.
The gap between work and time is the CIOS serial carry/borrow dependency chain:
fewer instructions, lower IPC.

**Does the C transcription transfer?** **No.** `PFP-6/CROSSOVER.md`'s
0.909–0.971 is a wall-time ratio of *C schedule transcriptions* measured at
256–4096 bits by `bench_mont.c`. It is not the Rust kernel, not this DSO, and
not the artefact's ladder operation. The artefact's 0.940 [0.912, 0.974] falls
inside that numeric range only coincidentally: it measures a different quantity
(a ladder operation that still contains 256 SOS squarings and allocation/
cleansing overhead), and the artefact's own multiply kernel shows a 0.678
*instruction* ratio that the C figure does not describe. **The C figures are
marked not applicable to this artefact and are not transferred, cited or used
to justify anything here.**

## 7. What this admits, and what it does not

Admitted: in the CIOS carrier as compiled into `5e75b694`/`12023efe`, **no
secret-derived flag reaches control flow**; the 15 secret carry/borrow `setcc`
values are consumed arithmetically; a fully tainted ladder operand produces no
memcheck context in either real carrier while a deliberately branchy copy of the
same kernel is flagged twice at the carrier. That is an artefact-level,
constant-time-*relevant* result for this kernel.

Not claimed:

* that the kernel is constant-time against a microarchitectural attacker
  (carry-flag latency, port contention; that needs dudect-class measurement —
  not run);
* that the ladder **operation** is branchless (the surrounding `run_mont_ladder`
  was not the carrier audited here; its exponent is public in the `sign` reach);
* that `mont_sqr_into` is artefact-audited — it is not in the artefact at all;
* that the C transcription's performance transfers.

## 8. Default selection

**`LADDER_SCHEDULE` stays `Sos`.** The artefact evidence supports a 6 %
faster ladder operation (CI excludes 1) and 32 % fewer instructions in the
multiply, but PFP-6's own rule is that selecting CIOS is a default change which
requires the *affected API performance rows* re-run at the same digest; those
rows are not in this record, and PFP-29 asks for a whole-path checkpoint at one
digest rather than a per-kernel decision. Nothing here justifies changing the
production default, and the constant-time classification gives no reason to
prefer CIOS (both schedules are class-(b)-free).

## 9. Residuals (stated, not deferred)

1. **Kernel-isolated wall time was not measured.** The audited artefact exports
   no direct kernel entry; adding one changes the binary and would break
   identity (Article 2). Hence the wall-time figure is the ladder operation.
   The C transcription is therefore marked not applicable rather than substituted.
2. **The dedicated squaring kernel has no artefact audit** because
   `LADDER_DEDICATED_SQUARING = false` removes it from both DSOs. Enabling it
   would require a new artefact and its own audit.
3. **The kernel-taint probe exercises `n = 4` only** (P-256 order). The `n == 1`,
   `n == 2` and odd-`n` branches are public-geometry specialisations that the
   probe does not execute; they are classified (a) statically and were not
   exercised dynamically.
4. **No dudect-class timing evidence** is claimed for either schedule.
5. **The three-way check of PFP-28** (a claim whose cited digest differs from
   its candidate digest is refused) is still not implemented; this record only
   carries the identities.

## 10. Reproduction

```sh
export OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g
C=evidence/performance-frontier/campaigns/PFP-6
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/artefact-audit/build_dsos.sh
bash docker/openssl-rs-court.sh exec bash $C/ctgrind/pfp27-2026-11-26/run_ctgrind.sh
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/artefact-audit/build_canary.sh
bash docker/openssl-rs-court.sh exec bash $C/artefact-audit/run_probe.sh
bash docker/openssl-rs-court.sh exec bash $C/artefact-audit/run_branch_audit.sh
python3 $C/artefact-audit/classify_sites.py        # on the host is fine: reads files only
bash docker/openssl-rs-court.sh exec bash $C/artefact-audit/run_domain_court.sh
bash docker/openssl-rs-court.sh exec bash $C/artefact-audit/run_timing.sh
bash docker/openssl-rs-court.sh exec bash $C/artefact-audit/run_probe_ir.sh
```
