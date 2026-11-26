# PFP-2 post-fix — the REDC borrow branch removed at source and re-measured

Companion to `../STOP-2026-11-26.md`. The STOP recorded a release
`test/jne` and `je` at `mont_reduce_into+0x34D/+0x361` on a borrow derived from
the secret scalar. This note records the source fix, the same minimal population
re-measured before and after, the sites changed, and what still remains open.

**Status: the constant-time conjunct is improved but not discharged.** The
engine now contributes **zero** origin contexts on the minimal population, but
the record is still not `CANDIDATE`: the binary branch audit still exits 1 on an
unrelated inlined target, and no timing measurement was re-run at the new digest.

## 1. Candidate identities

| field | pre-fix (STOP) | post-fix |
|---|---|---|
| source | `staging` + PFP-2 worktree `2004ea243` | `staging` `0b5c11e99` + this fix |
| distribution DSO | `467527ae…` | `83f67826…` |
| DSO build-id | `aa4b5195…` | `ef860b61…` |
| archive | `0ae8edb3…` | `b56eba46…` |
| debug test binary | `e5ef938a…` | `76050325…` |

Full digests: `post-fix-2026-11-26/dso-identity.txt`. Only `src/ec/p256.rs`
changed; the exported surface matched the tracked surface
(`tracked_surface_matches_fresh: true`), and no `#[repr(C)]` layout, exported
signature or `CRYPTO_*` seam moved.

## 2. Sites fixed

The class is "a comparison or `overflowing_*` bool derived from a secret limb
reaches control flow". `overflowing_add`/`overflowing_sub` produce an `i1`
predicate; the release optimiser lowered the REDC select to a branch. The fix
replaces every such bool on the engine's secret path with a borrow/carry read
from the **high half of a 128-bit operation**, so there is no predicate to
branch on, and adds the crate's sanctioned optimisation barrier
(`mask_barrier`, the `value_barrier_64` counterpart already used by
`ec::curve448`) on the secret-derived select masks, so the optimiser cannot
re-prove the mask is `0`/`!0` and if-convert the select.

| file:site | construct removed |
|---|---|
| `src/ec/p256.rs` `mont_reduce_into` (was :690) | `let (_, b) = t[2*LIMBS].overflowing_sub(borrow); Limb::from(!b).wrapping_neg()` — the STOP site |
| `src/ec/p256.rs` `mont_reduce_into` masked subtract | per-limb `overflowing_sub` ×2 and `Limb::from(b1) \| Limb::from(b2)` |
| `src/ec/p256.rs` `mont_reduce_into` carry pass | `overflowing_add` + `Limb::from(c)` |
| `src/ec/p256.rs` `correct_solinas` | `overflowing_sub` borrow chain + `Limb::from(!b)` top borrow |
| `src/ec/p256.rs` `add_canonical` | `overflowing_sub` borrow chain + `overflowing_sub(carry, borrow)` + `Limb::from(!top_borrow)` |
| `src/ec/p256.rs` `sub_canonical` | `overflowing_sub`/`overflowing_add` bool chains feeding `wrapping_neg` |
| `src/ec/p256.rs` `ct_ge` | bool borrow accumulation (`Limb::from(b1) \| Limb::from(b2)`) |
| `src/ec/p256.rs` `select_limbs`, `cswap_limbs` | barrier on the secret-derived mask (defensive; the XOR select was already branch-free) |
| `src/ec/p256.rs` `mont_mul`, `P256Ladder::step` | no site of their own: they reach the fixed primitives only |

New helpers, both `#[inline(always)]` and arithmetic-only:
`sub_borrow` and `add_carry` (high half of a `u128` operation), and
`mask_barrier` (`core::hint::black_box`).

Equivalence is preserved operation-for-operation: the borrow is
`a < b + borrow`, exactly the `b1 | b2` the old code formed; the masked subtract
of `m & subtract` is unchanged; only the representation and the optimiser
barrier changed. The `p256` differential and the full library suite pass (see
§3), so the arithmetic is unchanged.

## 3. Correctness (task 2)

- `cargo test --lib -- p256`: **18 passed, 0 failed** (11 of them the engine's
  own; the rest are the P-256 TLS/KEM consumers that match the filter).
  Differential over 48 adversarial cases × MONT/SOLINAS/ARCH, the 4096-value
  pseudorandom sweep and 2048 products: **0 disagreements**.
- Full library suite: **2466 passed, 0 failed, 54 ignored** (`--test-threads=4`).
- `cargo fmt --all -- --check`: clean. `cargo clippy --all-targets -- -D
  warnings`: clean. No lint weakened.
- Mutation control (debug profile, three rotated repetitions; the release
  `--test` rebuild hit a memory incident, see §6): SOLINAS/default MONT
  `mul` 3.80×, `sqr` 3.69×, `ladder` 2.71×, `add` 1.02×, `sub` 0.98×. The fast
  path is still load-bearing.

## 4. The minimal population, before and after (task 3)

Exact harness `repro-2026-11-26/minimal_mul.c` (`taint-value`), one
`EC_POINT_mul`; limiter run unchanged. Raw logs and per-context attribution are
in `post-fix-2026-11-26/`.

| population / DSO | errors | contexts | engine origins | engine-on-path |
|---|---:|---:|---:|---:|
| minimal MONT, pre-fix `467527ae` | 12,371 | 203 | **58** | — |
| minimal MONT, post-fix `83f67826` | 1,595 | 188 | **0** | 4 |
| minimal generic, pre-engine DSO | 794 | 29 | 0 | 0 |
| minimal generic, re-run | 794 | 29 | 0 | 0 |

The 4 engine-on-path contexts are **not** engine origins: they originate in
`ec::smpl::store_coordinate` (class D) with a `p256_ladder_run` frame on the
path, i.e. the write-back `normalise` residual (§5). Per-class post-fix MONT:
B=0, C=98, D=7, E=83.

The same run against the generic pre-engine DSO reproduces `794 / 29`, so the
harness and population are unchanged and the reduction is specific to the
engine.

### Debug binary (history kept)

| reading | errors | contexts | note |
|---|---:|---:|---|
| recorded `3,023 / 123` | 3,023 | 123 | pre-fix debug binary `e5ef938a…`; retained as history |
| post-fix debug binary `76050325…` | 3,025 | 129 | inside the recorded band 3,013–3,047 / 121–136; 0 engine origins |

The debug numbers never carried the engine finding (the branch is
release-only); they are reported so the change is visible against the record,
not as a gate.

### Binary branch audit (task 3)

`courts/phase18/timing/binary_branch_audit.py` at
`--expect-sha256 83f67826…`: **exit 1, 8 of 9 targets resolved**, refusing
`mod_exp_core_consttime_from_parts` (`missing`, inlined out) — the same
pre-existing gap. `mont_reduce_into` now has **2 conditional jumps**, both loop
bounds on the public `subtractions` argument (`test %r8,%r8` at `+0x2ed`,
`dec %r8` at `+0x415`); there is no jump on the borrow any more. Report:
`../audit/post-fix-binary-branch-audit.md`.

## 5. Residual obligations (not silent)

1. **`PFP2-WRITEBACK-NORMALISE`** — the write-back
   `store_coordinate` (`src/ec/smpl.rs:2624`) → `limbs::normalise`
   (`src/bn/limbs.rs:42`) branches on the secret top limb. It is the 4
   engine-on-path contexts above. It **cannot** be fixed inside this item: the
   exported `BIGNUM` representation is a `Vec<Limb>` with *no trailing zero
   limbs*, and `bit_len`, `cmp`, iteration and the ABI conversion points rely on
   that invariant. Storing a fixed 4-limb width would change the representation
   consumers observe, which this item is explicitly forbidden to do. It remains
   a named obligation, distinct from the engine arithmetic. The read-side
   `limbs_from_slice` length branch is the same representation class; the
   minimal population taints limb *values* only, so it is not in the count.
2. **`PFP2-BRANCH-AUDIT-INCOMPLETE`** — the audit still exits 1 on the inlined
   `mod_exp_core_consttime_from_parts`, so there is no passing branch audit at
   this digest and the arm cannot be `CANDIDATE`.
3. **`PFP2-POST-FIX-TIMING`** — no timing measurement was re-run at
   `83f67826`. The fix adds only a register-level mask barrier; the debug
   mutation control moved MONT `mul` by +0.5 % and the ladder by ~0 % against
   the immediately preceding build, which is not materially different. The
   recorded `ecdsa256` 18.69× is therefore **not** claimed as the post-fix
   figure.
4. **`P256Scalar::admit_be_bytes`** — `if ct_ge(...) != 0 { return None }` is a
   branch on a scalar range check. It is not on the ladder path (used by tests
   only today), and the accept/reject outcome is a required public admission
   decision; removing it would be a correctness bug. Reported, not "fixed".

## 6. Incident

The release `--test` rebuild needed for a release-profile mutation-control
re-run aborted with `rustc-LLVM ERROR: out of memory` against the court's
4 GiB `RLIMIT_DATA` (cgroup `oom=0`). Recorded at
`evidence/incidents/2026-11-25-4/RECEIPT.md`; the reduced unit was the debug
mutation control above. The release **library** build (no `--test`) fits and is
the DSO measured here.

## 7. Artifact status

PFP-2 stays **`EXPERIMENT`**. The measurement and a passing differential court
exist, but the branch audit exits 1 and no timing measurement is bound to the
new digest, so `CANDIDATE` is not earned.
