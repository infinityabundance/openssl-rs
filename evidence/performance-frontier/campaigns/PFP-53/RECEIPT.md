# PFP-53 — first mechanically verified arithmetic kernel (status: PARTIAL)

```yaml
task:            PFP-53
subject:         4-limb CIOS Montgomery multiply (mont_mul_cios_fixed::<4, 6>)
instrument:      Kani — ABSENT on this venue (see §1)
substitute:      Python model + independent oracle (forensics/tools/pfp53_cios_model.py)
verdict:         PARTIAL — harness committed but unrun; substitute is a finite sample
source_identity: HEAD c4a7d112 (branch staging), worktree uncommitted
date:            2026-11-28
```

## 1. Instrument status (literal output)

Kani is not installed, and no Kani toolchain or cache directory is present. The
five probes, run in order, returned:

```
$ command -v kani
(exit 1, no output)

$ kani --version
sh: kani: command not found
(exit 127)

$ cargo kani --version
error: no such command: `kani`

help: a command with a similar name exists: `yank`

help: view all installed commands with `cargo --list`
help: find a package to install `kani` with `cargo search cargo-kani`
(exit 101)

$ rustup toolchain list | grep -i kani
(exit 1, no output)

$ ls ~/.kani /opt/kani 2>/dev/null
(exit 2, no output)
```

`cargo` and `rustup` are present; `cargo kani` has no `kani` subcommand and
`rustup` has no `kani` toolchain. Nothing was installed. Because the instrument
is absent, **branch (A) of the task could not be run** and branch (B) applies.

## 2. What the Kani harness states (committed, unrun)

`src/bn/arith.rs` gains a `#[cfg(kani)] mod kani_proofs` module (compiled only
under `--cfg kani`; a normal build never sees it, so the `kani` crate is not an
ordinary build dependency). It holds one proof:

* **`cios4_equiv_full_width`** — for arbitrary 4-limb `a`, `b` and an odd
  modulus `m` with a non-zero top limb (`2^192 <= m < 2^256`) and `a, b < m`,
  the result of `mont_mul_cios_fixed::<4, 6>` equals `(a * b * 2^-256) mod m`.
  The postcondition is checked **inverse-free** and is computed only from limb
  vectors (schoolbook `mul4`, a fixed 256-iteration binary long division
  `reduce_512`, an independent `n0_of`): it asserts `0 <= r < m` and
  `r * 2^256 ≡ a * b (mod m)`. No crate helper is called for the oracle.

The harness is the bounded model check the acceptance text asks for, but it is
**committed and not run**: the instrument is absent (§1) and no compile is
permitted on this venue without the memory gate. It is not recorded as PASS.

## 3. What the substitute covers

`forensics/tools/pfp53_cios_model.py` reimplements
`mont_mul_cios_fixed::<4, 6>` limb-by-limb in Python with the same 64-bit
wrapping semantics, and compares it against an independent reference
`(a * b * R^-1) mod m` using Python big integers and `pow(R, -1, m)`.

Final result line (run on this venue):

```
PFP-53 CIOS 4x64 model: seed=20261128 edge_cases=134108 random_cases=100000 total=234108 mismatches=0 range_violations=0 RESULT=OK
```

Coverage:

* **Edge cases (134,108):** every admissible `(a, b)` below each small odd
  modulus `m ∈ {3,5,7,9,11,13,15,17,31,33,255,257}`; `m = 2^255 + 1` (just
  above `2^255`); `m = 2^256 - 1` (top limb all-ones, maximal modulus),
  including `a = b = m-1` so `a*b` is near `m*R - 1`; and `a*b < m` cases under
  a full-width modulus.
* **Random (100,000):** deterministic pseudo-random admissible cases from seed
  `20261128`, each an odd modulus with a non-zero top limb and `a, b` chosen
  uniformly in `[0, m)`.
* **Range invariant:** every case additionally checks `r < m`.

The substitute is a **model of the transcribed algorithm**, not a run of the
compiled Rust binary. It validates the algorithm *as transcribed* on a finite
sample.

## 4. What it does NOT cover

* It is **not a proof** and not a Kani result — the harness is unrun.
* It is a **finite sample**; it cannot establish the property for all inputs.
* It **models the transcribed algorithm**, so a transcription error — a mistake
  in copying the Rust source into Python that happens to still satisfy the
  oracle — is exactly the risk it cannot rule out.
* It does not check the compiled binary; code generation, inlining, and the
  const-generic unrolling of `mont_mul_cios_fixed::<4, 6>` are not exercised.
* The register entry (`forensics/performance/KERNELS.json`) is not moved off
  `NO_PROOF` by this receipt.

The words "proved" and "verified" are deliberately **not** used for the
substitute.

## 5. Reproduction commands

```
# Substitute (pure Python; no compile, no memory gate):
python3 forensics/tools/pfp53_cios_model.py
python3 -m unittest forensics.tools.tests.test_pfp53_cios_model -v

# Kani harness (only where Kani exists; not run here):
cargo kani --harness cios4_equiv_full_width
```

## 6. Files

* `src/bn/arith.rs` — appended `#[cfg(kani)] mod kani_proofs` (the harness).
* `forensics/tools/pfp53_cios_model.py` — the Python model + oracle.
* `forensics/tools/tests/test_pfp53_cios_model.py` — unittest (3 tests, OK).
* `docs/PERFORMANCE-FRONTIER-TODO.md` — PFP-53 row annotated `PARTIAL`.
