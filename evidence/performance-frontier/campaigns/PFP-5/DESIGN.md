# PFP-5 — design

## 1. What changed

`src/bn/arith.rs` only (release code): the constant-time exponentiation ladder
gains a fixed-window schedule selected by

```rust
const LADDER_WINDOW_BITS: Option<u32> = Some(5);
```

`run_mont_ladder` keeps the whole pre-ladder setup (exponent staging, base
reduction and conversion, allocation, final conversion) unchanged, then
dispatches to `run_mont_ladder_window` when the constant is `Some(w)`. `None`
runs the original bit-at-a-time loop, which is retained verbatim as the
reference and fallback (the same pattern PFP-6 used for `LADDER_SCHEDULE`).

`run_mont_ladder` now takes the window as a parameter so the differential court
can run `None` and `Some(4..=6)` over one population; the two production call
sites pass `LADDER_WINDOW_BITS`.

## 2. The schedule

Let `bits = 64 * width` (public), `n = md.len()` (public), `entries = 2^w`,
`windows = ceil(bits / w)` (public).

1. **Table.** `table[0] = R mod m` (the Montgomery one), `table[1] = base`, and
   `table[i] = table[i-1] · base` for `i = 2..entries`. Every row is a canonical
   residue in `[0, m)`, so the module's `a·b < m·R` induction still holds for
   every table multiply. The table is a `SecretBuf` (cleansed on every exit).
2. **Accumulator** starts as `table[0] = R mod m`.
3. **Windows, most significant first.** For `hi = windows-1 .. 0`:
   * build the digit from the staged exponent: for `k` in `0..w`,
     `bit = (exponent[(hi·w+k) >> 6] >> ((hi·w+k) & 63)) & 1` when the public
     index is below `bits`, else `0`; `digit |= bit << k`. Shifts and masks
     only — the digit is a value.
   * square `w` times (the last window included; leading-zero windows included);
   * `selected = table[digit]` by a **full masked scan** (below);
   * `acc = acc · selected`.
4. **Convert out of Montgomery form** with `acc · 1`, exactly as the reference.

## 3. Selection is a scan, never an index

```text
for j in 0..entries:                       // public
    mask = constant_time_eq_s(digit, j)    // all-ones iff j == digit
    for l in 0..n:                          // public
        out[l] |= table[j*n + l] & mask     // public address, secret value
```

* The address `table[j*n + l]` depends only on public loop counters.
* The only secret input, `digit`, enters through a mask that is either all-ones
  or all-zeros. The code reads public addresses and combines the rows with
  bitwise AND/OR, and `constant_time_eq_s` supplies the mask.
* **That is a design intent, not the evidence.** This project has already seen
  the optimiser lower a comparison-derived mask or a masked select into a
  conditional branch: PFP-2's REDC borrow became `test %rcx,%rcx; jne`, and
  PFP-31's ML-KEM equality mask became `test %dl,%dl; jne`. "AND/OR cannot be
  lowered to a branch" is therefore **not** a claim the source can support, and
  source-level reasoning is not what establishes constant time here.
* What was actually established is artefact-level: at DSO `842efa27`, the binary
  branch audit classified every `jcc`/`setcc`/`cmov` in `run_mont_ladder` and
  `mont_mul_sos_into` and found **no secret-derived transfer**, and ctgrind with
  the secret exponent tainted reported 0 errors from 0 contexts. Those results
  are bound to that exact digest, rustc 1.98.1, x86-64 and the release profile;
  any source, toolchain or target change requires the audit to be re-run. The
  barrier in `constant_time_select` remains, because it constrains the
  optimisation without being a guarantee about emitted code.
* `out` is zeroed before the scan, so the OR accumulation is exact.

## 4. Storage, bounds and constant-time discipline preserved

* **T3/T8 fixed-width storage.** The exponent is still staged once at the public
  `width` by `stage_fixed_width_exponent`; the window reads that buffer at public
  indices. No loop bound, allocation size or `Drop` extent depends on the
  exponent's normalised length.
* **Fail-closed geometry.** `mont_geometry_ok` remains the precondition of every
  kernel call; the table build and the ladder call it through
  `mont_mul_ladder_into`.
* **`T < m·R`.** Every table row and the accumulator are canonical residues, so
  each Montgomery multiply keeps the module-level inductive bound. The table's
  `entries · n` product is `checked_mul`, and every window offset is
  `checked_mul`/`checked_add`, failing closed (`None`) on overflow.
* **Secret memory.** The table, the selected row, the accumulator and the scratch
  all live in `SecretBuf`; the result is the returned `Vec`, adopted by the
  caller's cleansing `BIGNUM` store.
* **Allocation.** The window adds exactly two fallible per-operation allocations
  (the `2^w`-row table and the selected row, both `SecretBuf::try_zeroed`); the
  reference's allocations are unchanged. At 2048 bits this is sub-0.1 % of wall
  time. An allocation failure propagates as the entry points' ordinary `None`.
* **No new `unsafe`.** The new code is safe Rust over `SecretBuf` slices and the
  constant-time helpers. The three unsafe lints are untouched; the `CRYPTO_*`
  seam and every `#[repr(C)]` layout are untouched.

## 5. Blinding, RSA and DH

Blinding sits **above** the ladder and the window does not interact with it.

* **RSA.** `rsa_ossl_private_encrypt`/`_decrypt` call `rsa_get_blinding` then
  `rsa_blinding_convert` *before* `rsa->meth->rsa_mod_exp` (which reaches the
  ladder), and `rsa_blinding_invert` after it. The window therefore exponentiates
  the already-blinded input `I·r^e mod n` to the private exponent; the
  multiplicative factor cancels in the invert exactly as for the bit-at-a-time
  ladder. The CRT halves reach the window through
  `BN_mod_exp_mont_consttime_x2`. The window schedule depends only on the public
  bit width, so exponent blinding that changes the exponent's **value** does not
  change the number of windows or squarings.
* **DH.** `ossl_dh_compute_key` marks the private exponent `BN_FLG_CONSTTIME` and
  reaches the ladder through `BN_mod_exp_mont`; there is no blinding factor
  around it. The window is a drop-in replacement for the multiplication step of
  the same ladder.

Neither path loses a blinding, fault-check or constant-time property; the
differential in `DIFFERENTIAL.md` confirms the blinded and non-blinded results
are byte-identical to the authority.
