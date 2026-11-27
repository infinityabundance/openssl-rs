# M-A1 — fixed-width native Rust specialisation of the CIOS kernel: design

**Status: implemented and admitted as a performance candidate at DSO
`88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87`.**
The generic slice kernel is retained, unchanged, as the differential reference
and the fallback. This document describes the mechanism; `RESULTS.md` records
the measurements and `RECEIPT.md` the batch record.

## 1. The signal this arm tests, and why it is not an admission

M-A2 (reduced radix) was refuted, but its by-product was a useful gap: in one
standalone binary the **same radix-2^64 CIOS arithmetic** over fixed-size arrays
was 2.6× faster than a line-by-line slice-shaped transcription at 256 bits and
1.07× at 1024 bits. That is a signal from a standalone experiment, not evidence
about the crate. M-A1 tests it where it matters: inside `libcrypto.so.3`, against
the admitted CIOS kernel (`PFP-6/ADMISSION.md`, digest `6d002db2`), with the
generic slice kernel kept as the reference.

The hypothesis is narrow. The admitted CIOS kernel takes `n = m.len()` at
runtime, so every inner loop has a dynamic trip count and the compiler cannot
remove the slice bounds checks. Replacing `n` with a compile-time constant
should let it unroll and drop those checks. Nothing about the arithmetic,
schedule or accumulator bound changes.

## 2. The change

Two new functions in `src/bn/arith.rs`, and one line in the ladder boundary:

```
mont_mul_cios_fixed<const N: usize, const ACC: usize>(...) -> bool
mont_mul_cios_dispatch(...) -> bool
mont_mul_ladder_into:  MontSchedule::Cios => mont_mul_cios_dispatch(...)
```

`mont_mul_cios_fixed` is the admitted `mont_mul_cios_into` body with the runtime
`n` replaced by the const parameter `N`. `a`, `b`, `out`, `m` and `diff` are
converted from slices to `[Limb; N]` references at the boundary (a length check,
then `TryFrom`, both on public geometry). The accumulator is the first `ACC`
limbs of the caller's `t`, converted to `&mut [Limb; ACC]`; it remains in the
caller's `SecretBuf`, so the existing cleansing-on-drop is preserved. `ACC` is a
second const parameter only because `N + 2` is not a stable const-generic
expression.

`mont_mul_cios_dispatch` checks the same `mont_geometry_ok` contract as the
generic kernel and then selects on `m.len()`:

| modulus limbs | kernel | `ACC` | typical caller |
|---:|---|---:|---|
| 4 | `mont_mul_cios_fixed::<4, 6>` | 6 | P-256 order (ECDSA/ECDH) |
| 6 | `mont_mul_cios_fixed::<6, 8>` | 8 | P-384 order |
| 9 | `mont_mul_cios_fixed::<9, 11>` | 11 | P-521 order |
| 16 | `mont_mul_cios_fixed::<16, 18>` | 18 | 1024-bit RSA prime / MODP |
| 32 | `mont_mul_cios_fixed::<32, 34>` | 34 | 2048-bit RSA / DH |
| 48 | `mont_mul_cios_fixed::<48, 50>` | 50 | 3072-bit |
| 64 | `mont_mul_cios_fixed::<64, 66>` | 66 | 4096-bit |
| 128 | `mont_mul_cios_fixed::<128, 130>` | 130 | 8192-bit |
| anything else | `mont_mul_cios_into` (generic slice) | `n + 2` | fallback |

The six required widths are `4/16/32/48/64/128`; `6` and `9` are the odd widths
the EC callers actually reach (P-384 and P-521 group orders). The generic kernel
is exactly what `mont_mul_fallible_with(MontSchedule::Cios, ...)` uses, so the
per-width differential compares the new code against the old code, not against
itself. `mont_mul_fallible` (SOS), the window ladder, `select_window_digit`,
`LADDER_SCHEDULE`, `LADDER_WINDOW_BITS`, `LADDER_DEDICATED_SQUARING` and the
conversion sites are untouched.

## 3. Why the CIOS schedule and the accumulator bound are preserved

The specialised body is the same statement sequence as `mont_mul_cios_into`:

1. `acc.fill(0)` over the `N + 2` accumulator limbs;
2. for each `b_i`: the product row `acc[j] += a[j] * b_i` with the carry into
   `acc[N]` and the overflow bit into `acc[N + 1]`;
3. the reduction row `acc[j - 1] = (u * m[j] + acc[j] + carry)` with
   `u = acc[0] * n0`, the annihilated low limb dropped;
4. the single masked conditional subtraction: one `n`-limb difference, a borrow
   accumulated across limbs, `keep = high | (borrow ^ 1)`, and a
   `constant_time_select` per limb.

The accumulator extent is `N + 2` in both forms. Therefore the `T_i < 2m`
invariant of `mont_mul_cios_into` is **inherited verbatim** with `n := N`; it is
not re-derived and no extra reduction step is added. The final subtraction is
still a mask select, not a branch, and all loop counts are `N` (a compile-time
constant here, a public length there).

## 4. Constraints observed

- **Safe Rust only.** No new `unsafe`, no intrinsics, no assembly, no
  `#[repr(C)]` change, no allocator-seam change. `unsafe_op_in_unsafe_fn`,
  `undocumented_unsafe_blocks` and `missing_safety_doc` are untouched.
- **No schedule change.** The dispatch is only on the `Cios` arm; `Sos` still
  goes to `mont_mul_sos_into`.
- **Secret storage stays in the caller's `SecretBuf`.** The accumulator and the
  difference buffer are borrowed in place; no new stack copy of secret state is
  introduced and no cleansing path is removed.
- **Failure is fail-closed.** A length or `ACC` mismatch returns `false` and
  writes nothing, exactly as the generic kernel does.

## 5. What this design does not claim

- It is not a constant-time proof. The branch audit is an enumeration plus a
  local dataflow check of one artefact; ctgrind covers the width-4 path
  dynamically. The other widths rest on the structural argument.
- The timing is one venue's scoped observation, not a portable claim.
- No `SAFE_COMPATIBLE` or safety conclusion is asserted; this is a performance
  arm. The same-digest ABI transcript is compatibility evidence only.
