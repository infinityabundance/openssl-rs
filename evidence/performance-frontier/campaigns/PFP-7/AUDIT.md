# PFP-7 — branch audit at the digest

**DSO:** `6d002db2…`. Every site below is re-derived from this digest's
`objdump` with `disasm_sites.py` (PFP-6's extractor, unmodified); no count or
address is inherited from PFP-5/PFP-6 even though the digest is the same.
Raw: `raw/audit/*.dis`, `*.sites.tsv`, `counts.txt`, `symbols.txt`.

The audit is a review aid, not a constant-time proof (`PFP2-AUDIT-NOT-A-PROOF`).

## Carriers found in this DSO

| symbol | extent | jcc | setcc | cmovcc |
|---|---|---:|---:|---:|
| `mont_mul_ladder_into` (CIOS, the ladder's multiply) | `0x58ce60` + `0x36c` | 14 | 18 | 0 |
| `run_mont_ladder` (window driver and `select_window_digit`, inlined) | `0x58af00` + `0x1626` | 100 | 18 | 2 |
| `mont_mul_fallible` (SOS kernel, inlined; the variable-time reference and the result-check path) | `0x167190` + `0x717` | 31 | 10 | 0 |
| `mont_mul_sos_into` | **absent** as a symbol (inlined into `mont_mul_fallible`) | — | — | — |
| `run_mont_ladder_window`, `select_window_digit` | **absent** as symbols (inlined into `run_mont_ladder`) | — | — | — |

There is **no interleaved carrier**: `BN_mod_exp_mont_consttime_x2` is two
sequential calls to `BN_mod_exp_mont_consttime`, so nothing new is on the RSA
CRT path.

## Classification of the CIOS carrier (`mont_mul_ladder_into`)

**14 `jcc`, all public.** Every condition is a comparison of lengths, counters or
pointers, never of a limb from `a`, `b`, `m` or `acc`:

* 2 are the `mont_geometry_ok` predicate (`xor`/`or` of the three lengths and the
  pointer-equality tests, `sete`/`setne` feeding `jne`);
* 9 are loop counters and the two-limb unrolling (`cmp %r9,%r13`,
  `cmp 0x20(%rsp),%r14`, `cmp $0x1,%rax`, …);
* 3 are the small-`n` special cases (`cmp $0x2,%r13`, `test %rax,%rax`,
  `cmp $0x2,%rdi`).

**18 `setcc`, none reaching control.** 15 are `setb` capturing an add/`adc`
carry into a register that is consumed arithmetically by the next `add`/`adc`
(the CIOS carry propagation); 3 are `sete`/`setne` deriving the public geometry
predicate. All 18 feed a `mov`/`adc`/`or`, not a jump or a `cmov` condition.

**0 `cmovcc`.**

## The driver (`run_mont_ladder`, window schedule incl. the scan)

**100 `jcc`** — loop geometry of the table build, the `ceil(bits/w)` window loop,
the fixed `w` squarings, and the masked-scan loops. **18 `setcc`** — the same
carry captures of the inlined CIOS body. **2 `cmovcc`**, both `cmovb` with
register operands on a length comparison (`cmp %rbp,%rbx` /
`cmp %r13,%rbx`), inside `select_window_digit`'s zeroing path: they select a
slice length, i.e. public geometry. They are recorded, not waived: the PFP-34
gate requires an operand classification for every `cmov`, and this is it.

**Secret-derived conditional transfers: none** in either carrier. The secret
digit enters `select_window_digit` only as an equality mask (`constant_time_eq_s`)
applied to public addresses, and the exponent enters the ladder through the
staged buffer with value-only operations.

## The variable-time path

`mont_mul_fallible` (31 `jcc`) is the SOS kernel used by `BN_mod_exp_mont` — the
authority's own variable-time exponentiation, used here for the result check on
the secret result and for the base conversion. It is *not* on the CRT
exponentiation path and is not claimed constant-time; its presence in the taint
origin list (`TAINT.md`) is expected for that reason.
