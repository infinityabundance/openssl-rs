# PFP-8 — branch audit of the DH carriers

**Carrier identity:** candidate DSO
`88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87`
(`b2cca665…`, clean `src`); `raw/disasm/carrier-identity.txt`.
**Method:** `objdump` of each symbol, `disasm_sites.py` enumerates every `jcc`,
`setcc` and `cmovcc`; `classify_widths.py` (kernel) and `classify_ladder.py`
(window loop) assign a class, flag source and (for class-b setcc) the first
consumer. Any arithmetic-flag `jcc`, any class-b `setcc` consumed by a control
transfer, or any arithmetic-source `cmovcc` aborts the script.

No Rust source changed, so there is no new carrier. The two carriers the DH
profile reaches are audited at this digest:

| carrier | jcc | setcc | cmovcc | secret-derived control transfers |
|---|---:|---:|---:|---:|
| `mont_mul_ladder_into` (CIOS, 8 widths inlined) | 40 (all public) | 64 (all class b carry/borrow, consumed arithmetically) | 0 | **0** |
| `run_mont_ladder` (window loop + inlined masked scan) | 97 (all public) | 15 (14 public, 1 secret-bit data) | 2 (both public) | **0** |

## `run_mont_ladder` — public conditional transfers

Every `jcc` whose flags come from `cmp`/`test` is a loop bound or slice/pointer
length check. The following take flags from length/allocation arithmetic rather
than `cmp`/`test`; each is in the allocation/`finish_grow` or slice-geometry
path and operates on a length or pointer tag, not a limb:

| addr | source | role |
|---|---|---|
| `0x2f895b` | `shr $0x3a,%rax` | slice-length high-bit check |
| `0x2f8a2d` | `or %al,%cl` | allocation-length overflow mask |
| `0x2f8c43` | `or %cl,%dl` | allocation-length overflow mask |
| `0x2f8d27` | `or %al,%cl` | allocation-length overflow mask |
| `0x2f8de5` | `or %al,%cl` | allocation-length overflow mask |
| `0x2f90f6` | `or %al,%cl` | allocation-length overflow mask |
| `0x2f9239` | `shr $0x3b,%rax` | pointer/tag high-bit check |
| `0x2f931a` | `sub %rax,%rbp` | allocation-size difference |
| `0x2f9397` | `subq $0x1,0xd8(%rsp)` | allocation counter underflow |
| `0x2f93bb` | `mul %rbx` (`jo`) | allocation-size overflow |
| `0x2f9465` | `or %al,%cl` | allocation-length overflow mask |
| `0x2f94f0` | `or %al,%cl` | allocation-length overflow mask |
| `0x2f9a1f` | `mul %rbx` (`jo`) | allocation-size overflow |
| `0x2f9a2b` | `add %rbx,%rsi` | allocation-size overflow |
| `0x2f9a50` | `shr $0x3f,%rax` | length-difference sign mask |

These are the reviewed entries of `PUBLIC_ARITH` in `classify_ladder.py`; the
script prints the source for each in `ladder-classification.md`.

## The one secret flag source

`0x2f9710` is `setb %dl` after `bt %rax,%rcx`. `%rcx` is the exponent limb and
`%rax` the bit index: this is the digit construction for the masked scan. The
`setb` result is stored to `0x10(%rsp)` by the next `mov` and consumed as data
(an OR/AND mask), never by a branch. It is class (b) **data**; there are **0**
class-(b) control transfers.

The two `cmovcc` (`0x2f8eb3`, `0x2f9671`) both take `cmp` flags on allocation
lengths; both are class (a).

## Limit

This is an enumeration and local dataflow review of one artefact, not a proof of
secret independence. The dynamic ctgrind (`TAINT.md`) covers the width-4 ladder
with 0 contexts and a firing negative control; the other widths rest on this
structural audit. Neither instrument proves constant time.

Raw: `audit/raw/disasm/` (`cand-*.dis`, `*.sites.tsv`, `kernel-classification.*`,
`ladder-classification.*`, `carrier-identity.txt`, `carriers.tsv`).
