# PFP-41 — what LLVM emits per limb product in the CIOS kernel

**Item:** measurement task PFP-41. **No production source changed; nothing
committed or pushed.** This document is a *static disassembly* audit. A recorded
instruction count is a property of the emitted code; it is **not** a timing
measurement and does not by itself determine cycles (that needs ports, stalls and
IPC).

---

## 0. Answer in one paragraph

The shipped CIOS inner loop is **at the instruction floor of the instruction set
it is built for**. LLVM emits, per 64×64 limb product on plain `x86-64`:
`mov rax; mulq; xor; add(acc); setb; add; adc; mov(store)` = **8 arithmetic
instructions/product** (9.5 including the 3 loop-control instructions amortised
over 2 products). A first-principles floor for that ISA is **7–8/product**, so
there is no recoverable compiler inefficiency in the loop body. The quoted
"6,457 instructions per 2048-bit multiply ≈ 3.15/product" is a **category
error**: 6,457 was the *generic slice kernel at n = 16 (1024-bit), before the
M-A1 specialisation*, and 3.15 divides an n=16 count by an n=32 product count.
The current kernel executes **4,679 instructions per n=16 multiply (9.14/product)**
and **21,163 per n=32 multiply (10.33/product)**. The remaining ≈2× to the
authority is the per-product ISA idiom: the authority ships a hand-written
**BMI2/ADX** kernel (`mulx`/`adcx`/`adox`, **4.56/product**, zero `mulq`), which
this baseline build cannot emit.

---

## 1. Identity and environment

| field | value |
|---|---|
| branch / HEAD | `staging`, `74599ccfc3325138c05d0399d4844781df3b5513` |
| `src` tree | `2200c5cee7c24357b814cc950033a32929e71a59` |
| `src/bn/arith.rs` sha256 | `92057de39ec2333437a18f744132da9e0f1927725db62a31b261b01eb15f9739` |
| build-relevant dirty paths | *(none)* |
| rustc / cargo | 1.98.1 (48a229cea) / 1.98.1 (797e8a9bc) |
| cc | Debian 12.2.0-14+deb12u1 |
| target | `x86_64-unknown-linux-gnu`, **default `target-cpu` (baseline, no BMI2/ADX)** |
| profile | release, `overflow-checks = true` |
| archive sha256 | `b617862261e11f9c1ac5aa46aa1f573e3c346fac1ce625a55b6b027f0d5181da` |
| **DSO sha256** | **`86a636a35ae95eaf8cf0668eed467e9343ea0a6465e849b169696c6c8acd1876`** |
| DSO size / build-id | 17,140,704 B / `454dbe092178a8df5131bb5706cf84901b3cd2c5` |
| CPU features (host) | `avx2 bmi2 adx` (no `avx512f`, no `avx512ifma`) |

The DSO is built with the campaign shell (`artifacts/phase2/shell/libcrypto.shell.rs`)
and version script, exactly as M-A1/PFP-40 (`raw/build-inputs.txt`,
`raw/dso-identity.txt`). `overflow-checks = true` does not reach the kernel:
every arithmetic helper uses `wrapping_*`, and the only `call` in
`mont_mul_ladder_into` is `memset` (acc zeroing); there is no panic branch.

### Memory protocol per heavy command

| command | `available` | `Swap free` | cap used |
|---|---:|---:|---|
| baseline `cargo build --release --lib` | 25 GiB | 10 GiB | 4 GiB (court `memory.max=4294967296`, `memory.swap=4g`, oom=0) |
| disassembly / analysis (objdump/python) | 24–25 GiB | 10–12 GiB | 4 GiB RLIMIT_DATA |
| native probe rebuild | 24 GiB | 12 GiB | 4 GiB |

`Swap free` was below 16 GiB throughout (the host editor holds the rest), so the
§24.4 deviation applies: **cap = min(4, available − 8) = 4 GiB**, and the court
was already created at exactly 4 GiB (`oom=0 oom_kill=0`). `CARGO_BUILD_JOBS=1`,
one heavy command at a time.

---

## 2. Locating the kernels

`nm` on the DSO (all widths are inlined into one symbol):

| symbol | addr | size | role |
|---|---:|---:|---|
| `openssl_rs::bn::arith::mont_mul_ladder_into` | `0x2d3b80` | `0x2431` | the ladder's multiply; dispatches on `m.len()` |
| `openssl_rs::bn::arith::run_mont_ladder` | `0x2d1be0` | `0x1662` | the window driver; **8** `call`s to `mont_mul_ladder_into` + **1** to `mont_mul_fallible` |
| `openssl_rs::bn::arith::mont_mul_fallible` | `0x163730` | `0x717` | SOS reference (`mont_mul_sos_into` inlined), variable-time path + base conversion |

The dispatch is a jump table at `0x66f5e0`, indexed by `n−4` for `n∈[4,64]`, a
separate `cmp $0x80` for `n=128`, and the generic slice kernel otherwise. Arm
starts (`raw/disasm/mont_mul_ladder_into.dis`, decoded in `analyse_loops.py`):

| n | arm | n | arm |
|---:|---:|---:|---:|
| 4 | `0x2d3c1a` | 32 | `0x2d5a6a` |
| 6 | `0x2d56f0` | 48 | `0x2d5c44` |
| 9 | `0x2d4604` | 64 | `0x2d4428` |
| 16 | `0x2d4bd3` | 128 | `0x2d410a` |
| generic runtime-n CIOS | `0x2d424e` | | |

The RSA CRT halves (1024-bit moduli, 16 limbs) take the **n=16** arm; a full
2048-bit multiply takes the **n=32** arm. The generic **CIOS** fallback is
`0x2d424e`; the generic **SOS** fallback is `mont_mul_fallible` (the variable-time
reference, not the ladder's multiply).

---

## 3. What LLVM emits — verbatim loop bodies

### 3.1 n = 32 product row (16 iterations × 2 limb products), `0x2d5ae0`

```
2d5ae0  mov    %rcx,%rax
2d5ae3  mulq   -0x8(%rdi,%rsi,8)      ; a[j]
2d5ae8  xor    %r10d,%r10d            ; re-zero the setb byte register
2d5aeb  add    -0x8(%rbx,%rsi,8),%r9  ; acc[j]  (load folded into add)
2d5af0  setb   %r10b                  ; capture carry of acc += carry
2d5af4  add    %rax,%r9               ; + product lo
2d5af7  adc    %rdx,%r10              ; + product hi + carry
2d5afa  mov    %r9,-0x8(%rbx,%rsi,8)  ; store acc[j]
2d5aff  mov    %rcx,%rax
2d5b02  mulq   (%rdi,%rsi,8)
2d5b06  xor    %r9d,%r9d
2d5b09  add    (%rbx,%rsi,8),%r10
2d5b0d  setb   %r9b
2d5b11  add    %rax,%r10
2d5b14  adc    %rdx,%r9
2d5b17  mov    %r10,(%rbx,%rsi,8)
2d5b1b  add    $0x2,%rsi              ; loop control (below)
2d5b1f  cmp    $0x21,%rsi
2d5b23  jne    2d5ae0
```

**19 instructions / 2 products = 9.5** including loop control; **8.0/product**
of arithmetic (`mov,mul,xor,add,setb,add,adc,store`).

### 3.2 n = 32 reduction row (16 entries × 2 products), `0x2d5b60`

```
2d5b60  mov    %rcx,%rax
2d5b63  mulq   -0x8(%r12,%r9,8)       ; m[j]
2d5b68  xor    %r10d,%r10d
2d5b6b  add    -0x8(%rbx,%r9,8),%rsi  ; acc[j]
2d5b70  setb   %r10b
2d5b74  add    %rax,%rsi
2d5b77  adc    %rdx,%r10
2d5b7a  mov    %rsi,-0x10(%rbx,%r9,8)
2d5b7f  cmp    $0x20,%r9
2d5b83  je     2d5aa0                  ; last entry -> outer tail
2d5b89  mov    %rcx,%rax
2d5b8c  mulq   (%r12,%r9,8)
2d5b90  xor    %esi,%esi
2d5b92  add    (%rbx,%r9,8),%r10
2d5b96  setb   %sil
2d5b9a  add    %rax,%r10
2d5b9d  adc    %rdx,%rsi
2d5ba0  mov    %r10,-0x8(%rbx,%r9,8)
2d5ba5  add    $0x2,%r9
2d5ba9  jmp    2d5b60
```

Executed per outer iteration: `15×20 + 10 = 310` (the `je` is taken on the 16th
entry).

### 3.3 n = 16 outer body — first product row (of 16), `0x2d4e0f`

The n=16 inner rows are **fully unrolled**; the operands `a[]` and `m[]` are
pre-spilled to `%rsp` slots in the prologue and reloaded here:

```
2d4e0f  mov    0x20(%rsp),%rax
2d4e14  mov    (%rax,%rdx,1),%r10     ; b[i]
2d4e18  mov    %r10,%rax
2d4e1b  mulq   0x190(%rsp)            ; a[0] from its spill slot
2d4e23  mov    %rdx,%r11
2d4e26  mov    %rax,%r15
2d4e29  mov    %r10,%rax
2d4e2c  mulq   0x188(%rsp)            ; a[1]
2d4e34  mov    %rdx,%r12
2d4e37  add    %r13,%rax
2d4e3a  adc    $0x0,%r12
2d4e3e  add    %r14,%r15
2d4e41  adc    %r11,%rax
2d4e44  mov    %rax,%r13
2d4e47  adc    $0x0,%r12
2d4e4b  mov    %r10,%rax
2d4e4e  mulq   0x180(%rsp)            ; a[2]
...
```

The whole 272-instruction outer body (one of 16 iterations) is in
`raw/loop-bodies.dis` under `n16.outer_body`.

### 3.4 n = 4 — fully unrolled straight line, `0x2d3c1a`

No backedge: the entire CIOS (4 product rows + 4 reduction rows + final masked
subtraction) is straight-line. First row:

```
2d3c1a  mov    0x10(%rdi),%r10
2d3c1e  mov    %r10,0x28(%rsp)
2d3c23  mov    (%rdi),%rdx
2d3c26  mov    %rdx,0x48(%rsp)
...
2d3c3c  mov    %rsi,%rax
2d3c3f  mul    %rdx
2d3c42  mov    %rdx,0x10(%rsp)
2d3c47  mov    %rax,%r9
2d3c4a  mov    %rsi,%rax
2d3c4d  mul    %rcx
...
```

---

## 4. Instruction-mix tables

`raw/instruction-mix.txt` (all ranges, reproducible). "mem" = instructions with a
memory operand; arithmetic loads are folded into `mulq mem` / `add mem,reg`, so a
separate "load" count under-reports — the mem column is the truthful reference
measure.

### 4.1 n = 32 product inner loop (19 insns, 2 products)

| category | count | % |
|---|---:|---:|
| mul (`mulq`) | 2 | 10.5 |
| adc | 2 | 10.5 |
| adox / adcx | 0 / 0 | 0 |
| add/sub | 5 | 26.3 |
| mov (register) | 2 | 10.5 |
| loads (bare mov) | 0 | 0 |
| stores | 2 | 10.5 |
| shifts | 0 | 0 |
| branches | 1 | 5.3 |
| cmov/setcc (`setb`) | 2 | 10.5 |
| other (`xor`×2, `cmp`, pad) | 4 | 21.1 |
| **memory operands** | **6** | (3/product) |

### 4.2 n = 16 outer body (272 insns, 32 products)

| category | count | % |
|---|---:|---:|
| mul (incl. 1 `imul` for u) | 33 | 12.1 |
| adc | 63 | 23.2 |
| adox / adcx | 0 / 0 | 0 |
| add/sub | 63 | 23.2 |
| mov (register) | 78 | 28.7 |
| loads (bare mov) | 5 | 1.8 |
| stores | 23 | 8.5 |
| branches | 0 | 0 |
| cmov/setcc | 2 | 0.7 |
| other | 5 | 1.8 |
| **`%rsp/%rbp` refs** | **80** | **29.4** |

### 4.3 n = 4 core (283 insns, 32 products; before final subtraction)

| category | count | % |
|---|---:|---:|
| mul (incl. 4 `imul`) | 36 | 12.7 |
| adc | 56 | 19.8 |
| adox / adcx | 0 / 0 | 0 |
| add/sub | 48 | 17.0 |
| mov (register) | 96 | 33.9 |
| loads (bare mov) | 25 | 8.8 |
| stores | 16 | 5.7 |
| branches | 0 | 0 |
| cmov/setcc | 6 | 2.1 |
| other | 0 | 0 |
| **`%rsp/%rbp` refs** | **47** | **16.6** |

**Zero `mulx`, zero `adcx`, zero `adox`** anywhere in the shipped kernel
(`grep -Ec 'mulx|adcx|adox' = 0`).

---

## 5. First-principles lower bound

A radix-2^64 CIOS multiply does `2n²` limb products (`n²` product row, `n(n−1)`
reduction plus the `n` `u·m[0]` products). Per limb product
`p_j = acc[j] + a[j]·b_i + c`:

* **multiplies:** exactly 1 hardware 64×64→128 multiply (`mulq`/`mulx`).
* **carry-consuming word adds:** 2 — the low word add (with the carried term) and
  the high word add-with-carry; plus 1 carry capture out of the low add.
* **memory references:** 3 — read `a[j]`/`m[j]`, read `acc[j]`, write `acc[j]`.
  With the multiplicand kept in a register this is 2; the `n`-limb accumulator
  cannot live in 16 GPRs, so `acc` is necessarily in memory.

**Baseline `x86-64` (no BMI2/ADX) floor per product:**

| # | instruction | why |
|---:|---|---|
| 1 | `mul` | one product |
| 1 | `mov rax,·` | `mul` has an implicit `rax` operand |
| 1 | `add acc,carry` | consume incoming carry |
| 1 | `setb` | capture the low-add carry (only one flag chain exists) |
| 1 | `add lo` | add product low |
| 1 | `adc hi` | add product high + carry |
| 1 | `mov acc,·` | store |
| = | **7** | emitted adds one `xor` to re-zero the `setb` byte → **8** |

**Emitted = 8.0 arithmetic/product (9.5 incl. loop control).** The loop is at its
ISA floor; the only "overhead" (`mov rax`, `xor`) is the cost of `mul`'s implicit
operand and the single carry flag, i.e. exactly what `mulx`/`adcx`/`adox` remove.

**BMI2/ADX floor per product:** `mulx` (1) + `adcx` (1) + `adox` (1) + load/store
(≈1.5) = **≈4–5**. The authority's measured **4.56/product** is that floor.

**Delta:** 8.0 / 4.56 = **1.75×** (arithmetic only); 9.5 / 4.56 = **2.08×**
including the shipped rolled-loop control. This is the ≈2×.

---

## 6. Reconciliation of the 6,457 figure

The campaign figure comes from PFP-7 (`BOUND.md` §2.1: `16,297,811 / 2,524 =
6,457`), measured at digest `6d002db2…`, which is the **generic slice kernel**
(the M-A1 "prev" build), at **n = 16** (a 1024-bit CRT half).

| quantity | value | derivation |
|---|---:|---|
| products in an n=16 multiply | 512 | `2n²` |
| products in an n=32 multiply | 2048 | `2n²` |
| 6,457 ÷ 512 | **12.61/product** | correct normalisation of PFP-7 |
| 6,457 ÷ 2048 | 3.153/product | **invalid** — n=16 count ÷ n=32 products |
| generic n=16 tight-loop core | 4,992 | `16·(8·19 + 8·20)` (inner trip `n/2=8`) |
| 6,457 − 4,992 | 1,465 | per-outer tails + final REDC/subtract/prologue |
| **specialised n=16, current** | **4,679** | `100 + 16·272 + 227` |
| **specialised n=32, current** | **21,163** | `21 + 32·640 + 16·16 + 32·12 + 22` |

`raw/reconciliation.txt`. Therefore:

* `6457` **does not reproduce** from any single tight loop body multiplied by its
  trip count. For the current n=16 kernel `loop_body × iterations = 272 × 16 =
  4,352`, i.e. **the 6,457 figure is superseded** by M-A1: the shipped n=16 kernel
  executes **4,679** (−27.5 %).
* The premise "6,457 instructions per **2048-bit** multiply ≈ 3.15/product" is
  wrong three ways: it is an **n=16 / 1024-bit** count; it is the **generic
  pre-specialisation** kernel; and it is a **dynamic in-situ average** (kernel +
  ladder tails), not a static inner-loop count. The actual n=32 (2048-bit) figure
  is **21,163 instructions (10.33/product)**.

---

## 7. Register pressure and spills

| kernel / range | `%rsp`/`%rbp` refs | share | accumulator |
|---|---:|---:|---|
| n=32 product inner (19) | 0 | 0 % | `acc` in memory (`%rbx`+index); running carry in `%r9/%r10` |
| n=32 reduction inner (20) | 0 | 0 % | same; `%rsi/%r10` carry |
| n=32 outer body (640) | 0 | 0 % | no stack traffic at all |
| n=16 outer body (272) | 80 | 29.4 % | `a[]`,`m[]` pre-spilled to `%rsp`, reloaded per product; `acc` in memory |
| n=16 prologue (100) | 39 | 39 % | 48 stores + 49 loads: the pre-spill of `a[]`/`m[]` |
| n=4 core (283) | 47 | 16.6 % | operand spills |
| n=32 mask (12, 32 iters) | 4 | 33 % | negligible (end-only) |

**The n=32 accumulator is not in registers** — it is the `t[]` array in memory
by design; the *running carry* is in registers. **The n=32 inner loops have zero
spill/reload traffic.** The n=16 fully-unrolled strategy *does* spill both
operands (≈2.5 reloads/product) yet is still the cheapest per product (9.14),
because it trades loop control for stack reloads and the trade is favourable.

---

## 8. Width dependence (the n = 4 P-256 width)

Per limb product, fully accounting for trip counts:

| kernel | instructions / multiply | products | per product |
|---|---:|---:|---:|
| n = 4 (P-256 order width, fully unrolled) | 333 | 32 | **10.41** (core 283 → 8.84) |
| n = 16 (1024-bit, unrolled + spills) | 4,679 | 512 | **9.14** |
| n = 32 (2048-bit, rolled) | 21,163 | 2048 | **10.33** |

The figure is **essentially width-independent** (8.8–10.4, ±8 % around ≈9.6);
the arithmetic core is 6–8/product at every width. The small spread tracks
*loop overhead* (n=32 carries 3 control instructions per 2 products) and the
*spill/unroll trade* (n=16 reloads 2.5 stack words/product). It does **not**
track arithmetic: the multiply/add/adc/setb/store sequence per product is the
same at n=4, n=16 and n=32. This supports the conclusion that the inner-loop
arithmetic is uniform and near its floor, and that width differences are
scheduling artefacts.

> The `ec::p256` *field* multiply (`<Mont as FieldKernel>::mul`, `0x45aa40`) is a
> different, dedicated P-256 kernel (`wide_mul_x86` + `mont_reduce_into`); the
> n=4 above is the **same CIOS kernel family** used by the mod-exp ladder at
> 4-limb order width (M-A1 `mont_mul_cios_fixed::<4,6>`), which is the
> apples-to-apples width comparison.

---

## 9. The authority is an ADX/BMI2 kernel — the source of the ≈2×

The pinned authority (`forensics/authorities/build/openssl-3.6.4-production`):

* `bn_mul_mont` (`0x15c0c0`) dispatches to **`bn_mulx4x_mont` (`0x15cac0`)** when
  the CPU has BMI2+ADX, and to `bn_sqr8x_mont` when `a == b` (dedicated
  squaring). The host has `adx,bmi2`; no `avx512ifma`, so the IFMA path is
  ineligible.
* `bn_mulx4x_mont` opcode census: **`mulx` 32, `adcx` 35, `adox` 29, `mulq` 0.**
* Product block `0x15cb40..0x15ccb0`: **73 instructions / 16 `mulx` = 4.56
  instructions per limb product** (`mulx`16, `adcx`16, `adox`9, `mov`15, `lea`7).

| per limb product | instructions | idiom |
|---|---:|---|
| this crate (baseline DSO) | 8.0 arith (9.5 incl. control) | `mul` + `add` + `setb` + `adc` |
| this crate, `-C target-cpu=native` | **6.1** | `mulx` + `add` + `adc` (**no** `adcx`/`adox`) |
| authority (hand-written) | **4.56** | `mulx` + `adcx` + `adox` |

**Native probe** (`raw/disasm/native_mont_mul_ladder_into.dis`, separate target
dir, DSO `1570ac94…`): with `RUSTFLAGS="-C target-cpu=native"` LLVM emits
**140 `mulx` and 0 `mulq`, but 0 `adcx` and 0 `adox`**; the tight loops drop to
≈6.1/product (e.g. `197 insns / 32 mulx`). So `target-cpu` recovers ≈1.3× (it
removes `mul`'s implicit-`rax` marshalling), but **LLVM will not synthesise the
two independent carry chains**; the remaining ≈1.34× to the authority needs
hand-written ADX assembly (as OpenSSL ships).

Two further, separate schedule-level advantages of the authority (not in the
inner loop): it uses **dedicated squaring** (`bn_sqr8x_mont` / `bn_sqrx8x`),
whereas this crate's ladder keeps `LADDER_DEDICATED_SQUARING = false`
(`src/bn/arith.rs:1681`) and squares through the multiply kernel; and it uses the
`gather5` windowed reduction. These are additional to the per-product factor and
were not quantified here.

---

## 10. Verdict

* **No compiler inefficiency was found in the CIOS inner loop.** On its target
  (baseline x86-64) the loop emits 8 arithmetic instructions/product against a
  7–8 first-principles floor; the `mov rax` and `xor` are the unavoidable price
  of `mul` and a single carry flag. The loop is at its floor.
* **The ≈2× to the authority is the per-product ISA idiom, not loop overhead,
  table selection, reduction, operand scanning, memory traffic, or the ladder.**
  It is exactly the `mul`+`setb`+`adc` floor (8/product) versus the
  `mulx`+`adcx`+`adox` floor (4.56/product): 1.75× arithmetic, 2.08× including
  the rolled-loop control. Closing it requires either a BMI2+ADX build target
  (≈1.3×, at the cost of a higher deployment CPU baseline) or a hand-written ADX
  kernel (the full ≈2×). Neither is an algorithmic change to the CIOS kernel.
* **The quoted "3.15 per limb product" is superseded.** 6,457 is the pre-M-A1
  generic **n=16 (1024-bit)** dynamic count; the current kernel is 4,679 (n=16)
  and 21,163 (n=32), i.e. 9.14 and 10.33/product.

---

## 11. Caveats

* Every figure here is a **static instruction count from `objdump`**. It is not a
  timing measurement; cycles depend on ports, latency, IPC and the surrounding
  ladder. The PFP-7 IPC 4.62 is not re-derived here.
* Trip counts are read from the loop-control immediates and recorded in
  `raw/reconciliation.txt`; the `memset` callee's own instructions are counted as
  one `call`.
* The `-C target-cpu=native` DSO is a probe, not the shipped artefact.
* The authority's dedicated-squaring/gather5 advantage is named but not measured
  in this batch.

---

## 12. Evidence index (`raw/`)

| file | contents |
|---|---|
| `build-inputs.txt` | source identity, toolchain, dirty check |
| `dso-identity.txt` | archive/DSO digests, size, build-id |
| `symbols-mont-mangled.txt`, `symbols-mont-demangled.txt` | symbol enumeration |
| `disasm/mont_mul_ladder_into.dis` | full inlined dispatch + all arms |
| `disasm/run_mont_ladder.dis` | driver and its 8 kernel call sites |
| `disasm/mont_mul_fallible.dis` | SOS reference |
| `disasm/p256_*.dis` | the separate P-256 field kernel |
| `disasm/authority_bn_mul_mont*.dis`, `disasm/authority_bn_mulx4x_mont.dis` | authority kernels |
| `disasm/native_mont_mul_ladder_into.dis`, `disasm/native-probe-identity.txt` | `target-cpu=native` probe |
| `loop-bodies.dis` | verbatim listings for every analysed range |
| `instruction-mix.txt` | the mix tables |
| `reconciliation.txt` | executed-count arithmetic |
| `analyse_loops.py`, `classify_ranges.py`, `reconcile.py`, `build.sh`, `native_probe.sh` | reproduction |
