# PFP-46 — bound: what is available from a BMI2 target feature?

**Step 1 of PFP-46.** No source was changed for this measurement. The whole
crate was compiled twice from the same clean HEAD — once for the default
`x86_64-unknown-linux-gnu` baseline, once with `RUSTFLAGS="-C
target-feature=+bmi2"` — and the emitted CIOS ladder kernel was disassembled and
counted the way PFP-41 counted it. **This is a static instruction count, not a
timing measurement** (PFP-41 §11); it bounds the available *instruction*
reduction, and Step 5 measures whether that becomes latency.

Identity: branch `staging`, HEAD `4fcd2cc4c31ddffcaa365b40f5a51052759c7478`,
`src/bn/arith.rs` sha256 `2d0f42cc…2906e992` (clean), rustc/cargo 1.98.1, court
`openssl-rs-court` at `memory.max=4294967296` (4 GiB), `oom=0 oom_kill=0`.

## Method

`count_per_product.py` reads the dispatch jump table inside
`mont_mul_ladder_into` (entries are 4-byte signed offsets from the table base,
indexed by `n-4` for `n ∈ [4,64]`), takes each width arm's region, and counts:

* the **n = 4 arm**: fully unrolled, so the whole straight-line core
  `[arm, jmp-to-tail)` divided by the 32 limb products (16 product + 16
  reduction);
* the **n = 16 arm**: the unrolled outer body (one product row plus one
  reduction row = 32 products) divided by 32;
* the **n = 32 arm**: LLVM keeps the product loop rolled, so the tight
  product-accumulation loop body divided by its 2 products per iteration.

Raw: `raw/step1/counts.txt`, `raw/step1/disasm/`,
`raw/step1/build-inputs-{portable,bmi2}.txt`.

## Result

| width | portable insns / products | per product | `+bmi2` insns / products | per product | reduction |
|---|---|---:|---|---:|---:|
| n = 4  | 333 / 32 (straight-line core) | **10.41** | 239 / 32 | **7.47** | **−28.2 %** |
| n = 16 | 272 / 32 (unrolled outer body) | **8.50** | 196 / 32 | **6.13** | **−27.9 %** |
| n = 32 | 19 / 2 (tight product loop)  | **9.50** | 17 / 2 | **8.50** | **−10.5 %** |

Opcode census over `mont_mul_ladder_into`: portable `mulq=102, mulx=0`; `+bmi2`
`mulq=0, mulx=121`, `adcx=0, adox=0` — the same `mulx`-without-ADX idiom PFP-41
recorded for `target-cpu=native` (140 `mulx`, 0 `adcx/adox`).

For reference, PFP-41's head-line figures were 8.0 arithmetic/product in the
tight n = 32 loop (portable), ≈6.1/product for `target-cpu=native`, and 4.56 for
the hand-written ADX authority. The n = 16 `+bmi2` figure here (6.13) reproduces
the PFP-41 native probe to within 0.5 %.

The dispatched release wrappers (Step 2) reproduce the bound: the emitted
`mont_mul_cios_bmi2_16` outer body is 194 instructions / 32 = **6.06**/product,
`mont_mul_cios_bmi2_32` product loop is 17 / 2 = **8.50**, and
`mont_mul_cios_bmi2_4` is 239 core instructions / 32 = **7.47**.

## Go / no-go arithmetic

The campaign noise band is ~1.5 %. The smallest measured instruction reduction
is **10.5 %** (n = 32), the largest **28.2 %** (n = 4); every width is at least
7× the noise band. **Decision: GO** — implement the runtime dispatch.

Caveat carried to Step 5: an instruction-count reduction is not a cycle
reduction. On a wide out-of-order core the portable loop may be bound by the
single carry dependency chain rather than by instruction throughput, in which
case `mulx` changes the count but not the time. Step 5 measures that directly;
this document does not claim it.
