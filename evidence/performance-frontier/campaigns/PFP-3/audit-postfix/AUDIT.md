# PFP-3 — binary branch audit after the branch-free admission

**Result: PASS on the binary audit.** The shared auditor resolves all 31
inventory targets (exit 0) and the exact-symbol carrier audit resolves all six
fixed-base carriers. The inlined `ossl_ec_wNAF_mul` carrier has **no
secret-derived conditional transfer**: the pre-fix `je` at `+0x1938` on
`test $0x1,%cl` (the low bit of the `ct_ge(k, n)` mask) is absent, and no jcc in
the carrier has that flag setter.

## 1. Shared auditor, PFP-3 inventory (unchanged tool)

`courts/phase18/timing/binary_branch_audit.py` (`5d54f3a1…`) with
`targets-pfp3.json` (the PFP-31 31-target inventory, identical bytes), bound with
`--expect-sha256`:

```
binary_branch_audit: 31 expected targets resolved uniquely with complete
disassembly; 1 resolved through a verified inline mapping; 2 resolved through a
verified LLVM-suffix witness; candidate sha256=ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053
```

Exit status **0**. `ossl_ec_wNAF_mul` (in `mult`) is in that inventory; the
fixed-base admission and `try_fixed_base_mul` are inlined into it.

## 2. Exact-symbol carrier inventory (unchanged driver)

`capture_carriers.py` (`24563ac7…`, byte-identical to the pre-fix copy) imports
the auditor's own `symbol_table`, `disassemble`, `disassembly_problem`, `is_jcc`
and `cond_provenance`, and resolves each generic instantiation by exact v0
component with the same unique-symbol, non-zero-extent, complete-disassembly
contract.

| carrier | pre-fix `04611380` | post-fix `ecbefb7d` | classification |
|---|---|---|---|
| `rcb_add<Mont<FieldDomain>>` | jcc 0, cmov 0, setcc 40 | **0 / 0 / 40** | branch-free; setcc are carry/borrow masks |
| `table_mul<…>` (comb) | jcc 2, cmov 0, setcc 2 | **2 / 0 / 2** | both jcc are loop counters; setcc are mask material |
| `to_affine<…>` (invert) | jcc 2, cmov 0, setcc 0 | **2 / 0 / 0** | loop + public exponent bit |
| `build_table<…>` | jcc 1, cmov 0, setcc 0 | **1 / 0 / 0** | public table loop |
| `build_table::advance<…>` | jcc 1, cmov 0, setcc 0 | **1 / 0 / 0** | public doubling loop |
| `ossl_ec_wNAF_mul` (inlined entry/admission) | jcc 186, cmov 33, setcc 5 | **jcc 183, cmov 34, setcc 5** | general wNAF (pre-existing); no admission-mask jcc |

The only difference in the inlined carrier is the removal of the admission
branch: jcc 186 → 183. The pre-fix carrier had exactly one jcc whose flag setter
was `test $0x1,%cl` (`+0x1938`, target `0x240b1e`); the post-fix carrier has
**zero** jcc with that setter. The extra `cmov` count is aggregated over the
whole (pre-existing) wNAF carrier; it is not on the tainted fixed-base path —
the DSO ctgrind on the same digest reports **0 contexts** for `mul-g-fixed`, and
memcheck reports a conditional move on an undefined condition, so a
secret-derived `cmov` would have appeared there.

## 3. Cross-instrument agreement

* ctgrind at the same digest: `mul-g-fixed` **0 errors / 0 contexts** in all
  three repetitions (pre-fix: 1/1); sensitivity control still 4 engine-on-path
  per repetition.
* branch audit: no admission-mask jcc; the six carriers and all 31 inventory
  targets resolve.

Both instruments are bound to
`ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053` with
`--expect-sha256`; the shared-inventory run and the carrier run both exit 0.

## 4. What the source does now

`src/ec/p256/fixed_base.rs::try_fixed_base_mul` computes
`out_of_range = ct_ge(&k, &ORDER_MODULUS)` (all-ones iff `k >= n`) and folds it
into the scalar the comb consumes: `reduced = k - (n & out_of_range)`. A
four-limb non-negative scalar is below `2n`, so for `k >= n` the reduced value
is `k - n` — exactly the value the ladder multiplies — and for `k < n` it is
`k`. The decision is therefore exact and the select is arithmetic (`sub_borrow`
chain plus `select_limbs`, whose mask passes the crate's `value_barrier`); there
is no `if`/`match`/`?`/early return on the mask.

## 5. Identity and records

DSO `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053`
(17,123,976 bytes, build-id `01b4e75402b7c299d8b10c6293d4159f2cd85f9f`),
reproduced from `staging` `f8d5c4b33…` plus the uncommitted
`src/ec/p256/fixed_base.rs` change. Raw: `raw/audit-pfp3.md`,
`raw/audit-pfp3.stderr`, `raw/carriers.md`, `raw/carriers.json`,
`raw/audit-meta.env`.
