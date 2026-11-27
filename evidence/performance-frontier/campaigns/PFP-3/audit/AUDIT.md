# PFP-3 — binary branch audit at `04611380…`

**Result: STOP.** The shared auditor resolves all 31 inventory targets (exit
0), but the new fixed-base code contains **one secret-derived conditional
transfer**, reproduced independently of ctgrind: `je` at
`ossl_ec_wNAF_mul+0x1938` (`0x242138`), condition `ct_ge(k, n)`. All jcc/cmov/
setcc in the five out-of-line fixed-base carriers are public-bound or
branchless mask material.

## 1. Shared auditor, PFP-3 inventory (unchanged tool, exit 0)

`courts/phase18/timing/binary_branch_audit.py` (`5d54f3a1…`) with
`targets-pfp3.json` = the PFP-31 31-target inventory (`3a7f5697…`, identical
bytes), bound with `--expect-sha256`:

```
binary_branch_audit: 31 expected targets resolved uniquely with complete
disassembly; 1 resolved through a verified inline mapping; 2 resolved through a
verified LLVM-suffix witness; candidate sha256=04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4
```

Exit status **0**. `ossl_ec_wNAF_mul` (in `mult`) is in that inventory; the
fixed-base admission and `try_fixed_base_mul` are inlined into it, so its rows
are the inlined carriers.

## 2. Exact-symbol carrier inventory (generic instantiations)

The shared tool resolves a target only when its v0 mangled symbol *ends* with
`<len(identifier)><identifier>`. The five fixed-base carriers are generic over
`Mont<FieldDomain>`, so their symbols end with the generic-instantiation tail
and the short-name rule (correctly) does not match them. `capture_carriers.py`
(`24563ac7…`) imports the auditor's own `symbol_table`, `disassemble`,
`disassembly_problem`, `is_jcc` and `cond_provenance` — unchanged — and adds a
*stricter* resolution: the inventory names the exact v0 component
(`10fixed_base<len><name>`), the artefact must contain **exactly one** defined
`.text` symbol matching it, and admission still requires a non-zero extent and a
byte-complete disassembly. No existing resolution path is relaxed.

| carrier | extent | insns | jcc | cmov | setcc | div | classification |
|---|---:|---:|---:|---:|---:|---:|---|
| `rcb_add<Mont<FieldDomain>>` | 17258 | 3389 | 0 | 0 | 40 | 0 | branch-free; 40 `setcc` are carry/borrow **masks**, not transfers |
| `table_mul<…>` (comb) | 10574 | 1619 | 2 | 0 | 2 | 0 | both jcc are loop counters (64 columns, 15-entry scan) |
| `to_affine<…>` (invert) | 1557 | 326 | 2 | 0 | 0 | 0 | loop counter + `if word&1` on the **public** exponent `p-2` |
| `build_table<…>` | 2458 | 423 | 1 | 0 | 0 | 0 | `for v in 1..TABLE_LEN`, public data |
| `build_table::advance<…>` | 771 | 168 | 1 | 0 | 0 | 0 | `for _ in 1..COLUMNS`, public doubling |
| `ossl_ec_wNAF_mul` (inlined entry/admission) | 7223 | 1525 | 186 | 33 | 5 | 4 | general wNAF + inlined fixed-base admission |

### Classification of the new carriers

* **Public-bound:** `table_mul` (2 jcc), `to_affine` (2 jcc), `build_table`
  (1 jcc), `advance` (1 jcc). Each jcc is a fixed-bound loop or the public
  exponent bit; none reads the scalar.
* **Secret-data-dependent, not a transfer:** `rcb_add`'s 40 `setcc` and
  `table_mul`'s 2 `setcc`. These capture carry/borrow or the `ct_eq_u64` mask
  and feed the next arithmetic/select; they set a value, they do not branch.
  `rcb_add` has **0 jcc** and **0 cmov** — the RCB addition and doubling are
  branch-free.
* **Secret-derived conditional transfer (STOP):** exactly one, in the fixed-base
  region inlined into the driver:

  ```
  +0x1938  je  src=reg/arith  guarded=call  dir=back  target=0x240b1e
           [setter 0x242135: test $0x1,%cl]
  ```

  It is the `ct_ge(k, ORDER_MODULUS) != 0 → return None` admission early exit.
  ctgrind independently reports the same instruction as the only
  secret-dependent conditional transfer of the `mul-g-fixed` population.

The remaining `ossl_ec_wNAF_mul` jcc/cmov belong to the pre-existing general
wNAF path (public-scalar precomputation and its own branches), which PFP-29/
PFP-31 already audited; they are outside the new fixed-base carrier scope, and
the ctgrind taint population (which executes the fixed-base path) does not
report any of them as secret-dependent.

## 3. Identity and records

DSO `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`; the
carrier driver asserted the same digest with `--expect-sha256`. Raw:
`raw/audit-pfp3.md`, `raw/audit-pfp3.stderr`, `raw/carriers.md`,
`raw/carriers.json`, `raw/audit-meta.env`. The `wNAF+0x1938` jcc is re-derived
from the disassembly and cross-checked against the ctgrind address by
`run_audit.sh`.
