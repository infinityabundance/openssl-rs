# PFP-3 — constant-time taint and binary branch audit: **NOT_RUN at `04611380…`**

No ctgrind context count and no `jcc`/`setcc`/`cmov` classification exists for
the new fixed-base code at DSO `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`.
Both instruments were deferred this session; **no constant-time claim is made**
(Earned Trust article 8: a constant-time result is not a proof of constant time,
and here there is not even a result).

## What the code does by construction, and what that does **not** prove

These are design statements, not audit findings:

* **Selection is a full scan with a mask.** `select_point` reads all 15 non-zero
  table entries and folds the match with a full-width mask derived from
  `ct_eq_u64`; the secret column value is never used as an index. Cost is fixed
  at 15 masked selects of three field elements per column, 64 columns.
* **The comb loop is fixed.** 64 iterations, one doubling and one complete
  addition per iteration, independent of the scalar.
* **The point formulas branch on no value.** `rcb_add` is the complete RCB
  addition; doubling is the same formula at `P = Q`. Field add/sub/mul/sqr are
  the PFP-2 kernels, whose own evidence is at `553e1b8c`, not at this digest.
* **Inversion branches only on the public exponent `p-2`.** Square-and-multiply
  over a compile-time constant exponent; the secret base only feeds field
  multiplies.
* **Affine export uses masks.** `z` is written as `1 & !infinity_mask` and
  `z_is_one` from the same mask; the absolute-length normalisation is PFP-20's
  branchless `store_coordinate`.

**Obligations that an audit would have to check, not assume:**

1. The admission check branches on the scalar's *metadata* (`neg != 0`,
   `d.len() > 4`) before taking the fast path. These mirror the authority's own
   unusual-input handling in `ossl_ec_scalar_mul_ladder`, but a branch on scalar
   metadata must be shown not to depend on the secret value for the admitted
   population.
2. The compiler may if-convert a masked select into a conditional branch; only
   the binary audit can see that. The PFP-2 lesson (`mont_reduce_into`'s
   borrow predicate) is directly applicable to `ct_eq_u64` and `fselect`.
3. `store_coordinate`'s allocation size must be fixed (it is: `Canonical4`
   always exposes four limbs), but this must be confirmed at the artefact.

## What would be run

The PFP-2 harnesses, unchanged, rebound to `04611380…`:
`ctgrind/pfp21_dso_ct.c` (DSO-level valgrind memcheck, secret scalar tainted,
minimal and sign populations) and
`courts/phase18/timing/binary_branch_audit.py` against this DSO, with the PFP-34
coverage set extended to the new `fixed_base` symbols. A secret-derived
conditional transfer there is a STOP, not a note.

Until that is run, the constant-time conjunct is `NOT_RUN`; the PFP-3 row is
`PARTIAL`.
