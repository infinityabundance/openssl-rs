# PFP-3 — point-arithmetic formula comparison (measured)

Both schedules were measured by counting field operations with a counting
`FieldKernel` wrapper (`formula_weighted_cost_is_measured`), not asserted. The
counts are structural and deterministic. Weights use the conventional
`M = 1.0`, `S = 0.8`; additions/subtractions are modular and not charged.

| schedule | operation | M | S | weighted |
|---|---|---:|---:|---:|
| RCB complete (admitted) | addition (Algorithm 4) | 14 | 0 | 14.0 |
| RCB complete (admitted) | doubling = complete add `P=Q` | 14 | 0 | 14.0 |
| Jacobian `a=-3` (`dbl-2001-b`) | doubling | 3 | 5 | 7.0 |
| Jacobian (`add-2007-bl`) | addition | 11 | 5 | 15.0 |

The fixed-base comb's actual operation mix is **64 additions + 64 doublings**:

* RCB complete: `64 × (14.0 + 14.0) = 1792.0`
* Jacobian: `64 × (15.0 + 7.0) = 1408.0`

The raw weighted cost favours the Jacobian `a=-3` schedule by **21.4 %**
(`(1792 - 1408) / 1792`), driven entirely by its `a=-3` doubling.

## Admission decision

The faster raw schedule is **not admissible on the secret path**. The Jacobian
addition (`add-2007-bl`) is not complete: it assumes `P ≠ ±Q` and neither operand
at infinity. Routing the exceptional cases correctly requires comparing operand
coordinates that depend on the secret scalar and choosing between an addition, a
doubling and infinity — a secret-dependent conditional transfer, which the
standard forbids and which a constant-time audit would classify as a STOP.

The admitted arm therefore uses the **complete RCB addition**, and the complete
addition with `P = Q` as its doubling, so the exceptional cases are handled by
the formula rather than by a branch. The Jacobian schedule is retained **only as
a reference arm**, and `the_jacobian_reference_matches_the_ladder` confirms it is
correct on the non-exceptional inputs it admits (`2G`, `3G` against the ladder).

This is a measured comparison, not a benchmark; no wall-clock interval is
reported because the timing campaign was not executed at this digest (see
`TIMING.md`). The operation counts are the measurement.
