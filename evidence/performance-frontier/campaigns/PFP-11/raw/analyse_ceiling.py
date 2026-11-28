#!/usr/bin/env python3
"""Compute the PFP-11 Amdahl table from attribution.json.

f is the attributable field-arithmetic share (inclusive for ECDSA, the
field category for the 25519 curves). `reduction_fraction` is the fraction of
that field work that is modular reduction, derived arithmetically (see
BOUNDS.md §3), not measured independently. `s_half` is the field speedup from
removing half of the reduction work; `e2e` is the resulting end-to-end
reduction. `s_to_clear10` is the smallest field speedup that would clear the
campaign's 10% threshold.
"""
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
print("%-20s %7s %10s %9s %9s %9s %10s" %
      ("op", "f", "reduction", "ceiling", "s_for_10", "s_halfred", "e2e_halfred"))
for op, v in sorted(data["ops"].items()):
    cats = v["categories_pct"]
    if op.startswith("ecdsa"):
        f = v["inclusive"]["BN_mod_mul_montgomery"]["pct"] / 100.0
        red = 0.55
    elif op.startswith("ed25519"):
        f = cats["field_mul_sqr_reduce"] / 100.0
        red = 0.08
    else:
        f = cats["field_mul_sqr_reduce"] / 100.0
        red = 0.30
    s_need = f / (f - 0.10) if f > 0.10 else float("inf")
    s_half = 1.0 / (1.0 - red / 2.0)
    e2e = 1.0 - ((1.0 - f) + f / s_half)
    print("%-20s %6.2f%% %9.2f%% %8.2f%% %8.3fx %8.3fx %9.1f%%" %
          (op, 100 * f, 100 * f * red, 100 * f, s_need, s_half, 100 * e2e))
