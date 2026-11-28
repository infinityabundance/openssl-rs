#!/usr/bin/env python3
"""PFP-11 instruction attribution classifier.

Parses `callgrind_annotate --inclusive=no` output (self cost, a disjoint
partition) and groups functions into:

  field_mul_sqr_reduce   multiplication / squaring / modular reduction
  inversion              field or scalar inversion
  scalar_order           order-domain arithmetic and generic BIGNUM division
  alloc_memory           allocator, Vec growth, memset/memcpy
  other                  everything else (point glue, startup, hashing, RNG)

It also reads the `--inclusive=yes` output for the field-multiply entry so the
Amdahl input is the inclusive subtree share, not only self cost.

Classification is by symbol name only; the raw files are kept so the grouping
can be audited line by line.
"""
import argparse
import json
import os
import re

LINE_RE = re.compile(r"^\s*([0-9,]+) \(\s*([0-9.]+)%\)\s+(\S+):(\S+)")

FIELD = (
    "mont_mul_fallible",
    "mont_mul_ladder_into",
    "mont_mul_cios",
    "mont_sqr",
    "BN_mod_mul_montgomery",
    "bn_mul_mont_fixed_top",
    "BN_to_montgomery",
    "fe_conv",
    "fe_reduce",
    "fe64_full_mul",
    "fe64_fold",
    "fe64_mul_arr",
    "fe64_sqr_arr",
    "fe64_mul121666",
    "fe51_mul_arr",
    "fe51_sqr_arr",
    "fe51_mul121666",
    "fe_mul",
    "fe_sq",
    "fe_sq2",
)
INV = (
    "fe64_invert",
    "fe51_invert",
    "fe_invert",
    "fe_pow22523",
    "mod_exp",
    "BN_mod_inverse",
    "mod_inverse",
    "divstep",
    "inverse_ord",
)
ADDSUB = (
    "fe64_add_arr",
    "fe64_sub_arr",
    "fe51_add",
    "fe51_sub",
    "fe_add",
    "fe_sub",
    "BN_mod_add_quick",
    "BN_mod_sub_quick",
    "BN_uadd",
    "BN_usub",
    "BN_add",
    "BN_sub",
)
SCALAR = (
    "BN_nnmod",
    "rem_fallible",
    "mod_add_reduced_ct",
    "mod_lshift_quick",
    "BN_mod_lshift",
    "BN_div",
    "BN_mod_exp_consttime",
)
# Order-domain BN_mod_mul is deliberately checked before the generic field
# substring; it is not Montgomery when it appears on the scalar side.
SCALAR_EXACT = ("BN_mod_mul", "BN_mod_sqr")
ALLOC = (
    "malloc",
    "_int_free",
    ":free",
    "calloc",
    "realloc",
    "finish_grow",
    "try_zeroed",
    "__rdl_alloc",
    "memset",
    "memcpy",
    "memmove",
)


def classify(name):
    for s in FIELD:
        if s in name:
            return "field_mul_sqr_reduce"
    for s in INV:
        if s in name:
            return "inversion"
    for s in ADDSUB:
        if s in name:
            return "field_add_sub"
    for s in SCALAR:
        if s in name:
            return "scalar_order"
    for s in SCALAR_EXACT:
        if re.search(r"(^|:)" + re.escape(s) + r"($|::|\s|$)", name) or name.endswith(s):
            return "scalar_order"
    for s in ALLOC:
        if s in name:
            return "alloc_memory"
    return "other"


def parse_self(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LINE_RE.match(line)
            if m:
                rows.append((int(m.group(1).replace(",", "")), float(m.group(2)), m.group(4)))
    return rows


def parse_inclusive(path, needles):
    best = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LINE_RE.match(line)
            if not m:
                continue
            ir = int(m.group(1).replace(",", ""))
            pct = float(m.group(2))
            name = m.group(4)
            for n in needles:
                if n in name and (n not in best or ir > best[n][0]):
                    best[n] = (ir, pct, name)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    report = {"categories": {}, "ops": {}}
    print("%-20s %10s %10s %10s %10s %10s %10s" %
          ("op", "field%", "inv%", "addsub%", "scalar%", "alloc%", "other%"))
    for name in sorted(os.listdir(args.dir)):
        if not name.endswith(".self.txt"):
            continue
        op = name[: -len(".self.txt")]
        rows = parse_self(os.path.join(args.dir, name))
        total = sum(r[0] for r in rows)
        cats = {k: 0.0 for k in
                ("field_mul_sqr_reduce", "inversion", "field_add_sub",
                 "scalar_order", "alloc_memory", "other")}
        per_func = []
        for ir, _pct, func in rows:
            cat = classify(func)
            cats[cat] += ir
            if cat in ("field_mul_sqr_reduce", "inversion", "scalar_order"):
                per_func.append({"ir": ir, "pct": 100.0 * ir / total,
                                 "category": cat, "function": func})
        pct = {k: 100.0 * v / total for k, v in cats.items()}
        incl = parse_inclusive(os.path.join(args.dir, op + ".incl.txt"),
                               ["BN_mod_mul_montgomery", "fe_conv", "fe51_mul_arr",
                                "fe64_mul_arr", "BN_mod_exp_mont_consttime",
                                "ossl_ec_group_do_inverse_ord"])
        report["ops"][op] = {
            "total_ir": total,
            "categories_pct": pct,
            "categories_ir": cats,
            "inclusive": {k: {"ir": v[0], "pct": v[1], "function": v[2]}
                          for k, v in incl.items()},
            "field_inversion_scalar_functions": sorted(
                per_func, key=lambda x: -x["ir"]),
        }
        print("%-20s %9.2f %9.2f %9.2f %9.2f %9.2f %9.2f" %
              (op, pct["field_mul_sqr_reduce"], pct["inversion"],
               pct["field_add_sub"], pct["scalar_order"],
               pct["alloc_memory"], pct["other"]))

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")


if __name__ == "__main__":
    main()
