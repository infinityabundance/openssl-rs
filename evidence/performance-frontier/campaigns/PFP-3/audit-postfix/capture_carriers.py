#!/usr/bin/env python3
"""Exact-symbol carrier audit for the PFP-3 fixed-base code.

The shared auditor (`courts/phase18/timing/binary_branch_audit.py`) resolves a
target only when its Rust v0 mangled symbol *ends* with
``<len(identifier)><identifier>``.  The fixed-base carriers are generic over the
field kernel, so their mangled names end with the generic-instantiation tail
(``...INtB4_4MontNtB4_11FieldDomainEEB8_``) and the shared rule deliberately
does not relax to a prefix/substring match.

This driver does not change that instrument.  It imports it unchanged (so the
disassembler, the byte-coverage check ``disassembly_problem`` and the
condition-provenance classifier are the same code) and adds one resolution
form that is *stricter* than a short-name match: the inventory names the exact
structural v0 components (module ``fixed_base`` plus the length-prefixed
identifier) and the artefact must contain exactly one defined ``.text`` symbol
matching it.  The target is then admitted only with a non-zero declared extent
and a complete disassembly of that exact range -- the same fail-closed contract.

The classification of each jcc/setcc/cmov (public-bound vs secret-derived) is a
source review recorded by hand in AUDIT.md; this script only reports the
instructions and their condition provenance.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

AUDITOR = Path("/work/courts/phase18/timing/binary_branch_audit.py")


def load_auditor():
    spec = importlib.util.spec_from_file_location("bba", AUDITOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


# (family, v0-component regex anchored on the module + identifier, note)
CARRIERS = [
    (
        "RCB complete addition (secret path)",
        r"10fixed_base7rcb_addI",
        "rcb_add<Mont<FieldDomain>>: the complete addition carrier",
    ),
    (
        "Comb (table_mul: select + double + add)",
        r"10fixed_base9table_mulI",
        "table_mul<Mont<FieldDomain>>: 64 doublings + 64 masked selects + adds",
    ),
    (
        "Affine export (to_affine: Fermat inversion)",
        r"10fixed_base9to_affineI",
        "to_affine<Mont<FieldDomain>>: invert(base p-2) + canonical export",
    ),
    (
        "Table construction (build_table)",
        r"10fixed_base11build_tableI",
        "build_table<Mont<FieldDomain>>: public generator table",
    ),
    (
        "Table advance (build_table::advance)",
        r"10fixed_base11build_table7advanceI",
        "build_table::advance<Mont<FieldDomain>>: COLUMNS public doublings",
    ),
    (
        "Fixed-base entry and admission (inlined into wNAF)",
        r"2ec4mult16ossl_ec_wNAF_mul$",
        "ossl_ec_wNAF_mul: try_fixed_base_mul + admits + ct_ge inlined here",
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dso", required=True)
    ap.add_argument("--expect-sha256", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    bba = load_auditor()
    data = bba.read_dso(args.dso)
    import hashlib

    digest = hashlib.sha256(data).hexdigest()
    if digest != args.expect_sha256:
        print(f"audit-carriers REFUSED: sha256 {digest} != {args.expect_sha256}", file=sys.stderr)
        return 3
    symtab = bba.symbol_table(args.dso, args.timeout)

    record = {"dso": args.dso, "dso_sha256": digest, "carriers": {}, "refused": []}
    md = [
        "# PFP-3 exact-symbol carrier audit",
        "",
        f"DSO `{args.dso}` sha256 `{digest}`.",
        "",
        "| family | symbol (mangled) | extent | insns | jcc | cmov | setcc | div |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]

    for family, pattern, note in CARRIERS:
        rx = re.compile(pattern)
        hits = [(a, s, sym) for a, s, sym in symtab if rx.search(sym)]
        if len(hits) != 1:
            record["refused"].append(
                {"family": family, "reason": "not-unique", "matches": [s for _, _, s in hits]}
            )
            print(f"audit-carriers REFUSED {family}: {len(hits)} matches", file=sys.stderr)
            continue
        addr, size, sym = hits[0]
        if size == 0:
            record["refused"].append({"family": family, "reason": "zero-size", "symbol": sym})
            continue
        try:
            insns = bba.disassemble(args.dso, addr, addr + size, args.timeout)
        except bba.Refusal as exc:
            record["refused"].append(
                {"family": family, "reason": "tool", "detail": exc.message}
            )
            continue
        problem = bba.disassembly_problem(insns, addr, size)
        if problem is not None:
            record["refused"].append(
                {"family": family, "reason": problem, "symbol": sym}
            )
            continue

        counts = {"jcc": 0, "cmov": 0, "setcc": 0, "div": 0, "insns": len(insns)}
        jcc_rows, cmov_rows, setcc_rows = [], [], []
        for i, insn in enumerate(insns):
            if bba.base_mnem(insn.mnem) in {"div", "idiv"}:
                counts["div"] += 1
            if insn.mnem.startswith("cmov"):
                counts["cmov"] += 1
                src, _ = bba.cond_provenance(insns, i)
                cmov_rows.append({"addr": f"0x{insn.addr:x}", "off": f"+0x{insn.addr - addr:x}",
                                  "insn": insn.text, "src": src})
            elif insn.mnem.startswith("set"):
                counts["setcc"] += 1
                src, _ = bba.cond_provenance(insns, i)
                setcc_rows.append({"addr": f"0x{insn.addr:x}", "off": f"+0x{insn.addr - addr:x}",
                                   "insn": insn.text, "src": src})
            if not bba.is_jcc(insn):
                continue
            counts["jcc"] += 1
            src, setter = bba.cond_provenance(insns, i)
            guarded, _ = bba.guarded_window(insns, i)
            tgt = bba.target_of(insn)
            jcc_rows.append({
                "addr": f"0x{insn.addr:x}",
                "off": f"+0x{insn.addr - addr:x}",
                "jcc": insn.mnem,
                "src": src,
                "setter": "?" if setter is None else f"0x{setter.addr:x}: {setter.text}",
                "guarded": guarded,
                "target": "?" if tgt is None else f"0x{tgt:x}",
                "dir": "?" if tgt is None else ("back" if tgt < insn.addr else "fwd"),
            })
        record["carriers"][family] = {
            "symbol": sym,
            "addr": f"0x{addr:x}",
            "size": size,
            "note": note,
            "counts": counts,
            "jcc_rows": jcc_rows,
            "cmov_rows": cmov_rows,
            "setcc_rows": setcc_rows,
        }
        md.append(
            f"| {family} | `{sym}` | {size} | {counts['insns']} | {counts['jcc']} | "
            f"{counts['cmov']} | {counts['setcc']} | {counts['div']} |"
        )

    md += ["", "## jcc rows per carrier", ""]
    for family, c in record["carriers"].items():
        md += [f"### {family}", "", "```"]
        for r in c["jcc_rows"]:
            md.append(
                f"{r['off']:>9} {r['jcc']:<5} src={r['src']:<10} guarded={r['guarded']:<16} "
                f"dir={r['dir']:<4} target={r['target']}  [{r['setter']}]"
            )
        if c["cmov_rows"]:
            md.append("cmov:")
            for r in c["cmov_rows"]:
                md.append(f"{r['off']:>9} {r['insn']} src={r['src']}")
        if c["setcc_rows"]:
            md.append("setcc:")
            for r in c["setcc_rows"]:
                md.append(f"{r['off']:>9} {r['insn']} src={r['src']}")
        md += ["```", ""]

    Path(args.out_json).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    Path(args.out_md).write_text("\n".join(md) + "\n")

    if record["refused"]:
        print(f"audit-carriers REFUSED: {record['refused']}", file=sys.stderr)
        return 1
    total_j = sum(c["counts"]["jcc"] for c in record["carriers"].values())
    total_c = sum(c["counts"]["cmov"] for c in record["carriers"].values())
    total_s = sum(c["counts"]["setcc"] for c in record["carriers"].values())
    print(
        f"audit-carriers: {len(record['carriers'])} carriers resolved; "
        f"jcc={total_j} cmov={total_c} setcc={total_s}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
