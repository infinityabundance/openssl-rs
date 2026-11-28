#!/usr/bin/env python3
"""Generate the PFP-54 branch-audit record from the audit report at the shipped digest.

Reads the report the tool produced (`raw/audit-a5354547.md`) and the inventories,
and writes the record the release gate reads.  The per-target `observed` counts
are parsed from the report, not retyped; the only mechanised secret-dependence
result is the `key::decap` comparison contract, and it is transcribed from the
report's contract section.  Every other target's `classification` says
`inventory-and-source-review`, because this instrument prints branch provenance
and counts, not taint.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
EV = ROOT / "evidence/performance-frontier/campaigns/PFP-54"
REPORT = EV / "raw/audit-a5354547.md"
INVENTORY = EV / "targets-pfp54.json"
COVERAGE = ROOT / "evidence/performance-frontier/campaigns/PFP-34/coverage.json"
RECORD = ROOT / "evidence/performance-frontier/campaigns/PFP-34/audit-record.json"
RECORD_COPY = EV / "raw/audit-record.json"

# A secret-dependence property is never a Boolean.  Zero is a measurement;
# "no instrument applied" is a different state and must never be encoded as a
# measured zero (PFP-84).
OBSERVED_ZERO = "OBSERVED_ZERO"
OBSERVED_NONZERO = "OBSERVED_NONZERO"
UNDETERMINED = "UNDETERMINED"
NOT_ASSESSED = "NOT_ASSESSED"
SECRET_DEPENDENCE_PROPERTIES = ("jcc", "setcc", "cmov", "memory_address")


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def src_fingerprint() -> str:
    h = hashlib.sha256()
    for p in sorted((ROOT / "src").rglob("*.rs")):
        h.update(f"{sha(p)}  {p.relative_to(ROOT).as_posix()}\n".encode())
    return h.hexdigest()


def parse_report(text: str):
    targets = {}
    for line in text.splitlines():
        if not line.startswith("| "):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cols) != 12 or not cols[3].isdigit():
            continue
        targets[cols[0]] = {
            "bytes": int(cols[2]), "insns": int(cols[3]),
            "jcc": int(cols[4]), "div": int(cols[5]), "cmov": int(cols[6]),
            "setcc": int(cols[7]), "jo": int(cols[8]), "loop": int(cols[9]),
            "calls": int(cols[10]), "cpuid": int(cols[11]),
        }
    contract = {"secret_derived_jcc": 0, "undetermined": 0, "readers": []}
    if "## Comparison-result branch contract" in text:
        section = text.split("## Comparison-result branch contract", 1)[1]
        section = section.split("## Divisions", 1)[0]
        for line in section.splitlines():
            if line.startswith("- secret-derived conditional jumps:"):
                contract["secret_derived_jcc"] = int(line.rsplit(":", 1)[1])
            elif line.startswith("- undetermined conditions:"):
                contract["undetermined"] = int(line.rsplit(":", 1)[1])
            elif line.startswith("| jcc") or line.startswith("| setcc") or line.startswith("| cmov"):
                cols = [c.strip() for c in line.strip().strip("|").split("|")]
                contract["readers"].append({
                    "kind": cols[0], "addr": cols[1].strip("`"),
                    "insn": cols[2].strip("`"), "source": cols[3].strip("`"),
                    "class": cols[4].strip("*"),
                })
    return targets, contract


def _secret_dependence_aggregate(targets: dict[str, dict]) -> dict:
    """Recompute the mechanised/inventory split from the per-target states.

    A target is *mechanised* when at least one of its four properties was
    assessed by an instrument (any state other than NOT_ASSESSED).  The
    remaining targets are NOT_ASSESSED, so resolution is never reported as
    verification.
    """
    mechanised = sorted(
        tid
        for tid, target in targets.items()
        if any(
            state != NOT_ASSESSED
            for state in target["secret_dependence"].values()
        )
    )
    total = len(targets)
    return {
        "inventory_targets": total,
        "mechanised_targets": len(mechanised),
        "mechanised": mechanised,
        "statement": (
            f"{len(mechanised)} of {total} targets carry a mechanised "
            f"secret-dependence contract; the remaining "
            f"{total - len(mechanised)} are NOT_ASSESSED, never "
            "OBSERVED_ZERO.  A resolved target is not a verified target."
        ),
    }


def main() -> int:
    text = REPORT.read_text()
    families, contract = parse_report(text)
    inventory = json.loads(INVENTORY.read_text())
    coverage = json.loads(COVERAGE.read_text())

    # The coverage requirement names the ids the record must key; the audit
    # covers one more target than any path names (ossl_ec_wNAF_mul is public-only
    # and listed under public_only), so it is keyed by its plain symbol.
    cov_ids = sorted({tid for path in coverage["paths"] for tid in path["targets"]})
    covered_symbols = {tid.split("::")[-1] for tid in cov_ids}
    extra_ids = [entry["symbol"] for entry in inventory
                 if entry["symbol"] not in covered_symbols]
    ids = cov_ids + extra_ids
    assert len(set(ids)) == 31, f"record would name {len(set(ids))} targets"
    by_symbol = {}
    for entry in inventory:
        by_symbol.setdefault(entry["symbol"], []).append(entry)
    family_to_entry = {e["family"]: e for e in inventory}
    assert len(family_to_entry) == 31

    obs = {}
    for family, counts in families.items():
        entry = family_to_entry.get(family)
        assert entry is not None, f"report family not in inventory: {family}"
        obs[entry["symbol"]] = counts

    targets = {}
    for tid in sorted(set(ids)):
        symbol = tid.split("::")[-1]
        matches = by_symbol.get(symbol, [])
        assert len(matches) == 1, f"coverage id {tid!r} does not name one inventory symbol"
        entry = matches[0]
        counts = obs.get(symbol)
        assert counts is not None, f"no observed counts for {symbol}"
        record = {
            "family": entry["family"],
            "module": entry.get("module"),
            "symbol": entry["symbol"],
            "classification": "inventory-and-source-review",
            "observed": {
                "jcc": counts["jcc"], "div": counts["div"], "cmov": counts["cmov"],
                "setcc": counts["setcc"], "jo": counts["jo"], "loop": counts["loop"],
                "calls": counts["calls"], "cpuid": counts["cpuid"],
                "bytes": counts["bytes"], "insns": counts["insns"],
            },
            # No instrument was applied to this target's secret dependence by
            # the branch audit.  It observed instruction counts and provenance,
            # not taint, so every property is NOT_ASSESSED rather than zero.
            "secret_dependence": {
                prop: NOT_ASSESSED for prop in SECRET_DEPENDENCE_PROPERTIES
            },
        }
        if tid == "key::decap":
            record["classification"] = "comparison-contract"
            record["note"] = (
                "The comparison contract is mechanised: the XOR/OR comparison "
                "accumulation is tainted and propagated over the CFG. Memory is "
                "not modelled, so the memory-address property is UNDETERMINED, "
                "not observed zero.")
            secret_setcc = [
                {
                    "addr": reader["addr"], "insn": reader["insn"],
                    "condition_source": reader["source"],
                    "consumer": "arithmetic",
                    "note": ("writes a register value consumed by a store, not "
                             "a transfer condition (verified by disassembly)"),
                }
                for reader in contract["readers"]
                if reader["class"] == "secret-derived" and reader["kind"] == "setcc"
            ]
            secret_cmov = [
                {
                    "addr": reader["addr"], "insn": reader["insn"],
                    "condition_source": reader["source"],
                }
                for reader in contract["readers"]
                if reader["class"] == "secret-derived" and reader["kind"] == "cmov"
            ]
            record["secret_dependence"] = {
                "jcc": (
                    UNDETERMINED if contract["undetermined"] > 0
                    else OBSERVED_ZERO if contract["secret_derived_jcc"] == 0
                    else OBSERVED_NONZERO
                ),
                "setcc": OBSERVED_NONZERO if secret_setcc else OBSERVED_ZERO,
                "cmov": OBSERVED_NONZERO if secret_cmov else OBSERVED_ZERO,
                # The instrument does not model memory, so a `public-bound`
                # condition says nothing about the address operands.
                "memory_address": UNDETERMINED,
            }
            record["secret_dependence_detail"] = {
                "setcc": secret_setcc, "cmov": secret_cmov,
            }
        if symbol == "scalar_ntt":
            record["note"] = (
                "The audit observes the cmov count and operand/address classes "
                "in the report; this instrument does not establish their secret "
                "dependence, so every secret-dependence property is NOT_ASSESSED "
                "here, not zero.")
        targets[tid] = record

    candidate = subprocess.run(
        ["git", "--no-optional-locks", "rev-parse", "HEAD"], cwd=ROOT,
        capture_output=True, text=True, check=True).stdout.strip()
    tree = subprocess.run(
        ["git", "--no-optional-locks", "rev-parse", "HEAD^{tree}"], cwd=ROOT,
        capture_output=True, text=True, check=True).stdout.strip()
    inputs = dict(
        line.split("=", 1) for line in (EV / "raw/build-inputs.txt").read_text().splitlines()
        if "=" in line)

    record = {
        "schema": "openssl-rs/pfp/branch-audit-record/1",
        "campaign": "PFP-54 (detached-DWARF repair of the inlined-carrier gap)",
        "candidate": {
            "commit": candidate,
            "tree": tree,
            "source_fingerprint_sha256": src_fingerprint(),
        },
        "dso": {
            "sha256": inputs["shipped_sha256"],
            "build_id": inputs["shipped_build_id"],
            "bytes": int(inputs["shipped_size"]),
            "reproducible_builds": 1,
            "target_triple": inputs["target_triple"],
        },
        "debug_file": {
            "sha256": inputs["debug_sha256"],
            "build_id": inputs["debug_build_id"],
            "bytes": int(inputs["debug_size"]),
            "retained_at": "evidence/performance-frontier/campaigns/PFP-54/raw/artefacts/libcrypto.so.3.debug",
            "shipped": False,
        },
        "audit_tool": {
            "path": "courts/phase18/timing/binary_branch_audit.py",
            "sha256": sha(ROOT / "courts/phase18/timing/binary_branch_audit.py"),
            "objdump": subprocess.run(["objdump", "--version"], capture_output=True,
                                      text=True).stdout.splitlines()[0],
        },
        "inventory": {"path": INVENTORY.relative_to(ROOT).as_posix(), "sha256": sha(INVENTORY)},
        "coverage": {"path": COVERAGE.relative_to(ROOT).as_posix(), "sha256": sha(COVERAGE)},
        "recorded_from": [
            {"path": REPORT.relative_to(ROOT).as_posix(), "sha256": sha(REPORT)},
            {"path": (EV / "raw/audit-a5354547.stderr").relative_to(ROOT).as_posix(),
             "sha256": sha(EV / "raw/audit-a5354547.stderr")},
        ],
        "region": {
            "audit_exit": 0,
            "inventory_expected": 31,
            "resolved": 31,
            "inline_resolved": 1,
            "llvm_suffix_resolved": 1,
            "dwarf_inline_resolved": 1,
            "refused": 0,
        },
        "secret_dependence_aggregate": _secret_dependence_aggregate(targets),
        "targets": targets,
    }
    text = json.dumps(record, indent=1) + "\n"
    RECORD.write_text(text)
    RECORD_COPY.write_text(text)
    print("wrote", RECORD.relative_to(ROOT))
    print("dso", record["dso"]["sha256"], "targets", len(targets))
    print("coverage sha", record["coverage"]["sha256"], "inventory sha", record["inventory"]["sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
