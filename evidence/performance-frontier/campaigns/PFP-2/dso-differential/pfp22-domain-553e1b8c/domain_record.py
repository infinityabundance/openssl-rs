#!/usr/bin/env python3
"""Write the PFP-22 domain-completion differential record from the runner's raw
files.

The runner has already refused on any identity mismatch, population shortfall,
serialised-point difference, base-population drift or changed DSO digest; this
script turns the surviving evidence into the machine record the admission
register cites.  It re-reads the raw files and re-computes their digests and
counts, so the record cannot claim a PASS the files do not support.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

# class, mode, seed, cases, group, derivation
POPULATION = [
    ("base-mul-g", "mul-g", "0x5046503250485032", 4096, "existing_seed_driven",
     "original scalar_for generator: uniform in [1, 2^255), k*G; byte-identical to the earlier differential"),
    ("base-mul-p", "mul-p", "0x5046503250485032", 4096, "existing_seed_driven",
     "original scalar_for generator: uniform in [1, 2^255), k*P with P=j*G from domain BASE"),
    ("upper-g", "upper-g", "0x5050463232555047", 4096, "domain_completion",
     "upper_half_for: uniform in [2^255, q-1] by rejection, k*G"),
    ("upper-p", "upper-p", "0x5050463232555050", 4096, "domain_completion",
     "upper_half_for: uniform in [2^255, q-1] by rejection, k*P with P=j*G"),
    ("boundary-g", "boundary-g", "0x5050463232424f47", 8, "domain_completion",
     "fixed scalars 1, 2, q-2, q-1, q, q+1, 2q-1 (33 bytes), 2^256-1 as k*G; acceptance/rejection compared"),
    ("boundary-p", "boundary-p", "0x5050463232424f50", 8, "domain_completion",
     "the same fixed scalars as k*P with P=j*G; acceptance/rejection compared"),
    ("exceptional", "exceptional", "0x5050463232455845", 10, "domain_completion",
     "zero scalar (all-zero limbs) on G and P; 2^256-1 on G and P; infinity base with k=5 and k=0; "
     "generator and non-generator base with k=7; oct2point(generator) then 7*decoded; off-curve (0,0) "
     "decode rejection"),
    ("limb-g", "limb-g", "0x50504632324c4d47", 12, "domain_completion",
     "one non-zero 64-bit limb in each of the four positions (value 1 and 0xffffffffffffffff), "
     "and four values with the most-significant limb zero, as k*G"),
    ("limb-p", "limb-p", "0x50504632324c4d50", 12, "domain_completion",
     "the same twelve scalars as k*P with P=j*G"),
]
EXPECTED = {name: (mode, seed, cases, group, derivation)
            for name, mode, seed, cases, group, derivation in POPULATION}
TOTAL_CASES = sum(cases for _, _, _, cases, _, _ in POPULATION)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        key, _, value = line.partition("=")
        values[key] = value
    return values


def parse_tsv(path: Path) -> list[dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return []
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:] if line]


def count_points(path: Path) -> int:
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines()
               if line.startswith("POINT "))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    out = args.dir
    raw = out / "raw"
    meta = parse_env(raw / "run-meta.env")
    identity = parse_tsv(raw / "identity-check.tsv")
    comparisons = parse_tsv(raw / "comparison.tsv")

    identity_ok = bool(identity) and all(
        row.get("status") == "ok"
        and row.get("reported_realpath") == row.get("expected_realpath")
        and row.get("reported_dev") == row.get("expected_dev")
        and row.get("reported_ino") == row.get("expected_ino")
        and row.get("reported_size") == row.get("expected_size")
        and int(row.get("maps_entries", "0")) >= 1
        for row in identity
    )

    by_class = {row["class"]: row for row in comparisons}
    cases: dict[str, dict] = {}
    problems: list[str] = []

    if set(by_class) != set(EXPECTED):
        problems.append(
            f"class set {sorted(by_class)} != expected {sorted(EXPECTED)}")

    for name, (mode, seed, expected_cases, group, derivation) in EXPECTED.items():
        row = by_class.get(name)
        if row is None:
            problems.append(f"{name}: no comparison row")
            continue
        cand_points = raw / f"{name}-candidate.points"
        auth_points = raw / f"{name}-authority.points"
        cand_sha = sha256_file(cand_points)
        auth_sha = sha256_file(auth_points)
        cand_count = count_points(cand_points)
        auth_count = count_points(auth_points)
        if row["mode"] != mode or row["seed"] != seed:
            problems.append(f"{name}: mode/seed {row['mode']}/{row['seed']} != {mode}/{seed}")
        if int(row["compared_lines"]) != expected_cases or int(row["expected_cases"]) != expected_cases:
            problems.append(f"{name}: compared {row['compared_lines']} / expected {row['expected_cases']} != {expected_cases}")
        if int(row["mismatches"]) != 0:
            problems.append(f"{name}: {row['mismatches']} mismatches")
        if cand_count != expected_cases or auth_count != expected_cases:
            problems.append(f"{name}: point counts {cand_count}/{auth_count} != {expected_cases}")
        if cand_sha != auth_sha:
            problems.append(f"{name}: candidate/authority points differ")
        if row["candidate_output_sha256"] != cand_sha or row["authority_output_sha256"] != auth_sha:
            problems.append(f"{name}: recorded digests do not match the raw points files")
        cases[name] = {
            "class_group": group,
            "mode": mode,
            "seed": seed,
            "derivation": derivation,
            "compared_lines": cand_count,
            "expected_cases": expected_cases,
            "mismatches": 0 if cand_sha == auth_sha and cand_count == expected_cases else max(1, abs(cand_count - expected_cases)),
            "candidate_output_sha256": cand_sha,
            "authority_output_sha256": auth_sha,
        }

    comparability_ok = (
        cases.get("base-mul-g", {}).get("candidate_output_sha256") == meta.get("historical_mul_g_sha256")
        and cases.get("base-mul-p", {}).get("candidate_output_sha256") == meta.get("historical_mul_p_sha256")
    )
    if not comparability_ok:
        problems.append("the original 4096+4096 population did not reproduce its historical digests")

    result = "PASS" if (identity_ok and comparability_ok and not problems) else "FAIL"

    document = {
        "schema": "openssl-rs/performance/pfp22-domain-differential/v1",
        "campaign": "PFP-2",
        "record_id": "PFP2-DOMAIN-DIFFERENTIAL-553E1B8C",
        "result": result,
        "problems": problems,
        "subjects": {
            "candidate": {
                "label": "distribution-shaped libcrypto.so.3 at the PFP-20 candidate (P-256 engine, branchless write-back trim)",
                "path": meta["candidate_path"],
                "sha256": meta["candidate_sha256"],
            },
            "authority": {
                "label": "OpenSSL 3.6.4 production authority",
                "path": meta["authority_path"],
                "sha256": meta["authority_sha256"],
            },
        },
        "identity_proof": {
            "method": (
                "each process printed LOADED realpath/dev/ino/size for the file it mapped and LIB "
                "from dladdr(BN_new); the runner compared those fields with stat(2) on the expected "
                "on-disk DSO and required a /proc/self/maps entry"
            ),
            "rows": len(identity),
            "all_ok": identity_ok,
            "file": "raw/identity-check.tsv",
        },
        "instrument": {
            "source": "pfp22_domain_differential.c",
            "source_sha256": meta["instrument_source_sha256"],
            "binary_sha256": meta["instrument_binary_sha256"],
            "loader_pattern": (
                "dlopen(RTLD_NOW|RTLD_LOCAL), one libcrypto.so.3 per process; LOADED/MAPS/LIB "
                "checked against stat(2), unchanged from pfp2_dso_differential.c"
            ),
            "instrument_note": (
                "The loader, identity proof and serialised-point comparison are the PFP-2 court "
                "instrument (pfp2_dso_differential.c, sha256 "
                "fd67b943889ab710af9f3c246e3119c2f28561dc6a47084ee96f5a5d5f64affc). Only the "
                "population generator was extended; the original mul-g/mul-p modes reproduce the "
                "original bytes and line format."
            ),
            "serialisation": (
                "EC_POINT_point2oct(POINT_CONVERSION_UNCOMPRESSED); the original modes require 65 "
                "bytes, the population classes record the actual SEC1 length so the point at infinity "
                "(one 0x00 byte) is compared rather than treated as a failure"
            ),
        },
        "population": {
            "total_cases_per_subject": TOTAL_CASES,
            "classes": [
                {
                    "class": name,
                    "mode": mode,
                    "seed": seed,
                    "cases": cases_count,
                    "class_group": group,
                    "derivation": derivation,
                }
                for name, mode, seed, cases_count, group, derivation in POPULATION
            ],
        },
        "cases": cases,
        "comparability": {
            "historical_mul_g_sha256": meta.get("historical_mul_g_sha256"),
            "historical_mul_p_sha256": meta.get("historical_mul_p_sha256"),
            "reproduced": comparability_ok,
            "note": (
                "the original 4096 k*G and 4096 k*P population, at seed 0x5046503250485032, "
                "reproduces the digests recorded at the same two DSOs in "
                "dso-differential-pfp20/raw, so the added classes did not change the comparable population"
            ),
        },
        "raw_outputs": {
            f"{name}-{subject}.points": sha256_file(raw / f"{name}-{subject}.points")
            for name, _, _, _, _, _ in POPULATION
            for subject in ("candidate", "authority")
        },
        "limitations": [
            "Internal field operations (p256::mont_reduce_into, p256::wide_mul_x86, "
            "limbs::normalise_branchless) have no exported entry point and were not called directly; "
            "they are exercised only through EC_POINT_mul and EC_POINT_oct2point. No source-level test "
            "is substituted while this court is called DSO-bound.",
            "P-256 has prime group order n, so it has no non-trivial small-order point; the only "
            "order-1 point is infinity, exercised as an input base and as a result.",
            "2q-1 does not fit in 32 bytes and is supplied to EC_POINT_mul as a 33-byte BIGNUM; the "
            "API accepts arbitrary-precision scalars and does not reject out-of-range values, so "
            "agreement is on the computed result, and the only rejection compared is an off-curve "
            "point decode.",
            "The candidate is the frozen distribution DSO; it was not rebuilt in this court. Its "
            "digest is checked before and after execution.",
            "This is a compatibility/correctness court. It is not a constant-time result and not a "
            "safety conclusion.",
        ],
    }

    args.out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"record: {args.out} result={result} cases={TOTAL_CASES}")
    for problem in problems:
        print(f"  PROBLEM: {problem}")
    if result != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
