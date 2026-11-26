#!/usr/bin/env python3
"""Write the PFP-2 DSO-bound differential record from the runner's raw files.

The runner has already refused on any identity mismatch, population shortfall
or serialised-point difference; this script turns the surviving evidence into
the machine record cited by the admission register.  It re-reads the raw files
and re-computes their digests, so the record cannot claim a PASS the files do
not support.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


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
    cross = parse_tsv(raw / "cross-verification.tsv")

    identity_ok = bool(identity) and all(
        row.get("status") == "ok"
        and row.get("reported_realpath") == row.get("expected_realpath")
        and row.get("reported_dev") == row.get("expected_dev")
        and row.get("reported_ino") == row.get("expected_ino")
        and row.get("reported_size") == row.get("expected_size")
        and int(row.get("maps_entries", "0")) >= 1
        for row in identity
    )

    count = int(meta["count"])
    sig_count = int(meta["sig_count"])
    cases = {}
    for row in comparisons:
        cases[row["mode"]] = {
            "compared_lines": int(row["compared_lines"]),
            "mismatches": int(row["mismatches"]),
            "candidate_output_sha256": row["candidate_output_sha256"],
            "authority_output_sha256": row["authority_output_sha256"],
            "expected_compared_lines": count,
        }
    cases_ok = (
        set(cases) == {"mul-g", "mul-p"}
        and all(item["compared_lines"] == count and item["mismatches"] == 0 for item in cases.values())
    )

    cross_ok = (
        len(cross) == 2
        and all(int(row["signed"]) == sig_count for row in cross)
        and all(int(row["verified"]) == sig_count for row in cross)
        and len({row["public_key"] for row in cross}) == 1
    )

    result = "PASS" if (identity_ok and cases_ok and cross_ok) else "FAIL"

    def raw_digest(name: str) -> str:
        return sha256_file(raw / name)

    document = {
        "schema": "openssl-rs/performance/pfp2-dso-differential/v1",
        "campaign": "PFP-2",
        "record_id": "PFP2-DSO-DIFFERENTIAL-83f67826",
        "result": result,
        "population": {
            "description": (
                "scalar multiplications and ECDSA sign/cross-verify through the "
                "exported libcrypto.so.3 ABI"
            ),
            "seed": meta["seed"],
            "case_counts": {
                "mul_g": count,
                "mul_p": count,
                "ecdsa_sign_cross_verify_per_direction": sig_count,
            },
            "derivation": (
                "scalar_for(seed, domain, i) is splitmix64 over "
                "(seed ^ domain ^ i*0x9e3779b97f4a7c15); the 32-byte big-endian "
                "result has its top bit cleared and low bit set, so it is in "
                "[1, 2^255) and therefore a non-zero P-256 scalar below n. "
                "mul-p draws j for P=j*G from domain BASE and k for k*P from "
                "domain SCALAR. ECDSA draws d from domain KEY and each message "
                "digest from domain MSG. The authority and candidate do not "
                "derive the values themselves; the harness supplies identical "
                "bytes to both."
            ),
            "domains": {
                "mul_g": "0x503246474d554c31",
                "base": "0x5032464742415331",
                "scalar": "0x5032464753434c31",
                "key": "0x503246474b455931",
                "message": "0x503246474d534731",
            },
        },
        "subjects": {
            "candidate": {
                "label": "distribution-shaped libcrypto.so.3 (PFP-2 post-fix)",
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
                "each process printed LOADED realpath/dev/ino/size for the file "
                "it mapped and LIB from dladdr(BN_new); the runner compared "
                "those fields with stat(2) on the expected on-disk DSO and "
                "required a /proc/self/maps entry"
            ),
            "rows": len(identity),
            "all_ok": identity_ok,
            "file": "raw/identity-check.tsv",
        },
        "instrument": {
            "source": "pfp2_dso_differential.c",
            "source_sha256": meta["instrument_source_sha256"],
            "binary_sha256": meta["instrument_binary_sha256"],
            "loader_pattern": (
                "dlopen(RTLD_NOW|RTLD_LOCAL), one libcrypto.so.3 per process, "
                "as courts/phase18/timing/bench_api.c"
            ),
            "operation_shape": (
                "k*G as in the campaign's ctgrind harness minimal_mul.c, widened "
                "to a fixed population; k*P for the variable-base court"
            ),
        },
        "cases": cases,
        "ecdsa": {
            "directions": cross,
            "signatures_per_direction": sig_count,
            "signatures_file_sha256": {
                "candidate": raw_digest("signatures-candidate.bin"),
                "authority": raw_digest("signatures-authority.bin"),
            },
            "public_key_agreement": cross_ok,
        },
        "raw_outputs": {
            name: raw_digest(name)
            for name in (
                "mul-g-candidate.out",
                "mul-g-authority.out",
                "mul-p-candidate.out",
                "mul-p-authority.out",
                "sign-candidate.out",
                "verify-authority.out",
                "sign-authority.out",
                "verify-candidate.out",
            )
        },
        "limitations": [
            "Internal field operations (p256::mont_reduce_into, p256::wide_mul_x86, "
            "bn::limbs::normalise) have no exported entry point and were not called "
            "directly; they are exercised only through EC_POINT_mul and ECDSA. No "
            "source-level test is substituted while claiming this court is DSO-bound.",
            "ECDSA signatures are not compared byte-for-byte because the nonces are "
            "random; the court compares acceptance in both directions, the derived "
            "public key and the message sequence.",
            "The candidate is the frozen distribution DSO; it was not rebuilt in this "
            "court. Its digest is checked before and after execution.",
            "This is a compatibility/correctness court. It is not a constant-time "
            "result and not a safety conclusion.",
        ],
    }

    args.out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"record: {args.out} result={result}")
    if result != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
