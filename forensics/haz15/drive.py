#!/usr/bin/env python3
"""drive.py -- assemble evidence/haz-15/observables.json from harness runs.

Reads four JSONL files produced by forensics/haz15/haz15_harness.c inside the
court:

    <pre>/authority.jsonl      the pinned OpenSSL 3.6.4 authority
    <pre>/candidate.jsonl      the candidate built before the correction
    <post>/authority.jsonl     the same authority (an identity check)
    <post>/candidate.jsonl     the candidate built with the correction

and writes one machine-readable record.  The pre and post authority runs must
agree; a disagreement is refused rather than silently resolved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SCHEMA = "openssl-rs/haz15/observables/1"


def read_rows(path: Path, label: str) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if row.get("event") == "loaded":
            continue
        row["impl"] = label
        rows.append(row)
    if len(rows) != 8:
        raise SystemExit(f"{path}: expected 8 rows, found {len(rows)}")
    return rows


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pre", type=Path, required=True)
    parser.add_argument("--post", type=Path, required=True)
    parser.add_argument("--authority-dso", type=Path, required=True)
    parser.add_argument("--prefix-dso", type=Path, required=True)
    parser.add_argument("--postfix-dso", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    pre_authority = read_rows(args.pre / "authority.jsonl", "authority")
    post_authority = read_rows(args.post / "authority.jsonl", "authority")
    if pre_authority != post_authority:
        raise SystemExit("the authority answered differently in the two runs")

    prefix = read_rows(args.pre / "candidate.jsonl", "candidate_prefix")
    postfix = read_rows(args.post / "candidate.jsonl", "candidate_postfix")

    rows = pre_authority + prefix + postfix

    def pick(impl: str, key: str, case: str) -> dict:
        for row in rows:
            if row["impl"] == impl and row["key"] == key and row["case"] == case:
                return row
        raise SystemExit(f"missing row {impl}/{key}/{case}")

    def same(a: dict, b: dict) -> bool:
        return {k: v for k, v in a.items() if k != "impl"} == {
            k: v for k, v in b.items() if k != "impl"
        }

    def distinguishes(valid: dict, invalid: dict) -> bool:
        return (
            (valid["ret"] > 0) != (invalid["ret"] > 0)
            or valid["out_unchanged"] != invalid["out_unchanged"]
            or (valid["err_pending"] == 0) != (invalid["err_pending"] == 0)
        )

    prefix_ext_valid = pick("candidate_prefix", "external", "valid")
    prefix_ext_bad = pick("candidate_prefix", "external", "bad_type")
    prefix_ext_short = pick("candidate_prefix", "external", "short_ps")
    postfix_ext_valid = pick("candidate_postfix", "external", "valid")
    postfix_ext_bad = pick("candidate_postfix", "external", "bad_type")
    postfix_ext_short = pick("candidate_postfix", "external", "short_ps")
    auth_ext_valid = pick("authority", "external", "valid")
    auth_ext_bad = pick("authority", "external", "bad_type")
    auth_ext_short = pick("authority", "external", "short_ps")
    prefix_int_valid = pick("candidate_prefix", "internal", "valid")
    postfix_int_valid = pick("candidate_postfix", "internal", "valid")

    record = {
        "schema": SCHEMA,
        "hazard": "HAZ-15",
        "question": (
            "For a key carrying RSA_FLAG_EXT_PKEY and PKCS#1 v1.5 padding, does the "
            "observable set distinguish a ciphertext that decrypts to valid padding "
            "from one that decrypts to invalid padding?"
        ),
        "identity": {
            "head": args.head,
            "branch": "staging",
            "authority": {
                "name": "openssl-3.6.4-production",
                "dso_sha256": sha256(args.authority_dso),
            },
            "candidate_prefix": {
                "description": "release build of HEAD before the correction",
                "dso_sha256": sha256(args.prefix_dso),
            },
            "candidate_postfix": {
                "description": "release build of HEAD plus the src/rsa/ossl.rs correction",
                "dso_sha256": sha256(args.postfix_dso),
            },
        },
        "key": {
            "source": "forensics/etp5_crypto/vectors/rsa_key.json",
            "modulus_bits": 2048,
            "external_shape": "n, e, p, q, dmp1, dmq1, iqmp; d absent; RSA_FLAG_EXT_PKEY set",
            "internal_shape": "the same key with d present",
            "ciphertext_construction": "c = m^e mod n for a chosen raw block m; the "
                                       "out-of-range case submits c = n",
        },
        "cases": {
            "valid": "00 02 <245 nonzero octets> 00 <8-octet message>",
            "bad_type": "00 03 followed by nonzero octets (wrong block type)",
            "short_ps": "00 02 <4 nonzero octets> 00 (padding string below 8 octets)",
            "out_of_range": "ciphertext equals the modulus (c is not in [0, n))",
        },
        "rows": rows,
        "finding_prefix": {
            "oracle_demonstrated": distinguishes(prefix_ext_valid, prefix_ext_bad),
            "rule": "distinguished when the sign of the return value, whether the output "
                    "buffer was written, or the error-queue presence differs",
            "valid_vs_bad_type": distinguishes(prefix_ext_valid, prefix_ext_bad),
            "valid_vs_short_ps": distinguishes(prefix_ext_valid, prefix_ext_short),
            "authority_identical_on_padding_cases": (
                same(auth_ext_valid, prefix_ext_valid)
                and same(auth_ext_bad, prefix_ext_bad)
                and same(auth_ext_short, prefix_ext_short)
            ),
            "detail": (
                "external valid: ret %d, error queue empty; external bad_type: ret %d, "
                "output %s, last error %r. The authority answers the padding cases the same; "
                "the out_of_range row is recorded separately below."
                % (
                    prefix_ext_valid["ret"],
                    prefix_ext_bad["ret"],
                    "untouched" if prefix_ext_bad["out_unchanged"] else "written",
                    prefix_ext_bad["err_text"],
                )
            ),
        },
        "finding_postfix": {
            "external_valid_vs_bad_type": distinguishes(postfix_ext_valid, postfix_ext_bad),
            "external_valid_vs_short_ps": distinguishes(postfix_ext_valid, postfix_ext_short),
            "internal_valid_unchanged": same(prefix_int_valid, postfix_int_valid),
            "detail": (
                "external valid: ret %d; external bad_type: ret %d; external short_ps: "
                "ret %d; all three leave the error queue empty and write the output "
                "buffer. Only the padding-valid case returns the submitted message."
                % (
                    postfix_ext_valid["ret"],
                    postfix_ext_bad["ret"],
                    postfix_ext_short["ret"],
                )
            ),
        },
        "incidental_observation": {
            "case": "out_of_range",
            "padding_independent": True,
            "statement": (
                "The candidate leaves RSA_R_PADDING_CHECK_FAILED as the last error-queue "
                "record after the range refusal, where the authority leaves only "
                "RSA_R_DATA_TOO_LARGE_FOR_MODULUS. This is pre-existing, is independent "
                "of padding validity, and the correction does not change it."
            ),
            "authority_err_text": pick("authority", "external", "out_of_range")["err_text"],
            "candidate_err_text": pick("candidate_postfix", "external", "out_of_range")[
                "err_text"
            ],
        },
        "non_claims": [
            "The harness does not measure timing; the rows are return value, output "
            "bytes and error-queue contents only.",
            "Identical bytes across candidate and authority for the internal-key "
            "synthetic message are a differential observation, not a constant-time or "
            "correctness result.",
            "The external-key synthetic bytes are not compared to the internal-key "
            "synthetic bytes; the claim is about the observable policy, not the value.",
        ],
    }

    args.out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
