#!/usr/bin/env python3
"""Refuse a trend comparison between benchmark rows whose workload identities differ.

The problem this exists for
----------------------------
`PFP-11` reports P-256 at **13.040x** for **sign + verify** (verification is
inside the timed loop); `M-A1` reports **10.2012x** for **sign only**.  Both are
labelled `ecdsa256` and were placed side by side in review.  A name is not an
identity, so the fix is data:

    "workload_identity": {
        "workload_id": "ecdsa256",
        "timed_operations": ["ECDSA_do_sign", "ECDSA_do_verify"]
    }

`forensics/performance/WORKLOADS.json` declares the rule
(`workload_identity_schema`) and the PFP-0 population's `timed_operations`.
Campaign rows that time a different operation set carry their own block; the
`workload_id` remains a label and is **not** load-bearing.

Two rows are comparable only when both `workload_id` and `timed_operations`
are identical.  Otherwise the tool refuses with the specific code
`BENCH_TREND_IDENTITY_MISMATCH` and exits 1.

Usage
-----
    python3 forensics/tools/benchmark_trend.py \
        --first  evidence/performance-frontier/campaigns/M-A1/timing/raw/timing-summary.json \
        --first-row /workloads/ecdsa256 \
        --second evidence/performance-frontier/campaigns/PFP-11/raw/phase2-three-arm.json \
        --second-row /p256/ecdsa256

`--first-row` / `--second-row` are JSON pointers (RFC 6901) into the document;
omit them when the file is a single row record.

Exit codes
----------
  0  the identities match and the comparison is emitted
  1  refused (identity mismatch, absent or malformed identity)
  2  usage or IO error

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REGISTRY_SCHEMA = "openssl-rs/performance/workloads/v1"
IDENTITY_FIELD = "workload_identity"
OPERATIONS_FIELD = "timed_operations"
ID_FIELD = "workload_id"

BENCH_TREND_IDENTITY_MISMATCH = "BENCH_TREND_IDENTITY_MISMATCH"
BENCH_TREND_IDENTITY_ABSENT = "BENCH_TREND_IDENTITY_ABSENT"
BENCH_TREND_IDENTITY_MALFORMED = "BENCH_TREND_IDENTITY_MALFORMED"
BENCH_TREND_ROW_ABSENT = "BENCH_TREND_ROW_ABSENT"


class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def resolve_pointer(document: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 JSON pointer; `""` returns the document."""
    if pointer in ("", "/"):
        return document
    if not pointer.startswith("/"):
        raise Refusal(BENCH_TREND_ROW_ABSENT, f"not a JSON pointer: {pointer!r}")
    node = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            try:
                node = node[int(token)]
            except (ValueError, IndexError):
                raise Refusal(BENCH_TREND_ROW_ABSENT, f"pointer {pointer!r}: no index {token!r}")
        elif isinstance(node, dict) and token in node:
            node = node[token]
        else:
            raise Refusal(BENCH_TREND_ROW_ABSENT, f"pointer {pointer!r}: no member {token!r}")
    return node


def identity_of(row: Any, label: str) -> dict[str, Any]:
    """Validate and canonicalise a row's workload identity.

    The identity is the *operations list*, not the row's name.  A row that
    carries no block is refused rather than inferred from a sibling.
    """
    if not isinstance(row, dict):
        raise Refusal(BENCH_TREND_IDENTITY_ABSENT, f"{label}: row is not an object")
    block = row.get(IDENTITY_FIELD)
    if not isinstance(block, dict):
        raise Refusal(
            BENCH_TREND_IDENTITY_ABSENT,
            f"{label}: no {IDENTITY_FIELD!r} block",
        )
    workload_id = block.get(ID_FIELD)
    operations = block.get(OPERATIONS_FIELD)
    if not isinstance(workload_id, str) or not workload_id:
        raise Refusal(BENCH_TREND_IDENTITY_MALFORMED, f"{label}: {ID_FIELD!r} must be a non-empty string")
    if (
        not isinstance(operations, list)
        or not operations
        or not all(isinstance(op, str) and op for op in operations)
    ):
        raise Refusal(
            BENCH_TREND_IDENTITY_MALFORMED,
            f"{label}: {OPERATIONS_FIELD!r} must be a non-empty list of operation names",
        )
    return {
        "workload_id": workload_id,
        "timed_operations": list(operations),
    }


def compare(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    """Refuse unless both workload id and the timed operation list are equal."""
    a = identity_of(first, "first")
    b = identity_of(second, "second")
    if a[ID_FIELD] != b[ID_FIELD] or a[OPERATIONS_FIELD] != b[OPERATIONS_FIELD]:
        raise Refusal(
            BENCH_TREND_IDENTITY_MISMATCH,
            "workload identities differ: "
            f"first={{id={a[ID_FIELD]!r}, timed_operations={a[OPERATIONS_FIELD]!r}}} "
            f"second={{id={b[ID_FIELD]!r}, timed_operations={b[OPERATIONS_FIELD]!r}}}",
        )
    return {
        "schema": REGISTRY_SCHEMA,
        "comparable": True,
        "workload_id": a[ID_FIELD],
        "timed_operations": a[OPERATIONS_FIELD],
    }


def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--first", required=True, help="first benchmark record (JSON)")
    ap.add_argument("--first-row", default="", help="RFC 6901 pointer to the first row")
    ap.add_argument("--second", required=True, help="second benchmark record (JSON)")
    ap.add_argument("--second-row", default="", help="RFC 6901 pointer to the second row")
    args = ap.parse_args(argv)

    try:
        first_row = resolve_pointer(_load(args.first), args.first_row)
        second_row = resolve_pointer(_load(args.second), args.second_row)
        result = compare(first_row, second_row)
    except Refusal as refusal:
        print(f"BENCH_TREND_REFUSED code={refusal.code} detail={refusal.detail}")
        return 1
    except OSError as exc:
        print(f"BENCH_TREND_IO_ERROR detail={exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
