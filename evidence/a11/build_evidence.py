#!/usr/bin/env python3
"""Produce evidence/a11 deterministically: the scan, the differential, the controls.

Every number and digest is read from bytes or produced by the tool; nothing is
typed.  Re-running with the same inputs reproduces the same files.

Usage
-----
    python3 evidence/a11/build_evidence.py
    python3 evidence/a11/build_evidence.py --out /tmp/a11a --source-commit f1c1a535d

The default output is ``evidence/a11``.  The source identity is supplied; it is
never read from a live ``HEAD``.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import harden as h  # noqa: E402

BASE_COMMIT = "f1c1a535d"
EVIDENCE = REPO_ROOT / "evidence" / "a11"
TOOL_RELATIVE = "forensics/tools/harden.py"

SCAN_SCHEMA = "openssl-rs/a11/scan/2"
DIFFERENTIAL_SCHEMA = "openssl-rs/a11/differential/1"
CONTROLS_SCHEMA = "openssl-rs/a11/controls/1"

SCAN_RECORD = EVIDENCE / "SCAN.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tool_identity() -> dict[str, object]:
    raw = (REPO_ROOT / TOOL_RELATIVE).read_bytes()
    return {"path": TOOL_RELATIVE, "sha256": sha256_bytes(raw), "bytes": len(raw)}


def write_json(path: Path, document: dict) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------


def _seed_members() -> list[dict]:
    """The frozen population, read from the record and never from a live glob.

    The record is the declared candidate.  Once it carries ``population.members``
    those exact members are reused.  On the correction run that replaced the old
    live-glob record, the population is named only by ``results``; those paths are
    the population declared at the candidate, so they seed the frozen members and
    every digest they already carried is checked against the bytes now.
    """
    if not SCAN_RECORD.is_file():
        raise SystemExit(
            f"{SCAN_RECORD.relative_to(REPO_ROOT)} is the declared population and is "
            "missing; a live glob is not a substitute"
        )
    document = json.loads(SCAN_RECORD.read_text(encoding="utf-8"))
    population = document.get("population", {})
    members = population.get("members")
    if population.get("binding") == h.POPULATION_FROZEN and isinstance(members, list):
        return members
    results = document.get("results")
    if not isinstance(results, list) or not results:
        raise SystemExit(
            f"{SCAN_RECORD.relative_to(REPO_ROOT)} names no population to freeze"
        )
    frozen = h.freeze_population(row["path"] for row in results)
    by_path = {member["path"]: member for member in frozen}
    for row in results:
        recorded = row.get("sha256")
        if recorded is not None and by_path[row["path"]]["sha256"] != recorded:
            raise SystemExit(
                f"population member changed since it was declared: {row['path']}"
            )
    return frozen


def build_scan(source_commit: str) -> dict:
    members = _seed_members()
    result = h.scan_frozen_population(members)
    if result["files"] != len(members):
        raise AssertionError("the scan did not account for every population member")
    for row in result["results"]:
        if row["result"] not in ("STRICT_OK", "SKIPPED_SIZE"):
            raise AssertionError(
                f"a tracked evidence record is refused: {row['path']} {row['result']}"
            )
    if result["refused"] != 0:
        raise AssertionError(f"the scan reports {result['refused']} refusal(s)")
    return {
        "schema": SCAN_SCHEMA,
        "sourceIdentity": {
            "baseCommit": source_commit,
            "tool": tool_identity(),
        },
        "population": {
            "binding": h.POPULATION_FROZEN,
            "glob": h.SCAN_GLOB,
            "globSemantics": (
                "tracked files matched with fnmatch.fnmatchcase; '*' matches "
                "across '/'"
            ),
            "basis": (
                "the explicit member list below, declared at the candidate; not "
                "a live glob"
            ),
            "excludedPrefixes": list(h.SCAN_EXCLUDED_PREFIXES),
            "excludedReason": (
                "the records this item emits are excluded so the scan cannot "
                "depend on its own bytes"
            ),
            "frozenAtCandidate": source_commit,
            "files": len(members),
            "members": members,
            "growthPolicy": (
                "a later verification re-hashes every member and reports a glob "
                "match that is not a member as NEW_SINCE_RECORD, counted "
                "separately; growth never changes this count, and a removed or "
                "changed member is refused with PH_REFUSED_POPULATION_DRIFT"
            ),
        },
        "parameters": result["parameters"],
        "summary": {
            "files": result["files"],
            "examined": result["examined"],
            "strictOk": result["strictOk"],
            "skippedSize": result["skippedSize"],
            "skippedOther": result["skippedOther"],
            "refused": result["refused"],
        },
        "results": result["results"],
    }


# ---------------------------------------------------------------------------
# The differential
# ---------------------------------------------------------------------------


def _case(description: str, first: bytes, second: bytes, **bounds) -> dict:
    pair = h.differential_pair(first, second, **bounds)
    return {
        "description": description,
        "parameters": {
            "max_bytes": bounds.get("max_bytes", h.DEFAULT_MAX_BYTES),
            "max_depth": bounds.get("max_depth", h.DEFAULT_MAX_DEPTH),
            "integer_bits": bounds.get("integer_bits", h.DEFAULT_INTEGER_BITS),
        },
        "pair": pair,
    }


def _variants(inputs: list[tuple[str, bytes]], **bounds) -> list[dict]:
    rows = []
    for label, raw in inputs:
        record = h.differential(raw, **bounds)
        record["label"] = label
        rows.append(record)
    return rows


def build_differential(source_commit: str) -> dict:
    duplicate = _case(
        "two distinct byte strings: a document that repeats a key, and the "
        "document the permissive reader collapses it to",
        b'{"a":1,"a":2}',
        b'{"a":2}',
    )
    number_form = _case(
        "two distinct byte strings: -0 loses its sign to an integer reader, so "
        "the permissive reader returns the same object as 0",
        b'{"n":-0}',
        b'{"n":0}',
    )
    integer_float = _case(
        "the same numeric quantity written as an integer and as a float parses to "
        "two values equal under == but of different type; the strict reader "
        "preserves the distinction and the differential records the type move",
        b'{"n":1}',
        b'{"n":1.0}',
    )
    non_finite = _case(
        "NaN is accepted by the permissive reader; the strict reader refuses it",
        b'{"n":NaN}',
        b'{"n":0}',
    )
    bom = _case(
        "a UTF-8 BOM is stripped by a permissive utf-8-sig reader and refused by "
        "the strict reader",
        b"\xef\xbb\xbf" + b'{"a":1}',
        b'{"a":1}',
    )
    trailing = _case(
        "a second document after the first is ignored by a permissive reader and "
        "refused by the strict reader",
        b'{"a":1}{"b":2}',
        b'{"a":1}',
    )
    depth = _case(
        "a document at max_depth=64 is accepted and one level deeper is refused",
        b"[" * 64 + b"1" + b"]" * 64,
        b"[" * 65 + b"1" + b"]" * 65,
        max_depth=64,
    )
    lone_surrogate = _case(
        "an unpaired high-surrogate escape is a str in the permissive reader and "
        "refused by the strict reader",
        b'"\\ud800"',
        b'"ok"',
    )
    control_character = _variants(
        [
            ("raw-newline", b'{"a":"x\ny"}'),
            ("raw-nul", b'{"a":"x\x00y"}'),
        ]
    )

    cases = {
        "duplicateKey": duplicate,
        "numberForm": number_form,
        "integerVsFloat": integer_float,
        "nonFinite": non_finite,
        "bom": bom,
        "trailingData": trailing,
        "depth": depth,
        "loneSurrogate": lone_surrogate,
        "controlCharacter": {
            "description": (
                "a raw control character in a string is accepted by a strict=False "
                "reader and refused by this reader"
            ),
            "variants": control_character,
        },
        "nonFiniteVariants": {
            "description": (
                "the other non-finite spellings the permissive reader accepts, and "
                "a finite literal that overflows to infinity in a double"
            ),
            "variants": _variants(
                [
                    ("NaN", b'{"n":NaN}'),
                    ("Infinity", b'{"n":Infinity}'),
                    ("negative-Infinity", b'{"n":-Infinity}'),
                    ("overflow-to-infinity", b'{"n":1e400}'),
                ]
            ),
        },
    }

    decisive = cases["duplicateKey"]["pair"]
    if not decisive["samePermissiveValue"]:
        raise AssertionError("the duplicate-key pair does not collapse")
    if decisive["first"]["strict"]["code"] != h.PH_REFUSED_DUPLICATE_KEY:
        raise AssertionError("the duplicate-key control did not fire")
    if not cases["numberForm"]["pair"]["samePermissiveValue"]:
        raise AssertionError("the -0 pair does not collapse to 0")
    if cases["bom"]["pair"]["first"]["strict"]["code"] != h.PH_REFUSED_BOM:
        raise AssertionError("the BOM control did not fire")
    if cases["trailingData"]["pair"]["first"]["strict"]["code"] != h.PH_REFUSED_TRAILING_DATA:
        raise AssertionError("the trailing-data control did not fire")
    if cases["depth"]["pair"]["second"]["strict"]["code"] != h.PH_REFUSED_DEPTH:
        raise AssertionError("the depth control did not fire")
    if cases["nonFinite"]["pair"]["first"]["strict"]["code"] != h.PH_REFUSED_NONFINITE:
        raise AssertionError("the non-finite control did not fire")

    return {
        "schema": DIFFERENTIAL_SCHEMA,
        "sourceIdentity": {
            "baseCommit": source_commit,
            "tool": tool_identity(),
        },
        "readers": {
            "strict": "harden.loads",
            "permissive": "harden.loads_permissive",
            "permissiveBehaviour": (
                "utf-8-sig decode; raw_decode ignoring trailing bytes; default "
                "parse_constant accepting NaN/Infinity; no duplicate-key hook; "
                "strict=False; unbounded integers and double floats"
            ),
        },
        "decisiveCase": "duplicateKey",
        "decisiveClaim": (
            "two distinct byte strings have distinct SHA-256 digests and the "
            "permissive reader returns one value for both; the strict reader "
            "refuses the first with PH_REFUSED_DUPLICATE_KEY"
        ),
        "cases": cases,
    }


# ---------------------------------------------------------------------------
# The controls
# ---------------------------------------------------------------------------


CONTROLS: list[dict] = [
    {
        "control": "encoding",
        "code": h.PH_REFUSED_ENCODING,
        "input": b'{"a":"\xff"}',
    },
    {
        "control": "bom",
        "code": h.PH_REFUSED_BOM,
        "input": b"\xef\xbb\xbf" + b'{"a":1}',
    },
    {
        "control": "duplicate-key",
        "code": h.PH_REFUSED_DUPLICATE_KEY,
        "input": b'{"a":1,"a":2}',
    },
    {
        "control": "depth",
        "code": h.PH_REFUSED_DEPTH,
        "input": b"[" * 4 + b"1" + b"]" * 4,
        "parameters": {"max_depth": 3},
    },
    {
        "control": "size",
        "code": h.PH_REFUSED_SIZE,
        "input": b"[1,2,3,4]",
        "parameters": {"max_bytes": 8},
    },
    {
        "control": "nonfinite",
        "code": h.PH_REFUSED_NONFINITE,
        "input": b'{"a":NaN}',
    },
    {
        "control": "trailing-data",
        "code": h.PH_REFUSED_TRAILING_DATA,
        "input": b'{"a":1}{"b":2}',
    },
    {
        "control": "integer-range",
        "code": h.PH_REFUSED_INTEGER_RANGE,
        "input": b"18446744073709551616",
    },
    {
        "control": "number-form",
        "code": h.PH_REFUSED_NUMBER_FORM,
        "input": b"-0",
    },
    {
        "control": "lone-surrogate",
        "code": h.PH_REFUSED_LONE_SURROGATE,
        "input": b'"\\ud800"',
    },
    {
        "control": "control-character",
        "code": h.PH_REFUSED_CONTROL_CHARACTER,
        "input": b'{"a":"x\ny"}',
    },
    {
        "control": "key-not-text",
        "code": h.PH_REFUSED_KEY_NOT_TEXT,
        "input": b"{1:2}",
    },
    {
        "control": "syntax",
        "code": h.PH_REFUSED_SYNTAX,
        "input": b'{"a":}',
    },
]


def build_controls(source_commit: str) -> dict:
    rows = []
    codes_fired = []
    for entry in CONTROLS:
        bounds = dict(entry.get("parameters", {}))
        parameters = {
            "max_bytes": bounds.get("max_bytes", h.DEFAULT_MAX_BYTES),
            "max_depth": bounds.get("max_depth", h.DEFAULT_MAX_DEPTH),
            "integer_bits": bounds.get("integer_bits", h.DEFAULT_INTEGER_BITS),
        }
        record = h.differential(entry["input"], **parameters)
        fired = record["strict"]["code"]
        if fired != entry["code"]:
            raise AssertionError(
                f"control {entry['control']!r} fired {fired}, not {entry['code']}"
            )
        codes_fired.append(fired)
        rows.append(
            {
                "control": entry["control"],
                "code": entry["code"],
                "condition": h.REFUSALS[entry["code"]]["condition"],
                "prevents": h.REFUSALS[entry["code"]]["prevents"],
                "inputHex": entry["input"].hex(),
                "inputBytes": len(entry["input"]),
                "inputSha256": sha256_bytes(entry["input"]),
                "parameters": parameters,
                "strictResult": record["strict"],
                "permissiveResult": record["permissive"],
            }
        )
    if sorted(codes_fired) != sorted(h.REFUSALS):
        missing = sorted(set(h.REFUSALS) - set(codes_fired))
        raise AssertionError(f"refusal codes without a control: {missing}")
    return {
        "schema": CONTROLS_SCHEMA,
        "sourceIdentity": {
            "baseCommit": source_commit,
            "tool": tool_identity(),
        },
        "codes": {code: h.REFUSALS[code] for code in sorted(h.REFUSALS)},
        "controls": rows,
        "summary": {
            "codes": len(h.REFUSALS),
            "controls": len(rows),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce evidence/a11")
    parser.add_argument("--out", default=str(EVIDENCE))
    parser.add_argument("--source-commit", default=BASE_COMMIT)
    arguments = parser.parse_args(argv)
    output = Path(arguments.out)
    output.mkdir(parents=True, exist_ok=True)

    scan = build_scan(arguments.source_commit)
    differential = build_differential(arguments.source_commit)
    controls = build_controls(arguments.source_commit)

    write_json(output / "SCAN.json", scan)
    write_json(output / "DIFFERENTIAL.json", differential)
    write_json(output / "CONTROLS.json", controls)

    print(
        f"a11: population={scan['population']['binding']} "
        f"files={scan['population']['files']} "
        f"examined={scan['summary']['examined']} "
        f"strictOk={scan['summary']['strictOk']} "
        f"skippedSize={scan['summary']['skippedSize']} "
        f"refused={scan['summary']['refused']} "
        f"codes={controls['summary']['codes']} "
        f"controls={controls['summary']['controls']} "
        f"commit={arguments.source_commit}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
