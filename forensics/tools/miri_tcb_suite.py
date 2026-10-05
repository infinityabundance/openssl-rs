#!/usr/bin/env python3
"""openssl-rs — the machine-owned, fail-closed Miri TCB-suite recorder.

`forensics/miri-tcb-suite.json` names the tests Miri is admitted to run and the
tests it is not, each with a reason. This tool is what makes that manifest bind:
it parses a real `cargo +nightly miri test --lib <filter>` log and **fails closed**
unless

  * every `admitted` test is present in the log and reported `ok`;
  * no `unsupported` test appears in the log at all;
  * no `miri_tcb` test in the log is absent from both lists (an unclassified test
    is a failure, not an omission).

A missing run is never a pass: an absent log, an empty log, or a build failure all
exit non-zero. `--self-test` proves the validator rejects a log whose admitted test
failed and a log with an unclassified test, so "it passed" is never the only
evidence.

The recorded result is `artifacts/phase18/miri-tcb.json`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "forensics" / "miri-tcb-suite.json"
OUT = REPO_ROOT / "artifacts" / "phase18" / "miri-tcb.json"
MANIFEST_SCHEMA = "openssl-rs/miri-tcb-suite/v1"
OUT_SCHEMA = "openssl-rs/miri-tcb-result/v1"

# A libtest result line: `test <path> ... ok` / `... FAILED` / `... ignored`.
_RESULT = re.compile(r"^test\s+(?P<name>\S+)\s+\.\.\.\s+(?P<status>ok|FAILED|ignored)\s*$")


def parse_log(text: str) -> dict[str, str]:
    """Every libtest result in `text`, as `{qualified-name: status}`."""
    results: dict[str, str] = {}
    for line in text.splitlines():
        m = _RESULT.match(line.strip())
        if m:
            results[m.group("name")] = m.group("status")
    return results


def validate(manifest: dict, results: dict[str, str], filter_: str) -> list[str]:
    """Every way `results` fails to match the manifest's admitted/unsupported split."""
    problems: list[str] = []
    admitted = set(manifest.get("admitted") or [])
    unsupported = {u.get("test") for u in manifest.get("unsupported") or []}
    if not admitted:
        problems.append("the manifest's admitted set is empty; fail-closed")
    for name in sorted(admitted):
        status = results.get(name)
        if status is None:
            problems.append(f"admitted test {name} did not run")
        elif status != "ok":
            problems.append(f"admitted test {name} is {status}")
    for name in sorted(unsupported):
        if name in results:
            problems.append(f"unsupported test {name} ran under Miri")
    for name, status in sorted(results.items()):
        if filter_ not in name:
            continue
        if name not in admitted and name not in unsupported:
            problems.append(f"unclassified {filter_} test {name} is {status}")
    return problems


def self_test(manifest: dict, filter_: str) -> int:
    """Prove the validator rejects a failed admitted test and an unclassified one."""
    admitted = sorted(manifest.get("admitted") or [])
    if not admitted:
        print("[miri-tcb-suite] SELF-TEST FAIL: no admitted tests", file=sys.stderr)
        return 1
    good = {name: "ok" for name in admitted}
    if validate(manifest, good, filter_):
        print("[miri-tcb-suite] SELF-TEST FAIL: a clean log was rejected", file=sys.stderr)
        return 1
    failed = dict(good)
    failed[admitted[0]] = "FAILED"
    if not any("is FAILED" in p for p in validate(manifest, failed, filter_)):
        print("[miri-tcb-suite] SELF-TEST FAIL: a FAILED admitted test was accepted",
              file=sys.stderr)
        return 1
    extra = dict(good)
    extra[f"{filter_}::rogue_test"] = "ok"
    if not any("unclassified" in p for p in validate(manifest, extra, filter_)):
        print("[miri-tcb-suite] SELF-TEST FAIL: an unclassified test was accepted",
              file=sys.stderr)
        return 1
    missing = {k: v for k, v in good.items() if k != admitted[-1]}
    if not any("did not run" in p for p in validate(manifest, missing, filter_)):
        print("[miri-tcb-suite] SELF-TEST FAIL: a missing admitted test was accepted",
              file=sys.stderr)
        return 1
    print("[miri-tcb-suite] self-test: rejects FAILED, missing and unclassified tests")
    return 0


def load_manifest() -> dict:
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if doc.get("schema") != MANIFEST_SCHEMA:
        raise SystemExit(f"miri-tcb-suite: manifest schema {doc.get('schema')!r} != "
                         f"{MANIFEST_SCHEMA!r}")
    return doc


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--record", metavar="LOG", help="a `cargo miri test` log to validate")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args(argv)
    manifest = load_manifest()
    filter_ = manifest.get("filter", "miri_tcb")
    if args.self_test:
        return self_test(manifest, filter_)
    if not args.record:
        print("[miri-tcb-suite] --record LOG or --self-test is required; a missing run is not a pass",
              file=sys.stderr)
        return 2
    log = Path(args.record)
    if not log.is_file():
        print(f"[miri-tcb-suite] log {log} is absent; fail-closed", file=sys.stderr)
        return 1
    results = parse_log(log.read_text(encoding="utf-8", errors="replace"))
    problems = validate(manifest, results, filter_)
    doc = {
        "schema": OUT_SCHEMA,
        "phase": 18,
        "tool": "forensics/tools/miri_tcb_suite.py",
        "command": manifest.get("command"),
        "filter": filter_,
        "miri_flags": manifest.get("miri_flags"),
        "seeds": manifest.get("seeds"),
        "admitted": sorted(manifest.get("admitted") or []),
        "unsupported": manifest.get("unsupported") or [],
        "results": results,
        "problems": problems,
        "verdict": "pass" if not problems else "fail",
    }
    Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for p in problems:
        print(f"[miri-tcb-suite] FAIL: {p}", file=sys.stderr)
    print(f"[miri-tcb-suite] {len(results)} result(s), {len(problems)} problem(s) -> "
          f"{doc['verdict']} ({args.out})")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
