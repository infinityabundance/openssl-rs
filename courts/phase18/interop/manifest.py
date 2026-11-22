#!/usr/bin/env python3
"""Build an O11 manifest from a harness log.

Every number here is *derived* from the log with a stated rule; nothing is typed
in by hand. The rules:

  executed  a `run test <script> ...` line (the harness announced it)
  ok        an `ok <description>` line
  failed    a `failed <description>` line
  skipped   a `SKIPPED: <reason>` line
  blocked   a script that was announced and produced no ok, failed or SKIPPED
            line before the next `run test` (the harness could not decide)

A script may print several ok lines, so `ok` counts assertions, not scripts; the
manifest reports both. `blocked` is deliberately not folded into `skipped`: a
script that says nothing is not a script that said "skip".

Usage:
    manifest.py --log LOG --subject A|B --out FILE [--tarball SHA] [--dso SHA]
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys
import time

RUN = re.compile(r"^run test (\S+) \.\.\.\s*$")
OK = re.compile(r"^ok (.+?)\s*$")
FAILED = re.compile(r"^failed (.+?)\s*$")
# The harness has at least three spellings of a skip, all of them observed in
# published logs: `SKIPPED: reason`, `skipped (reason)` and `Skipped: reason`.
# One case-insensitive rule covers them; a script that prints none of the three
# is `blocked`, which is not the same claim as a skip.
SKIPPED_ANY = re.compile(r"^skipped\b.*$", re.I)
UNIT = re.compile(r"^(\w+): [.]+ (\d+) tests ok\s*$")


def parse(path):
    scripts = []
    current = None
    per_script = {}
    unit = {}
    for line in pathlib.Path(path).read_text(errors="replace").splitlines():
        m = RUN.match(line)
        if m:
            current = m.group(1)
            scripts.append(current)
            per_script[current] = {"ok": 0, "failed": 0, "skipped": 0}
            continue
        m = UNIT.match(line)
        if m:
            unit[m.group(1)] = int(m.group(2))
            continue
        if current is None:
            continue
        if OK.match(line):
            per_script[current]["ok"] += 1
        elif FAILED.match(line):
            per_script[current]["failed"] += 1
        elif SKIPPED_ANY.match(line):
            per_script[current]["skipped"] += 1
    blocked = [s for s, c in per_script.items() if c["ok"] == 0 and c["failed"] == 0 and c["skipped"] == 0]
    return {
        "log": str(path),
        "counts": {
            "scripts_executed": len(scripts),
            "ok_assertions": sum(c["ok"] for c in per_script.values()),
            "failed_assertions": sum(c["failed"] for c in per_script.values()),
            "skipped_assertions": sum(c["skipped"] for c in per_script.values()),
            "scripts_blocked": len(blocked),
            "scripts_with_failures": sum(1 for c in per_script.values() if c["failed"]),
            "unit_assertions": sum(unit.values()),
        },
        "per_script": per_script,
        "blocked_scripts": blocked,
        "rules": {
            "executed": "a `run test <script> ...` line",
            "ok": "an `ok <description>` line (assertions, not scripts)",
            "failed": "a `failed <description>` line",
            "skipped": "any line beginning `skipped` in any case (`SKIPPED: reason`, `skipped (reason)`, `Skipped: reason`); every dialect is counted and none is a pass",
            "blocked": "announced, with no ok/failed/SKIPPED line of its own",
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--subject", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tarball-sha256", default="unknown")
    ap.add_argument("--libcrypto-sha256", default="unknown")
    ap.add_argument("--command", action="append", default=[])
    args = ap.parse_args()

    body = parse(args.log)
    # The manifest carries the digest of the bytes it was derived from, so a
    # verifier can check the log it reads is the log that was counted.
    raw = pathlib.Path(args.log).read_bytes()
    body["log_sha256"] = hashlib.sha256(raw).hexdigest()
    body["log_bytes"] = len(raw)
    manifest = {
        "schema": "openssl-rs/interop-manifest/1",
        "item": "O11 of docs/ETP-TODO.md",
        "subject": args.subject,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "identity": {
            "openssh_tarball_sha256": args.tarball_sha256,
            "libcrypto_sha256": args.libcrypto_sha256,
        },
        "reproduction": args.command,
        "result": body,
        "note": "Every count is derived from the log by the rules recorded here; none is hand-authored. A skipped script is not a pass and a blocked script is not a skip.",
    }
    pathlib.Path(args.out).write_text(json.dumps(manifest, indent=1) + "\n")
    c = body["counts"]
    print(
        f"{args.subject}: {c['scripts_executed']} scripts, {c['ok_assertions']} ok, "
        f"{c['failed_assertions']} failed, {c['skipped_assertions']} skipped, "
        f"{c['scripts_blocked']} blocked, {c['unit_assertions']} unit assertions"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
