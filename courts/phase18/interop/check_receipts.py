#!/usr/bin/env python3
"""Check the interop receipts and manifests for the evidence-integrity properties.

Each rule below is one of the failures the review named, made mechanical:

  R1  every receipt parses as JSON (a machine must not have to guess);
  R2  a receipt marked `withdrawn` must say what supersedes it -- a withdrawal
      that names nothing is just a deletion;
  R3  a receipt whose `status` is not WITHDRAWN must not carry `withdrawn: true`
      or a `mapping_status` other than `ok`: a cell that could not prove which
      library each side ran is not a cell result;
  R4  every manifest's log must exist at the path it names, and its sha256 must
      match the file. `court/` is gitignored, so a manifest that points there
      fails this rule in a clean checkout -- which is the point;
  R5  a manifest must not claim a count it did not derive: the rules block has
      to be present, and the log must actually contain as many `run test` lines
      as the manifest reports scripts.

`--summary` prints one line per artefact; otherwise a failure list is printed.
Exit status: 0 only when every rule holds.
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
DIR = ROOT / "courts" / "phase18" / "interop"
RUN = re.compile(r"^run test \S+ \.\.\.\s*$", re.M)


def load(p):
    try:
        return json.loads(p.read_text()), None
    except Exception as e:  # noqa: BLE001 - reported as R1
        return None, f"R1 {p.name}: not valid JSON ({e})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--dir", default=str(DIR), help="directory to check (for negative controls)")
    args = ap.parse_args()

    problems = []
    target = pathlib.Path(args.dir)
    receipts = sorted(target.glob("RECEIPT-*.json"))
    manifests = sorted(target.glob("MANIFEST-*.json"))

    for p in receipts:
        d, err = load(p)
        if err:
            problems.append(err)
            continue
        withdrawn = d.get("withdrawn") is True
        status = str(d.get("status", "")).upper()
        if withdrawn and not d.get("superseded_by"):
            problems.append(f"R2 {p.name}: withdrawn without superseded_by")
        if not withdrawn:
            if status == "WITHDRAWN":
                problems.append(f"R3 {p.name}: status WITHDRAWN but not marked withdrawn")
            ms = d.get("mapping_status")
            if ms is not None and ms != "ok":
                problems.append(f"R3 {p.name}: mapping_status {ms!r} on a live receipt")
            if d.get("cell") and status != "WITHDRAWN" and d.get("make_k_tests_exit") not in (None, 0):
                # A non-zero harness exit is allowed only when the receipt says which
                # scripts failed; otherwise the number is uninterpretable.
                if not d.get("failed_scripts"):
                    problems.append(f"R3 {p.name}: non-zero harness exit with no failed-script record")
        if args.summary:
            print(f"receipt  {p.name:<28} {'WITHDRAWN' if withdrawn else 'live'}")

    for p in manifests:
        d, err = load(p)
        if err:
            problems.append(err)
            continue
        res = d.get("result", {})
        log = res.get("log")
        want = res.get("log_sha256")
        if not log or not want:
            problems.append(f"R4 {p.name}: no log path + digest")
        else:
            lp = ROOT / log
            if not lp.exists():
                problems.append(f"R4 {p.name}: log {log} does not exist in this checkout")
            else:
                got = hashlib.sha256(lp.read_bytes()).hexdigest()
                if got != want:
                    problems.append(f"R4 {p.name}: log digest {got[:12]} != recorded {want[:12]}")
                declared = res.get("counts", {}).get("scripts_executed")
                actual = len(RUN.findall(lp.read_text(errors="replace")))
                if declared is not None and declared != actual:
                    problems.append(
                        f"R5 {p.name}: manifest says {declared} scripts, log contains {actual}")
        if "rules" not in res:
            problems.append(f"R5 {p.name}: no derivation rules recorded")
        if args.summary:
            print(f"manifest {p.name:<28} log={'present' if (ROOT / (log or '')).exists() else 'missing'}")

    for line in problems:
        print(line, file=sys.stderr)
    print(f"\nreceipts={len(receipts)} manifests={len(manifests)} problems={len(problems)}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
