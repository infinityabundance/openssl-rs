#!/usr/bin/env python3
"""The A24 package entry point: recompute the A23 records and compare them.

Run it in the unpacked package with a Python interpreter at or above the
declared minimum. It imports nothing from the producing checkout: every module it
loads is a package member and every input is a package member.

    python3 verify.py                 # compare, print one JSON line, exit 0/1
    python3 verify.py --records DIR   # also copy the produced records to DIR

A pass means: the packaged producer reproduced the packaged specification, the
differential, the properties and the controls, and every produced record is
byte-identical to the record the manifest binds. It does not mean that any
external party has run the package.
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import runpy
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MINIMUM = (3, 11)
RECORDS = ("SPEC.json", "DIFFERENTIAL.json", "PROPERTIES.json", "CONTROLS.json")
PRODUCER = "evidence/a23/build_evidence.py"
MANIFEST = "PACKAGE-MANIFEST.json"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_digest(manifest: dict) -> str:
    body = {key: value for key, value in manifest.items() if key != "packageDigest"}
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _check_package() -> str | None:
    """The package checks itself: the manifest body and every member digest."""
    path = ROOT / MANIFEST
    if not path.is_file():
        return "EV_REFUSED_MISSING_INPUT"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "EV_REFUSED_PACKAGE_MUTATED"
    if manifest.get("packageDigest") != _manifest_digest(manifest):
        return "EV_REFUSED_PACKAGE_MUTATED"
    for row in manifest.get("members", []):
        target = ROOT / row["path"]
        if not target.is_file():
            return "EV_REFUSED_MISSING_INPUT"
        data = target.read_bytes()
        if len(data) != row["bytes"] or _digest(target) != row["sha256"]:
            return "EV_REFUSED_MANIFEST_MISMATCH"
    return None


def _run_producer() -> tuple[int, Path]:
    out = Path(tempfile.mkdtemp(prefix="a24-records-"))
    argv = list(sys.argv)
    sys.argv = [PRODUCER, "--out", str(out)]
    code = 0
    try:
        runpy.run_path(str(ROOT / PRODUCER), run_name="__main__")
    except SystemExit as exc:
        code = 0 if exc.code is None else int(exc.code)
    finally:
        sys.argv = argv
    return code, out


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if sys.version_info[:2] < MINIMUM:
        print("a24-package: code=EV_REFUSED_UNDECLARED_TOOL outcome=PACKAGE_INVALID")
        print("a24-package: the interpreter is below the declared minimum 3.11")
        return 1
    integrity = _check_package()
    if integrity is not None:
        print("a24-package: code=%s outcome=PACKAGE_INVALID" % integrity)
        print("a24-package: the package does not match its own manifest")
        return 1
    records = None
    if "--records" in arguments:
        index = arguments.index("--records")
        if index + 1 >= len(arguments):
            print("a24-package: code=EV_USAGE outcome=PACKAGE_INVALID")
            return 2
        records = Path(arguments[index + 1])
    code, out = _run_producer()
    rows = []
    ok = code == 0
    for name in RECORDS:
        produced = out / name
        expected = ROOT / "evidence/a23" / name
        equal = (
            produced.is_file()
            and expected.is_file()
            and produced.read_bytes() == expected.read_bytes()
        )
        rows.append(
            {
                "record": name,
                "producedSha256": _digest(produced) if produced.is_file() else None,
                "expectedSha256": _digest(expected) if expected.is_file() else None,
                "equal": equal,
            }
        )
        ok = ok and equal
    if records is not None:
        records.mkdir(parents=True, exist_ok=True)
        for name in RECORDS:
            produced = out / name
            if produced.is_file():
                shutil.copyfile(produced, records / name)
    shutil.rmtree(out, ignore_errors=True)
    overall = "EV_OK" if ok else "EV_REFUSED_MANIFEST_MISMATCH"
    outcome = "PACKAGE_VERIFIED_IN_VENUE" if ok else "PACKAGE_INVALID"
    print(
        json.dumps(
            {
                "code": overall,
                "outcome": outcome,
                "externalStatus": "EXTERNAL_REVIEW_PENDING",
                "producerExit": code,
                "records": rows,
            },
            sort_keys=True,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
