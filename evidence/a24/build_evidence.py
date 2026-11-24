#!/usr/bin/env python3
"""Deterministic producer of the A24 records.

It builds the real external package, verifies it in this venue exactly as the
package tool would verify any package, and writes:

    PACKAGE/        the package directory plus PACKAGE-MANIFEST.json
    RUN.json        the in-venue run: stripped environment, commands, exit
                    status, records compared and the outcome
    STATUS.json     the external status, what would count as external
                    reproduction, and what the external party must publish
    CONTROLS.json   one control per refusal code, every row ``controlOnly``

    python3 evidence/a24/build_evidence.py [--out DIR]

``--out`` defaults to this file's directory; it exists so the gate can compare
two runs. No timestamp is written, every array is built in a sorted order, and
the candidate commit is a constant so a re-run after the orchestrator commits
still reproduces these bytes.

The producer exits 0 only when the package verifies in this venue and every
control observed the code it declares. The in-venue outcome is
``PACKAGE_VERIFIED_IN_VENUE``; the external status is always
``EXTERNAL_REVIEW_PENDING``, because no party outside this project has run it.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

HERE = Path(__file__).resolve().parent
PACKAGE = HERE / "PACKAGE"

BASE_COMMIT = "b19869e224d2610656bbc22321d4734b21875dae"
RECORDED_AT = "2026-11-24"

SCHEMA_RUN = "openssl-rs/a24/run/1"
SCHEMA_STATUS = "openssl-rs/a24/status/1"
SCHEMA_CONTROLS = "openssl-rs/a24/controls/1"

import package_external as pe  # noqa: E402

MINI_RECORD = b"{}\n"


# ---------------------------------------------------------------------------
# Mini packages for the controls. They are deliberately small: a control must
# exercise one refusal, not re-run the A23 differential.
# ---------------------------------------------------------------------------

_MINI_ENTRY = '''import json
import sys
from pathlib import Path

RECORDS = ("SPEC.json", "DIFFERENTIAL.json", "PROPERTIES.json", "CONTROLS.json")


def main() -> int:
    arguments = list(sys.argv[1:])
    if "--records" not in arguments:
        return 2
    out = Path(arguments[arguments.index("--records") + 1])
    out.mkdir(parents=True, exist_ok=True)
    for name in RECORDS:
        (out / name).write_bytes(b"{}\\n")
    print('{"code":"EV_OK"}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

_MINI_ENTRY_TAMPERED = _MINI_ENTRY.replace(
    '(out / name).write_bytes(b"{}\\n")',
    '(out / name).write_bytes(b"{\\"tampered\\":true}\\n" if name == "SPEC.json" '
    'else b"{}\\n")',
)

_MINI_ENTRY_RANDOM = _MINI_ENTRY.replace(
    "import json\nimport sys",
    "import json\nimport os\nimport sys",
).replace(
    '(out / name).write_bytes(b"{}\\n")',
    '(out / name).write_bytes(os.urandom(8).hex().encode() + b"\\n")',
)

_MINI_ENTRY_OUTSIDE = '''import sys
from pathlib import Path


def main() -> int:
    Path("/etc/hostname").read_bytes()
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

_MINI_ENTRY_FAIL = '''import sys

sys.exit(1)
'''


def mini_members(entry: str, extra: dict[str, bytes] | None = None) -> dict[str, bytes]:
    members = {
        "verify.py": entry.encode("utf-8"),
        "evidence/a23/SPEC.json": MINI_RECORD,
        "evidence/a23/DIFFERENTIAL.json": MINI_RECORD,
        "evidence/a23/PROPERTIES.json": MINI_RECORD,
        "evidence/a23/CONTROLS.json": MINI_RECORD,
    }
    members.update(extra or {})
    return members


def write_mini(root: Path, entry: str, extra: dict[str, bytes] | None = None) -> Path:
    pe.write_package(
        root,
        mini_members(entry, extra),
        commit=BASE_COMMIT,
        recorded_at=RECORDED_AT,
    )
    return root


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def _observe(action: Any) -> tuple[str, str]:
    try:
        action()
    except pe.Refusal as refusal:
        return refusal.code, refusal.message
    return pe.CODE_OK, "no refusal fired"


def controls(package_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def record(
        identifier: str, code: str, fixture: str, action: Any, detail: str
    ) -> None:
        observed, message = _observe(action)
        rows.append(
            {
                "id": identifier,
                "controlOnly": True,
                "expectedCode": code,
                "observedCode": observed,
                "fixture": fixture,
                "detail": detail,
                "observation": message,
            }
        )

    # 1. A package whose metadata names a private scratch path.
    def private_state() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(
                Path(directory) / "pkg",
                _MINI_ENTRY,
                {"notes/NOTES.md": b"the run used court/tmp/a24/scratch\n"},
            )
            pe.verify(root)

    record(
        "private-state-reference",
        "EV_REFUSED_PRIVATE_STATE",
        "a well-formed package with one member naming court/tmp",
        private_state,
        "a package that only works on the producing machine is refused before it runs",
    )

    # 2. A declared input that is absent at build time.
    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory) / "pkg"
        record(
            "missing-build-input",
            "EV_REFUSED_MISSING_INPUT",
            "build(['evidence/a23/ABSENT.json']) with that path declared",
            lambda: pe.build(
                ["evidence/a23/ABSENT.json"],
                out,
                declared={"evidence/a23/ABSENT.json": "expected-record"},
            ),
            "an absent input is refused, never skipped",
        )

    # 3. An absolute path handed to the builder.
    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory) / "pkg"
        record(
            "absolute-path-input",
            "EV_REFUSED_ABSOLUTE_PATH",
            "build(['/etc/passwd']) with that absolute path declared",
            lambda: pe.build(
                ["/etc/passwd"], out, declared={"/etc/passwd": "test-only"}
            ),
            "a member is a relative path inside the tree or it is not packaged",
        )

    # 4. A member that imports a network client.
    def network_import() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(
                Path(directory) / "pkg",
                _MINI_ENTRY,
                {"helper/net.py": b"import socket\n"},
            )
            pe.verify(root)

    record(
        "network-import",
        "EV_REFUSED_NETWORK",
        "a package with a member importing socket",
        network_import,
        "the structural import scan refuses before the entry point runs",
    )

    # 5a. A member that imports a program runner.
    def undeclared_tool() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(
                Path(directory) / "pkg",
                _MINI_ENTRY,
                {"helper/tool.py": b"import subprocess\n"},
            )
            pe.verify(root)

    record(
        "subprocess-import",
        "EV_REFUSED_UNDECLARED_TOOL",
        "a package with a member importing subprocess",
        undeclared_tool,
        "a package that runs another program depends on an undeclared toolchain",
    )

    # 5b. The entry point opens a file outside the package.
    def outside_dependency() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY_OUTSIDE)
            pe.verify(root)

    record(
        "outside-package-read",
        "EV_REFUSED_UNDECLARED_DEPENDENCY",
        "a package whose entry point reads a file outside the package",
        outside_dependency,
        "the audit hook records the open and the verifier refuses",
    )

    # 5c. A build path outside the declared set.
    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory) / "pkg"
        record(
            "undeclared-build-path",
            "EV_REFUSED_UNDECLARED_DEPENDENCY",
            "build(['docs/ETP-TODO.md']) with the default declared set",
            lambda: pe.build(["docs/ETP-TODO.md"], out),
            "a member cannot arrive by being adjacent to the tree",
        )

    # 6a. A member's bytes differ from the manifest.
    def member_digest() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY)
            target = root / "evidence/a23/SPEC.json"
            target.write_bytes(MINI_RECORD + b" ")
            pe.verify(root)

    record(
        "member-digest-mismatch",
        "EV_REFUSED_MANIFEST_MISMATCH",
        "a package whose SPEC.json gained one byte after the manifest was written",
        member_digest,
        "the digest check fails before any execution",
    )

    # 6b. The entry point produces a record the package does not bind.
    def produced_mismatch() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY_TAMPERED)
            pe.verify(root)

    record(
        "produced-record-mismatch",
        "EV_REFUSED_MANIFEST_MISMATCH",
        "a package whose entry point produces a SPEC.json that differs from the expected record",
        produced_mismatch,
        "the produced record is compared byte-for-byte, so a mis-reporting entry point fails",
    )

    # 7. Two runs differ.
    def non_reproducible() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY_RANDOM)
            pe.verify(root)

    record(
        "non-reproducible-entrypoint",
        "EV_REFUSED_REPRODUCIBLE",
        "a package whose entry point writes random bytes into every record",
        non_reproducible,
        "two runs in fresh directories are compared; a one-shot result is refused",
    )

    # 8. A declared input that Git does not track.
    def untracked_input() -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            (repo / "tracked.py").write_text("x = 1\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(repo), "add", "tracked.py"],
                check=True,
                capture_output=True,
            )
            (repo / "untracked.py").write_text("x = 2\n", encoding="utf-8")
            pe.build(
                ["untracked.py"],
                Path(directory) / "pkg",
                declared={"untracked.py": "test-only"},
                repo=repo,
            )

    record(
        "untracked-input",
        "EV_REFUSED_UNTRACKED_INPUT",
        "a temporary repository with one added file and one untracked file",
        untracked_input,
        "the candidate contains tracked files; an untracked input is not part of it",
    )

    # 9. A file the manifest does not name.
    def whole_package_mutation() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY)
            (root / "extra.txt").write_text("not declared\n", encoding="utf-8")
            pe.verify(root)

    record(
        "whole-package-mutation",
        "EV_REFUSED_PACKAGE_MUTATED",
        "a well-formed package plus one undeclared file",
        whole_package_mutation,
        "the member set is compared with the manifest in both directions",
    )

    # 9b. The manifest body changed after it was written.
    def manifest_body_tamper() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY)
            path = root / pe.MANIFEST_NAME
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["candidate"]["recordedAt"] = "2026-11-25"
            path.write_bytes(pe.pretty(manifest))
            pe.verify(root)

    record(
        "manifest-body-tamper",
        "EV_REFUSED_PACKAGE_MUTATED",
        "a package whose manifest recordedAt was edited without re-deriving its digest",
        manifest_body_tamper,
        "the manifest is bound by its own digest, so a silent edit is visible",
    )

    # 10. An external run is claimed with no external record.
    def claimed_external() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY)
            pe.verify(root, claim="external")

    record(
        "claimed-external-run",
        "EV_REFUSED_EXTERNAL_NOT_RUN",
        "a valid package verified with claim='external' and no external record",
        claimed_external,
        "an in-venue run is never reported as external reproduction",
    )

    # 11. The entry point fails.
    def entrypoint_failed() -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = write_mini(Path(directory) / "pkg", _MINI_ENTRY_FAIL)
            pe.verify(root)

    record(
        "failing-entrypoint",
        "EV_REFUSED_ENTRYPOINT_FAILED",
        "a package whose entry point exits 1",
        entrypoint_failed,
        "a crash is an observation, not a pass",
    )

    # 12. The real package, verified in this venue, is the positive control.
    def real_package() -> None:
        pe.verify(package_dir)

    record(
        "real-package-verified",
        pe.CODE_OK,
        "evidence/a24/PACKAGE as produced by this file",
        real_package,
        "the positive control: the real package verifies with no refusal",
    )

    return rows


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def write_json(path: Path, value: Any) -> bytes:
    body = pe.pretty(value)
    path.write_bytes(body)
    return body


def status_document(package_digest: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA_STATUS,
        "item": "A24",
        "candidate": {"commit": BASE_COMMIT, "recordedAt": RECORDED_AT},
        "package": "evidence/a24/PACKAGE",
        "packageDigest": package_digest,
        "externalStatus": "EXTERNAL_REVIEW_PENDING",
        "externalPartyRan": False,
        "isPass": False,
        "inVenueOutcome": "PACKAGE_VERIFIED_IN_VENUE",
        "inVenueRunIsNotExternal": True,
        "refusalIfClaimed": "EV_REFUSED_EXTERNAL_NOT_RUN",
        "whatWouldCountAsExternalReproduction": [
            "a party outside this project unpacks the package in its own environment, "
            "with no access to this checkout, and runs the declared command",
            "that party reports the package digest, the interpreter version, the "
            "command it ran, the four record digests and the exit status",
            "that party's verdict is signed by an identity in a trust domain distinct "
            "from this project's (Earned Trust Article 5), and the record names that "
            "domain and how it was established",
        ],
        "evidenceTheExternalPartyMustPublish": [
            "the exact package digest it received and the digest of every record it produced",
            "the interpreter identity and operating system it used",
            "the command line and the stripped or unstripped environment it ran under",
            "its own signed verdict naming the outcome and any refusal code it observed",
        ],
        "whatThisRecordDoesNotEstablish": [
            "that a claim in the A23 records is true",
            "that the A23 differential is a machine-checked proof",
            "that any party outside this project has run the package",
        ],
        "articles": {
            "1": "the claim is the in-venue outcome, not external reproduction",
            "2": "the evidence is bound to this package digest and interpreter",
            "5": "no external party has an independent trust domain here",
        },
    }


def run_document(result: dict[str, Any], package_digest: str) -> dict[str, Any]:
    def identity(relative: str) -> dict[str, str]:
        return {
            "path": relative,
            "sha256": hashlib.sha256((REPO / relative).read_bytes()).hexdigest(),
        }

    return {
        "schema": SCHEMA_RUN,
        "item": "A24",
        "package": "evidence/a24/PACKAGE",
        "packageDigest": package_digest,
        "candidate": {"commit": BASE_COMMIT, "recordedAt": RECORDED_AT},
        "verifier": identity("forensics/tools/package_external.py"),
        "producer": identity("evidence/a24/build_evidence.py"),
        "venue": "in-venue: this project's own machine and container; not external",
        "inVenueCommand": "python3 forensics/tools/package_external.py verify evidence/a24/PACKAGE",
        "entryPoint": pe.ENTRY_POINT,
        "entryPointRuns": result["runs"],
        "entryIsolation": result["environment"]["isolationFlags"],
        "strippedEnvironment": {
            "stripped": result["environment"]["stripped"],
            "inheritedVariables": result["environment"]["inheritedVariables"],
            "pythonpath": result["environment"]["pythonpath"],
            "pathEntries": result["environment"]["pathEntries"],
            "path": result["environment"]["path"],
            "home": result["environment"]["home"],
            "tmpdir": result["environment"]["tmpdir"],
        },
        "interpreter": result["interpreter"],
        "minimumInterpreter": result["minimumInterpreter"],
        "exitStatus": 0,
        "recordsCompared": result["recordsCompared"],
        "records": result["records"],
        "checks": result["checks"],
        "codes": [result["code"]],
        "outcome": result["outcome"],
        "externalStatus": result["externalStatus"],
        "externalPartyRan": result["externalPartyRan"],
        "isExternal": result["isExternal"],
        "notExternal": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce the A24 records deterministically")
    parser.add_argument("--out", default=str(HERE), help="output directory")
    arguments = parser.parse_args(argv)
    out = Path(arguments.out)
    out.mkdir(parents=True, exist_ok=True)

    package_dir = out / "PACKAGE"
    manifest = pe.build(
        None,
        package_dir,
        commit=BASE_COMMIT,
        recorded_at=RECORDED_AT,
    )

    result = pe.verify(package_dir)
    rows = controls(package_dir)

    write_json(out / "RUN.json", run_document(result, manifest["packageDigest"]))
    write_json(out / "STATUS.json", status_document(manifest["packageDigest"]))
    control_rows = {
        "schema": SCHEMA_CONTROLS,
        "item": "A24",
        "candidate": {"commit": BASE_COMMIT, "recordedAt": RECORDED_AT},
        "controls": rows,
        "controlCount": len(rows),
        "codesCovered": sorted(
            {row["expectedCode"] for row in rows} & set(pe.REFUSAL_CODES)
        ),
        "coversEveryCode": sorted(
            {row["expectedCode"] for row in rows} & set(pe.REFUSAL_CODES)
        )
        == sorted(pe.REFUSAL_CODES),
        "positiveControl": "real-package-verified",
        "code": (
            pe.CODE_OK
            if all(row["observedCode"] == row["expectedCode"] for row in rows)
            else "EV_REFUSED_CONTROL"
        ),
    }
    write_json(out / "CONTROLS.json", control_rows)

    failing = [row["id"] for row in rows if row["observedCode"] != row["expectedCode"]]
    overall = pe.CODE_OK if not failing else "EV_REFUSED_CONTROL"
    print(
        f"a24: base={BASE_COMMIT[:9]} members={len(manifest['members'])} "
        f"package={manifest['packageDigest']} records={result['recordsCompared']} "
        f"runs={result['runs']} outcome={result['outcome']} "
        f"controls={len(rows)} codesCovered={len(control_rows['codesCovered'])} "
        f"failing={len(failing)} codes={overall} "
        f"external={result['externalStatus']}"
    )
    return (
        0
        if overall == pe.CODE_OK and result["outcome"] == "PACKAGE_VERIFIED_IN_VENUE"
        else 1
    )


if __name__ == "__main__":
    sys.exit(main())
