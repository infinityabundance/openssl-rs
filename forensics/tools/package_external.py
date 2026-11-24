#!/usr/bin/env python3
"""package_external.py -- A24: a self-contained external verification package.

The problem
-----------
A run on this project's own machine is not external evidence. It shares the
candidate, the author, the network and every private path. A third party can
only reproduce the result if it receives the *frozen verifier and its frozen
inputs* in a bundle that runs with nothing from this working tree: no absolute
path, no network, no interpreter search path, no untracked file, no secret, no
toolchain beyond a declared Python interpreter.

This tool builds that bundle and verifies it the same way an outside party
would have to.

Contract
--------
``build(paths, out)`` writes a package directory plus ``PACKAGE-MANIFEST.json``.
The manifest records, for every member, its relative path, byte size and
SHA-256; the entry point; the declared minimum interpreter; the exact commands;
and the declarations ``network: false`` and ``privateState: none``. The builder
refuses a path that is absolute or escapes the tree, a path outside the declared
set, an untracked file, a missing file, a member that names ``court/tmp``, a
private scratch path or an environment token, a member that imports a network
client, and a member that imports or calls another program.

``verify(package_dir)`` copies the declared members into a fresh temporary
directory, runs the entry point twice with a stripped environment (no
``PYTHONPATH``, no repository variable, a ``PATH`` containing only the
interpreter), audits every file the entry opens, and compares the produced
records with the packaged expected records. It refuses with a stable code when
the package is invalid; the outcome names what the run actually established.

Outcomes
--------
``PACKAGE_VERIFIED_IN_VENUE``  every check passed in the venue that ran it.
``PACKAGE_UNVERIFIED``         the package is intact but was not run here.
``PACKAGE_INVALID``            a refusal fired; nothing is established.
``EXTERNAL_REVIEW_PENDING``    a party outside this project has not run it.
                               This is not a pass, and no code path in this
                               module upgrades it to one.

Refusal codes are stable and documented in ``docs/EXTERNAL-PACKAGE.md``; the
test suite refuses a code that appears in one and not the other.

Usage
-----
    python3 forensics/tools/package_external.py build --out DIR [--commit REV]
    python3 forensics/tools/package_external.py verify DIR [--claim in-venue|external]
    python3 forensics/tools/package_external.py inventory DIR [--json]

Exit status: 0 for success, 1 for a refusal, 2 for a usage error. Every command
prints the code and the outcome.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_MANIFEST = "openssl-rs/a24/external-package-manifest/1"
SCHEMA_RESULT = "openssl-rs/a24/verify-result/1"
SCHEMA_PIPELINE = "openssl-rs/a24/pipeline/1"

MANIFEST_NAME = "PACKAGE-MANIFEST.json"
ENTRY_POINT = "verify.py"
ENTRY_SHELL = "verify.sh"

MINIMUM_INTERPRETER = "3.11"
MINIMUM_INTERPRETER_TUPLE = (3, 11)

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

CODE_OK = "EV_OK"
CODE_USAGE = "EV_USAGE"

#: The records the entry point must reproduce. Each is compared byte-for-byte
#: with the record the manifest binds; a producer wrapper field is not a licence
#: to differ.
RECORDS: tuple[str, ...] = (
    "SPEC.json",
    "DIFFERENTIAL.json",
    "PROPERTIES.json",
    "CONTROLS.json",
)

#: The only inputs a package may contain. ``build`` refuses any other path, so a
#: member cannot arrive by being adjacent to the tree: it has to be declared
#: here, in the change that adds it.
DECLARED_INPUTS: dict[str, str] = {
    "forensics/tools/verifier_formalisation.py": "verifier",
    "forensics/tools/policy_engine.py": "verifier-dependency",
    "forensics/tools/thresholds.py": "verifier-dependency",
    "forensics/tools/authorisation.py": "verifier-dependency",
    "forensics/tools/corrections.py": "verifier-dependency",
    "forensics/tools/dsse.py": "verifier-dependency",
    "evidence/a23/build_evidence.py": "producer",
    "evidence/a23/SPEC.json": "expected-input",
    "evidence/a23/DIFFERENTIAL.json": "expected-record",
    "evidence/a23/PROPERTIES.json": "expected-record",
    "evidence/a23/CONTROLS.json": "expected-record",
}

GENERATED_INPUTS: dict[str, str] = {
    ENTRY_POINT: "generated-entry-point",
    ENTRY_SHELL: "generated-entry-point-shell",
    "README.md": "generated-readme",
    "PIPELINE.json": "generated-pipeline",
}

#: The rule that excluded every other file. A file is packaged only when every
#: input it reads is in the package and every program it executes is the
#: declared interpreter; anything that needs the court, the Rust toolchain, a C
#: compiler, binutils, a shell script or private state is excluded and named.
EXCLUSION_RULE = (
    "A file is packaged only when every input it reads is in the package and "
    "every program it executes is the declared Python interpreter. A file that "
    "needs the court container, the Rust toolchain, a C compiler, binutils, a "
    "shell script, a network service or private state is excluded and named "
    "with the reason it cannot run offline."
)

EXCLUDED_INPUTS: list[dict[str, str]] = [
    {
        "path": "forensics/tools/adversarial_qualification.py",
        "rule": "R1-no-external-program",
        "reason": (
            "E1-E3 do not run on constructed inputs: harness_binsec_verdicts and "
            "harness_binsec_population execute courts/phase18/timing/binsec_checkct.sh "
            "with bash and call compile_elf, and harness_branch_audit calls "
            "require_tool('objdump') and compile_asm; compile_elf and compile_asm "
            "call require_tool('cc'). A package containing this tool would depend "
            "on a shell, a C compiler and binutils, which are outside the declared "
            "Python-only minimum."
        ),
    },
    {
        "path": "courts/phase18/timing/binsec_checkct.sh",
        "rule": "R1-no-external-program",
        "reason": "the E1/E2 instrument is a shell script that invokes the BINSEC and Z3 stand-ins",
    },
    {
        "path": "courts/phase18/timing/binary_branch_audit.py",
        "rule": "R1-no-external-program",
        "reason": "the E3 instrument invokes objdump and is measured against compiled shared objects",
    },
    {
        "path": "courts/phase18/timing/third_party/dudect/dudect.h",
        "rule": "R1-no-external-program",
        "reason": "the E4 timing experiment compiles a C harness; no Rust or C build is in this package",
    },
    {
        "path": "evidence/etp-t7/DUDECT-ETP-T7.json",
        "rule": "R2-no-unproduced-evidence",
        "reason": "E4 reads a recorded timing receipt; the receipt is evidence about a run this package cannot re-execute",
    },
    {
        "path": "forensics/tools/etp6_package.py",
        "rule": "R1-no-external-program",
        "reason": "the ETP-6 builder calls git, rustc/cargo and the court container; it cannot run in the declared minimum environment",
    },
    {
        "path": "docker/",
        "rule": "R3-no-court",
        "reason": "the court launcher is out of scope for conversion items and needs Docker",
    },
    {
        "path": "src/",
        "rule": "R4-no-rust-build",
        "reason": "no Rust source is needed: the packaged verifier reads JSON records and Python modules only",
    },
    {
        "path": "evidence/* (other than evidence/a23)",
        "rule": "R2-no-unproduced-evidence",
        "reason": "an evidence record is packaged only when a packaged verifier reads it; a record added without its reader would imply a check that does not run",
    },
]

#: Import roots that are network clients. A structural import is enough to
#: refuse: the package must not be able to reach a network even accidentally.
NETWORK_MODULES: frozenset[str] = frozenset(
    {
        "aiohttp",
        "asyncio",
        "ftplib",
        "http",
        "httplib",
        "httpx",
        "imaplib",
        "nntplib",
        "poplib",
        "requests",
        "smtplib",
        "socket",
        "socketserver",
        "ssl",
        "telnetlib",
        "urllib",
        "urllib2",
        "webbrowser",
        "xmlrpc",
    }
)

#: Imports that execute a program. A package that runs a program depends on a
#: toolchain this package did not declare.
PROCESS_MODULES: frozenset[str] = frozenset(
    {"ctypes", "multiprocessing", "pty", "subprocess"}
)

#: Attribute calls on ``os`` that execute a program or a shell.
PROCESS_CALLS: tuple[str, ...] = (
    "os.exec",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.popen",
    "os.spawn",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.system",
    "pty.spawn",
)

#: Private-state markers. A member that names one of these is not self-contained:
#: it would only work on the machine that produced this tree.
PRIVATE_STATE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"court/tmp"), "a court scratch path"),
    (re.compile(r"(?<![\w.])/work/"), "an absolute court work path"),
    (re.compile(r"(?<![\w.])/home/[A-Za-z0-9._-]+"), "a home directory"),
    (re.compile(r"(?<![\w.])/tmp/"), "an absolute temporary path"),
    (re.compile(r"(?<![\w.])/(?:root|var/tmp|mnt|opt)/"), "an absolute private path"),
    (re.compile(r"\bOPENSSL_RS_[A-Z0-9_]+\b"), "an environment token"),
    (re.compile(r"\bPYTHONPATH\b"), "an environment token"),
    (re.compile(r"\bCARGO_[A-Z0-9_]+\b"), "an environment token"),
    (re.compile(r"\bRUSTUP_[A-Z0-9_]+\b"), "an environment token"),
    (re.compile(r"\bos\.(?:environ|getenv)\b"), "an environment read"),
)

REFUSALS: dict[str, dict[str, str]] = {
    "EV_REFUSED_PRIVATE_STATE": {
        "condition": "a member or the package metadata names court/tmp, a private "
                     "scratch path or an environment token",
        "prevents": "a package that only verifies on the machine that produced the "
                    "tree, presented as if it were self-contained",
    },
    "EV_REFUSED_MISSING_INPUT": {
        "condition": "a declared input is absent at build time, or a manifest-declared "
                     "member is absent at verification time",
        "prevents": "a package that silently omits a file and still reports success",
    },
    "EV_REFUSED_ABSOLUTE_PATH": {
        "condition": "a path is absolute, contains a parent traversal, or is a symlink "
                     "that resolves outside the tree",
        "prevents": "a member that is really a path on the producing machine",
    },
    "EV_REFUSED_NETWORK": {
        "condition": "a member imports a network client, or the entry point loads one "
                     "at run time",
        "prevents": "an offline claim that hides a network read",
    },
    "EV_REFUSED_UNDECLARED_DEPENDENCY": {
        "condition": "the entry point opens a file outside the package and outside the "
                     "interpreter's own library, or a build path is outside the declared set",
        "prevents": "a package that needs this checkout, a site-packages module or an "
                    "undeclared file to pass",
    },
    "EV_REFUSED_MANIFEST_MISMATCH": {
        "condition": "a member's bytes do not match its recorded size and SHA-256, or a "
                     "produced record is not byte-identical to the expected record",
        "prevents": "a package whose contents, or whose own result, differ from the "
                    "identity the manifest binds",
    },
    "EV_REFUSED_REPRODUCIBLE": {
        "condition": "two runs of the entry point in fresh directories produce different "
                     "output or different records",
        "prevents": "a one-shot result that cannot be reproduced by the recipient",
    },
    "EV_REFUSED_UNDECLARED_TOOL": {
        "condition": "a member imports or calls a program (subprocess, ctypes, a shell), "
                     "or the interpreter is below the declared minimum",
        "prevents": "a package that depends on a compiler, a shell or a tool version the "
                    "manifest did not declare",
    },
    "EV_REFUSED_PACKAGE_MUTATED": {
        "condition": "the package directory contains a file the manifest does not name, "
                     "or the manifest body no longer matches its own digest",
        "prevents": "a package that changed after the manifest was written",
    },
    "EV_REFUSED_EXTERNAL_NOT_RUN": {
        "condition": "an external run is claimed but no party outside this project has "
                     "produced a verdict",
        "prevents": "an in-venue run being reported as external reproduction",
    },
    "EV_REFUSED_UNTRACKED_INPUT": {
        "condition": "a declared input is not tracked by Git at the named candidate",
        "prevents": "a package that depends on a working-tree file the candidate does not "
                    "contain",
    },
    "EV_REFUSED_ENTRYPOINT_FAILED": {
        "condition": "the entry point exits nonzero or raises before writing its records",
        "prevents": "a crashed verification being read as a pass",
    },
}

REFUSAL_CODES: tuple[str, ...] = tuple(REFUSALS)


class Refusal(Exception):
    """A stable refusal code and the observation that fired it."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _refuse(code: str, message: str) -> None:
    if code not in REFUSALS:
        raise AssertionError(f"{code!r} is not a registered refusal code")
    raise Refusal(code, message)


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def canonical(value: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no insignificant whitespace."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def pretty(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    body = {key: value for key, value in manifest.items() if key != "packageDigest"}
    return sha256_bytes(canonical(body))


def _git(repo: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(repo), *arguments],
        capture_output=True,
        check=False,
    )


def _resolve_commit(repo: Path) -> str:
    result = _git(repo, "rev-parse", "HEAD")
    if result.returncode != 0:
        raise Refusal("EV_REFUSED_MISSING_INPUT", "the candidate commit cannot be resolved")
    return result.stdout.decode("utf-8").strip()


def _tracked(repo: Path, relative: str) -> bool:
    result = _git(repo, "ls-files", "--error-unmatch", "--", relative)
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Structural scans. Each returns the first offending (path, detail) or None.
# ---------------------------------------------------------------------------


def scan_private_state(members: Mapping[str, bytes]) -> tuple[str, str] | None:
    for path in sorted(members):
        text = members[path].decode("utf-8", errors="replace")
        for pattern, description in PRIVATE_STATE_PATTERNS:
            match = pattern.search(text)
            if match is not None:
                return path, f"names {match.group(0)!r} ({description})"
    return None


def _imports(source: bytes) -> set[str]:
    """Top-level module names imported by a Python member, without executing it."""
    import ast

    try:
        tree = ast.parse(source.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError) as error:
        _refuse("EV_REFUSED_UNDECLARED_TOOL", f"a Python member does not parse: {error}")
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def _calls(source: bytes) -> set[str]:
    import ast

    tree = ast.parse(source.decode("utf-8"))
    names: set[str] = set()

    def dotted(node: ast.AST) -> str | None:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name is not None:
                names.add(name)
    return names


def scan_network(members: Mapping[str, bytes]) -> tuple[str, str] | None:
    for path in sorted(members):
        if not path.endswith(".py"):
            continue
        found = sorted(_imports(members[path]) & NETWORK_MODULES)
        if found:
            return path, f"imports {found[0]!r}"
    return None


def scan_undeclared_tool(members: Mapping[str, bytes]) -> tuple[str, str] | None:
    for path in sorted(members):
        if not path.endswith(".py"):
            continue
        source = members[path]
        found = sorted(_imports(source) & PROCESS_MODULES)
        if found:
            return path, f"imports {found[0]!r}"
        for call in sorted(_calls(source)):
            if any(call == prefix or call.startswith(prefix) for prefix in PROCESS_CALLS):
                return path, f"calls {call!r}"
    return None


def scan_members(members: Mapping[str, bytes]) -> None:
    """Run every structural refusal over an in-memory member table."""
    private = scan_private_state(members)
    if private is not None:
        _refuse("EV_REFUSED_PRIVATE_STATE", f"{private[0]} {private[1]}")
    network = scan_network(members)
    if network is not None:
        _refuse("EV_REFUSED_NETWORK", f"{network[0]} {network[1]}")
    tool = scan_undeclared_tool(members)
    if tool is not None:
        _refuse("EV_REFUSED_UNDECLARED_TOOL", f"{tool[0]} {tool[1]}")


# ---------------------------------------------------------------------------
# Generated members. They are constants: the package bytes must not depend on
# the host, the clock or the working directory.
# ---------------------------------------------------------------------------

_VERIFY_PY = '''#!/usr/bin/env python3
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
'''

_VERIFY_SH = """#!/bin/sh
# The shell convenience form of verify.py. It uses no external command: the
# directory of this script is derived by parameter expansion, and the interpreter
# is taken from PATH, which the caller must set to the interpreter's directory.
set -eu
here=${0%/*}
[ "$here" = "$0" ] && here=.
exec python3 -B "$here/verify.py" "$@"
"""

_README = """# A24 external verification package

This directory is a self-contained bundle: the A23 verifier, its frozen
specification, its producer and the expected records. It runs with a Python
interpreter at or above the declared minimum and nothing else.

## What it is

* `verify.py` recomputes the A23 records from `evidence/a23/SPEC.json` with the
  packaged producer, compares each produced record byte-for-byte with the
  packaged expected record, and first checks the package against its own
  manifest (the manifest body digest and every member digest), so a tampered
  package is refused before anything runs.
* `evidence/a23/build_evidence.py` is the producer; `forensics/tools/` holds the
  reference evaluator and the implementation adapters it imports.
* `PACKAGE-MANIFEST.json` names every member by path, size and SHA-256, the entry
  point, the minimum interpreter, the exact commands, and the declarations
  `network: false` and `privateState: none`.

## How to run it

Unpack or copy this directory into an empty place that is not the project
checkout, then run, with a fresh home and temporary directory:

    env -i PATH=<directory containing python3> HOME=<fresh dir> TMPDIR=<fresh dir> \\
        python3 verify.py

The same command is `sh verify.sh` when a POSIX shell is available. A run prints
one JSON line and exits 0 when every record matched.

## What a pass establishes, and what it does not

It establishes that, from these files alone, the packaged producer reproduces the
packaged specification and that the four records are byte-identical. It does not
establish that any claim in those records is true, that the A23 differential is a
proof, or that a party outside this project has run the package. No external
party has run this package, so its external status is
`EXTERNAL_REVIEW_PENDING`, which is not a pass.

## What it must not need

No network, no interpreter search path, no environment token, no absolute path,
no file outside this directory, no shell beyond the convenience wrapper, and no
toolchain beyond the interpreter. The builder and the verifier refuse a package
that violates any of these.
"""


def _pipeline_document() -> dict[str, Any]:
    return {
        "schema": SCHEMA_PIPELINE,
        "records": list(RECORDS),
        "steps": [
            {
                "id": "produce",
                "command": "<interpreter> -I -S -B evidence/a23/build_evidence.py --out <fresh records directory>",
                "establishes": "the packaged producer recomputes the specification, the "
                               "differential, the properties and the controls from the "
                               "packaged inputs",
                "doesNotEstablish": "that the differential is a proof, or that any "
                                    "record is true",
            },
            {
                "id": "compare",
                "command": "byte comparison of each produced record with the packaged expected record",
                "establishes": "the produced records are byte-identical to the records the "
                               "manifest binds",
                "doesNotEstablish": "that the packaged records are the latest ones, or that "
                                    "an external party reproduced them",
            },
        ],
        "externalStatus": "EXTERNAL_REVIEW_PENDING",
    }


def _generated_members() -> dict[str, bytes]:
    return {
        ENTRY_POINT: _VERIFY_PY.encode("utf-8"),
        ENTRY_SHELL: _VERIFY_SH.encode("utf-8"),
        "README.md": _README.encode("utf-8"),
        "PIPELINE.json": pretty(_pipeline_document()),
    }


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def _check_path(relative: str, declared: Mapping[str, str], repo: Path) -> Path:
    if not isinstance(relative, str) or not relative:
        _refuse("EV_REFUSED_ABSOLUTE_PATH", "a path is not a non-empty string")
    if os.path.isabs(relative):
        _refuse("EV_REFUSED_ABSOLUTE_PATH", f"{relative!r} is absolute")
    parts = Path(relative).parts
    if any(part in ("..", ".") for part in parts):
        _refuse("EV_REFUSED_ABSOLUTE_PATH", f"{relative!r} contains a parent traversal")
    if relative not in declared:
        _refuse(
            "EV_REFUSED_UNDECLARED_DEPENDENCY",
            f"{relative!r} is not in the declared input set",
        )
    target = repo / relative
    if target.is_symlink():
        resolved = target.resolve()
        try:
            resolved.relative_to(repo.resolve())
        except ValueError:
            _refuse(
                "EV_REFUSED_ABSOLUTE_PATH",
                f"{relative!r} is a symlink that resolves outside the tree",
            )
    if not target.is_file():
        _refuse("EV_REFUSED_MISSING_INPUT", f"{relative!r} does not exist as a file")
    if not _tracked(repo, relative):
        _refuse("EV_REFUSED_UNTRACKED_INPUT", f"{relative!r} is not tracked by Git")
    return target


def manifest_document(
    members: Mapping[str, bytes],
    *,
    commit: str,
    recorded_at: str,
) -> dict[str, Any]:
    """The manifest body. Deterministic: the member table is sorted by path."""
    rows = [
        {
            "path": path,
            "role": DECLARED_INPUTS.get(path)
            or GENERATED_INPUTS.get(path, "generated"),
            "bytes": len(members[path]),
            "sha256": sha256_bytes(members[path]),
        }
        for path in sorted(members)
    ]
    manifest: dict[str, Any] = {
        "schema": SCHEMA_MANIFEST,
        "kind": "external-verification-package",
        "packageId": "openssl-rs-a24-a23-admission",
        "candidate": {"commit": commit, "recordedAt": recorded_at},
        "entryPoint": ENTRY_POINT,
        "entryShell": ENTRY_SHELL,
        "minimumInterpreter": MINIMUM_INTERPRETER,
        "exactCommands": [
            "python3 verify.py",
            "sh verify.sh",
            "python3 verify.py --records <fresh records directory>",
        ],
        "strippedEnvironmentCommand": (
            "env -i PATH=<directory containing python3> HOME=<fresh dir> "
            "TMPDIR=<fresh dir> python3 verify.py"
        ),
        "declarations": {
            "network": False,
            "privateState": "none",
            "absolutePaths": False,
            "untrackedFiles": False,
            "externalToolchain": "none beyond the declared interpreter",
        },
        "records": list(RECORDS),
        "members": rows,
        "exclusionRule": EXCLUSION_RULE,
        "excluded": EXCLUDED_INPUTS,
        "refusalCodes": {code: REFUSALS[code]["condition"] for code in REFUSAL_CODES},
        "outcomes": [
            "PACKAGE_VERIFIED_IN_VENUE",
            "PACKAGE_UNVERIFIED",
            "PACKAGE_INVALID",
            "EXTERNAL_REVIEW_PENDING",
        ],
        "externalStatus": "EXTERNAL_REVIEW_PENDING",
    }
    manifest["packageDigest"] = manifest_digest(manifest)
    return manifest


def write_package(
    out: Path,
    members: Mapping[str, bytes],
    *,
    commit: str,
    recorded_at: str,
    replace: bool = True,
) -> dict[str, Any]:
    """Write the package bytes and the manifest. No admissibility check.

    This is the low-level constructor. ``build`` is the entry point a caller must
    use for a real package: it checks every input before this function sees it.
    The controls use this function because they construct packages that are
    deliberately inadmissible.
    """
    out = Path(out)
    if out.exists():
        if not replace:
            _refuse("EV_REFUSED_PACKAGE_MUTATED", f"{out} already exists")
        resolved = out.resolve()
        repository = REPO_ROOT.resolve()
        if resolved == repository or repository.is_relative_to(resolved):
            raise ValueError(
                f"refusing to replace {out}: it contains the repository"
            )
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for path in sorted(members):
        target = out / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(members[path])
    manifest = manifest_document(members, commit=commit, recorded_at=recorded_at)
    (out / MANIFEST_NAME).write_bytes(pretty(manifest))
    return manifest


def build(
    paths: Sequence[str] | None,
    out: Path,
    *,
    declared: Mapping[str, str] | None = None,
    repo: Path | None = None,
    commit: str | None = None,
    recorded_at: str = "2026-11-24",
) -> dict[str, Any]:
    """Build a package from the declared inputs.

    ``paths=None`` includes every declared input. A path that is absolute,
    escapes the tree, is outside ``declared``, is untracked or is missing is
    refused; so is a file that names private state, imports a network client or
    imports/calls another program.
    """
    repo = Path(repo if repo is not None else REPO_ROOT)
    declared = dict(declared if declared is not None else DECLARED_INPUTS)
    chosen = sorted(declared) if paths is None else list(paths)
    if not chosen:
        _refuse("EV_REFUSED_MISSING_INPUT", "the declared input set is empty")
    members: dict[str, bytes] = {}
    for relative in chosen:
        target = _check_path(relative, declared, repo)
        members[relative] = target.read_bytes()
    members.update(_generated_members())
    scan_members(members)
    manifest = write_package(
        out,
        members,
        commit=commit or _resolve_commit(repo),
        recorded_at=recorded_at,
        replace=True,
    )
    return manifest


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _files_under(directory: Path) -> set[str]:
    return {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.is_file()
    }


def _load_manifest(package_dir: Path) -> dict[str, Any]:
    path = package_dir / MANIFEST_NAME
    if not path.is_file():
        _refuse("EV_REFUSED_MISSING_INPUT", f"{MANIFEST_NAME} is absent")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        _refuse("EV_REFUSED_PACKAGE_MUTATED", f"{MANIFEST_NAME} does not parse: {error}")
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA_MANIFEST:
        _refuse("EV_REFUSED_PACKAGE_MUTATED", f"{MANIFEST_NAME} is not {SCHEMA_MANIFEST!r}")
    recorded = manifest.get("packageDigest")
    if not isinstance(recorded, str) or recorded != manifest_digest(manifest):
        _refuse(
            "EV_REFUSED_PACKAGE_MUTATED",
            "the manifest body no longer matches its recorded digest",
        )
    return manifest


def _check_package_bytes(
    package_dir: Path, manifest: Mapping[str, Any]
) -> dict[str, bytes]:
    declared = {
        row["path"]: row for row in manifest.get("members", []) if isinstance(row, dict)
    }
    if not declared:
        _refuse("EV_REFUSED_PACKAGE_MUTATED", "the manifest declares no members")
    present = _files_under(package_dir) - {MANIFEST_NAME}
    extra = sorted(present - set(declared))
    if extra:
        _refuse(
            "EV_REFUSED_PACKAGE_MUTATED",
            f"{len(extra)} file(s) present but not declared, first {extra[0]!r}",
        )
    missing = sorted(set(declared) - present)
    if missing:
        _refuse(
            "EV_REFUSED_MISSING_INPUT",
            f"{len(missing)} declared member(s) absent, first {missing[0]!r}",
        )
    members: dict[str, bytes] = {}
    for path in sorted(declared):
        data = (package_dir / path).read_bytes()
        row = declared[path]
        if len(data) != row.get("bytes") or sha256_bytes(data) != row.get("sha256"):
            _refuse(
                "EV_REFUSED_MANIFEST_MISMATCH",
                f"{path} does not match its recorded size and SHA-256",
            )
        members[path] = data
    return members


_AUDIT_DRIVER = '''"""Run the package entry point and record every file it opens.

Written by the verifier into its fresh temporary directory; it is not a package
member. The hook records an open whose resolved path is outside the package, the
interpreter's own library and the temporary run directory. It records rather
than blocks, so the observation is the evidence.
"""
from __future__ import annotations

import json
import os
import runpy
import sys
import sysconfig

NETWORK = {
    "aiohttp", "ftplib", "httpx", "imaplib", "nntplib", "poplib",
    "requests", "smtplib", "socket", "socketserver", "ssl", "telnetlib",
    "urllib.request", "webbrowser", "xmlrpc.client",
}


def _real(path):
    try:
        return os.path.realpath(os.fsdecode(path))
    except (TypeError, ValueError):
        return None


def _within(path, roots):
    for root in roots:
        if path == root or path.startswith(root.rstrip(os.sep) + os.sep):
            return True
    return False


def main(argv):
    package, records, result_path, allow = argv
    roots = [os.path.realpath(item) for item in allow.split(os.pathsep) if item]
    reads, writes = [], []

    def hook(event, args):
        if event not in ("open", "os.open"):
            return
        raw = args[0]
        if not isinstance(raw, (str, bytes, os.PathLike)):
            return
        path = _real(raw)
        if path is None or _within(path, roots):
            return
        mode = args[1] if len(args) > 1 else None
        writing = isinstance(mode, str) and any(ch in mode for ch in "wax+")
        (writes if writing else reads).append(path)

    sys.addaudithook(hook)
    entry = os.path.join(package, "verify.py")
    sys.argv = [entry, "--records", records]
    code = 0
    error = None
    try:
        runpy.run_path(entry, run_name="__main__")
    except SystemExit as exc:
        code = 0 if exc.code is None else (exc.code if isinstance(exc.code, int) else 1)
    except BaseException as exc:  # a crash is an observation, not a pass
        code = 1
        error = f"{type(exc).__name__}: {exc}"
    loaded = sorted(set(sys.modules) & NETWORK)
    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "exit": code,
                "error": error,
                "networkModules": loaded,
                "outsideReads": sorted(set(reads)),
                "outsideWrites": sorted(set(writes)),
            },
            handle,
            sort_keys=True,
        )
        handle.write("\\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''


def _interpreter_directory() -> Path:
    return Path(sys.executable).resolve().parent


def run_environment(home: Path, tmpdir: Path) -> dict[str, str]:
    """The stripped environment: one PATH entry, no inherited variable."""
    return {
        "PATH": str(_interpreter_directory()),
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "LANG": "C",
        "LC_ALL": "C",
    }


def _allowed_roots(package: Path, run_root: Path) -> list[str]:
    roots = [str(package.resolve()), str(run_root.resolve())]
    try:
        import sysconfig

        paths = sysconfig.get_paths()
        for key in ("stdlib", "platstdlib"):
            value = paths.get(key)
            if value:
                roots.append(value)
    except Exception:  # pragma: no cover - sysconfig is stdlib
        pass
    roots.append(str(_interpreter_directory()))
    return sorted(dict.fromkeys(roots))


def _unpack(package_dir: Path, members: Mapping[str, bytes], run_root: Path) -> Path:
    target = run_root / "package"
    for path in sorted(members):
        destination = target / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(members[path])
    (target / MANIFEST_NAME).write_bytes((package_dir / MANIFEST_NAME).read_bytes())
    return target


def _one_run(
    package_dir: Path, members: Mapping[str, bytes], run_root: Path
) -> dict[str, Any]:
    run_root.mkdir(parents=True)
    unpacked = _unpack(package_dir, members, run_root)
    home = run_root / "home"
    tmpdir = run_root / "tmpdir"
    records = run_root / "records"
    home.mkdir()
    tmpdir.mkdir()
    records.mkdir()
    driver = run_root / "audit_driver.py"
    driver.write_text(_AUDIT_DRIVER, encoding="utf-8")
    result_path = run_root / "audit.json"
    allow = os.pathsep.join(_allowed_roots(unpacked, run_root))
    command = [
        sys.executable,
        "-I",
        "-S",
        "-B",
        str(driver),
        str(unpacked),
        str(records),
        str(result_path),
        allow,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(unpacked),
            env=run_environment(home, tmpdir),
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        process_exit = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired:
        process_exit = -1
        stdout = ""
        stderr = "the entry point did not finish within 900 seconds"
    audit: dict[str, Any] = {}
    if result_path.is_file():
        audit = json.loads(result_path.read_text(encoding="utf-8"))
    produced = {
        name: (records / name).read_bytes()
        for name in RECORDS
        if (records / name).is_file()
    }
    return {
        "processExit": process_exit,
        "stdout": stdout,
        "stderrTail": stderr.strip().splitlines()[-1] if stderr.strip() else "",
        "audit": audit,
        "records": produced,
    }


def verify(
    package_dir: Path,
    *,
    claim: str = "in-venue",
    out: Path | None = None,
    recorded_at: str = "2026-11-24",
) -> dict[str, Any]:
    """Verify a package the way an outside party would have to.

    Returns a deterministic result document. A refusal raises ``Refusal``; the
    CLI turns it into the printed code and the ``PACKAGE_INVALID`` outcome.
    """
    package_dir = Path(package_dir)
    if not package_dir.is_dir():
        _refuse("EV_REFUSED_MISSING_INPUT", f"{package_dir} is not a directory")
    manifest = _load_manifest(package_dir)
    members = _check_package_bytes(package_dir, manifest)
    scan_members(members)
    entry = manifest.get("entryPoint")
    if entry != ENTRY_POINT or ENTRY_POINT not in members:
        _refuse("EV_REFUSED_MISSING_INPUT", f"the entry point {ENTRY_POINT!r} is not declared")
    if tuple(manifest.get("records", ())) != RECORDS:
        _refuse("EV_REFUSED_MANIFEST_MISMATCH", "the manifest declares a different record set")

    workdir = Path(tempfile.mkdtemp(prefix="a24-verify-"))
    try:
        first = _one_run(package_dir, members, workdir / "run-1")
        second = _one_run(package_dir, members, workdir / "run-2")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    for index, run in enumerate((first, second), 1):
        if run["processExit"] != 0 or run["audit"].get("exit", 1) != 0:
            _refuse(
                "EV_REFUSED_ENTRYPOINT_FAILED",
                f"run {index} exited {run['processExit']} "
                f"(entry {run['audit'].get('exit')}): "
                f"{run['stderrTail'] or run['audit'].get('error') or ''}".strip(),
            )
        if run["audit"].get("outsideReads") or run["audit"].get("outsideWrites"):
            outside = (run["audit"].get("outsideReads") or run["audit"].get("outsideWrites"))[0]
            _refuse(
                "EV_REFUSED_UNDECLARED_DEPENDENCY",
                f"run {index} opened {outside!r}, which is outside the package",
            )
        if run["audit"].get("networkModules"):
            _refuse(
                "EV_REFUSED_NETWORK",
                f"run {index} loaded {run['audit']['networkModules'][0]!r}",
            )

    if first["stdout"] != second["stdout"] or first["records"] != second["records"]:
        _refuse("EV_REFUSED_REPRODUCIBLE", "two runs produced different output")

    rows = []
    for name in RECORDS:
        expected = members[f"evidence/a23/{name}"]
        produced = first["records"].get(name)
        equal = produced == expected
        rows.append(
            {
                "record": name,
                "expectedSha256": sha256_bytes(expected),
                "producedSha256": sha256_bytes(produced) if produced is not None else None,
                "equal": equal,
            }
        )
        if not equal:
            _refuse(
                "EV_REFUSED_MANIFEST_MISMATCH",
                f"the produced {name} is not the record the package binds",
            )

    if claim not in ("in-venue", "external"):
        _refuse("EV_REFUSED_EXTERNAL_NOT_RUN", f"unknown claim {claim!r}")
    if claim == "external":
        _refuse(
            "EV_REFUSED_EXTERNAL_NOT_RUN",
            "no party outside this project has produced a verdict for this package; "
            "an in-venue run is not external reproduction",
        )

    result = {
        "schema": SCHEMA_RESULT,
        "packageDigest": manifest["packageDigest"],
        "candidate": manifest.get("candidate", {}),
        "minimumInterpreter": MINIMUM_INTERPRETER,
        "interpreter": sys.version.split()[0],
        "claim": claim,
        "runs": 2,
        "environment": {
            "stripped": True,
            "inheritedVariables": False,
            "pythonpath": None,
            "pathEntries": 1,
            "path": str(_interpreter_directory()),
            "home": "<fresh temporary directory>",
            "tmpdir": "<fresh temporary directory>",
            "isolationFlags": ["-I", "-S", "-B"],
        },
        "records": rows,
        "recordsCompared": len(rows),
        "checks": [
            {"id": "manifest-body", "result": "PASS"},
            {"id": "member-set", "result": "PASS"},
            {"id": "member-digests", "result": "PASS"},
            {"id": "private-state", "result": "PASS"},
            {"id": "no-network", "result": "PASS"},
            {"id": "no-external-program", "result": "PASS"},
            {"id": "entry-point", "result": "PASS"},
            {"id": "no-outside-read", "result": "PASS"},
            {"id": "reproducible", "result": "PASS"},
            {"id": "records-match", "result": "PASS"},
        ],
        "code": CODE_OK,
        "outcome": "PACKAGE_VERIFIED_IN_VENUE",
        "externalStatus": "EXTERNAL_REVIEW_PENDING",
        "externalPartyRan": False,
        "isExternal": False,
        "recordedAt": recorded_at,
    }
    if out is not None:
        Path(out).write_bytes(pretty(result))
    return result


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def inventory(package_dir: Path) -> dict[str, Any]:
    """Describe a package without running it. Intact but not run is UNVERIFIED."""
    package_dir = Path(package_dir)
    manifest = _load_manifest(package_dir)
    members = _check_package_bytes(package_dir, manifest)
    scan_members(members)
    return {
        "schema": SCHEMA_RESULT,
        "packageDigest": manifest["packageDigest"],
        "candidate": manifest.get("candidate", {}),
        "entryPoint": manifest.get("entryPoint"),
        "minimumInterpreter": manifest.get("minimumInterpreter"),
        "exactCommands": manifest.get("exactCommands", []),
        "members": [
            {"path": row["path"], "role": row.get("role"), "bytes": row["bytes"],
             "sha256": row["sha256"]}
            for row in manifest.get("members", [])
        ],
        "memberCount": len(members),
        "records": list(RECORDS),
        "code": CODE_OK,
        "outcome": "PACKAGE_UNVERIFIED",
        "externalStatus": "EXTERNAL_REVIEW_PENDING",
        "externalPartyRan": False,
    }


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _print(code: str, outcome: str, external: str = "EXTERNAL_REVIEW_PENDING") -> None:
    print(f"package-external: code={code} outcome={outcome} external={external}")


class _Parser(argparse.ArgumentParser):
    """An argument parser whose errors still print the code and the outcome."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"package-external: usage {message}")
        _print(CODE_USAGE, "PACKAGE_UNVERIFIED")
        raise SystemExit(EXIT_USAGE)


def _print_refusal(refusal: Refusal) -> None:
    outcome = "PACKAGE_INVALID"
    external = "EXTERNAL_REVIEW_PENDING"
    if refusal.code == "EV_REFUSED_EXTERNAL_NOT_RUN":
        outcome = "EXTERNAL_REVIEW_PENDING"
    print(f"package-external: refused {refusal.code}: {refusal.message}")
    _print(refusal.code, outcome, external)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(
        prog="package_external.py",
        description="build, verify and inventory an A24 external verification package",
    )
    sub = parser.add_subparsers(dest="command", parser_class=_Parser)
    build_parser = sub.add_parser("build", help="build a package from the declared inputs")
    build_parser.add_argument("--out", required=True)
    build_parser.add_argument("--commit", default=None)
    build_parser.add_argument("--json", action="store_true")
    verify_parser = sub.add_parser("verify", help="verify a package in this venue")
    verify_parser.add_argument("package")
    verify_parser.add_argument("--claim", default="in-venue", choices=("in-venue", "external"))
    verify_parser.add_argument("--out", default=None)
    verify_parser.add_argument("--json", action="store_true")
    inventory_parser = sub.add_parser("inventory", help="describe a package without running it")
    inventory_parser.add_argument("package")
    inventory_parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args(argv)

    if arguments.command is None:
        print("package-external: usage package_external.py build|verify|inventory")
        _print(CODE_USAGE, "PACKAGE_UNVERIFIED")
        return EXIT_USAGE

    try:
        if arguments.command == "build":
            manifest = build(None, Path(arguments.out), commit=arguments.commit)
            if arguments.json:
                print(pretty(manifest).decode("utf-8"), end="")
            print(
                f"package-external: built {len(manifest['members'])} member(s) "
                f"digest={manifest['packageDigest']}"
            )
            _print(CODE_OK, "PACKAGE_UNVERIFIED")
            return EXIT_OK

        if arguments.command == "verify":
            result = verify(
                Path(arguments.package),
                claim=arguments.claim,
                out=Path(arguments.out) if arguments.out else None,
            )
            if arguments.json:
                print(pretty(result).decode("utf-8"), end="")
            print(
                f"package-external: {result['recordsCompared']} record(s) compared, "
                f"2 run(s), interpreter {result['interpreter']}"
            )
            _print(result["code"], result["outcome"], result["externalStatus"])
            return EXIT_OK

        record = inventory(Path(arguments.package))
        if arguments.json:
            print(pretty(record).decode("utf-8"), end="")
        print(
            f"package-external: {record['memberCount']} member(s), "
            f"entry {record['entryPoint']}, interpreter >= {record['minimumInterpreter']}"
        )
        _print(record["code"], record["outcome"], record["externalStatus"])
        return EXIT_OK
    except Refusal as refusal:
        _print_refusal(refusal)
        return EXIT_REFUSED
    except (OSError, ValueError) as error:
        print(f"package-external: usage {error}")
        _print(CODE_USAGE, "PACKAGE_INVALID")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
