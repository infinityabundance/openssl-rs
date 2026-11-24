#!/usr/bin/env python3
"""build_evidence.py -- deterministic producer of the A25 public-surface records.

Writes four records into ``evidence/a25/`` and nothing else:

  SURFACE.json   the declaration: every command, its arguments, exit codes, JSON
                 fields, stability level, evidence and private-state reads;
  INVENTORY.json the executable surface as the verifier itself reports it, with
                 every discrepancy found by reading the source and a re-checked
                 witness for each;
  VERIFY.json    the declaration-vs-executable comparison, per command;
  CONTROLS.json  one control per refusal code, each isolating exactly one defect.

The producer is the authority for the bytes: it embeds the declaration, measures
the executable, runs the controls and writes sorted JSON.  Re-running it on the
same checkout reproduces every file byte for byte.  It exits 1 when the real
comparison refuses, when a control does not produce exactly its declared code,
or when a recorded discrepancy no longer reproduces -- a stale finding is a
failure of the record, not a pass.

Control stubs are test-only fixtures.  They imitate the real verifier's text so
that every check except the one under test succeeds; they are written into a
temporary directory, never into the package, and never appear in a shipped
configuration.

Python 3.11 standard library only.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics" / "tools"))

import public_surface as ps  # noqa: E402

EVIDENCE = ROOT / "evidence" / "a25"
VERIFIER = ROOT / "forensics" / "tools" / "verify.py"
BASE_COMMIT = "a9bcb54808eddfc11f7ab10215894e3c1064b21c"
BASE_SHORT = "a9bcb5480"

JSON_FIELDS = [
    "candidate", "counts", "environment", "interface", "invocation",
    "non_passing", "private_state", "root", "schema", "status", "steps",
    "warnings",
]

SINCE = "2026-11-23 (ETP-T12); this surface declared 2026-11-24 at a9bcb5480"

EVIDENCE_PATHS = ["forensics/tools/verify.py", "docs/PUBLIC-VERIFIER.md"]

ARGUMENTS = [
    {"name": "command", "kind": "positional", "takesValue": False,
     "summary": "one declared command name, or `all`; a bare invocation is refused"},
    {"name": "--json", "kind": "option", "takesValue": False,
     "summary": "emit the machine-readable document instead of the text report; "
                "no effect on the discovery commands"},
    {"name": "--network", "kind": "option", "takesValue": False,
     "summary": "declare that the network is available; a declaration, not a probe"},
    {"name": "--explain", "kind": "option", "takesValue": False,
     "summary": "print the declared prerequisites, establishment and non-claims; "
                "takes precedence over running a command"},
    {"name": "--list", "kind": "option", "takesValue": False,
     "summary": "print the command set as tab-separated name, role and "
                "all-membership; takes precedence over every other argument"},
    {"name": "--tmp", "kind": "option", "takesValue": True, "metavar": "TMP",
     "summary": "use this directory as the temporary root instead of a fresh one"},
    {"name": "--help", "kind": "option", "takesValue": False, "aliases": ["-h"],
     "summary": "print the usage message and exit 0"},
]

EXIT_CONTRACT = {
    "0": {"meaning": "every selected required step is PASS; a single requested step "
                     "gates on itself and must be PASS",
          "scope": "step commands and `all`"},
    "1": {"meaning": "at least one selected step is not PASS: FAIL, BLOCKED or "
                     "NOT_RUN. NOT_RUN is never a pass",
          "scope": "step commands and `all`"},
    "2": {"meaning": "the invocation was refused before any step ran: an unknown "
                     "subcommand, a malformed argument list, or a surface that "
                     "cannot be read",
          "scope": "every command"},
}

DISCOVERY = {
    "listing": {"argv": ["--list"], "format": "tsv",
                "columns": ["name", "role", "in_all"]},
    "listJson": {"argv": ["--list", "--json"], "format": "tsv", "emitsJson": False,
                 "note": "`--json` is accepted and has no effect on the listing; "
                         "the listing stays tab-separated"},
    "help": {"argv": ["--help"]},
    "explain": {"argv": ["--explain"]},
    "jsonProbe": {"command": "authority", "argv": ["authority", "--json"],
                  "environmentKey": "environment",
                  "environmentDeclaration": "environment-input",
                  "note": "`authority` without --network is NOT_RUN, which still "
                          "emits a complete document and exits 1; it therefore "
                          "costs nothing and depends on no candidate state"},
}

# Probes are the only way a declared exit code becomes an observed one.  Each is
# cheap, offline and independent of the candidate's verification verdicts.
EXIT_PROBES = [
    {"id": "list", "argv": ["--list"], "code": 0,
     "note": "the discovery listing; exercises the parser and exits 0"},
    {"id": "help", "argv": ["--help"], "code": 0,
     "note": "argparse's help path"},
    {"id": "explain", "argv": ["--explain"], "code": 0,
     "note": "the self-description path"},
    {"id": "explain-all", "argv": ["--explain", "all"], "code": 0,
     "note": "`all` is recognised as a command token by the same special case the "
             "run path uses"},
    {"id": "authority-offline", "argv": ["authority"], "code": 1,
     "note": "a single optional step gates on itself: with no network declared it "
             "is NOT_RUN and the run exits 1. No step executes"},
    {"id": "unknown-command", "argv": ["nosuch-command"], "code": 2,
     "note": "an unknown subcommand is refused before any step runs"},
    {"id": "malformed-arguments", "argv": ["--tmp"], "code": 2,
     "note": "an option missing its value is refused by the parser"},
    {"id": "explain-unknown", "argv": ["--explain", "nosuch-command"], "code": 2,
     "note": "explaining an undeclared command is refused"},
]

SUPPORT_TESTS = [
    "test_the_executable_inventory_matches_the_surface",
    "test_every_declared_exit_code_is_observed_or_command_specific",
    "test_two_listing_runs_are_byte_identical",
    "test_the_json_fields_are_exactly_the_declared_set",
    "test_every_refusal_code_is_documented",
]

EXIT_ZERO_BASIS = ("exit 0 is the PASS status of this command's own run; the surface "
                   "check does not execute step commands (cost and candidate state), "
                   "so the code is declared and not observed")
EXIT_ONE_BASIS = ("exit 1 is any non-PASS status of this command's own run; the "
                  "surface check does not execute step commands, so the code is "
                  "declared and not observed")

# name, summary, prerequisites, delegates, private roots
STEPS = [
    ("manifest", "check the tracked ETP-6 package manifest against this commit",
     ["git"], ["forensics/tools/etp6_package.py"], []),
    ("rebuild", "build the release library twice and compare the builds byte for byte",
     ["bash", "rustc", "cargo", "court", "memory:24"],
     ["forensics/tools/build_reproducibility.sh"], []),
    ("proofs", "regenerate the independent reference's vectors and run its "
               "classifier self-test",
     ["python"],
     ["forensics/etp5_crypto/make_vectors.py", "forensics/etp5_crypto/driver.py"], []),
    ("differential", "compare the reference, the candidate and the pinned authority "
                     "on sampled populations",
     ["bash", "rustc", "cargo", "court", "memory:24", "authority-prefix"],
     ["forensics/etp5_crypto/run_etp5.sh"],
     ["forensics/authorities/prefix", "court"]),
    ("instruments", "check the instrument register's identities and execute its "
                    "sensitivity controls",
     ["python"], ["forensics/tools/instrument_qualify.py"], ["court"]),
    ("controls", "run the verification tools' own negative controls and refusal paths",
     ["python"], ["forensics/tools/tests"], []),
    ("receipts", "apply rules R1-R5 to the committed interoperability receipts",
     ["python"], ["courts/phase18/interop/check_receipts.py"], []),
    ("claims", "validate the committed claim set, its laws and its Git-bound digests",
     ["python", "git"], ["forensics/tools/etp_claims.py"], []),
    ("freshness", "check every artefact's freshness verdict and the refusal rules "
                  "over them",
     ["python", "git"], ["forensics/tools/freshness.py"], []),
    ("independence", "check independence assignments and keep the recorded dissent",
     ["python", "git"], ["forensics/tools/independence.py"], []),
    ("closure", "audit the five-requirement exclusion bar and opaque-operation scope",
     ["python", "git"], ["forensics/tools/closure_discipline.py"], []),
    ("scheduling", "report the minimum verification tier each recorded change set "
                   "needs",
     ["python", "git"], ["forensics/tools/scheduling.py"], []),
    ("traceability", "validate the typed traceability graph and its declared orphans",
     ["python", "git"], ["forensics/tools/traceability.py"], []),
    ("hazards", "reconcile the hazard register with the traceability graph",
     ["python", "git"], ["forensics/tools/hazard_register.py"], []),
    ("binary", "check every asserted binary claim names its artefact, target and TCB",
     ["python"], ["forensics/tools/binary_assurance.py"], []),
    ("docs", "compare the documents' derived figures with the artefacts they cite",
     ["python"], ["forensics/tools/docs_consistency.py"], []),
    ("authority", "verify the local authority archives against their published "
                  "digests; needs the network",
     ["python", "network"], ["forensics/tools/authority_acquire.py"],
     ["forensics/authorities/downloads", "forensics/authorities/prefix"]),
    ("consumer-curl", "audit one consumer family's recorded closure receipt",
     ["python", "git"], ["forensics/tools/closure_discipline.py"],
     ["court", "artifacts/phase2/install"]),
    ("consumer-ssh", "audit one consumer family's recorded closure receipt",
     ["python", "git"], ["forensics/tools/closure_discipline.py"],
     ["court", "artifacts/phase2/install"]),
    ("consumer-sshd", "audit one consumer family's recorded closure receipt",
     ["python", "git"], ["forensics/tools/closure_discipline.py"],
     ["court", "artifacts/phase2/install"]),
]

ALL_DELEGATES = sorted({delegate for _name, _summary, _needs, delegates, _private
                        in STEPS for delegate in delegates})
ALL_PREREQUISITES = sorted({need for _name, _summary, needs, _delegates, _private
                            in STEPS for need in needs} - {"network"})


def _steps_exits(name: str) -> list[dict]:
    one = {"code": 1,
           "meaning": "the command is not PASS: FAIL, BLOCKED or NOT_RUN",
           "basis": EXIT_ONE_BASIS}
    if name == "authority":
        one = {"code": 1,
               "meaning": "the command is not PASS: here, NOT_RUN because the "
                          "network is not declared",
               "observedBy": "authority-offline"}
    return [
        {"code": 0, "meaning": "the command is PASS", "basis": EXIT_ZERO_BASIS},
        one,
        {"code": 2,
         "meaning": "the invocation was refused before any step ran",
         "observedBy": "unknown-command"},
    ]


def build_surface() -> dict:
    """The declaration.  Authored here, then checked against the executable."""
    commands: list[dict] = []
    for name, summary, needs, delegates, private in STEPS:
        commands.append({
            "name": name,
            "kind": "step",
            "invocation": [name],
            "summary": summary,
            "arguments": ["command", "--json", "--network", "--explain", "--list",
                          "--tmp", "--help"],
            "prerequisites": list(needs),
            "delegatesTo": list(delegates),
            "privateState": list(private),
            "exitCodes": _steps_exits(name),
            "jsonForm": "document",
            "jsonFields": list(JSON_FIELDS),
            "stability": "stable",
            "since": SINCE,
            "evidence": list(EVIDENCE_PATHS),
            "replacement": None,
        })
    commands.append({
        "name": "all",
        "kind": "aggregate",
        "invocation": ["all"],
        "recognisedBy": "explain-all",
        "summary": "run every step the listing marks `in all`, in the listed order",
        "arguments": ["command", "--json", "--network", "--explain", "--list",
                      "--tmp", "--help"],
        "prerequisites": ALL_PREREQUISITES,
        "delegatesTo": ALL_DELEGATES,
        "privateState": ["artifacts/phase2/install", "court",
                         "forensics/authorities/prefix"],
        "exitCodes": [
            {"code": 0, "meaning": "every selected required step is PASS",
             "basis": "`all` runs nineteen steps, including builds and the whole "
                      "tools suite; the surface check does not execute it, so the "
                      "code is declared and not observed"},
            {"code": 1, "meaning": "at least one selected step is not PASS",
             "basis": "as above: not executed by the surface check"},
            {"code": 2, "meaning": "the invocation was refused before any step ran",
             "observedBy": "unknown-command"},
        ],
        "jsonForm": "document",
        "jsonFields": list(JSON_FIELDS),
        "stability": "stable",
        "since": SINCE,
        "evidence": list(EVIDENCE_PATHS),
        "replacement": None,
        "notes": "`--explain` prints no block for `all`; its prerequisites and "
                 "delegates are the union of the nineteen steps it selects, "
                 "declared here and not printed by the executable",
    })
    commands.append({
        "name": "list",
        "kind": "discovery",
        "invocation": ["--list"],
        "recognisedBy": "list",
        "summary": "print the command set with each command's role and whether "
                   "`all` selects it",
        "arguments": ["command", "--json", "--network", "--explain", "--list",
                      "--tmp", "--help"],
        "prerequisites": ["python"],
        "delegatesTo": [],
        "privateState": [],
        "exitCodes": [
            {"code": 0, "meaning": "the listing was printed", "observedBy": "list"},
            {"code": 2, "meaning": "the invocation was malformed",
             "observedBy": "malformed-arguments"},
        ],
        "jsonForm": "none",
        "jsonFields": [],
        "stability": "stable",
        "since": SINCE,
        "evidence": list(EVIDENCE_PATHS),
        "replacement": None,
        "notes": "the only accepted form is the `--list` flag; the bare word `list` "
                 "is refused (recorded as discrepancy D1), and `--json` has no "
                 "effect on this output (D2)",
    })
    commands.append({
        "name": "explain",
        "kind": "discovery",
        "invocation": ["--explain"],
        "recognisedBy": "explain",
        "summary": "print each command's prerequisites, delegate, establishment and "
                   "non-claims, so the interface documents itself",
        "arguments": ["command", "--json", "--network", "--explain", "--list",
                      "--tmp", "--help"],
        "prerequisites": ["python"],
        "delegatesTo": [],
        "privateState": [],
        "exitCodes": [
            {"code": 0, "meaning": "the explanation was printed",
             "observedBy": "explain"},
            {"code": 2, "meaning": "an undeclared command was named",
             "observedBy": "explain-unknown"},
        ],
        "jsonForm": "none",
        "jsonFields": [],
        "stability": "stable",
        "since": SINCE,
        "evidence": list(EVIDENCE_PATHS),
        "replacement": None,
        "notes": "`--json` has no effect on this output",
    })
    return {
        "schemaVersion": ps.SCHEMA,
        "interface": "ETP-T12",
        "verifier": "forensics/tools/verify.py",
        "declaredAt": "2026-11-24",
        "declaredAtCommit": BASE_SHORT,
        "exitCodeContract": EXIT_CONTRACT,
        "discovery": DISCOVERY,
        "exitCodeProbes": EXIT_PROBES,
        "arguments": ARGUMENTS,
        "supportTestsPath": "forensics/tools/tests/test_public_surface.py",
        "supportTests": SUPPORT_TESTS,
        "privateStateRule": {
            "rule": "the surface reads no private state; each command declares the "
                    "gitignored roots its own delegate may read, and the document "
                    "reports which of them exist and how many untracked or ignored "
                    "entries each holds. Presence is never evidence",
            "enforcedBy": "PV_REFUSED_PRIVATE_STATE",
            "knownGap": "D4: `artifacts/phase2/install` is declared private by the "
                        "consumer commands but is outside the interface's audited "
                        "root set, so its presence can never be reported",
        },
        "determinismRule": {
            "rule": "two runs of a command emit the same deterministic record; the "
                    "declared `environment` block is an input and is not compared",
            "enforcedBy": "PV_REFUSED_UNSTABLE_OUTPUT",
            "knownGap": "D5: the top-level `private_state` entry counts are live "
                        "`git status` readings and are inside the compared record",
        },
        "stabilityRule": {
            "levels": {
                "stable": "the command name, arguments, exit codes and JSON fields "
                          "will not change incompatibly within this schema version; "
                          "a change needs a new schemaVersion and a recorded migration",
                "experimental": "may change without notice; do not program against it",
                "deprecated": "still executable; a replacement is named and removal "
                              "happens at the next schema version",
            },
            "supportRule": "every level needs `since` and an evidence path that "
                           "exists; `stable` also needs the surface's support tests "
                           "to exist in the declared test file",
            "enforcedBy": "PV_REFUSED_STABILITY_OVERCLAIM",
        },
        "commands": commands,
    }


# ---------------------------------------------------------------------------
# witnesses for the source-reading discrepancies
# ---------------------------------------------------------------------------


def _probe(argv: list[str]) -> ps.Run:
    return ps.run_verifier(VERIFIER, argv, ROOT)


def witness_exit(argv: list[str], code: int, contains: str | None = None) -> dict:
    run = _probe(argv)
    ok = run.exit == code and (contains is None or contains in run.combined)
    return {"kind": "exit", "argv": list(argv), "expectedExit": code,
            "observedExit": run.exit, "contains": contains,
            "observedHead": ps._head(run.combined), "reproduced": ok}


def witness_source(path: str, contains: list[str], absent: list[str]) -> dict:
    text = (ROOT / path).read_text(encoding="utf-8")
    missing = [item for item in contains if item not in text]
    unexpected = [item for item in absent if item in text]
    return {"kind": "source", "path": path, "contains": contains, "absent": absent,
            "missingFromSource": missing, "unexpectedlyPresent": unexpected,
            "reproduced": not missing and not unexpected}


def witness_block(path: str, start: str, end: str, contains: list[str],
                  absent: list[str]) -> dict:
    """Check a statement inside one named region of a file, not the whole file."""
    text = (ROOT / path).read_text(encoding="utf-8")
    begin = text.find(start)
    finish = text.find(end, begin + len(start)) if begin >= 0 else -1
    block = text[begin:finish + len(end)] if begin >= 0 and finish >= 0 else ""
    missing = [item for item in contains if item not in block]
    unexpected = [item for item in absent if item in block]
    return {"kind": "block", "path": path, "start": start, "end": end,
            "contains": contains, "absent": absent, "extracted": bool(block),
            "missingFromBlock": missing, "unexpectedlyPresent": unexpected,
            "reproduced": bool(block) and not missing and not unexpected}


def witness_json_absent(argv: list[str], pointer: list[str], key: str) -> dict:
    run = _probe(argv)
    try:
        node: object = json.loads(run.stdout)
        for part in pointer:
            node = node[part]  # type: ignore[index]
        absent = key not in node  # type: ignore[operator]
        keys = sorted(node) if isinstance(node, dict) else []
    except (TypeError, ValueError, KeyError):
        absent = False
        keys = []
    return {"kind": "json-absent", "argv": list(argv), "pointer": pointer,
            "key": key, "absent": absent, "reproduced": absent,
            "observedKeys": keys}


def witness_text(path: str, contains: list[str], absent: list[str]) -> dict:
    text = (ROOT / path).read_text(encoding="utf-8")
    missing = [item for item in contains if item not in text]
    unexpected = [item for item in absent if item in text]
    return {"kind": "text", "path": path, "contains": contains, "absent": absent,
            "missingFromText": missing, "unexpectedlyPresent": unexpected,
            "reproduced": not missing and not unexpected}


def witness_test_count(module: str, expected: int) -> dict:
    """The number of tests the loader actually executes for one module.

    ``discover`` over the containing directory is used rather than importing the
    module by dotted name, so the count is the runner's own count and does not
    depend on which package roots happen to be importable.
    """
    directory = ROOT / Path(*module.split(".")[:-1])
    suite = unittest.defaultTestLoader.discover(str(directory),
                                                pattern=f"{module.split('.')[-1]}.py")
    observed = suite.countTestCases()
    return {"kind": "test-count", "module": module, "expected": expected,
            "observed": observed, "reproduced": observed == expected}


def witness_shape(observation: str, holds: bool) -> dict:
    return {"kind": "shape", "observation": observation, "reproduced": bool(holds)}


def build_discrepancies() -> list[dict]:
    """What reading the source found that a shape comparison cannot see.

    Every entry carries a witness, and the producer refuses to write the record
    when a witness no longer reproduces.  A finding that has quietly stopped
    being true is a stale record, not a pass.
    """
    listing_json = _probe(["--list", "--json"]).stdout
    list_explain = _probe(["--list", "--explain"]).stdout
    authority_document = json.loads(_probe(["authority", "--json"]).stdout)
    return [
        {
            "id": "D1",
            "title": "`list` is advertised as a subcommand and is refused as one",
            "class": "TOOL_DEFECT_QUEUED",
            "statement":
                "`--help` calls the positional value 'a subcommand name, `all`, or "
                "`list`', the unknown-subcommand message lists `list` among the known "
                "names, and `main` writes `name = args.command or \"list\"`; but no "
                "dispatch branch accepts `list`, so `verify.py list` and a bare "
                "`verify.py` both print \"unknown subcommand 'list'\" and exit 2. "
                "The only accepted form is the `--list` flag, and that is the form "
                "the surface declares.",
            "witness": [
                witness_exit(["list"], 2, "unknown subcommand 'list'"),
                witness_exit([], 2, "unknown subcommand 'list'"),
                witness_source("forensics/tools/verify.py",
                               ["args.command or \"list\""],
                               ["elif name == \"list\""]),
            ],
            "surfaceEffect": "command `list` declares `invocation: [\"--list\"]`; the "
                             "bare word is never claimed",
            "documentEffect": "docs/PUBLIC-VERIFICATION.md's subcommand table row is "
                              "corrected from `list` to `--list` (old wording kept in "
                              "the A25 receipt)",
            "queued": "make `list` a real subcommand, or remove it from the help and "
                      "the refusal message; a flag and a subcommand of the same name "
                      "is a trap",
        },
        {
            "id": "D2",
            "title": "`--json` is accepted by the discovery commands and ignored",
            "class": "TOOL_DEFECT_QUEUED_DOCUMENTED",
            "statement":
                "`verify.py --list --json` prints the tab-separated listing and exits "
                "0; it does not emit a JSON document, because the listing branch "
                "returns before serialisation. The help text describes `--json` as "
                "'emit one machine-readable document' without an exception, and the "
                "descriptive document repeated that sentence. The surface declares "
                "the observed behaviour: the listing is TSV and only step runs emit "
                "a document.",
            "witness": [
                witness_exit(["--list", "--json"], 0),
                witness_shape("`--list --json` emits tab-separated text, not a JSON "
                              "object",
                              (not ps._is_json_object(listing_json))
                              and "\t" in listing_json),
                witness_source("forensics/tools/verify.py",
                               ["if args.list:"], []),
            ],
            "surfaceEffect": "`list`/`explain` declare `jsonForm: none`; the discovery "
                             "block records `emitsJson: false`",
            "documentEffect": "a clause naming the exception is added to the "
                              "descriptive document's `--json` paragraph (old wording "
                              "kept in the A25 receipt)",
            "queued": "either honour `--json` on the discovery commands or reject the "
                      "combination; a silently ignored flag is not a public argument",
        },
        {
            "id": "D3",
            "title": "the argument precedence among the discovery commands is "
                     "undocumented",
            "class": "DOCUMENTED_HERE",
            "statement":
                "`--list` takes precedence over `--explain`, which takes precedence "
                "over running the named command; `--json`, `--network` and `--tmp` "
                "have no effect on `--list` or `--explain`. The behaviour is stable "
                "and defensible, but it was in no document, so a caller could not "
                "tell which output to expect from `--list --explain`.",
            "witness": [
                witness_exit(["--list", "--explain"], 0),
                witness_shape("`--list --explain` prints the listing, not the "
                              "explanation blocks",
                              "\t" in list_explain and "needs:" not in list_explain),
            ],
            "surfaceEffect": "the precedence is part of the documented contract",
            "documentEffect": "docs/PUBLIC-VERIFIER.md states the precedence rule",
            "queued": None,
        },
        {
            "id": "D4",
            "title": "a declared private root is outside the audited root set",
            "class": "TOOL_DEFECT_QUEUED",
            "statement":
                "The three consumer commands declare `artifacts/phase2/install` as a "
                "private path, but the interface's audited root set names "
                "`artifacts/phase2/shell` instead. The declared path is therefore "
                "never counted, so `private_state_present` can never report it and "
                "the document's `known_roots` block omits it. A declared private read "
                "that presence-reporting cannot see is an under-report, not a "
                "declaration.",
            "witness": [
                witness_block("forensics/tools/verify.py", "PRIVATE_ROOTS = (", ")",
                              ["artifacts/phase2/shell"],
                              ["artifacts/phase2/install"]),
                witness_json_absent(["authority", "--json"],
                                    ["private_state", "known_roots"],
                                    "artifacts/phase2/install"),
                witness_exit(["--explain", "consumer-curl"], 0,
                             "artifacts/phase2/install"),
            ],
            "surfaceEffect": "the declaration is transcribed exactly; the surface does "
                             "not hide the interface's own declaration",
            "documentEffect": "the descriptive document's claim that a declared "
                              "private path is reported present or absent is left "
                              "unedited: the defect is the tool's, not the prose's",
            "queued": "add `artifacts/phase2/install` to the audited root set, or stop "
                      "declaring it private; then re-derive the presence fields",
        },
        {
            "id": "D5",
            "title": "live private-state readings sit inside the deterministic record",
            "class": "TOOL_DEFECT_QUEUED_DOCUMENTED",
            "statement":
                "The `environment` block is declared as an input and excluded from the "
                "two-run comparison, but `private_state` is a separate top-level block "
                "computed from `git status` and is inside the compared record. Two "
                "runs over the same checkout therefore differ if an untracked or "
                "ignored entry appears between them, and the published sentence "
                "excluded only the `environment` block.",
            "witness": [
                witness_block("forensics/tools/verify.py",
                              "def private_state_report(", "    return report\n",
                              ["private_entries", "\"status\", \"--porcelain\""], []),
                witness_json_absent(["authority", "--json"], ["environment"],
                                    "private_state"),
                witness_shape("the document carries `private_state` at top level, "
                              "outside the declared `environment` input block",
                              "private_state" in authority_document),
            ],
            "surfaceEffect": "the determinism rule is declared with its exact scope and "
                             "this gap named",
            "documentEffect": "one clause is added to the descriptive document's "
                              "determinism paragraph (old wording kept in the A25 "
                              "receipt)",
            "queued": "declare the private-state readings as an environment input, or "
                      "project them out of the compared record",
        },
        {
            "id": "D6",
            "title": "the descriptive document's test count was stale",
            "class": "DOCUMENT_DEFECT_CORRECTED",
            "statement":
                "docs/PUBLIC-VERIFICATION.md said `test_verify.py` holds 19 tests in "
                "two places. The module currently executes 37. The figure is a live "
                "quantity in a descriptive document that no generator corrects, which "
                "is exactly the drift the document was written to warn about.",
            "witness": [
                witness_test_count("forensics.tools.tests.test_verify", 37),
                witness_text("docs/PUBLIC-VERIFICATION.md", ["37 tests"],
                             ["19 tests"]),
            ],
            "surfaceEffect": "none",
            "documentEffect": "both mentions are corrected to 37; the old wording is "
                              "preserved in the A25 receipt",
            "queued": None,
        },
    ]


# ---------------------------------------------------------------------------
# control-only stubs
# ---------------------------------------------------------------------------

STUB_SOURCE = '''#!/usr/bin/env python3
"""control-only stub: imitates one verifier's observable surface."""
import json
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
config = json.loads((here / "stub.json").read_text(encoding="utf-8"))
counter = here / "counter"
count = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(count + 1))

argv = sys.argv[1:]
response = (config["responses"].get(json.dumps(argv))
            or config["responses"]["*"])
out = response.get("stdout", "")
if response.get("vary"):
    out = out.replace("__RUN__", str(count))
sys.stdout.write(out)
sys.exit(int(response["exit"]))
'''

FAITHFUL_DOCUMENT = {
    "candidate": {"clean": True, "commit": "0" * 40, "tracked_changes": 0,
                  "untracked_changes": 0},
    "counts": {"by_status": {"BLOCKED": 0, "FAIL": 0, "NOT_RUN": 1, "PASS": 0},
               "selected": 1},
    "environment": {"declared": "environment-input", "mem_available_bytes": 1,
                    "floor_met": False, "court": "control-stub"},
    "interface": "ETP-T12",
    "invocation": {"network": False, "steps": ["authority"], "tmpdir": "<tmp>"},
    "non_passing": ["authority"],
    "private_state": {"present": []},
    "root": "<root>",
    "schema": "openssl-rs/verify/1",
    "status": "FAIL",
    "steps": [],
    "warnings": [],
}

_BASE: dict | None = None


def base_text() -> dict:
    """The real verifier's own words, captured once, to imitate faithfully."""
    global _BASE
    if _BASE is None:
        _BASE = {
            "listing": _probe(["--list"]).stdout,
            "help": _probe(["--help"]).stdout,
            "explain": _probe(["--explain"]).stdout,
        }
    return _BASE


def stub_config(*, listing: str | None = None, help_text: str | None = None,
                explain_text: str | None = None, document: dict | None = None,
                exits: dict[str, int] | None = None,
                vary: bool = False) -> dict:
    base = base_text()
    listing = base["listing"] if listing is None else listing
    help_text = base["help"] if help_text is None else help_text
    explain_text = base["explain"] if explain_text is None else explain_text
    document = FAITHFUL_DOCUMENT if document is None else document
    if vary:
        document = copy.deepcopy(document)
        document["counts"] = {"by_status": {}, "selected": "__RUN__"}
    exits = exits or {}
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    responses = {
        json.dumps(["--list"]): {"stdout": listing, "exit": exits.get("list", 0)},
        json.dumps(["--list", "--json"]): {"stdout": listing,
                                           "exit": exits.get("list", 0)},
        json.dumps(["--help"]): {"stdout": help_text, "exit": 0},
        json.dumps(["--explain"]): {"stdout": explain_text, "exit": 0},
        json.dumps(["--explain", "all"]): {"stdout": explain_text, "exit": 0},
        json.dumps(["authority"]): {"stdout": "", "exit": exits.get("authority", 1)},
        json.dumps(["nosuch-command"]): {"stdout": "",
                                         "exit": exits.get("unknown-command", 2)},
        json.dumps(["--tmp"]): {"stdout": "", "exit": 2},
        json.dumps(["--explain", "nosuch-command"]): {"stdout": "", "exit": 2},
        json.dumps(["authority", "--json"]): {"stdout": text,
                                              "exit": exits.get("authority", 1),
                                              "vary": vary},
        "*": {"stdout": "", "exit": 2},
    }
    return {"responses": responses}


def write_stub(directory: Path, config: dict) -> Path:
    stub = directory / "stub_verifier.py"
    stub.write_text(STUB_SOURCE, encoding="utf-8")
    (directory / "stub.json").write_text(json.dumps(config, indent=2, sort_keys=True),
                                         encoding="utf-8")
    return stub


def _run_stub(surface: dict, config: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="a25-control-") as tmp:
        stub = write_stub(Path(tmp), config)
        return ps.verify(surface, stub, root=ROOT, verifier_label="control-stub")


def build_controls(surface: dict) -> list[dict]:
    controls: list[dict] = []

    def control(identifier: str, code: str | None, mutation: str,
                verdict: dict, expected: set[str]) -> None:
        observed = sorted({finding["code"] for finding in verdict["findings"]})
        controls.append({
            "id": identifier,
            "controlOnly": True,
            "code": code,
            "mutation": mutation,
            "expectedCodes": sorted(expected),
            "observedCodes": observed,
            "matches": set(observed) == set(expected),
            "findings": verdict["findings"],
        })

    # Positive control: an unmutated stub that imitates the real surface.
    control("faithful-stub", None,
            "no mutation: the stub repeats the real verifier's listing, help, "
            "explain and document", _run_stub(surface, stub_config()), set())

    # 1. an executable subcommand the surface does not declare
    config = stub_config()
    config["responses"][json.dumps(["--list"])]["stdout"] = (
        base_text()["listing"] + "surprise-step\trequired\tin all\n")
    control("undocumented-command", "PV_REFUSED_COMMAND_UNDOCUMENTED",
            "the stub lists `surprise-step`, which the surface does not declare",
            _run_stub(surface, config), {"PV_REFUSED_COMMAND_UNDOCUMENTED"})

    # 2. a documented command that is not executable
    mutated = copy.deepcopy(surface)
    mutated["commands"].append({
        "name": "sphinx", "kind": "step", "invocation": ["sphinx"],
        "summary": "a command the executable does not have",
        "arguments": ["command"], "prerequisites": [], "delegatesTo": [],
        "privateState": [], "exitCodes": [{"code": 0, "meaning": "PASS",
                                           "basis": EXIT_ZERO_BASIS}],
        "jsonForm": "none", "jsonFields": [], "stability": "experimental",
        "since": SINCE, "evidence": list(EVIDENCE_PATHS), "replacement": None,
    })
    control("absent-command", "PV_REFUSED_COMMAND_ABSENT",
            "the surface declares the step `sphinx`; the stub does not list it",
            _run_stub(mutated, stub_config()), {"PV_REFUSED_COMMAND_ABSENT"})

    # 3. an observed exit code with no declared meaning
    control("undefined-exit", "PV_REFUSED_EXIT_UNDEFINED",
            "the stub's unknown-subcommand path exits 7, which the exit contract "
            "does not define; exit 2 stays observed by two other probes",
            _run_stub(surface, stub_config(exits={"unknown-command": 7})),
            {"PV_REFUSED_EXIT_UNDEFINED"})

    # 4. a declared exit code no probe observes
    mutated = copy.deepcopy(surface)
    mutated["exitCodeContract"]["4"] = {"meaning": "a code nobody returns",
                                        "scope": "none"}
    control("unused-exit", "PV_REFUSED_EXIT_UNUSED",
            "the contract declares exit 4 and no probe produces it",
            _run_stub(mutated, stub_config()), {"PV_REFUSED_EXIT_UNUSED"})

    # 5. help text naming an argument the surface does not declare
    help_text = base_text()["help"] + "\n  --verbose   an argument nobody declared\n"
    control("help-drift", "PV_REFUSED_HELP_DRIFT",
            "`--help` names `--verbose`, which the surface does not declare",
            _run_stub(surface, stub_config(help_text=help_text)),
            {"PV_REFUSED_HELP_DRIFT"})

    # 6. an undeclared JSON field, and a missing declared field
    document = copy.deepcopy(FAITHFUL_DOCUMENT)
    document["surprise"] = True
    control("json-extra-field", "PV_REFUSED_JSON_FIELD",
            "the document carries the undeclared field `surprise`",
            _run_stub(surface, stub_config(document=document)),
            {"PV_REFUSED_JSON_FIELD"})
    document = copy.deepcopy(FAITHFUL_DOCUMENT)
    del document["counts"]
    control("json-missing-field", "PV_REFUSED_JSON_FIELD",
            "the document lacks the declared field `counts`",
            _run_stub(surface, stub_config(document=document)),
            {"PV_REFUSED_JSON_FIELD"})

    # 7. two runs producing different JSON
    control("unstable-output", "PV_REFUSED_UNSTABLE_OUTPUT",
            "the document's declared `counts` value carries a run counter, so two "
            "runs differ while the field set stays valid",
            _run_stub(surface, stub_config(vary=True)),
            {"PV_REFUSED_UNSTABLE_OUTPUT"})

    # 8. private state read without being declared
    explain_text = base_text()["explain"].replace(
        "manifest  (required; in `all`)",
        "manifest  (required; in `all`)\n  private:      court", 1)
    control("undeclared-private-state", "PV_REFUSED_PRIVATE_STATE",
            "the stub's `manifest` block declares a private read the surface does "
            "not", _run_stub(surface, stub_config(explain_text=explain_text)),
            {"PV_REFUSED_PRIVATE_STATE"})

    # 9. a surface with no schema version
    mutated = copy.deepcopy(surface)
    mutated.pop("schemaVersion")
    control("unversioned-schema", "PV_REFUSED_UNVERSIONED_SCHEMA",
            "the surface declares no `schemaVersion`",
            _run_stub(mutated, stub_config()), {"PV_REFUSED_UNVERSIONED_SCHEMA"})

    # 10. a deprecated command with no replacement
    mutated = copy.deepcopy(surface)
    for entry in mutated["commands"]:
        if entry["name"] == "docs":
            entry["stability"] = "deprecated"
            entry["replacement"] = None
    control("deprecated-without-replacement",
            "PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT",
            "`docs` is marked deprecated and names no successor",
            _run_stub(mutated, stub_config()),
            {"PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT"})

    # 11. a stability level the evidence does not support
    mutated = copy.deepcopy(surface)
    for entry in mutated["commands"]:
        if entry["name"] == "manifest":
            entry["evidence"] = ["evidence/a25/no-such-evidence.json"]
    control("stability-overclaim", "PV_REFUSED_STABILITY_OVERCLAIM",
            "`manifest` claims `stable` on an evidence path that does not exist",
            _run_stub(mutated, stub_config()), {"PV_REFUSED_STABILITY_OVERCLAIM"})

    # 12. a structurally invalid surface
    mutated = copy.deepcopy(surface)
    mutated["commands"].append(copy.deepcopy(
        next(entry for entry in mutated["commands"] if entry["name"] == "claims")))
    control("duplicate-command", "PV_REFUSED_SURFACE_INVALID",
            "the surface declares `claims` twice",
            _run_stub(mutated, stub_config()), {"PV_REFUSED_SURFACE_INVALID"})

    # 13. a malformed invocation of the detector itself
    run = subprocess.run([sys.executable, str(Path(ps.__file__)), "bogus-action"],
                         capture_output=True, text=True)
    tail = (run.stderr.strip().splitlines() or [""])[-1]
    controls.append({
        "id": "malformed-invocation",
        "controlOnly": True,
        "code": "PV_REFUSED_USAGE",
        "mutation": "the detector is invoked with an unknown action",
        "expectedCodes": ["PV_REFUSED_USAGE"],
        "observedCodes": (["PV_REFUSED_USAGE"]
                          if "PV_REFUSED_USAGE" in run.stderr else ["<none>"]),
        "matches": run.returncode == 2 and "PV_REFUSED_USAGE" in run.stderr,
        "findings": [{"code": "PV_REFUSED_USAGE", "detail": tail}],
    })

    return controls


# ---------------------------------------------------------------------------
# emission
# ---------------------------------------------------------------------------


def _write(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stamp(document: dict) -> dict:
    """Bind a record to the bytes of the two tools that produced it."""
    document["producer"] = {"path": "evidence/a25/build_evidence.py",
                            "sha256": _digest(Path(__file__))}
    document["detector"] = {"path": "forensics/tools/public_surface.py",
                            "sha256": _digest(Path(ps.__file__))}
    return document


def main() -> int:
    surface = build_surface()
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    _write(EVIDENCE / "SURFACE.json", surface)

    discrepancies = build_discrepancies()
    inventory = ps.inventory(surface, VERIFIER, root=ROOT,
                             discrepancies=discrepancies)
    _write(EVIDENCE / "INVENTORY.json", _stamp(inventory))

    verdict = ps.verify(surface, VERIFIER, root=ROOT)
    _write(EVIDENCE / "VERIFY.json", _stamp(verdict))

    controls = build_controls(surface)
    _write(EVIDENCE / "CONTROLS.json", _stamp({
        "schema": "openssl-rs/public-surface/controls/1",
        "candidate": {"commit": BASE_COMMIT, "short": BASE_SHORT},
        "note": "every row is control-only: a test-only stub or an in-memory "
                "mutation of the declaration, never a shipped configuration",
        "controls": controls,
        "counts": {
            "controls": len(controls),
            "codesCovered": len({row["code"] for row in controls if row["code"]}),
            "codes": sorted(ps.CODES),
            "failing": len([row for row in controls if not row["matches"]]),
        },
    }))

    reproduced = [w for entry in discrepancies for w in entry["witness"]
                  if not w["reproduced"]]
    failing = [row["id"] for row in controls if not row["matches"]]
    codes = sorted({finding["code"] for finding in verdict["findings"]})
    print(f"a25: base={BASE_SHORT} commands={len(surface['commands'])} "
          f"steps={inventory['counts']['listedSteps']} "
          f"json-fields={inventory['counts']['declaredJsonFields']} "
          f"discrepancies={len(discrepancies)} "
          f"control-codes={len(ps.CODES)} "
          f"controls={len(controls)} failing={len(failing)} "
          f"witnesses-not-reproduced={len(reproduced)} "
          f"verify={','.join(codes) or 'PV_OK'}")
    if codes:
        for finding in verdict["findings"]:
            print(f"  {finding['code']}: {finding['detail']}")
    for witness in reproduced:
        print(f"  STALE WITNESS: {witness.get('kind')} "
              f"{witness.get('argv') or witness.get('path')}")
    for identifier in failing:
        row = next(item for item in controls if item["id"] == identifier)
        print(f"  CONTROL FAILED: {identifier}: expected {row['expectedCodes']} "
              f"observed {row['observedCodes']}")
    ok = not codes and not failing and not reproduced
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
