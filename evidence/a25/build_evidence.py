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
or when a live discrepancy witness no longer reproduces -- a stale finding is a
failure of the record, not a pass.

``declaredAtCommit`` is an explicit input, never the live ``HEAD``.  It defaults
to the value already in ``SURFACE.json`` when one exists, and ``--declared-at
COMMIT`` re-declares it.  The declaration also records the SHA-256 of the two
sources it is about (``DECLARED_SOURCES``).  If either source moves, the record
refuses with a named code instead of reproducing bytes that now describe a
different executable; the refusal codes are ``A25_REFUSED_DECLARED_SOURCE_MOVED``
(a recorded declaration no longer matches the measured tool),
``A25_REFUSED_DECLARED_AT_UNKNOWN`` (the named commit is not in this repository)
and ``A25_REFUSED_DECLARED_AT_MISMATCH`` (the named commit does not contain the
measured tool).  A refusal exits 3 and writes nothing.

Discrepancies are historical where they have been repaired: each entry keeps the
old behaviour and the old witness (``observedAt`` the A25 candidate, expected
**not** to reproduce now), and carries a live witness for the repaired
behaviour, which must reproduce.  A historical witness that starts reproducing
again is a regression and fails the producer.

Control stubs are test-only fixtures.  They imitate the real verifier's text so
that every check except the one under test succeeds; they are written into a
temporary directory, never into the package, and never appear in a shipped
configuration.

Python 3.11 standard library only.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
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
SURFACE_PATH = EVIDENCE / "SURFACE.json"
VERIFIER = ROOT / "forensics" / "tools" / "verify.py"

# The declaration is *about* these two files.  If either changes, the record must
# refuse rather than reproduce bytes that describe a different executable.  The
# producer itself is deliberately absent: its digest is written into the records,
# and a declaration cannot be bound to the bytes of the program that writes it.
DECLARED_SOURCES = [
    "forensics/tools/public_surface.py",
    "forensics/tools/verify.py",
]

# Historical facts, not live readings: the candidate at which A25 first declared
# the surface, and the date of that declaration.  Neither is re-derived from HEAD.
OLD_COMMIT = "a9bcb54808eddfc11f7ab10215894e3c1064b21c"
OLD_SHORT = "a9bcb5480"
DEFAULT_DECLARED_AT = "2026-11-24"

REFUSED_SOURCE_MOVED = "A25_REFUSED_DECLARED_SOURCE_MOVED"
REFUSED_COMMIT_UNKNOWN = "A25_REFUSED_DECLARED_AT_UNKNOWN"
REFUSED_COMMIT_MISMATCH = "A25_REFUSED_DECLARED_AT_MISMATCH"
EXIT_REFUSED_DECLARATION = 3

JSON_FIELDS = [
    "candidate", "counts", "environment", "interface", "invocation",
    "non_passing", "private_state", "root", "schema", "status", "steps",
    "warnings",
]

SINCE = ("2026-11-23 (ETP-T12); this surface declared 2026-11-24 at a9bcb5480")
# `since` names when the stability level began (the A25 declaration).  It is a
# historical token and is not rewritten when the record is re-derived at a later
# candidate: `declaredAtCommit` names that candidate.

EVIDENCE_PATHS = ["forensics/tools/verify.py", "docs/PUBLIC-VERIFIER.md"]

ARGUMENTS = [
    {"name": "command", "kind": "positional", "takesValue": False,
     "summary": "one declared command name, or `all`; a bare invocation is refused"},
    {"name": "--json", "kind": "option", "takesValue": False,
     "summary": "emit the machine-readable document: the run document for a step "
                "run or `all`, and the listing document for `list` or `--list`; "
                "`--explain` and `--help` print text"},
    {"name": "--network", "kind": "option", "takesValue": False,
     "summary": "declare that the network is available; a declaration, not a probe"},
    {"name": "--explain", "kind": "option", "takesValue": False,
     "summary": "print the declared prerequisites, establishment and non-claims; "
                "takes precedence over running a command"},
    {"name": "--list", "kind": "option", "takesValue": False,
     "summary": "print the command set as tab-separated name, role and "
                "all-membership (or, with `--json`, the listing document); takes "
                "precedence over every other argument"},
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
    "listJson": {"argv": ["--list", "--json"], "format": "json",
                 "emitsJson": True,
                 "schema": "openssl-rs/verify-listing/1",
                 "fields": ["commands", "interface", "schema"],
                 "note": "`--json` is honoured on the listing: `--list --json` "
                         "and `list --json` emit the listing document (A25 D2 "
                         "repaired)"},
    "help": {"argv": ["--help"]},
    "explain": {"argv": ["--explain"]},
    "jsonProbe": {"command": "authority", "argv": ["authority", "--json"],
                  "environmentKey": "environment",
                  "environmentDeclaration": "environment-input",
                  "privateStateKey": "private_state",
                  "privateStateDeclaration": "private-state-input",
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
    {"id": "list-subcommand", "argv": ["list"], "code": 0,
     "note": "the discovery command as a real subcommand; exercises the repaired "
             "D1 dispatch and exits 0"},
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
     ["python", "git"], ["forensics/tools/closure_discipline.py"], ["court"]),
    ("consumer-ssh", "audit one consumer family's recorded closure receipt",
     ["python", "git"], ["forensics/tools/closure_discipline.py"], ["court"]),
    ("consumer-sshd", "audit one consumer family's recorded closure receipt",
     ["python", "git"], ["forensics/tools/closure_discipline.py"], ["court"]),
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


def build_surface(declaration: dict) -> dict:
    """The declaration.  Authored here, then checked against the executable.

    ``declaration`` carries the explicit identity this record is derived at:
    ``commit``, ``commitShort``, ``date`` and the ``sources`` digests.  Nothing in
    the document is read from the live ``HEAD``.
    """
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
        "privateState": ["court", "forensics/authorities/prefix"],
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
        "jsonForm": "document",
        "jsonFields": ["commands", "interface", "schema"],
        "stability": "stable",
        "since": SINCE,
        "evidence": list(EVIDENCE_PATHS),
        "replacement": None,
        "notes": "accepted as the `list` subcommand and as the `--list` flag; a "
                 "bare invocation is refused (exit 2). `--json` emits the "
                 "listing document (A25 D1 and D2 repaired)",
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
        "notes": "`--json` has no effect on this output (D7: accepted and "
                 "ignored; the contract states it, the `--help` sentence does not)",
    })
    return {
        "schemaVersion": ps.SCHEMA,
        "interface": "ETP-T12",
        "verifier": "forensics/tools/verify.py",
        "declaredAt": declaration["date"],
        "declaredAtCommit": declaration["commit"],
        "declaredAtCommitShort": declaration["commitShort"],
        "declaredSources": declaration["sources"],
        "exitCodeContract": EXIT_CONTRACT,
        "discovery": DISCOVERY,
        "exitCodeProbes": EXIT_PROBES,
        "arguments": ARGUMENTS,
        "supportTestsPath": "forensics/tools/tests/test_public_surface.py",
        "supportTests": SUPPORT_TESTS,
        "privateStateRule": {
            "rule": "the surface reads no private state; each command declares the "
                    "gitignored roots its own delegate may read, and the document "
                    "reports which of those roots exist and how many untracked or "
                    "ignored entries each holds. The audited root set is the "
                    "interface's known roots plus every declared read, so a "
                    "declared path cannot lie outside presence reporting. Presence "
                    "is never evidence",
            "enforcedBy": "PV_REFUSED_PRIVATE_STATE",
            "knownGap": None,
        },
        "determinismRule": {
            "rule": "two runs of a command emit the same deterministic record; the "
                    "declared `environment` and `private_state` blocks are inputs, "
                    "required to be present and populated, and are not compared",
            "enforcedBy": "PV_REFUSED_UNSTABLE_OUTPUT",
            "knownGap": None,
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


def witness_shape(observation: str, holds: bool) -> dict:
    return {"kind": "shape", "observation": observation, "reproduced": bool(holds)}


def witness_explain_private(step: str, expected: list[str]) -> dict:
    """One command's declared private roots, as the executable itself prints them."""
    blocks = ps.parse_explain(_probe(["--explain"]).stdout)
    observed = sorted(blocks.get(step, {}).get("private") or [])
    return {"kind": "explain-private", "argv": ["--explain"], "step": step,
            "expected": sorted(expected), "observed": observed,
            "reproduced": observed == sorted(expected)}


def witness_declared_reads_audited(surface: dict) -> dict:
    """Every private read the surface declares is inside the audited root set."""
    document = json.loads(_probe(["authority", "--json"]).stdout)
    known = set((document.get("private_state") or {}).get("known_roots") or {})
    declared = sorted({root for entry in surface["commands"]
                       for root in entry.get("privateState") or []})
    missing = [root for root in declared if root not in known]
    return {"kind": "declared-reads-audited", "argv": ["authority", "--json"],
            "declaredReads": declared, "auditedRoots": sorted(known),
            "missingFromAudit": missing, "reproduced": not missing}


def witness_json_value(argv: list[str], pointer: list[str], key: str,
                       expected: object) -> dict:
    run = _probe(argv)
    try:
        node: object = json.loads(run.stdout)
        for part in pointer:
            node = node[part]  # type: ignore[index]
        observed = node.get(key) if isinstance(node, dict) else None
    except (TypeError, ValueError, KeyError):
        observed = None
    return {"kind": "json-value", "argv": list(argv), "pointer": pointer,
            "key": key, "expected": expected, "observed": observed,
            "reproduced": observed == expected}


def witness_listing_document() -> dict:
    """The listing document: its schema, its fields, and both accepted forms."""
    flag = _probe(["--list", "--json"])
    word = _probe(["list", "--json"])
    try:
        document = json.loads(flag.stdout)
    except ValueError:
        document = None
    fields = sorted(document) if isinstance(document, dict) else []
    schema = document.get("schema") if isinstance(document, dict) else None
    return {"kind": "listing-document", "argv": ["--list", "--json"],
            "fields": fields, "schema": schema,
            "subcommandIdentical": flag.stdout == word.stdout,
            "observedExit": flag.exit,
            "reproduced": (fields == ["commands", "interface", "schema"]
                           and schema == "openssl-rs/verify-listing/1"
                           and flag.stdout == word.stdout and flag.exit == 0)}


def witness_surface_private(surface: dict, step: str, expected: list[str]) -> dict:
    entry = next((item for item in surface["commands"] if item["name"] == step), None)
    observed = sorted((entry or {}).get("privateState") or [])
    return {"kind": "surface-private", "step": step,
            "expected": sorted(expected), "observed": observed,
            "reproduced": observed == sorted(expected)}


def witness_test_count_matches_document(module: str, path: str) -> dict:
    """The figure a descriptive document states for a module is the executed count."""
    directory = ROOT / Path(*module.split(".")[:-1])
    suite = unittest.defaultTestLoader.discover(str(directory),
                                                pattern=f"{module.split('.')[-1]}.py")
    executed = suite.countTestCases()
    text = (ROOT / path).read_text(encoding="utf-8")
    claim = f"{executed} tests"
    return {"kind": "test-count-document", "module": module, "path": path,
            "executed": executed, "claim": claim,
            "containsClaim": claim in text, "staleClaimPresent": "19 tests" in text,
            "reproduced": claim in text and "19 tests" not in text}


def build_discrepancies(surface: dict, declaration: dict) -> list[dict]:
    """What reading the source found that a shape comparison cannot see.

    A discrepancy is *historical* once it has been repaired or documented.  Each
    entry keeps the behaviour that was observed at ``OLD_COMMIT`` and the witness
    that observed it, marked ``historicalWitness`` and ``observedAt``.  A
    historical witness is expected **not** to reproduce at this candidate: if it
    does, the repair has regressed and the producer fails.  Each entry also
    carries a live ``witness`` for the behaviour that holds now, which must
    reproduce; a witness that stops reproducing is a stale record, not a pass.
    """
    listing_json = _probe(["--list", "--json"]).stdout
    list_explain = _probe(["--list", "--explain"]).stdout
    explain_json = _probe(["--explain", "--json"])
    help_json = _probe(["--help", "--json"])
    repaired = {"repairedAt": declaration["commit"],
                "repairedAtShort": declaration["commitShort"]}
    return [
        {
            "id": "D1",
            "title": "`list` was advertised as a subcommand and refused as one",
            "class": "TOOL_DEFECT_REPAIRED",
            "status": "repaired",
            "foundAt": OLD_COMMIT,
            **repaired,
            "statement":
                "At a9bcb5480 `--help` called the positional value 'a subcommand "
                "name, `all`, or `list`', the unknown-subcommand message listed "
                "`list` among the known names, and `main` wrote `name = "
                "args.command or \"list\"`; but no dispatch branch accepted "
                "`list`, so `verify.py list` and a bare `verify.py` both printed "
                "\"unknown subcommand 'list'\" and exited 2. The only accepted "
                "form was the `--list` flag.",
            "oldBehaviour": "`verify.py list` -> exit 2, `unknown subcommand "
                            "'list'`; a bare `verify.py` -> exit 2 with the same "
                            "message; source carried `args.command or \"list\"`.",
            "repair": "`list` is a real subcommand routed through `emit_listing` "
                      "and exits 0; the `args.command or \"list\"` default is "
                      "replaced by an explicit `None` refusal whose message names "
                      "the accepted forms. Repaired in the D1-D5 batch at "
                      f"{declaration['commitShort']} "
                      "(evidence/defects/d1-d5/RECEIPT.md).",
            "witness": [
                witness_exit(["list"], 0, "manifest\trequired\tin all"),
                witness_exit([], 2, "no subcommand"),
                witness_source("forensics/tools/verify.py",
                               ["args.command == \"list\""],
                               ["args.command or \"list\""]),
            ],
            "historicalWitness": [
                {**witness_exit(["list"], 2, "unknown subcommand 'list'"),
                 "observedAt": OLD_COMMIT, "supersededAt": declaration["commit"]},
                {**witness_exit([], 2, "unknown subcommand 'list'"),
                 "observedAt": OLD_COMMIT, "supersededAt": declaration["commit"]},
                {**witness_source("forensics/tools/verify.py",
                                  ["args.command or \"list\""], []),
                 "observedAt": OLD_COMMIT, "supersededAt": declaration["commit"]},
            ],
            "surfaceEffect": "command `list` declares `invocation: [\"--list\"]` and "
                             "the `list` subcommand probe; the bare word is refused",
            "documentEffect": "docs/PUBLIC-VERIFIER.md §2.1 states the repaired "
                              "dispatch; §9 records it as repaired",
            "queued": None,
        },
        {
            "id": "D2",
            "title": "`--json` was accepted by the discovery listing and ignored",
            "class": "TOOL_DEFECT_REPAIRED",
            "status": "repaired",
            "foundAt": OLD_COMMIT,
            **repaired,
            "statement":
                "At a9bcb5480 `verify.py --list --json` printed the tab-separated "
                "listing and exited 0; no JSON document was emitted, because the "
                "listing branch returned before serialisation. The help text "
                "described `--json` as 'emit one machine-readable document' with "
                "no exception.",
            "oldBehaviour": "`--list --json` -> exit 0 with TSV, not a JSON object; "
                            "`verify.py` contained no `LISTING_SCHEMA`.",
            "repair": "`listing_rows`, `listing_document`, `render_listing` and "
                      "`emit_listing` emit the listing document when `--json` is "
                      "set, in both the `list` and `--list` forms. Repaired in the "
                      "D1-D5 batch at " f"{declaration['commitShort']}.",
            "witness": [
                witness_exit(["--list", "--json"], 0),
                witness_listing_document(),
                witness_source("forensics/tools/verify.py",
                               ["LISTING_SCHEMA", "def emit_listing"], []),
            ],
            "historicalWitness": [
                {**witness_shape("`--list --json` emits tab-separated text, not a "
                                  "JSON object",
                                  (not ps._is_json_object(listing_json))
                                  and "\t" in listing_json),
                 "observedAt": OLD_COMMIT, "supersededAt": declaration["commit"]},
                {**witness_source("forensics/tools/verify.py", [],
                                  ["LISTING_SCHEMA"]),
                 "observedAt": OLD_COMMIT, "supersededAt": declaration["commit"]},
            ],
            "surfaceEffect": "`list` declares `jsonForm: document` with the listing "
                             "document's three fields; the discovery block records "
                             "`emitsJson: true` and the schema",
            "documentEffect": "docs/PUBLIC-VERIFIER.md §4 documents the listing "
                              "document; §9 records the repair",
            "queued": None,
        },
        {
            "id": "D3",
            "title": "the argument precedence among the discovery commands was "
                     "undocumented",
            "class": "DOCUMENTED_HERE",
            "status": "documented",
            "foundAt": OLD_COMMIT,
            "repairedAt": None,
            "repairedAtShort": None,
            "statement":
                "`--list` takes precedence over `--explain`, which takes precedence "
                "over running the named command; `--json`, `--network` and `--tmp` "
                "have no effect on `--list` or `--explain`. The behaviour is stable "
                "and defensible, but it was in no document, so a caller could not "
                "tell which output to expect from `--list --explain`.",
            "oldBehaviour": "the precedence existed but no document stated it.",
            "repair": "documented as part of the contract (docs/PUBLIC-VERIFIER.md "
                      "§2.1); no executable change was needed or made.",
            "witness": [
                witness_exit(["--list", "--explain"], 0),
                witness_shape("`--list --explain` prints the listing, not the "
                              "explanation blocks",
                              "\t" in list_explain and "needs:" not in list_explain),
                witness_source("docs/PUBLIC-VERIFIER.md",
                               ["takes precedence over `--explain`"], []),
            ],
            "historicalWitness": [],
            "surfaceEffect": "the precedence is part of the documented contract",
            "documentEffect": "docs/PUBLIC-VERIFIER.md §2.1 states the precedence "
                              "rule; §9 records it as documented",
            "queued": None,
        },
        {
            "id": "D4",
            "title": "a declared private root was outside the audited root set",
            "class": "TOOL_DEFECT_REPAIRED",
            "status": "repaired",
            "foundAt": OLD_COMMIT,
            **repaired,
            "statement":
                "At a9bcb5480 the three consumer commands declared "
                "`artifacts/phase2/install` as a private path, but the interface's "
                "audited root set named `artifacts/phase2/shell` instead. The "
                "declared path was therefore never counted, so presence-reporting "
                "could never report it. A declared private read that presence "
                "reporting cannot see is an under-report, not a declaration.",
            "oldBehaviour": "`--explain consumer-curl` printed `private: court, "
                            "artifacts/phase2/install`; the audited set omitted "
                            "`install`.",
            "repair": "the declaration is removed, because all 155 files under "
                      "`artifacts/phase2/install` are Git-tracked checkout content "
                      "with no untracked or ignored entry; and "
                      "`audited_private_roots()` now derives the audited set from "
                      "the known roots plus every declared read. Repaired in the "
                      "D1-D5 batch at " f"{declaration['commitShort']}.",
            "witness": [
                witness_explain_private("consumer-curl", ["court"]),
                witness_declared_reads_audited(surface),
                witness_surface_private(surface, "consumer-curl", ["court"]),
            ],
            "historicalWitness": [
                {**witness_surface_private(surface, "consumer-curl",
                                           ["artifacts/phase2/install", "court"]),
                 "observedAt": OLD_COMMIT, "supersededAt": declaration["commit"]},
                {**witness_explain_private("consumer-curl",
                                           ["artifacts/phase2/install", "court"]),
                 "observedAt": OLD_COMMIT, "supersededAt": declaration["commit"]},
            ],
            "surfaceEffect": "the consumer commands declare `court` only; the "
                             "private-state rule names the derived audited set and "
                             "no known gap",
            "documentEffect": "docs/PUBLIC-VERIFIER.md §6 states the derived "
                              "audited set; §9 records the repair",
            "queued": None,
        },
        {
            "id": "D5",
            "title": "live private-state readings sat inside the deterministic "
                     "record",
            "class": "TOOL_DEFECT_REPAIRED",
            "status": "repaired",
            "foundAt": OLD_COMMIT,
            **repaired,
            "statement":
                "At a9bcb5480 the `environment` block was declared as an input and "
                "excluded from the two-run comparison, but `private_state` was a "
                "separate top-level block computed from `git status` and was inside "
                "the compared record. Two runs over the same checkout therefore "
                "differed if an untracked or ignored entry appeared between them, "
                "and the published sentence excluded only `environment`.",
            "oldBehaviour": "`private_state` carried no `declared` marker; "
                            "`verify.py` had no `INPUT_KEYS`; the block was "
                            "compared between runs.",
            "repair": "`private_state` is declared as `private-state-input`, "
                      "required to be present and populated, and excluded from the "
                      "compared projection alongside `environment`; the detector "
                      "refuses a document that does not declare it. Repaired in the "
                      "D1-D5 batch at " f"{declaration['commitShort']}.",
            "witness": [
                witness_json_value(["authority", "--json"], ["private_state"],
                                   "declared", "private-state-input"),
                witness_source("forensics/tools/verify.py",
                               ["INPUT_KEYS", "PRIVATE_STATE_DECLARATION"], []),
                witness_shape("the surface's determinism rule names both declared "
                              "inputs and records no known gap",
                              surface["determinismRule"]["knownGap"] is None
                              and "private_state" in surface["determinismRule"]["rule"]),
            ],
            "historicalWitness": [
                {**witness_json_absent(["authority", "--json"], ["private_state"],
                                       "declared"),
                 "observedAt": OLD_COMMIT, "supersededAt": declaration["commit"]},
                {**witness_source("forensics/tools/verify.py", [], ["INPUT_KEYS"]),
                 "observedAt": OLD_COMMIT, "supersededAt": declaration["commit"]},
            ],
            "surfaceEffect": "the determinism rule names both inputs and clears "
                             "`knownGap`",
            "documentEffect": "docs/PUBLIC-VERIFIER.md §7 states both inputs; §9 "
                              "records the repair",
            "queued": None,
        },
        {
            "id": "D6",
            "title": "the descriptive document's test count was stale",
            "class": "DOCUMENT_DEFECT_CORRECTED",
            "status": "corrected",
            "foundAt": OLD_COMMIT,
            "repairedAt": None,
            "repairedAtShort": None,
            "statement":
                "docs/PUBLIC-VERIFICATION.md said `test_verify.py` holds 19 tests in "
                "two places while the module executed 37. The figure is a live "
                "quantity in a descriptive document that no generator corrects.",
            "oldBehaviour": "the document said '19 tests' in two places.",
            "repair": "the figure is derived from the loader by the producer and by "
                      "test_the_descriptive_document_no_longer_carries_the_stale_count; "
                      "the document states the executed count.",
            "witness": [
                witness_test_count_matches_document(
                    "forensics.tools.tests.test_verify",
                    "docs/PUBLIC-VERIFICATION.md"),
            ],
            "historicalWitness": [],
            "surfaceEffect": "none",
            "documentEffect": "both mentions are corrected; the old wording is "
                              "preserved in evidence/a25/RECEIPT.md",
            "queued": None,
        },
        {
            "id": "D7",
            "title": "`--json` is accepted by `--explain` and `--help` and ignored",
            "class": "TOOL_BEHAVIOUR_DOCUMENTED",
            "status": "documented",
            "foundAt": declaration["commit"],
            "repairedAt": None,
            "repairedAtShort": None,
            "statement":
                "Found while re-deriving this record. D2 repaired the listing, but "
                "`verify.py --explain --json` and `verify.py --help --json` still "
                "accept `--json` and print text, emitting no document. The contract "
                "states that exception (PUBLIC-VERIFIER.md §2.1, §2.2 and §4) and "
                "the surface declares `explain` as `jsonForm: none`, so the "
                "declaration and the executable agree; the executable's own "
                "`--help` sentence does not name the exception, and an outside "
                "caller reading only `--help` would expect a document.",
            "oldBehaviour": "not recorded by A25, which named the listing only.",
            "repair": "none in this refresh: the behaviour is documented in the "
                      "contract, and changing `--help` prose would change "
                      "`verify.py`, which this record only measures. Recorded, not "
                      "hidden.",
            "witness": [
                witness_exit(["--explain", "--json"], 0),
                witness_shape("`--explain --json` prints the explanation text and "
                              "emits no JSON document",
                              not ps._is_json_object(explain_json.stdout)
                              and explain_json.stdout.startswith("manifest")),
                witness_exit(["--help", "--json"], 0),
                witness_shape("`--help --json` prints usage and emits no document",
                              not ps._is_json_object(help_json.combined)),
                witness_source("forensics/tools/verify.py",
                               ["the listing document for the list command"], []),
                witness_text("docs/PUBLIC-VERIFIER.md",
                             ["`--explain` and `--help` print"], []),
            ],
            "historicalWitness": [],
            "surfaceEffect": "`explain` keeps `jsonForm: none`; the declaration is "
                             "accurate about the executable",
            "documentEffect": "the contract already states the exception; §9 records "
                              "D7 as documented and names the help-text gap",
            "queued": "either make `--help`'s `--json` sentence name the "
                      "`--explain`/`--help` exception, or honour `--json` there; "
                      "a silently ignored flag is not a public argument",
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
    "private_state": {
        "declared": "private-state-input",
        "known_roots": {"court": {"exists": False, "tracked_files": 0,
                                   "private_entries": 0}},
        "present": [],
    },
    "root": "<root>",
    "schema": "openssl-rs/verify/1",
    "status": "FAIL",
    "steps": [],
    "warnings": [],
}


def _listing_document(listing: str) -> str:
    """The listing document that imitates the real verifier's `--json` form."""
    return json.dumps({
        "schema": "openssl-rs/verify-listing/1",
        "interface": "ETP-T12",
        "commands": [{"name": row["name"], "role": row["role"],
                      "in_all": row["in_all"] == "in all"}
                     for row in ps.parse_listing(listing)],
    }, indent=2, sort_keys=True) + "\n"

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
        json.dumps(["list"]): {"stdout": listing,
                               "exit": exits.get("list-subcommand", 0)},
        json.dumps(["--list", "--json"]): {"stdout": _listing_document(listing),
                                           "exit": exits.get("list", 0)},
        json.dumps(["list", "--json"]): {"stdout": _listing_document(listing),
                                         "exit": exits.get("list-subcommand", 0)},
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


def _stamp(document: dict, declaration: dict) -> dict:
    """Bind a record to the declaration identity and to the tools that produced it."""
    document["producer"] = {"path": "evidence/a25/build_evidence.py",
                            "sha256": _digest(Path(__file__))}
    document["detector"] = {"path": "forensics/tools/public_surface.py",
                            "sha256": _digest(Path(ps.__file__))}
    document["declaredAtCommit"] = declaration["commit"]
    document["declaredAtCommitShort"] = declaration["commitShort"]
    document["declaredSources"] = declaration["sources"]
    return document


# ---------------------------------------------------------------------------
# the declared-commit input and its freeze checks
# ---------------------------------------------------------------------------


def _git_bytes(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "--no-optional-locks", *argv], cwd=str(ROOT),
                          capture_output=True)


def _resolve_commit(value: str) -> str | None:
    run = _git_bytes("rev-parse", "--verify", "--quiet", f"{value}^{{commit}}")
    if run.returncode != 0:
        return None
    return run.stdout.decode("utf-8", "replace").strip() or None


def _working_sources() -> dict[str, dict]:
    return {path: {"sha256": _digest(ROOT / path)} for path in DECLARED_SOURCES}


def _commit_sources(commit: str) -> dict[str, dict] | None:
    """The declared sources as the named commit carries them, or None."""
    sources: dict[str, dict] = {}
    for path in DECLARED_SOURCES:
        run = _git_bytes("show", f"{commit}:{path}")
        if run.returncode != 0:
            return None
        sources[path] = {"sha256": hashlib.sha256(run.stdout).hexdigest()}
    return sources


def _recorded_surface() -> dict | None:
    if not SURFACE_PATH.exists():
        return None
    try:
        document = json.loads(SURFACE_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return document if isinstance(document, dict) else None


def resolve_declaration(requested: str | None) -> tuple[dict | None, dict | None]:
    """Resolve the declared candidate, or refuse with a named code.

    The default is the commit already in the record when one exists, never the
    live HEAD.  ``--declared-at`` re-declares explicitly.  A record may only be
    reproduced when the sources it was declared against are still the measured
    sources; a re-declaration may only name a commit that carries them.
    """
    record = _recorded_surface()
    recorded_commit = (record or {}).get("declaredAtCommit")
    recorded_sources = (record or {}).get("declaredSources") or {}
    target = requested or (recorded_commit if isinstance(recorded_commit, str) else None)
    if target is None:
        run = _git_bytes("rev-parse", "HEAD")
        target = run.stdout.decode("utf-8", "replace").strip()
    commit = _resolve_commit(target)
    if commit is None:
        return None, {
            "code": REFUSED_COMMIT_UNKNOWN,
            "detail": (f"the declared candidate {target!r} is not a commit in this "
                       f"repository; a record cannot be bound to a commit that does "
                       f"not exist"),
        }
    working = _working_sources()
    if isinstance(recorded_commit, str) and _resolve_commit(recorded_commit) == commit:
        moved = [path for path in DECLARED_SOURCES
                 if (recorded_sources.get(path) or {}).get("sha256")
                 != working[path]["sha256"]]
        if moved:
            detail = "; ".join(
                f"{path}: recorded "
                f"{(recorded_sources.get(path) or {}).get('sha256')} != measured "
                f"{working[path]['sha256']}" for path in moved)
            return None, {
                "code": REFUSED_SOURCE_MOVED,
                "detail": (f"the record declares itself at {commit[:9]} but a source "
                           f"it is about has changed: {detail}. Re-declare with "
                           f"--declared-at <commit> once the tool is committed"),
            }
    else:
        in_commit = _commit_sources(commit)
        if in_commit is None:
            return None, {
                "code": REFUSED_COMMIT_MISMATCH,
                "detail": (f"commit {commit[:9]} does not carry the declared sources "
                           f"{DECLARED_SOURCES}"),
            }
        different = [path for path in DECLARED_SOURCES
                     if in_commit[path]["sha256"] != working[path]["sha256"]]
        if different:
            detail = "; ".join(f"{path}: commit has {in_commit[path]['sha256']} "
                               f"but the measured file is "
                               f"{working[path]['sha256']}" for path in different)
            return None, {
                "code": REFUSED_COMMIT_MISMATCH,
                "detail": (f"the declaration cannot be made at {commit[:9]}: it does "
                           f"not contain the measured source(s): {detail}"),
            }
    date = (record or {}).get("declaredAt")
    if not isinstance(date, str) or not date.strip():
        date = DEFAULT_DECLARED_AT
    return {"commit": commit, "commitShort": commit[:9], "date": date,
            "sources": working}, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic producer of the A25 public-surface records.")
    parser.add_argument(
        "--declared-at", default=None, metavar="COMMIT",
        help="the candidate this record is declared at; defaults to the value "
             "already in SURFACE.json (re-declare explicitly when a declared "
             "source changes)")
    args = parser.parse_args(argv)

    declaration, refusal = resolve_declaration(args.declared_at)
    if refusal is not None:
        print(f"a25: refused codes={refusal['code']}")
        print(f"  {refusal['detail']}")
        return EXIT_REFUSED_DECLARATION
    assert declaration is not None

    surface = build_surface(declaration)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    _write(SURFACE_PATH, surface)

    discrepancies = build_discrepancies(surface, declaration)
    inventory = ps.inventory(surface, VERIFIER, root=ROOT,
                             discrepancies=discrepancies)
    _write(EVIDENCE / "INVENTORY.json", _stamp(inventory, declaration))

    verdict = ps.verify(surface, VERIFIER, root=ROOT)
    _write(EVIDENCE / "VERIFY.json", _stamp(verdict, declaration))

    controls = build_controls(surface)
    _write(EVIDENCE / "CONTROLS.json", _stamp({
        "schema": "openssl-rs/public-surface/controls/1",
        "note": "every row is control-only: a test-only stub or an in-memory "
                "mutation of the declaration, never a shipped configuration",
        "controls": controls,
        "counts": {
            "controls": len(controls),
            "codesCovered": len({row["code"] for row in controls if row["code"]}),
            "codes": sorted(ps.CODES),
            "failing": len([row for row in controls if not row["matches"]]),
        },
    }, declaration))

    live = [w for entry in discrepancies for w in entry["witness"]
            if not w["reproduced"]]
    regressed = [w for entry in discrepancies
                 for w in entry.get("historicalWitness") or [] if w["reproduced"]]
    failing = [row["id"] for row in controls if not row["matches"]]
    codes = sorted({finding["code"] for finding in verdict["findings"]})
    repaired = len([entry for entry in discrepancies
                    if entry["status"] == "repaired"])
    print(f"a25: declared-at={declaration['commitShort']} "
          f"commands={len(surface['commands'])} "
          f"steps={inventory['counts']['listedSteps']} "
          f"json-fields={inventory['counts']['declaredJsonFields']} "
          f"discrepancies={len(discrepancies)} repaired={repaired} "
          f"control-codes={len(ps.CODES)} "
          f"controls={len(controls)} failing={len(failing)} "
          f"witnesses-not-reproduced={len(live)} regressed-repairs={len(regressed)} "
          f"verify={','.join(codes) or 'PV_OK'}")
    if codes:
        for finding in verdict["findings"]:
            print(f"  {finding['code']}: {finding['detail']}")
    for witness in live:
        print(f"  STALE WITNESS: {witness.get('kind')} "
              f"{witness.get('argv') or witness.get('path') or witness.get('step')}")
    for witness in regressed:
        print(f"  REPAIR REGRESSED: {witness.get('kind')} "
              f"{witness.get('argv') or witness.get('path') or witness.get('step')}")
    for identifier in failing:
        row = next(item for item in controls if item["id"] == identifier)
        print(f"  CONTROL FAILED: {identifier}: expected {row['expectedCodes']} "
              f"observed {row['observedCodes']}")
    ok = not codes and not failing and not live and not regressed
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
