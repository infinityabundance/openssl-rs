#!/usr/bin/env python3
"""public_surface.py -- declare a verifier's public surface and refuse when it drifts.

The problem this tool answers
-----------------------------
`forensics/tools/verify.py` is an interface an outsider is invited to drive.  An
interface is only public if a person who has never read its source can find out
what it accepts, what each exit status means, what the machine-readable document
contains, and which parts of that promise may change.  A description in prose
cannot answer that question for long: the prose and the program drift, and the
drift is invisible until somebody programs against the old text.

So the surface is *declared* in one machine-readable record, and this tool
compares the declaration with the executable's own observable behaviour:

  * the command set the executable lists and explains;
  * each command's arguments, as its own ``--help`` and ``--explain`` print them;
  * the exit statuses the contract declares, against statuses actually observed;
  * the top-level fields of the JSON document, and the document's stability
    across two runs;
  * the gitignored roots each command's delegate may read;
  * each command's declared stability level, against the evidence offered for it.

A disagreement is a refusal with a stable code, not a warning.  The detector
never imports the verifier: it starts it, reads its standard output and its exit
status, and compares those with the declaration.  A tool that shared code with
its subject could agree with it by construction.

What it does not establish
--------------------------
* It does not decide that a command's *check* is meaningful, only that the
  command exists, is described the same way in both places, and behaves as the
  contract says at the shape level.
* It cannot see an undocumented behaviour that leaves the listed surface
  unchanged (a flag accepted and ignored, for example).  Such cases are recorded
  as discrepancies by the producer that reads the source, not inferred here.
* A stubbed verifier can satisfy every shape check while doing nothing.  The
  controls use exactly that: stubs isolate one refusal each, and the real
  verifier is the positive case, not the stubs.
* It is not a sandbox and not a signature.

Usage
-----
    python3 forensics/tools/public_surface.py inventory [--json]
    python3 forensics/tools/public_surface.py verify [--json]
    python3 forensics/tools/public_surface.py explain <command>

Exit status: 0 when the requested operation succeeded and nothing was refused,
1 when at least one refusal fired, 2 for a usage error.  The command line always
prints ``codes=PV_OK`` or the refusal codes it returned.

Python 3.11 standard library only.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "openssl-rs/public-surface/1"
INVENTORY_SCHEMA = "openssl-rs/public-surface/inventory/1"
VERDICT_SCHEMA = "openssl-rs/public-surface/verdict/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

OK_CODE = "PV_OK"

# The stable refusal codes.  Each names the wrong conclusion it prevents.  The
# set is closed: a new situation gets a new code and a new documented meaning.
CODES = (
    "PV_REFUSED_COMMAND_UNDOCUMENTED",
    "PV_REFUSED_COMMAND_ABSENT",
    "PV_REFUSED_EXIT_UNDEFINED",
    "PV_REFUSED_EXIT_UNUSED",
    "PV_REFUSED_HELP_DRIFT",
    "PV_REFUSED_JSON_FIELD",
    "PV_REFUSED_UNSTABLE_OUTPUT",
    "PV_REFUSED_PRIVATE_STATE",
    "PV_REFUSED_UNVERSIONED_SCHEMA",
    "PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT",
    "PV_REFUSED_STABILITY_OVERCLAIM",
    "PV_REFUSED_SURFACE_INVALID",
    "PV_REFUSED_USAGE",
)

STABILITY_LEVELS = ("stable", "experimental", "deprecated")
KINDS = ("step", "aggregate", "discovery")

DEFAULT_VERIFIER = "forensics/tools/verify.py"
DEFAULT_SURFACE = "evidence/a25/SURFACE.json"
DEFAULT_SUPPORT_TESTS = "forensics/tools/tests/test_public_surface.py"

# Two observation runs per JSON probe.  Two is the minimum that can detect a
# change; a third run would only detect a period-2 oscillation, which the schema
# forbids anyway.
RUNS = 2

BACKTICK = re.compile(r"`([^`\n]+)`")
OPTION_TOKEN = re.compile(r"(?<![\w-])(--[A-Za-z0-9][\w-]*|-[A-Za-z])(?![\w-])")
EXPLAIN_HEADER = re.compile(
    r"^(?P<name>[A-Za-z][A-Za-z0-9_-]*)  \((?P<required>required|optional); "
    r"(?P<scope>in `all`|not in `all`)\)$"
)
EXPLAIN_FIELD = re.compile(r"^  (?P<key>needs|delegates to|establishes|does not|private):\s*(?P<value>.*)$")
COMMAND_WORD = re.compile(r"^[a-z][a-z0-9-]*$")


class SurfaceError(Exception):
    """A usage-level problem: the surface or the verifier cannot be read."""


# ---------------------------------------------------------------------------
# reading inputs
# ---------------------------------------------------------------------------


def load_surface(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SurfaceError(f"cannot read the surface {path}: {exc}") from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise SurfaceError(f"the surface {path} is not one JSON document: {exc}") from exc
    if not isinstance(document, dict):
        raise SurfaceError(f"the surface {path} is not one JSON object")
    return document


def digest_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "unreadable"


def _relpath(path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    return path.name


# ---------------------------------------------------------------------------
# running the verifier
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Run:
    argv: tuple[str, ...]
    exit: int | None
    stdout: str
    stderr: str
    started: bool = True

    @property
    def combined(self) -> str:
        return self.stdout + self.stderr


def run_verifier(verifier: Path, argv: Iterable[str], cwd: Path | None = None,
                 timeout: int = 120) -> Run:
    """Start ``verifier`` with ``argv`` and capture what it said.

    The interpreter is this process's own ``sys.executable`` so that a verifier
    without an executable bit is still runnable, and so that a control stub is
    exercised the same way as the real tool.
    """
    command = [sys.executable, str(verifier), *argv]
    try:
        proc = subprocess.run(
            command, cwd=str(cwd) if cwd else None, capture_output=True,
            text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Run(tuple(argv), None, "", str(exc), started=False)
    return Run(tuple(argv), proc.returncode, proc.stdout, proc.stderr)


# ---------------------------------------------------------------------------
# parsing what it said
# ---------------------------------------------------------------------------


def parse_listing(text: str) -> list[dict]:
    """Parse the tab-separated listing into rows.

    A line that is not exactly three tab-separated non-empty fields is reported
    as a malformed row rather than being silently dropped: the listing is the
    command set, and a row the parser cannot read is a command the surface cannot
    account for.
    """
    rows: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3 or not all(part.strip() for part in parts):
            rows.append({"name": "", "role": "", "in_all": "", "malformed": line})
            continue
        rows.append({"name": parts[0], "role": parts[1], "in_all": parts[2]})
    return rows


def parse_explain(text: str) -> dict[str, dict]:
    """Parse ``--explain`` into one block per command.

    Fields: needs, delegates, establishes, does_not, private.  A field the
    executable omits is absent here too; the comparison treats "absent" and
    "empty" as the same declaration, because both say the command names nothing.
    """
    blocks: dict[str, dict] = {}
    current: str | None = None
    for line in text.splitlines():
        header = EXPLAIN_HEADER.match(line)
        if header:
            current = header.group("name")
            blocks[current] = {
                "required": header.group("required"),
                "scope": header.group("scope"),
            }
            continue
        if not line.strip():
            continue
        entry = EXPLAIN_FIELD.match(line)
        if entry and current is not None:
            key = {"delegates to": "delegates"}.get(entry.group("key"), entry.group("key"))
            value = entry.group("value").strip()
            if key in ("needs", "delegates", "private"):
                blocks[current][key] = [
                    item.strip() for item in value.split(",") if item.strip()
                ]
            else:
                blocks[current][key] = value
    return blocks


def help_option_tokens(help_text: str) -> set[str]:
    return set(OPTION_TOKEN.findall(help_text))


def help_command_tokens(help_text: str) -> set[str]:
    """Backticked lowercase words in the help text: names the help advertises."""
    return {token for token in BACKTICK.findall(help_text) if COMMAND_WORD.match(token)}


def canonical(document: Any) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _differing_paths(first: Any, second: Any, prefix: str = "") -> list[str]:
    if type(first) is not type(second):
        return [prefix or "<document>"]
    if isinstance(first, dict):
        paths: list[str] = []
        for key in sorted(set(first) | set(second)):
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in first or key not in second:
                paths.append(child)
            else:
                paths.extend(_differing_paths(first[key], second[key], child))
        return paths
    if isinstance(first, list):
        paths = []
        if len(first) != len(second):
            paths.append(f"{prefix or '<document>'}[len {len(first)} != {len(second)}]")
        for index, (left, right) in enumerate(zip(first, second)):
            paths.extend(_differing_paths(left, right, f"{prefix}[{index}]"))
        return paths
    return [] if first == second else [prefix or "<document>"]


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


@dataclass
class Observed:
    """Everything the executable said, normalised and free of live values."""

    listing: list[dict] = field(default_factory=list)
    listing_text: str = ""
    listing_second_text: str = ""
    listing_exit: int | None = None
    help_text: str = ""
    help_exit: int | None = None
    explain: dict[str, dict] = field(default_factory=dict)
    explain_text: str = ""
    explain_exit: int | None = None
    list_json_text: str = ""
    list_json_exit: int | None = None
    list_json_emits_json: bool = False
    probes: dict[str, dict] = field(default_factory=dict)
    json_documents: dict[str, list] = field(default_factory=dict)
    json_errors: dict[str, str] = field(default_factory=dict)
    runs: list[dict] = field(default_factory=list)

    @property
    def steps(self) -> list[str]:
        return [row["name"] for row in self.listing if row["name"]]

    @property
    def exit_codes_observed(self) -> dict[int, list[str]]:
        codes: dict[int, list[str]] = {}
        for name, probe in self.probes.items():
            if probe.get("exit") is None:
                continue
            codes.setdefault(probe["exit"], []).append(name)
        return codes


def discover(surface: dict, verifier: Path, cwd: Path | None = None) -> Observed:
    """Run the discovery commands the surface declares, and record what happened.

    The invocations come from the surface's ``discovery`` block, so a surface
    that declared a different discovery command would be exercised through that
    command rather than through a path this tool hardcodes.
    """
    discovery = surface.get("discovery") or {}
    observed = Observed()

    listing_spec = discovery.get("listing") or {}
    listing_argv = list(listing_spec.get("argv") or ["--list"])
    first = run_verifier(verifier, listing_argv, cwd)
    second = run_verifier(verifier, listing_argv, cwd)
    observed.listing_text = first.stdout
    observed.listing_second_text = second.stdout
    observed.listing_exit = first.exit
    observed.listing = parse_listing(first.stdout)
    observed.runs.append({"what": "listing", "argv": listing_argv, "exit": first.exit})

    list_json_spec = discovery.get("listJson") or {}
    if list_json_spec.get("argv"):
        run = run_verifier(verifier, list(list_json_spec["argv"]), cwd)
        observed.list_json_text = run.stdout
        observed.list_json_exit = run.exit
        observed.list_json_emits_json = _is_json_object(run.stdout)
        observed.runs.append({"what": "listing-plus-json",
                              "argv": list(list_json_spec["argv"]), "exit": run.exit})

    help_spec = discovery.get("help") or {}
    if help_spec.get("argv"):
        run = run_verifier(verifier, list(help_spec["argv"]), cwd)
        observed.help_text = run.combined
        observed.help_exit = run.exit
        observed.runs.append({"what": "help", "argv": list(help_spec["argv"]), "exit": run.exit})

    explain_spec = discovery.get("explain") or {}
    if explain_spec.get("argv"):
        run = run_verifier(verifier, list(explain_spec["argv"]), cwd)
        observed.explain_text = run.stdout
        observed.explain_exit = run.exit
        observed.explain = parse_explain(run.stdout)
        observed.runs.append({"what": "explain", "argv": list(explain_spec["argv"]),
                              "exit": run.exit})

    for probe in surface.get("exitCodeProbes") or []:
        name = probe.get("id") or " ".join(probe.get("argv") or [])
        run = run_verifier(verifier, list(probe.get("argv") or []), cwd)
        observed.probes[name] = {
            "argv": list(probe.get("argv") or []),
            "declared": probe.get("code"),
            "exit": run.exit,
            "started": run.started,
            "stdout_head": _head(run.stdout),
            "stderr_head": _head(run.stderr),
        }
        observed.runs.append({"what": f"probe:{name}", "argv": list(probe.get("argv") or []),
                              "exit": run.exit})

    json_spec = discovery.get("jsonProbe") or {}
    argv = list(json_spec.get("argv") or [])
    if argv:
        documents: list[Any] = []
        errors: list[str] = []
        for _ in range(max(RUNS, 2)):
            run = run_verifier(verifier, argv, cwd)
            try:
                documents.append(json.loads(run.stdout))
            except (TypeError, ValueError) as exc:
                documents.append(None)
                errors.append(str(exc))
            observed.runs.append({"what": "json-probe", "argv": argv, "exit": run.exit})
        key = json_spec.get("command") or argv[0]
        observed.json_documents[key] = documents
        if errors:
            observed.json_errors[key] = errors[0]
    return observed


def _is_json_object(text: str) -> bool:
    try:
        return isinstance(json.loads(text), dict)
    except (TypeError, ValueError):
        return False


def _head(text: str, limit: int = 120) -> str:
    line = next((line for line in text.splitlines() if line.strip()), "")
    return line[:limit]


# ---------------------------------------------------------------------------
# the comparison
# ---------------------------------------------------------------------------


def _command_entries(surface: dict) -> tuple[list[dict], list[str]]:
    """Return the surface's commands and any structural problems with them."""
    problems: list[str] = []
    raw = surface.get("commands")
    if not isinstance(raw, list) or not raw:
        return [], ["the surface declares no command list"]
    names: list[str] = []
    entries: list[dict] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            problems.append(f"commands[{index}] is not an object")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            problems.append(f"commands[{index}] declares no name")
            continue
        if name in names:
            problems.append(f"command {name!r} is declared twice")
            continue
        if entry.get("kind") not in KINDS:
            problems.append(f"command {name!r} declares kind {entry.get('kind')!r}, "
                            f"not one of {', '.join(KINDS)}")
        names.append(name)
        entries.append(entry)
    return entries, problems


def _stability_supported(entry: dict, surface: dict, root: Path | None) -> str:
    """Why the declared stability level is not supported, or ``""``.

    The rule is evidence-based, not adjective-based:

    * every level needs a ``since`` token and an ``evidence`` path that exists;
    * ``stable`` additionally needs the surface's declared support tests to exist
      in the declared test file -- a promise nobody tests is not stable, it is
      merely old;
    * ``deprecated`` needs a replacement, which is checked with its own code.
    """
    level = entry.get("stability")
    if level not in STABILITY_LEVELS:
        return f"declares stability {level!r}, not one of {', '.join(STABILITY_LEVELS)}"
    if not isinstance(entry.get("since"), str) or not entry["since"].strip():
        return f"declares {level} with no `since`"
    evidence = entry.get("evidence") or []
    if not evidence or not isinstance(evidence, list):
        return f"declares {level} with no evidence"
    if root is not None:
        for path in evidence:
            if not (root / str(path)).exists():
                return f"declares {level} on evidence {path!r}, which does not exist"
    if level != "stable":
        return ""
    tests = surface.get("supportTests") or []
    tests_path = surface.get("supportTestsPath") or DEFAULT_SUPPORT_TESTS
    if not tests:
        return "declares `stable` with no support test declared"
    if root is None:
        return ""
    target = root / str(tests_path)
    if not target.is_file():
        return f"declares `stable` but the support test file {tests_path!r} is absent"
    text = target.read_text(encoding="utf-8", errors="replace")
    missing = [name for name in tests if name not in text]
    if missing:
        return (f"declares `stable` but the support test(s) "
                f"{', '.join(missing)} do not appear in {tests_path}")
    return ""


def verify(surface: dict, verifier: Path, *, root: Path | None = None,
           verifier_label: str | None = None, cwd: Path | None = None) -> dict:
    """Compare ``surface`` with what ``verifier`` does, and return the verdict.

    Every check runs even when an earlier one refused: the record is a report of
    what was observed, not a short-circuit.  ``root`` is the tree against which
    declared evidence paths are resolved; it is not passed to the verifier.
    """
    findings: list[dict] = []
    checks: list[dict] = []

    def refuse(code: str, detail: str) -> None:
        findings.append({"code": code, "detail": detail})

    def note(check: str, detail: str) -> None:
        checks.append({"check": check, "detail": detail})

    if root is None:
        candidate = Path(verifier).resolve().parents[2]
        root = candidate if candidate.exists() else None

    # -- the schema must say which schema it is ---------------------------
    version = surface.get("schemaVersion")
    if not isinstance(version, str) or not version.strip():
        refuse("PV_REFUSED_UNVERSIONED_SCHEMA",
               "the surface declares no `schemaVersion`; a declaration whose schema "
               "can change without a version cannot be a contract")
        note("schema", "unversioned")
    else:
        note("schema", f"schemaVersion={version}")

    entries, problems = _command_entries(surface)
    for problem in problems:
        refuse("PV_REFUSED_SURFACE_INVALID", problem)

    observed = discover(surface, verifier, cwd)
    label = verifier_label or _relpath(Path(verifier), root)
    note("discovery",
         f"{len(observed.runs)} invocation(s); listing exit={observed.listing_exit}; "
         f"help exit={observed.help_exit}; explain exit={observed.explain_exit}")

    declared_names = [entry["name"] for entry in entries]
    declared_by_name = {entry["name"]: entry for entry in entries}
    executable_steps = observed.steps

    # -- the command set --------------------------------------------------
    for row in observed.listing:
        if row.get("malformed"):
            refuse("PV_REFUSED_COMMAND_UNDOCUMENTED",
                   f"the listing contains a row the surface cannot account for: "
                   f"{row['malformed']!r}")
    for name in executable_steps:
        if name not in declared_by_name:
            refuse("PV_REFUSED_COMMAND_UNDOCUMENTED",
                   f"the executable lists the command {name!r}; the surface does not "
                   f"declare it")
    for entry in entries:
        name = entry["name"]
        kind = entry.get("kind")
        if kind == "step":
            if name not in executable_steps:
                refuse("PV_REFUSED_COMMAND_ABSENT",
                       f"the surface declares the step {name!r}; the executable does not "
                       f"list it")
            elif name not in observed.explain:
                refuse("PV_REFUSED_COMMAND_ABSENT",
                       f"the surface declares the step {name!r}; the executable's own "
                       f"`--explain` does not describe it")
        elif kind in ("aggregate", "discovery"):
            probe_id = entry.get("recognisedBy")
            probe = observed.probes.get(str(probe_id)) if probe_id else None
            if probe is None:
                refuse("PV_REFUSED_COMMAND_ABSENT",
                       f"the surface declares the {kind} {name!r} with no "
                       f"`recognisedBy` probe, so nothing shows it is accepted")
            elif probe.get("exit") != 0:
                refuse("PV_REFUSED_COMMAND_ABSENT",
                       f"the {kind} {name!r} was expected to be accepted by probe "
                       f"{probe_id!r}; that probe exited {probe.get('exit')}")
            if kind == "discovery" and entry.get("invocation") and \
                    not any(item.get("argv") == entry["invocation"] for item in observed.runs):
                refuse("PV_REFUSED_COMMAND_ABSENT",
                       f"the surface declares the discovery invocation "
                       f"{entry['invocation']!r} for {name!r}; it was never exercised")
    note("commands",
         f"{len(executable_steps)} step(s) listed, {len(entries)} declared")

    # -- help text names arguments the surface does not -------------------
    declared_args = {arg.get("name") for arg in surface.get("arguments") or []
                     if isinstance(arg, dict)}
    for arg in surface.get("arguments") or []:
        if isinstance(arg, dict):
            declared_args.update(arg.get("aliases") or [])
    help_tokens = help_option_tokens(observed.help_text)
    for token in sorted(help_tokens - declared_args):
        refuse("PV_REFUSED_HELP_DRIFT",
               f"`--help` names the argument {token}; the surface does not declare it")
    for token in sorted(declared_args - help_tokens):
        if token.startswith("-"):
            refuse("PV_REFUSED_HELP_DRIFT",
                   f"the surface declares the argument {token}; `--help` does not name it")
    for token in sorted(help_command_tokens(observed.help_text) - set(declared_names)):
        refuse("PV_REFUSED_COMMAND_ABSENT",
               f"`--help` advertises the command name {token!r}; the surface declares "
               f"no such command")
    note("help", f"{len(help_tokens)} option token(s) in `--help`")

    # -- explain's prerequisites and delegates ---------------------------
    for entry in entries:
        name = entry["name"]
        block = observed.explain.get(name)
        if block is None:
            continue
        declared_needs = set(entry.get("prerequisites") or [])
        observed_needs = set(block.get("needs") or [])
        if declared_needs != observed_needs:
            refuse("PV_REFUSED_HELP_DRIFT",
                   f"{name}: the surface declares prerequisite(s) "
                   f"{sorted(declared_needs)}; `--explain` prints "
                   f"{sorted(observed_needs)}")
        declared_delegates = set(entry.get("delegatesTo") or [])
        observed_delegates = set(block.get("delegates") or [])
        if declared_delegates != observed_delegates:
            refuse("PV_REFUSED_HELP_DRIFT",
                   f"{name}: the surface declares delegate(s) "
                   f"{sorted(declared_delegates)}; `--explain` prints "
                   f"{sorted(observed_delegates)}")
        declared_private = set(entry.get("privateState") or [])
        observed_private = set(block.get("private") or [])
        if declared_private != observed_private:
            refuse("PV_REFUSED_PRIVATE_STATE",
                   f"{name}: the surface declares private state "
                   f"{sorted(declared_private)}; the executable's own declaration is "
                   f"{sorted(observed_private)} -- an undeclared read is the defect "
                   f"this code names")
    note("explain", f"{len(observed.explain)} block(s) parsed")

    # -- exit codes -------------------------------------------------------
    contract = {str(k): v for k, v in (surface.get("exitCodeContract") or {}).items()}
    for probe_name, probe in observed.probes.items():
        exit_code = probe.get("exit")
        if exit_code is None:
            refuse("PV_REFUSED_EXIT_UNDEFINED",
                   f"probe {probe_name!r} did not start, so its exit code is not "
                   f"observed")
            continue
        if str(exit_code) not in contract:
            refuse("PV_REFUSED_EXIT_UNDEFINED",
                   f"probe {probe_name!r} exited {exit_code}; the exit contract "
                   f"declares no meaning for that code")
        if probe.get("declared") is not None and exit_code != probe.get("declared"):
            refuse("PV_REFUSED_EXIT_UNDEFINED",
                   f"probe {probe_name!r} declares exit {probe['declared']}; it "
                   f"observed {exit_code}")
    observed_codes = observed.exit_codes_observed
    for code in sorted(contract, key=lambda value: int(value) if value.isdigit() else 0):
        if not code.isdigit() or int(code) not in observed_codes:
            refuse("PV_REFUSED_EXIT_UNUSED",
                   f"the exit contract declares {code} "
                   f"({(contract[code] or {}).get('meaning', 'no meaning')!r}); no probe "
                   f"observes it")
    for entry in entries:
        name = entry["name"]
        for declared in entry.get("exitCodes") or []:
            if not isinstance(declared, dict) or "code" not in declared:
                refuse("PV_REFUSED_SURFACE_INVALID",
                       f"{name}: an exitCodes entry is not an object with a code")
                continue
            code = int(declared["code"])
            if str(code) not in contract:
                refuse("PV_REFUSED_EXIT_UNDEFINED",
                       f"{name}: declares exit {code}, which the exit contract does not "
                       f"define")
            source = declared.get("observedBy")
            if source:
                probe = observed.probes.get(str(source))
                if probe is None:
                    refuse("PV_REFUSED_EXIT_UNUSED",
                           f"{name}: declares exit {code} observed by probe {source!r}, "
                           f"which does not exist")
                elif probe.get("exit") != code:
                    refuse("PV_REFUSED_EXIT_UNDEFINED",
                           f"{name}: declares exit {code} observed by {source!r}; that "
                           f"probe observed {probe.get('exit')}")
            elif not str(declared.get("basis") or "").strip():
                refuse("PV_REFUSED_EXIT_UNUSED",
                       f"{name}: declares exit {code} with no observation and no "
                       f"command-specific basis")
    note("exit-codes",
         "observed " + ", ".join(str(code) for code in sorted(observed_codes)))

    # -- the JSON document ------------------------------------------------
    json_spec = (surface.get("discovery") or {}).get("jsonProbe") or {}
    environment_key = json_spec.get("environmentKey") or "environment"
    json_command = json_spec.get("command")
    documents = observed.json_documents.get(str(json_command)) or []
    for entry in entries:
        name = entry["name"]
        form = entry.get("jsonForm")
        declared_fields = entry.get("jsonFields")
        if form == "none":
            if not isinstance(declared_fields, list):
                refuse("PV_REFUSED_SURFACE_INVALID",
                       f"{name}: jsonForm is none but jsonFields is not a list")
            if name == json_command and any(_plausible_document(doc) for doc in documents):
                refuse("PV_REFUSED_JSON_FIELD",
                       f"{name}: the surface declares no JSON document, and the "
                       f"command emitted one")
            continue
        if form != "document":
            refuse("PV_REFUSED_SURFACE_INVALID",
                   f"{name}: jsonForm {form!r} is not `document` or `none`")
            continue
        if not isinstance(declared_fields, list) or not declared_fields:
            refuse("PV_REFUSED_SURFACE_INVALID",
                   f"{name}: declares a JSON document with no declared fields")
            continue
        if name != json_command:
            continue
        if not documents:
            refuse("PV_REFUSED_JSON_FIELD",
                   f"{name}: no JSON probe was declared for it, so the declared "
                   f"fields are unverified")
            continue
        first = documents[0]
        if not isinstance(first, dict):
            refuse("PV_REFUSED_JSON_FIELD",
                   f"{name}: the declared document is not a JSON object "
                   f"({observed.json_errors.get(name, 'not emitted')})")
            continue
        declared_set = set(declared_fields)
        observed_set = set(first)
        for missing in sorted(declared_set - observed_set):
            refuse("PV_REFUSED_JSON_FIELD",
                   f"{name}: the surface declares the field {missing!r}; the document "
                   f"does not contain it")
        for extra in sorted(observed_set - declared_set):
            refuse("PV_REFUSED_JSON_FIELD",
                   f"{name}: the document contains the field {extra!r}; the surface "
                   f"does not declare it")
        environment = first.get(environment_key)
        if not isinstance(environment, dict) or \
                environment.get("declared") != json_spec.get("environmentDeclaration"):
            refuse("PV_REFUSED_UNSTABLE_OUTPUT",
                   f"{name}: the document does not declare {environment_key!r} as "
                   f"{json_spec.get('environmentDeclaration')!r}, so the determinism "
                   f"claim has no scope")
        details = []
        for index in range(1, len(documents)):
            if canonical(_projection(documents[0], environment_key)) != \
                    canonical(_projection(documents[index], environment_key)):
                differing = _differing_paths(_projection(documents[0], environment_key),
                                             _projection(documents[index], environment_key))
                refuse("PV_REFUSED_UNSTABLE_OUTPUT",
                       f"{name}: two runs differ at "
                       f"{', '.join(differing[:6]) or '<document>'}")
            details.append(index)
        note("json",
             f"{name}: {len(observed_set)} field(s) observed, "
             f"{len(documents)} run(s) compared"
             + (f", {len(details)} repeat(s)" if details else ""))
    if observed.listing_text != observed.listing_second_text:
        differ = _first_line_difference(observed.listing_text,
                                       observed.listing_second_text)
        refuse("PV_REFUSED_UNSTABLE_OUTPUT",
               f"two `--list` runs differ ({differ}); the command set is an input to "
               f"every other comparison")
    declared_list_json = ((surface.get("discovery") or {}).get("listJson") or {}).get(
        "emitsJson")
    if declared_list_json is not None and \
            bool(declared_list_json) != observed.list_json_emits_json:
        refuse("PV_REFUSED_JSON_FIELD",
               f"the surface declares that the listing-with-`--json` form emits "
               f"{'a document' if declared_list_json else 'no document'}; it emitted "
               f"{'one' if observed.list_json_emits_json else 'none'}")

    # -- stability and deprecation ---------------------------------------
    for entry in entries:
        name = entry["name"]
        problem = _stability_supported(entry, surface, root)
        if problem:
            refuse("PV_REFUSED_STABILITY_OVERCLAIM", f"{name}: {problem}")
        if entry.get("stability") == "deprecated":
            replacement = entry.get("replacement")
            if not replacement:
                refuse("PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT",
                       f"{name}: declares `deprecated` with no `replacement`; a "
                       f"deprecation that names no successor removes a command instead "
                       f"of migrating it")
            elif replacement == name:
                refuse("PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT",
                       f"{name}: declares itself as its own replacement")
            elif replacement not in declared_by_name:
                refuse("PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT",
                       f"{name}: declares the replacement {replacement!r}, which the "
                       f"surface does not declare")
            elif declared_by_name[replacement].get("stability") == "deprecated":
                refuse("PV_REFUSED_DEPRECATED_WITHOUT_REPLACEMENT",
                       f"{name}: declares the replacement {replacement!r}, which is "
                       f"itself deprecated")
    note("stability",
         "levels " + ", ".join(sorted({str(entry.get('stability')) for entry in entries})))

    codes = _unique(finding["code"] for finding in findings)
    ok = not findings
    return {
        "schema": VERDICT_SCHEMA,
        "surface": {
            "schemaVersion": surface.get("schemaVersion"),
            "interface": surface.get("interface"),
            "commandCount": len(entries),
        },
        "verifier": {
            "path": label,
            "sha256": digest_file(Path(verifier)),
        },
        "ok": ok,
        "codes": codes if not ok else [OK_CODE],
        "findings": findings,
        "checks": checks,
        "commands": _command_report(entries, observed, surface, root),
        "observed": {
            "steps": len(executable_steps),
            "explainBlocks": len(observed.explain),
            "exitCodes": {str(code): sorted(names)
                          for code, names in sorted(observed.exit_codes_observed.items())},
            "helpOptionTokens": sorted(help_option_tokens(observed.help_text)),
            "listingStable": observed.listing_text == observed.listing_second_text,
            "listJsonEmitsJson": observed.list_json_emits_json,
            "jsonFields": sorted((observed.json_documents.get(str(json_command)) or
                                  [{}])[0]) if documents and isinstance(documents[0], dict)
                                 else [],
            "invocations": observed.runs,
        },
    }


def _plausible_document(value: Any) -> bool:
    return isinstance(value, dict) and bool(value)


def _projection(document: Any, environment_key: str) -> Any:
    if not isinstance(document, dict):
        return document
    return {key: value for key, value in document.items() if key != environment_key}


def _first_line_difference(first: str, second: str) -> str:
    left = first.splitlines()
    right = second.splitlines()
    for index, (one, two) in enumerate(zip(left, right), start=1):
        if one != two:
            return f"line {index}: {one!r} != {two!r}"
    if len(left) != len(right):
        return f"{len(left)} line(s) != {len(right)} line(s)"
    return "surrounding output"


def _unique(items: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _command_report(entries: list[dict], observed: Observed, surface: dict,
                    root: Path | None) -> dict:
    """Per-command comparison: declared against observed, without live values."""
    contract = {str(k): v for k, v in (surface.get("exitCodeContract") or {}).items()}
    report: dict[str, dict] = {}
    for entry in entries:
        name = entry["name"]
        block = observed.explain.get(name) or {}
        observed_codes = [declared.get("code") for declared in entry.get("exitCodes") or []
                          if isinstance(declared, dict)]
        if entry.get("kind") == "step":
            recognised = name in observed.steps and name in observed.explain
            probe: dict | None = None
        else:
            source = str(entry.get("recognisedBy") or "")
            probe = observed.probes.get(source) if source else None
            recognised = probe is not None and probe.get("exit") == 0
        report[name] = {
            "kind": entry.get("kind"),
            "invocation": entry.get("invocation"),
            "stability": entry.get("stability"),
            "declaredExitCodes": observed_codes,
            "recognised": recognised,
            "recognisedBy": (entry.get("recognisedBy")
                             if entry.get("kind") != "step" else "--list and --explain"),
            "recognitionExit": (probe or {}).get("exit"),
            "argumentsDeclared": list(entry.get("arguments") or []),
            "jsonForm": entry.get("jsonForm"),
            "jsonFieldsDeclared": len(entry.get("jsonFields") or []),
            "privateStateDeclared": sorted(entry.get("privateState") or []),
            "privateStateObserved": sorted(block.get("private") or []),
            "prerequisitesDeclared": sorted(entry.get("prerequisites") or []),
            "prerequisitesObserved": sorted(block.get("needs") or []),
            "delegatesToDeclared": sorted(entry.get("delegatesTo") or []),
            "delegatesToObserved": sorted(block.get("delegates") or []),
            "stabilitySupported": _stability_supported(entry, surface, root) == "",
            "exitContractDefined": all(str(code) in contract for code in observed_codes),
        }
    return report


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------


def inventory(surface: dict, verifier: Path, *, root: Path | None = None,
              verifier_label: str | None = None,
              discrepancies: Iterable[dict] | None = None) -> dict:
    """The executable surface as observed, with the declaration beside it.

    ``discrepancies`` is the record of what reading the source found that the
    shape comparison cannot see (a flag accepted and ignored, a declared-private
    path outside the audited roots).  Each entry is carried verbatim; the
    producer is responsible for having checked its witness.
    """
    entries, problems = _command_entries(surface)
    observed = discover(surface, verifier, root)
    label = verifier_label or _relpath(Path(verifier), root)
    rows = []
    for entry in entries:
        name = entry["name"]
        block = observed.explain.get(name) or {}
        rows.append({
            "name": name,
            "kind": entry.get("kind"),
            "invocation": entry.get("invocation"),
            "stability": entry.get("stability"),
            "listed": name in observed.steps,
            "explained": name in observed.explain,
            "arguments": list(entry.get("arguments") or []),
            "exitCodes": list(entry.get("exitCodes") or []),
            "jsonFields": list(entry.get("jsonFields") or []),
            "privateState": sorted(entry.get("privateState") or []),
            "prerequisites": sorted(entry.get("prerequisites") or []),
            "delegatesTo": sorted(entry.get("delegatesTo") or []),
            "observed": {
                "listingRow": next((row for row in observed.listing
                                    if row.get("name") == name), None),
                "needs": sorted(block.get("needs") or []),
                "delegates": sorted(block.get("delegates") or []),
                "private": sorted(block.get("private") or []),
                "establishes": block.get("establishes", ""),
                "doesNot": block.get("does_not", ""),
            },
        })
    json_spec = (surface.get("discovery") or {}).get("jsonProbe") or {}
    json_command = str(json_spec.get("command") or "")
    documents = observed.json_documents.get(json_command) or []
    first = documents[0] if documents and isinstance(documents[0], dict) else {}
    return {
        "schema": INVENTORY_SCHEMA,
        "surfaceSchemaVersion": surface.get("schemaVersion"),
        "interface": surface.get("interface"),
        "verifier": {"path": label, "sha256": digest_file(Path(verifier))},
        "discovery": {
            "invocations": observed.runs,
            "listingColumns": ((surface.get("discovery") or {}).get("listing") or {})
                              .get("columns"),
            "listingStable": observed.listing_text == observed.listing_second_text,
            "listJsonEmitsJson": observed.list_json_emits_json,
            "helpOptionTokens": sorted(help_option_tokens(observed.help_text)),
            "helpAdvertisedNames": sorted(help_command_tokens(observed.help_text)),
        },
        "counts": {
            "listedSteps": len(observed.steps),
            "explainBlocks": len(observed.explain),
            "declaredCommands": len(entries),
            "declaredArguments": len([arg for arg in surface.get("arguments") or []
                                      if isinstance(arg, dict)]),
            "declaredJsonFields": len(first),
        },
        "exitCodes": {
            "contract": {str(k): (v or {}).get("meaning")
                         for k, v in (surface.get("exitCodeContract") or {}).items()},
            "observed": {str(code): sorted(names)
                         for code, names in sorted(observed.exit_codes_observed.items())},
            "probes": observed.probes,
        },
        "jsonFields": sorted(first),
        "commands": rows,
        "structuralProblems": problems,
        "discrepancies": list(discrepancies or []),
        "notes": [
            "The listing, the help text and the explain blocks are the executable's "
            "own words; nothing here is copied from the declaration.",
            "The JSON field set is read from one probe run; value-level determinism "
            "is the separate two-run comparison in the verdict.",
            "A discrepancy is a finding from reading the source, not a shape "
            "comparison: the detector cannot see behaviour that leaves the listed "
            "surface unchanged.",
        ],
    }


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------


def _codes_line(codes: Iterable[str]) -> str:
    return "codes=" + ",".join(codes)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _print_findings(document: dict) -> int:
    for finding in document["findings"]:
        print(f"public-surface: {finding['code']}: {finding['detail']}")
    print(f"public-surface: {_codes_line(document['codes'])}")
    return EXIT_OK if document["ok"] else EXIT_REFUSED


def command_inventory(args: argparse.Namespace) -> int:
    root = _repo_root()
    surface = load_surface(Path(args.surface))
    verifier = Path(args.verifier)
    document = inventory(surface, verifier, root=root,
                         discrepancies=_load_discrepancies(args.discrepancies))
    if args.json:
        sys.stdout.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
        print(f"public-surface: {_codes_line([OK_CODE])}", file=sys.stderr)
        return EXIT_OK
    counts = document["counts"]
    print(f"public-surface: inventory verifier={document['verifier']['path']} "
          f"commands={counts['declaredCommands']} steps={counts['listedSteps']} "
          f"json-fields={counts['declaredJsonFields']} "
          f"source-findings-carried={len(document['discrepancies'])}")
    observed = ", ".join(sorted(document["exitCodes"]["observed"]))
    print(f"public-surface: exit codes observed {observed}; "
          f"listing stable={document['discovery']['listingStable']}; "
          f"listing-with-json emits a document={document['discovery']['listJsonEmitsJson']}")
    print(f"public-surface: {_codes_line([OK_CODE])}")
    return EXIT_OK


def command_verify(args: argparse.Namespace) -> int:
    root = _repo_root()
    surface = load_surface(Path(args.surface))
    verifier = Path(args.verifier)
    document = verify(surface, verifier, root=root)
    if args.out:
        Path(args.out).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                                  encoding="utf-8")
    if args.json:
        sys.stdout.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    elif document["ok"]:
        observed = document["observed"]
        print(f"public-surface: {len(document['commands'])} declared command(s) match "
              f"the executable surface; exit codes "
              f"{', '.join(sorted(observed['exitCodes']))} observed; "
              f"{len(observed['jsonFields'])} JSON field(s); "
              f"{len(CODES)} refusal code(s) available")
        print(f"public-surface: two-run determinism: listing "
              f"{'stable' if observed['listingStable'] else 'DIFFERS'}; "
              f"JSON document compared over {len(observed['invocations'])} invocation(s)")
        print(f"public-surface: {_codes_line([OK_CODE])}")
    else:
        return _print_findings(document)
    return EXIT_OK if document["ok"] else EXIT_REFUSED


def command_explain(args: argparse.Namespace) -> int:
    surface = load_surface(Path(args.surface))
    entries, _ = _command_entries(surface)
    by_name = {entry["name"]: entry for entry in entries}
    entry = by_name.get(args.command)
    if entry is None:
        print(f"public-surface: PV_REFUSED_COMMAND_ABSENT: {args.command!r} is not a "
              f"declared command", file=sys.stderr)
        print(f"public-surface: {_codes_line(['PV_REFUSED_COMMAND_ABSENT'])}",
              file=sys.stderr)
        return EXIT_USAGE
    print(f"public-surface: command={entry['name']} kind={entry.get('kind')} "
          f"stability={entry.get('stability')} since={entry.get('since')}")
    print(f"public-surface: summary: {entry.get('summary', '')}")
    print(f"public-surface: invocation: {entry.get('invocation', '')}")
    print(f"public-surface: arguments: {', '.join(entry.get('arguments') or [])}")
    for declared in entry.get("exitCodes") or []:
        basis = (f"observed by {declared['observedBy']}" if declared.get("observedBy")
                 else declared.get("basis", "command-specific"))
        print(f"public-surface: exit {declared.get('code')}: "
              f"{declared.get('meaning')} [{basis}]")
    print(f"public-surface: json-form: {entry.get('jsonForm')} "
          f"fields: {', '.join(entry.get('jsonFields') or []) or '(none)'}")
    print(f"public-surface: private-state: "
          f"{', '.join(entry.get('privateState') or []) or '(none)'}")
    print(f"public-surface: prerequisites: "
          f"{', '.join(entry.get('prerequisites') or []) or '(none)'}")
    print(f"public-surface: evidence: {', '.join(entry.get('evidence') or [])}")
    if entry.get("replacement"):
        print(f"public-surface: replacement: {entry['replacement']}")
    print(f"public-surface: {_codes_line([OK_CODE])}")
    return EXIT_OK


def _load_discrepancies(path: str | None) -> list[dict]:
    if not path:
        return []
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(document, dict):
        document = document.get("discrepancies") or []
    if not isinstance(document, list):
        raise SurfaceError(f"{path} does not hold a discrepancy list")
    return document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Declare a verifier's public surface and refuse when it drifts.",
        epilog="Exit 0 when nothing was refused; 1 when a refusal fired; 2 for a "
               "usage error.  The command line always prints the code.",
    )
    parser.add_argument("--surface", default=DEFAULT_SURFACE,
                        help=f"the surface declaration (default: {DEFAULT_SURFACE})")
    parser.add_argument("--verifier", default=DEFAULT_VERIFIER,
                        help=f"the verifier to compare (default: {DEFAULT_VERIFIER})")
    subparsers = parser.add_subparsers(dest="action", required=True)

    inventory_parser = subparsers.add_parser(
        "inventory", help="print the executable surface as observed")
    inventory_parser.add_argument("--json", action="store_true",
                                  help="emit the inventory document")
    inventory_parser.add_argument("--discrepancies", default=None,
                                  help="a JSON list of source-reading findings to carry")
    inventory_parser.set_defaults(handler=command_inventory)

    verify_parser = subparsers.add_parser(
        "verify", help="compare the declaration with the executable")
    verify_parser.add_argument("--json", action="store_true",
                               help="emit the verdict document")
    verify_parser.add_argument("--out", default=None,
                               help="write the verdict document to this path")
    verify_parser.set_defaults(handler=command_verify)

    explain_parser = subparsers.add_parser(
        "explain", help="print one command's declared contract")
    explain_parser.add_argument("command", help="a declared command name")
    explain_parser.set_defaults(handler=command_explain)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse already printed its own usage message; this tool's contract
        # says the command line always prints a code, including when the
        # invocation is its own malformed one.
        code = exc.code if isinstance(exc.code, int) else EXIT_USAGE
        if code == 0:
            print(f"public-surface: {_codes_line([OK_CODE])}", file=sys.stderr)
        else:
            print(f"public-surface: {_codes_line(['PV_REFUSED_USAGE'])}",
                  file=sys.stderr)
        return code
    try:
        return args.handler(args)
    except SurfaceError as exc:
        print(f"public-surface: {exc}", file=sys.stderr)
        print(f"public-surface: {_codes_line(['PV_REFUSED_SURFACE_INVALID'])}",
              file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
