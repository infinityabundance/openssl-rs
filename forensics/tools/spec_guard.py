#!/usr/bin/env python3
"""spec_guard.py -- fail-closed guard against implementation-shaped specifications.

A specification that restates the implementation proves nothing.  This tool
makes one part of that rule mechanical for the tracked specification artefacts:

  * every artefact in the population declares a refinement level;
  * the text of an artefact must not reference an internal identifier of the
    implementation it refines -- a Rust function, type or module name defined
    under ``src/``, or a ``src/...``/``crate::``/``super::``/``self::`` path;
  * an ABI observable (an exported symbol, ``#[no_mangle]``, ``extern "C"``
    declaration or ``.ld`` export) is not an internal identifier and needs no
    exemption;
  * a genuinely needed internal identifier may be named only through an
    exemption that records a justification and a reviewer, and an exemption that
    no longer matches the text is refused rather than left to accumulate.

The population is derived, not hand-listed: the distinct source documents of the
T1 ``requirement`` nodes, plus the contract documents the ETP-T3 registry names.
A population member that is neither a registered specification, a recorded known
nonconformance, nor an explicitly excluded control, is refused.  A recorded known
nonconformance whose token set changes, or which no longer reproduces, is also
refused: a register that drifts away from the text is not evidence.

Usage:

    python3 forensics/tools/spec_guard.py check     [--config PATH] [--repo-root PATH]
    python3 forensics/tools/spec_guard.py inventory [--config PATH] [--json]
    python3 forensics/tools/spec_guard.py self-test

Exit status: 0 only when every requested check passed; 1 for a refusal; 2 for a
usage error.  Output is deterministic and sorted.

Limits (stated, not hidden): the identifier lexicon is a static scan of
``src/**/*.rs`` and the exported-symbol records.  It detects a reference written
inside a code span or as a source path; it does not detect an internal concept
restated in prose without naming it, and it cannot decide whether a
specification is *semantically* independent.  Those remain review obligations.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "evidence" / "etp-t3" / "SPECIFICATIONS.json"
GRAPH = REPO_ROOT / "evidence" / "etp-t1" / "TRACEABILITY.json"

SCHEMA = "openssl-rs/etp/spec-guard/1"
EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

# Generic CamelCase words that a Rust source happens to define but that a
# specification may use without naming an internal implementation detail.
GENERIC_TYPES = {
    "Action", "Actor", "Builder", "Config", "Context", "Entry", "Error", "Event",
    "Handle", "Item", "Kind", "Level", "List", "Manager", "Map", "Method", "Mode",
    "Node", "Option", "Policy", "Provider", "Record", "Result", "Session", "Set",
    "State", "Store", "Tree", "Value", "Wrapper",
}
GENERIC_FUNCTIONS = {
    "build", "check", "clone", "decode", "default", "drop", "encode", "final",
    "free", "init", "main", "new", "parse", "update", "validate", "value",
}

DEFS = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:const\s+)?(?:async\s+)?"
    r"(fn|struct|enum|trait|type|mod)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
CODE_SPAN = re.compile(r"`([^`\n]+)`")
SRC_PATH = re.compile(r"\bsrc/[A-Za-z0-9_/]+\.rs\b")
RUST_PATH = re.compile(r"\b(?:crate|super|self)::")


class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(repo), *args],
        capture_output=True, check=False,
    )


def tracked(repo: Path, pattern: str) -> list[str]:
    result = _git(repo, "ls-files", pattern)
    if result.returncode != 0:
        raise Refusal("SP_GIT_UNAVAILABLE", f"git ls-files {pattern} failed")
    return [line for line in result.stdout.decode("utf-8").splitlines() if line]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal("SP_UNREADABLE", f"{path}: {exc}") from exc


# --------------------------------------------------------------------------
# Identifier lexicon
# --------------------------------------------------------------------------


def _strip_comments(text: str) -> str:
    """Remove comments so a commented-out item is not a definition."""
    text = re.sub(r"/\*[\s\S]*?\*/", "", text)
    return re.sub(r"//[^\n]*", "", text)


def _code_only(text: str) -> str:
    """Remove comments and string literals for definition scanning."""
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', _strip_comments(text))


def _exported_symbols(repo: Path) -> set[str]:
    exports: set[str] = set()
    for path in tracked(repo, "artifacts/*.ld"):
        for line in read_text(repo / path).splitlines():
            match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*;?\s*$", line)
            if match:
                exports.add(match.group(1))
    for path in tracked(repo, "src/**/*.rs"):
        text = _strip_comments(read_text(repo / path))
        exports.update(re.findall(
            r'#\[no_mangle\][\s\S]{0,300}?fn\s+([A-Za-z_][A-Za-z0-9_]*)', text
        ))
        exports.update(re.findall(
            r'#\[export_name\s*=\s*"([A-Za-z_][A-Za-z0-9_]*)"\]', text
        ))
        for block in re.findall(r'extern\s+"C"\s*\{([\s\S]*?)\n\}', text):
            exports.update(re.findall(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", block))
    return exports


def internal_identifiers(repo: Path) -> dict[str, str]:
    """Return {name: kind} for implementation-internal identifiers.

    A type is internal when it is a Rust ``struct``/``enum``/``trait``/``type``
    with a mixed-case name that is not an exported symbol.  A function is
    internal when it is a Rust ``fn`` with a distinctive snake_case name that is
    not an exported symbol.  Module names are not included on their own: a bare
    lowercase word is not evidence of a module reference, while ``crate::mod``
    and ``src/...`` paths are detected separately.
    """
    exports = _exported_symbols(repo)
    lexicon: dict[str, str] = {}
    for path in tracked(repo, "src/**/*.rs"):
        text = _code_only(read_text(repo / path))
        for kind, name in DEFS.findall(text):
            if name in exports:
                continue
            if kind in ("struct", "enum", "trait", "type"):
                if (
                    name in GENERIC_TYPES
                    or not name[0].isupper()
                    or len(name) < 5
                    or not any(c.islower() for c in name)
                    or name.endswith("_st")
                ):
                    continue
                lexicon.setdefault(name, kind)
            elif kind == "fn":
                if (
                    name in GENERIC_FUNCTIONS
                    or len(name) < 6
                    or ("_" not in name and len(name) < 12)
                ):
                    continue
                lexicon.setdefault(name, "fn")
    return lexicon


def scan(text: str, lexicon: dict[str, str]) -> list[tuple[int, str]]:
    """Return (line, token) for every internal reference in a specification.

    Only code spans and explicit source/Rust paths are examined.  A reference in
    ordinary prose is outside this detector's claim; that limit is documented in
    the module docstring and in ``docs/REFINEMENT-ARCHITECTURE.md``.
    """
    findings: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()

    def add(line: int, token: str) -> None:
        key = (line, token)
        if key not in seen:
            seen.add(key)
            findings.append(key)

    for match in CODE_SPAN.finditer(text):
        span = match.group(1)
        line = text.count("\n", 0, match.start()) + 1
        for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", span):
            if ident in lexicon:
                add(line, ident)
        if SRC_PATH.search(span):
            add(line, "src-path")
        if RUST_PATH.search(span):
            add(line, "rust-path")
    for match in SRC_PATH.finditer(text):
        add(text.count("\n", 0, match.start()) + 1, "src-path")
    return sorted(findings)


# --------------------------------------------------------------------------
# Configuration and artefact checks
# --------------------------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise Refusal("SP_JSON_DUPLICATE_KEY", f"duplicate key {key!r}")
        seen[key] = value
    return seen


def load_config(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except OSError as exc:
        raise Refusal("SP_CONFIG_UNREADABLE", f"{path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise Refusal("SP_CONFIG_MALFORMED", f"{path}: {exc}") from exc
    if not isinstance(document, dict):
        raise Refusal("SP_CONFIG_MALFORMED", f"{path}: top level is not an object")
    if document.get("schema") != SCHEMA:
        raise Refusal("SP_SCHEMA", f"schema is {document.get('schema')!r}")
    if not isinstance(document.get("levels"), list) or not document["levels"]:
        raise Refusal("SP_SCHEMA", "levels must be a non-empty array")
    return document


def level_ids(config: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for entry in config["levels"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise Refusal("SP_SCHEMA", "a level has no string id")
        ids.add(entry["id"])
    return ids


def check_artefact(
    repo: Path,
    path: str,
    level: str | None,
    exemptions: Iterable[dict[str, Any]],
    levels: set[str],
    lexicon: dict[str, str],
) -> list[str]:
    """Return refusal strings for one specification artefact (empty = accepted)."""
    errors: list[str] = []
    if not isinstance(level, str) or not level:
        errors.append(f"SP_NO_LEVEL: {path}: the artefact declares no refinement level")
    elif level not in levels:
        errors.append(f"SP_UNKNOWN_LEVEL: {path}: level {level!r} is not in the registry")
    target = repo / path
    if not target.is_file():
        return errors + [f"SP_UNREADABLE: {path}: no such tracked file"]
    text = read_text(target)
    findings = scan(text, lexicon)
    present = {token for _, token in findings}
    if not isinstance(exemptions, list):
        return errors + [f"SP_SCHEMA: {path}: exemptions is not an array"]

    exempted: set[str] = set()
    for entry in exemptions:
        if not isinstance(entry, dict) or not isinstance(entry.get("token"), str):
            errors.append(f"SP_EXEMPTION_UNJUSTIFIED: {path}: exemption without a token")
            continue
        token = entry["token"]
        missing = [key for key in ("justification", "reviewer", "reviewed")
                   if not isinstance(entry.get(key), str) or not entry.get(key, "").strip()]
        if missing:
            errors.append(
                f"SP_EXEMPTION_UNJUSTIFIED: {path}: exemption for {token!r} "
                f"is missing {', '.join(missing)}"
            )
            continue
        if token not in present:
            errors.append(
                f"SP_STALE_EXEMPTION: {path}: exemption names {token!r}, "
                "which the text no longer contains"
            )
            continue
        exempted.add(token)

    for line, token in findings:
        if token in exempted:
            continue
        errors.append(
            f"SP_INTERNAL_IDENTIFIER: {path}:{line}: {token!r} names an internal "
            f"identifier of the refined implementation"
        )
    return errors


def requirement_sources(repo: Path) -> list[str]:
    path = repo / "evidence" / "etp-t1" / "TRACEABILITY.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise Refusal("SP_GRAPH_UNREADABLE", f"{path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise Refusal("SP_GRAPH_MALFORMED", f"{path}: {exc}") from exc
    sources = {
        node["source"]["path"]
        for node in document.get("nodes", [])
        if node.get("type") == "requirement"
        and isinstance(node.get("source"), dict)
        and isinstance(node["source"].get("path"), str)
    }
    if not sources:
        raise Refusal("SP_GRAPH_EMPTY", "the graph records no requirement source")
    return sorted(sources)


def population(config: dict[str, Any], repo: Path) -> list[str]:
    declared = config.get("population")
    if not isinstance(declared, dict):
        raise Refusal("SP_SCHEMA", "population is absent")
    contract = declared.get("contract_documents")
    if not isinstance(contract, list) or not all(isinstance(p, str) for p in contract):
        raise Refusal("SP_SCHEMA", "population.contract_documents is not a string array")
    return sorted(set(requirement_sources(repo)) | set(contract))


def _entries(config: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = config.get(key, [])
    if not isinstance(value, list):
        raise Refusal("SP_SCHEMA", f"{key} is not an array")
    for entry in value:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise Refusal("SP_SCHEMA", f"a {key} entry has no string path")
    return value


def check(repo: Path, config: dict[str, Any]) -> list[str]:
    levels = level_ids(config)
    lexicon = internal_identifiers(repo)
    specs = _entries(config, "specifications")
    known = _entries(config, "known_failures")
    excluded = _entries(config, "excluded")

    errors: list[str] = []
    seen: dict[str, str] = {}
    for entry in specs:
        path = entry["path"]
        if path in seen:
            errors.append(f"SP_DUPLICATE_CLASSIFICATION: {path}: also named under {seen[path]}")
        seen[path] = "specifications"
    for entry in known:
        path = entry["path"]
        if path in seen:
            errors.append(f"SP_DUPLICATE_CLASSIFICATION: {path}: also named under {seen[path]}")
        seen[path] = "known_failures"

    members = population(config, repo)
    member_set = set(members)
    for entry in specs + known:
        if entry["path"] not in member_set:
            errors.append(
                f"SP_UNKNOWN_CLASSIFICATION: {entry['path']}: not in the derived "
                "specification population"
            )
    for path in members:
        if path not in seen:
            errors.append(
                f"SP_UNCLASSIFIED: {path}: in the specification population but "
                "neither registered nor recorded as a known nonconformance"
            )

    for entry in specs:
        errors.extend(check_artefact(
            repo, entry["path"], entry.get("level"), entry.get("exemptions", []),
            levels, lexicon,
        ))

    for entry in known:
        path = entry["path"]
        if not isinstance(entry.get("level"), str) or entry["level"] not in levels:
            errors.append(
                f"SP_NO_LEVEL: {path}: a known nonconformance must still declare a level"
            )
        tokens = entry.get("tokens")
        if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
            errors.append(f"SP_SCHEMA: {path}: known_failures.tokens is not a string array")
            continue
        target = repo / path
        if not target.is_file():
            errors.append(f"SP_UNREADABLE: {path}: no such tracked file")
            continue
        discovered = sorted({token for _, token in scan(read_text(target), lexicon)})
        expected = sorted(set(tokens))
        if not discovered:
            errors.append(
                f"SP_STALE_KNOWN_FAILURE: {path}: recorded as a known nonconformance "
                "but now names no internal identifier"
            )
        elif discovered != expected:
            added = sorted(set(discovered) - set(expected))
            removed = sorted(set(expected) - set(discovered))
            errors.append(
                f"SP_KNOWN_FAILURE_DRIFT: {path}: tokens added {added}, removed {removed}"
            )

    for entry in excluded:
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            errors.append(f"SP_EXCLUSION_UNJUSTIFIED: {entry['path']}: no reason recorded")

    return errors


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def command_check(repo: Path, config_path: Path) -> int:
    config = load_config(config_path)
    errors = check(repo, config)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return EXIT_REFUSED
    levels = level_ids(config)
    specs = _entries(config, "specifications")
    known = _entries(config, "known_failures")
    print(
        f"spec-guard: {len(specs)} registered specification(s), "
        f"{len(known)} recorded known nonconformance(s), "
        f"{len(levels)} level(s); 0 unclassified, 0 unjustified exemptions"
    )
    return EXIT_OK


def command_inventory(repo: Path, config_path: Path, as_json: bool) -> int:
    config = load_config(config_path)
    levels = level_ids(config)
    lexicon = internal_identifiers(repo)
    specs = {entry["path"]: entry for entry in _entries(config, "specifications")}
    known = {entry["path"]: entry for entry in _entries(config, "known_failures")}
    rows: list[dict[str, Any]] = []
    failing = 0
    for path in population(config, repo):
        entry = specs.get(path) or known.get(path)
        level = entry.get("level") if entry else None
        findings = scan(read_text(repo / path), lexicon)
        tokens = sorted({token for _, token in findings})
        state = "PASS" if not tokens else "FAIL"
        if state == "FAIL":
            failing += 1
        rows.append({
            "path": path,
            "level": level,
            "state": state,
            "tokens": tokens,
            "locations": [{"line": line, "token": token} for line, token in findings],
        })
    payload = {
        "population": len(rows),
        "failing": failing,
        "levels": sorted(levels),
        "rows": rows,
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for row in sorted(rows, key=lambda r: (-len(r["tokens"]), r["path"])):
            if row["state"] == "FAIL":
                print(f"{len(row['tokens']):4d} {row['path']}: " + ", ".join(row["tokens"]))
        print(
            f"{failing}/{len(rows)} specification-bearing documents name an internal "
            "identifier"
        )
    return EXIT_REFUSED if failing else EXIT_OK


def command_self_test(repo: Path, config_path: Path) -> int:
    config = load_config(config_path)
    levels = level_ids(config)
    lexicon = internal_identifiers(repo)
    controls = config.get("controls", [])
    if not isinstance(controls, list) or not controls:
        print("SP_SCHEMA: no controls recorded", file=sys.stderr)
        return EXIT_REFUSED
    failures = 0
    for control in controls:
        if not isinstance(control, dict) or not isinstance(control.get("path"), str):
            print("SP_SCHEMA: a control has no string path", file=sys.stderr)
            failures += 1
            continue
        path = control["path"]
        expected = control.get("expect", [])
        errors = check_artefact(
            repo, path, control.get("level"), control.get("exemptions", []),
            levels, lexicon,
        )
        observed = sorted({error.split(":", 1)[0] for error in errors})
        if observed != sorted(expected):
            failures += 1
            print(
                f"SP_CONTROL_MISMATCH: {path}: expected {sorted(expected)}, "
                f"observed {observed} ({errors})",
                file=sys.stderr,
            )
    if failures:
        return EXIT_REFUSED
    print(f"spec-guard self-test: {len(controls)} controls behaved as recorded")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "inventory", "self-test"))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            return command_check(args.repo_root, args.config)
        if args.command == "inventory":
            return command_inventory(args.repo_root, args.config, args.json)
        return command_self_test(args.repo_root, args.config)
    except Refusal as refusal:
        print(f"{refusal.code}: {refusal.detail}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
