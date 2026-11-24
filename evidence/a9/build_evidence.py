#!/usr/bin/env python3
"""build_evidence.py -- produce the A9 in-toto statement evidence.

The producer of `evidence/a9/STATEMENTS/*.json`, `evidence/a9/STATEMENTS.json`
and `evidence/a9/CONTROLS.json`. Every subject digest is read from the bytes by
`forensics/tools/intoto.py`; every predicate value is read from the named record
and compared with a fresh reading of it. No digest, count, state or identity is
typed here, and an absent record stops the producer rather than producing a
statement with no source.

The four real statements are the ones the records support:

  * `evidence/a1/SARIF.json`          -- SARIF 2.1.0 emission (4,245 results);
  * `evidence/a5/ADMISSION.json`      -- the `a1-sarif-results` population at
                                         the COMPLETE state its declaration admits;
  * `evidence/a7/DELTA.json`          -- the admitted `a3-fingerprint-migration`
                                         delta, with zero RESOLVED;
  * `evidence/a8/SHARD-000.sarif`     -- a shard, `subset: true`, with the
                                         parent population recorded but not claimed.

Seven further attempts are made so their refusals are measured, not asserted:
the two refused aggregate admissions, the UNKNOWN population, a COMPLETE claim
over the bounded curl population, a RESOLVED claim over a delta with none, a
verified claim over a RECORDED-only instrument, and an ACTIVE suppression with
no expiry. Each refusal code is read from the tool, never from this file.

Usage:
    python3 evidence/a9/build_evidence.py --source-commit <token>
    python3 evidence/a9/build_evidence.py --out DIR

Re-running at one source identity reproduces every file byte-for-byte.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import intoto as t  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent
STATEMENTS_DIR = OUT_DIR / "STATEMENTS"
INDEX_NAME = "STATEMENTS.json"
CONTROLS_NAME = "CONTROLS.json"

#: The records this item reads directly. The A5 re-derivation's transitive reads
#: are the ones `evidence/a5/POPULATIONS.json` names, audited by A5.
INPUTS = (
    "evidence/a1/SARIF.json",
    "evidence/a5/ADMISSION.json",
    "evidence/a5/POPULATIONS.json",
    "evidence/a7/DELTA.json",
    "evidence/a8/SHARD-000.sarif",
    "evidence/etp3/instruments.json",
    "evidence/a6/SUPPRESSIONS.json",
)

STATEMENT_SPECS = (
    {
        "file": "a1-sarif.json",
        "short": "sarif-emission",
        "subject": "evidence/a1/SARIF.json",
        "select": None,
        "fields": ("runs", "results", "subset"),
    },
    {
        "file": "a5-admission.json",
        "short": "population",
        "subject": "evidence/a5/ADMISSION.json",
        "select": "a1-sarif-results",
        "fields": ("population", "state", "examined", "omitted"),
    },
    {
        "file": "a7-delta.json",
        "short": "baseline-delta",
        "subject": "evidence/a7/DELTA.json",
        "select": "a3-fingerprint-migration",
        "fields": ("delta", "records", "resolved", "admitted"),
    },
    {
        "file": "a8-shard-000.json",
        "short": "sarif-emission",
        "subject": "evidence/a8/SHARD-000.sarif",
        "select": None,
        "fields": ("runs", "results", "subset", "parentResultCount"),
    },
)


def _git(repo_root: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *args], capture_output=True, check=False
        )
    except OSError:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.decode("utf-8", "replace").strip()


def _recorded_commit(index_path: Path) -> str | None:
    if not index_path.is_file():
        return None
    try:
        document = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    identity = document.get("sourceIdentity")
    if isinstance(identity, dict) and isinstance(identity.get("commit"), str):
        return identity["commit"]
    return None


def source_identity(repo_root: Path, commit: str) -> dict[str, Any]:
    """The measured source identity, supplied rather than read live.

    The commit token is an audit of *when the inputs were measured*. It is never a
    subject digest: every subject below is the SHA-256 of the exact bytes.
    """
    as_of = _git(repo_root, "show", "-s", "--format=%cs", commit)
    if not as_of:
        raise AssertionError(f"the source commit {commit!r} is not readable")
    inputs = []
    for relative in INPUTS:
        path = repo_root / relative
        if not path.is_file():
            raise AssertionError(f"the measured input {relative} is absent")
        inputs.append(
            {"path": relative, "sha256": t.sha256_bytes(path.read_bytes())}
        )
    return {"asOf": as_of, "commit": commit, "inputs": inputs}


def _builder(short: str) -> Callable[..., dict[str, Any]]:
    return {
        "sarif-emission": t.sarif_predicate,
        "population": t.population_predicate,
        "baseline-delta": t.delta_predicate,
        "instrument-qualification": t.instrument_predicate,
        "suppression": t.suppression_predicate,
    }[short]


def _facts(short: str, repo_root: Path, subject: str, select: str | None):
    if short == "sarif-emission":
        return t.sarif_facts(repo_root, subject)
    if short == "population":
        return t.population_facts(repo_root, subject, select)
    if short == "baseline-delta":
        return t.delta_facts(repo_root, subject, select)
    if short == "instrument-qualification":
        return t.instrument_facts(repo_root, subject, select)
    return t.suppression_facts(repo_root, subject, select)


def _projection(facts: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: facts.get(field) for field in fields}


def _refusal(action: Callable[[], Any], expected: str) -> dict[str, Any]:
    try:
        action()
    except t.Refusal as refusal:
        if refusal.code != expected:
            raise AssertionError(
                f"the refusal was {refusal.code}, expected {expected}: {refusal.message}"
            )
        return {"code": refusal.code, "reason": refusal.message}
    raise AssertionError(f"the attempt was not refused; expected {expected}")


def not_attested(repo_root: Path) -> list[dict[str, Any]]:
    """The real records the statements cannot report, with the measured refusal."""
    admission = "evidence/a5/ADMISSION.json"
    delta = "evidence/a7/DELTA.json"
    instruments = "evidence/etp3/instruments.json"
    suppressions = "evidence/a6/SUPPRESSIONS.json"
    entries: list[tuple[str, str, str | None, str, Callable[[], Any], str]] = [
        (
            admission,
            "population",
            "t4-suppressions",
            "a census over an aggregate record whose declaration is refused",
            lambda: t.population_predicate(repo_root, admission, "t4-suppressions"),
            t.IT_REFUSED_RECORD_INADMISSIBLE,
        ),
        (
            admission,
            "population",
            "t11-satisfied-runs",
            "a census over an aggregate record whose declaration is refused",
            lambda: t.population_predicate(repo_root, admission, "t11-satisfied-runs"),
            t.IT_REFUSED_RECORD_INADMISSIBLE,
        ),
        (
            admission,
            "population",
            "o11-interop-scripts",
            "a completeness claim over the HAZ-15 population admitted UNKNOWN",
            lambda: t.population_predicate(repo_root, admission, "o11-interop-scripts"),
            t.IT_REFUSED_CLAIM_UPGRADE,
        ),
        (
            admission,
            "population",
            "curl-residual-sites",
            "COMPLETE claimed over a TRUNCATED_BOUNDED population",
            lambda: t.population_predicate(
                repo_root,
                admission,
                "curl-residual-sites",
                {"state": "COMPLETE"},
            ),
            t.IT_REFUSED_CLAIM_UPGRADE,
        ),
        (
            delta,
            "baseline-delta",
            "a3-fingerprint-migration",
            "a RESOLVED claim over a delta with zero resolutions",
            lambda: t.delta_predicate(
                repo_root,
                delta,
                "a3-fingerprint-migration",
                {
                    "resolved": 1,
                    "dispositions": {
                        **t.delta_facts(
                            repo_root, delta, "a3-fingerprint-migration"
                        )["dispositions"],
                        "RESOLVED": 1,
                    },
                },
            ),
            t.IT_REFUSED_CLAIM_UPGRADE,
        ),
        (
            instruments,
            "instrument-qualification",
            "timecop-supercop",
            "a verified instrument claim over a RECORDED-only control",
            lambda: t.instrument_predicate(
                repo_root,
                instruments,
                "timecop-supercop",
                {"status": "PASS", "verified": True},
            ),
            t.IT_REFUSED_CLAIM_UPGRADE,
        ),
        (
            suppressions,
            "suppression",
            "t4-suppressions",
            "an ACTIVE suppression with neither an expiry nor an unbounded claim",
            lambda: t.suppression_predicate(
                repo_root,
                suppressions,
                "t4-suppressions",
                {"disposition": "ACTIVE", "expiry": None},
            ),
            t.IT_REFUSED_CLAIM_UPGRADE,
        ),
    ]
    recorded = []
    for record, short, select, attempted, action, expected in entries:
        outcome = _refusal(action, expected)
        recorded.append(
            {
                "record": record,
                "predicate": short,
                "select": select,
                "attempted": attempted,
                **outcome,
            }
        )
    return recorded


def build(repo_root: Path, commit: str) -> dict[str, str]:
    files: dict[str, str] = {}
    index: list[dict[str, Any]] = []
    for spec in STATEMENT_SPECS:
        short = spec["short"]
        subject_path = spec["subject"]
        select = spec["select"]
        builder = _builder(short)
        predicate = (
            builder(repo_root, subject_path)
            if select is None
            else builder(repo_root, subject_path, select)
        )
        subject = t.subject_for(subject_path, repo_root=repo_root)
        document = t.statement(
            [subject], t.PREDICATE_BY_SHORT[short], predicate
        )
        text = t.encode(document)
        # The statement must verify against a fresh reading before it is written.
        report = t.verify_statement(text, repo_root)
        if report["subject"] != subject["name"]:
            raise AssertionError(f"{spec['file']}: verified the wrong subject")

        facts = _facts(short, repo_root, subject_path, select)
        asserted = _projection(predicate, spec["fields"])
        recorded = _projection(facts, spec["fields"])
        if asserted != recorded:
            raise AssertionError(
                f"{spec['file']}: the predicate states {asserted}, the record "
                f"states {recorded}"
            )

        relative = f"STATEMENTS/{spec['file']}"
        files[relative] = text
        index.append(
            {
                "statement": relative,
                "statementSha256": t.sha256_bytes(text.encode("utf-8")),
                "subject": subject["name"],
                "digest": subject["digest"],
                "predicateType": t.PREDICATE_BY_SHORT[short],
                "record": facts["record"],
                "assertedState": asserted,
                "recordState": recorded,
                "relation": "equal",
            }
        )

    refused = not_attested(repo_root)
    controls = t.build_controls(repo_root)
    if len(controls) < len(t.REFUSALS):
        raise AssertionError(f"{len(controls)} controls over {len(t.REFUSALS)} codes")
    if {control["code"] for control in controls} != set(t.REFUSALS):
        raise AssertionError("the controls do not cover every refusal code")
    if {entry["code"] for entry in refused} - set(t.REFUSALS):
        raise AssertionError("a not-attested entry carries an unregistered code")

    predicate_types = {entry["predicateType"] for entry in index}
    documents = {
        "STATEMENTS.json": t.dump_document(
            {
                "schema": t.STATEMENTS_SCHEMA,
                "model": t.MODEL_ID,
                "purpose": (
                    "the in-toto Statement v1 attestations this project emits, the "
                    "exact bytes each subject digest was computed from, and the "
                    "attempts the records refuse"
                ),
                "statementType": t.STATEMENT_TYPE,
                "sourceIdentity": source_identity(repo_root, commit),
                "statements": index,
                "notAttested": refused,
                "totals": {
                    "statements": len(index),
                    "subjects": len({entry["subject"] for entry in index}),
                    "predicateTypes": len(predicate_types),
                    "notAttested": len(refused),
                    "controls": len(controls),
                    "codes": len(t.REFUSALS),
                },
            }
        ),
        "CONTROLS.json": t.dump_document(t.controls_document(controls)),
    }
    files.update(documents)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--source-commit", default=None)
    args = parser.parse_args(argv)

    commit = args.source_commit or _recorded_commit(OUT_DIR / INDEX_NAME)
    if commit is None:
        print(
            "producer: the source identity is an explicit input; pass "
            "--source-commit <token> on the first run",
            file=sys.stderr,
        )
        return 2
    try:
        documents = build(args.repo_root, commit)
    except t.Refusal as refusal:
        print(f"producer: code={refusal.code}: {refusal.message}", file=sys.stderr)
        return 2
    except AssertionError as error:
        print(f"producer assertion failed: {error}", file=sys.stderr)
        return 1

    for relative, text in documents.items():
        path = args.out / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    index = json.loads(documents["STATEMENTS.json"])
    for entry in index["statements"]:
        print(
            f"statement {entry['statement']}: subject={entry['subject']} "
            f"sha256={entry['digest']['sha256']} "
            f"predicateType={entry['predicateType']} "
            f"asserted={json.dumps(entry['assertedState'], sort_keys=True)}"
        )
    for entry in index["notAttested"]:
        print(
            f"refused {entry['record']} {entry['select']}: code={entry['code']}"
        )
    totals = index["totals"]
    print(
        f"statements={totals['statements']} subjects={totals['subjects']} "
        f"predicateTypes={totals['predicateTypes']} "
        f"notAttested={totals['notAttested']} controls={totals['controls']} "
        f"codes={totals['codes']} commit={index['sourceIdentity']['commit']}"
    )
    print(
        "wrote "
        + ", ".join(
            f"{relative} ({len(text.encode('utf-8'))} bytes)"
            for relative, text in documents.items()
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
