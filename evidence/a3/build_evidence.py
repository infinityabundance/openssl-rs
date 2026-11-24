#!/usr/bin/env python3
"""build_evidence.py -- derive the A3 evidence from the identity model.

This script is the producer of `evidence/a3/{CODE-MOTION,COLLISIONS,MIGRATION}.json`.
It constructs each case through `forensics/tools/finding_identity.py`, compares the
observed relation with the declared expectation, and writes deterministic JSON.
Nothing is hand-typed into the outputs: a case that does not match its expectation
stops the script with an assertion.

Usage:
    python3 evidence/a3/build_evidence.py
    python3 evidence/a3/build_evidence.py --out DIR

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import finding_identity as fi  # noqa: E402
import sarif_adapter as adapter  # noqa: E402

A1_SARIF = REPO_ROOT / "evidence" / "a1" / "SARIF.json"
CANDIDATE = {"branch": "staging", "commit": "a" * 40}
DIGEST_A = "1" * 64
DIGEST_B = "2" * 64

RULE_REGISTER = "A1-SECRET-CLEANSING-UNMET"
RULE_PATH = "A1-UNSAFE-CONTRACT-ABSENT"


def _make(
    rule: str,
    key_class: str,
    fields: dict,
    uri: str,
    digest: str,
    scope: str,
    region: fi.Region,
    locator: str,
) -> fi.Finding:
    return fi.identify(
        rule_id=rule,
        key_class=key_class,
        binding=fi.Binding(uri=uri, digest=digest, digest_scope=scope),
        region=region,
        candidate=CANDIDATE,
        native_locator=locator,
        **fields,
    )


def _register(uri, digest, line, identifier="SEC-1"):
    return _make(
        RULE_REGISTER,
        "register-entry",
        {"id": identifier},
        uri,
        digest,
        "source-tree",
        fi.Region("source", line=line),
        f"entries/id={identifier}",
    )


def _path_site(uri, digest, line, symbol="OpenSSL_foo", status="VACUOUS_PRECONDITION"):
    return _make(
        RULE_PATH,
        "path-symbol-status",
        {"path": uri, "symbol": symbol, "status": status},
        uri,
        digest,
        "source-tree",
        fi.Region("source", line=line),
        f"sites/{uri}/{symbol}",
    )


def _variant(
    name: str,
    key_class: str,
    before: fi.Finding,
    after: fi.Finding,
    expect_logical: bool,
    expect_exact: bool,
    expect_relation: str,
    note: str,
) -> dict:
    verdict = fi.classify_motion(before, after)
    assert verdict.logical_preserved is expect_logical, (name, verdict)
    assert verdict.exact_preserved is expect_exact, (name, verdict)
    assert verdict.relation == expect_relation, (name, verdict.relation, expect_relation)
    if expect_logical:
        fi.require_preservation(before, after)
    else:
        try:
            fi.require_preservation(before, after)
        except fi.IdentityRefusal as refusal:
            assert refusal.code == fi.FI_REFUSED_UNJUSTIFIED_PRESERVATION, refusal
        else:  # pragma: no cover - an unjustified preservation must be refused
            raise AssertionError(f"{name}: preservation was not refused")
    return {
        "name": name,
        "keyClass": key_class,
        "before": before.as_dict(),
        "after": after.as_dict(),
        "observed": verdict.as_dict(),
        "expected": {
            "logicalPreserved": expect_logical,
            "exactPreserved": expect_exact,
            "relation": expect_relation,
        },
        "matchesExpectation": True,
        "note": note,
    }


def build_code_motion() -> dict:
    cases = []

    cases.append(
        {
            "case": "moved-within-file",
            "description": (
                "a function is moved inside its file; the finding's own native fields "
                "are unchanged and only its line moves"
            ),
            "variants": [
                _variant(
                    "register-keyed, location only",
                    "register-entry",
                    _register("src/a.rs", DIGEST_A, 40),
                    _register("src/a.rs", DIGEST_A, 120),
                    True,
                    False,
                    fi.RELATION_LOCATION_MOVED,
                    "the key is the register id, which did not move; the exact region did",
                ),
                _variant(
                    "path-keyed, location only",
                    "path-symbol-status",
                    _path_site("src/a.rs", DIGEST_A, 40),
                    _path_site("src/a.rs", DIGEST_A, 120),
                    True,
                    False,
                    fi.RELATION_LOCATION_MOVED,
                    "path, symbol and status are unchanged; only the region moved",
                ),
                _variant(
                    "path-keyed, with the file rebuilt",
                    "path-symbol-status",
                    _path_site("src/a.rs", DIGEST_A, 40),
                    _path_site("src/a.rs", DIGEST_B, 120),
                    True,
                    False,
                    fi.RELATION_ARTEFACT_BYTES_CHANGED,
                    "a real move changes the file, so the source-tree digest changes "
                    "too; the exact identity changes for both reasons",
                ),
            ],
        }
    )

    cases.append(
        {
            "case": "moved-to-another-file",
            "description": "the function is moved from one source file to another",
            "variants": [
                _variant(
                    "register-keyed",
                    "register-entry",
                    _register("src/a.rs", DIGEST_A, 40),
                    _register("src/b.rs", DIGEST_B, 60),
                    True,
                    False,
                    fi.RELATION_SUBJECT_CHANGED,
                    "the register id is unchanged, so the logical finding is the same; "
                    "the subject artefact changed, so the exact occurrence is new",
                ),
                _variant(
                    "path-keyed",
                    "path-symbol-status",
                    _path_site("src/a.rs", DIGEST_A, 40),
                    _path_site("src/b.rs", DIGEST_B, 60),
                    False,
                    False,
                    fi.RELATION_LOGICAL_KEY_CHANGED,
                    "path is a logical-key field, so moving the function to another "
                    "file yields a new logical identity; reusing the old one is a defect",
                ),
            ],
        }
    )

    cases.append(
        {
            "case": "renamed",
            "description": "the function is renamed with its body unchanged",
            "variants": [
                _variant(
                    "register-keyed",
                    "register-entry",
                    _register("src/a.rs", DIGEST_A, 40),
                    _register("src/a.rs", DIGEST_B, 40),
                    True,
                    False,
                    fi.RELATION_ARTEFACT_BYTES_CHANGED,
                    "the identity is the register entry id, which a rename does not "
                    "change; the file bytes changed, so the exact occurrence is new",
                ),
                _variant(
                    "path-keyed",
                    "path-symbol-status",
                    _path_site("src/a.rs", DIGEST_A, 40, symbol="OpenSSL_foo"),
                    _path_site("src/a.rs", DIGEST_B, 40, symbol="OpenSSL_bar"),
                    False,
                    False,
                    fi.RELATION_LOGICAL_KEY_CHANGED,
                    "symbol is a logical-key field; a rename is a new logical identity, "
                    "not a moved occurrence",
                ),
            ],
        }
    )

    cases.append(
        {
            "case": "reformatted",
            "description": (
                "the file is reformatted with no semantic change; the finding's line and "
                "native fields are unchanged but the bytes are not"
            ),
            "variants": [
                _variant(
                    "path-keyed",
                    "path-symbol-status",
                    _path_site("src/a.rs", DIGEST_A, 40),
                    _path_site("src/a.rs", DIGEST_B, 40),
                    True,
                    False,
                    fi.RELATION_ARTEFACT_BYTES_CHANGED,
                    "the logical key is unchanged; a source-tree-scoped exact identity "
                    "includes the tree digest, so a reformat changes it",
                ),
                _variant(
                    "register-keyed",
                    "register-entry",
                    _register("src/a.rs", DIGEST_A, 40),
                    _register("src/a.rs", DIGEST_B, 40),
                    True,
                    False,
                    fi.RELATION_ARTEFACT_BYTES_CHANGED,
                    "the register id is unchanged; the exact identity moves with the "
                    "artefact bytes",
                ),
            ],
        }
    )

    for case, delta in (("insertion-above", 14), ("deletion-above", -14)):
        cases.append(
            {
                "case": case,
                "description": (
                    "lines are inserted above (or deleted above) the finding; the "
                    "finding's own text and native fields are unchanged"
                ),
                "variants": [
                    _variant(
                        "path-keyed, location only",
                        "path-symbol-status",
                        _path_site("src/a.rs", DIGEST_A, 40),
                        _path_site("src/a.rs", DIGEST_A, 40 + delta),
                        True,
                        False,
                        fi.RELATION_LOCATION_MOVED,
                        "line numbers are not logical-key fields, so the logical "
                        "identity is preserved while the exact identity moves",
                    ),
                    _variant(
                        "path-keyed, with the file rebuilt",
                        "path-symbol-status",
                        _path_site("src/a.rs", DIGEST_A, 40),
                        _path_site("src/a.rs", DIGEST_B, 40 + delta),
                        True,
                        False,
                        fi.RELATION_ARTEFACT_BYTES_CHANGED,
                        "in a real edit both the region and the tree digest change; the "
                        "logical identity is still preserved",
                    ),
                ],
            }
        )

    cases.append(
        {
            "case": "file-split",
            "description": "one file is split into two and the function moves to the new file",
            "variants": [
                _variant(
                    "path-keyed",
                    "path-symbol-status",
                    _path_site("src/a.rs", DIGEST_A, 40),
                    _path_site("src/a_part.rs", DIGEST_B, 10),
                    False,
                    False,
                    fi.RELATION_LOGICAL_KEY_CHANGED,
                    "the path changed, so a path-keyed logical identity is new; the "
                    "model does not infer that the two paths hold the same code",
                ),
                _variant(
                    "register-keyed",
                    "register-entry",
                    _register("src/a.rs", DIGEST_A, 40),
                    _register("src/a_part.rs", DIGEST_B, 10),
                    True,
                    False,
                    fi.RELATION_SUBJECT_CHANGED,
                    "a location-independent key survives the split; only the subject "
                    "binding changes",
                ),
            ],
        }
    )

    cases.append(
        {
            "case": "file-merge",
            "description": "two files are merged and the function moves to the merged file",
            "variants": [
                _variant(
                    "path-keyed",
                    "path-symbol-status",
                    _path_site("src/a.rs", DIGEST_A, 40),
                    _path_site("src/merged.rs", DIGEST_B, 100),
                    False,
                    False,
                    fi.RELATION_LOGICAL_KEY_CHANGED,
                    "the path changed, so a path-keyed logical identity is new",
                ),
                _variant(
                    "register-keyed",
                    "register-entry",
                    _register("src/a.rs", DIGEST_A, 40),
                    _register("src/merged.rs", DIGEST_B, 100),
                    True,
                    False,
                    fi.RELATION_SUBJECT_CHANGED,
                    "a location-independent key survives the merge; the exact identity "
                    "is bound to the new artefact",
                ),
            ],
        }
    )

    assert [case["case"] for case in cases] == list(fi.MOTION_CASES)
    return {
        "schema": "openssl-rs/a3/code-motion/1",
        "model": fi.MODEL_ID,
        "tool": "evidence/a3/build_evidence.py",
        "rule": (
            "a logical identity is preserved only when every field of its registered "
            "logical key is unchanged, and an exact identity only when the rule, key, "
            "artefact binding, scope, digest and region are unchanged; where "
            "preservation cannot be derived, a new identity is correct and reuse is a "
            "defect"
        ),
        "cases": cases,
        "caseCount": len(cases),
        "variantCount": sum(len(case["variants"]) for case in cases),
        "allMatchExpectation": True,
    }


def _logical_collision_fixture() -> list[fi.Finding]:
    # Two genuinely different findings: different artefacts, different lines, the
    # same native register id. They are two members of one logical identity.
    return [
        _register("src/c.rs", DIGEST_A, 30, identifier="SEC-DUP"),
        _register("src/d.rs", DIGEST_B, 40, identifier="SEC-DUP"),
    ]


def _recorded_scan() -> dict:
    document = json.loads(A1_SARIF.read_text(encoding="utf-8"))
    per_run = []
    all_findings: list[fi.Finding] = []
    for run in document["runs"]:
        record = run["properties"]["a1"]["record"]["path"]
        findings = [adapter.identity_from_result(result) for result in run["results"]]
        all_findings.extend(findings)
        exact = fi.collision_report(findings, "exact")
        logical = fi.collision_report(findings, "logical")
        per_run.append(
            {
                "record": record,
                "results": len(findings),
                "fingerprintsVerified": len(findings) * len(fi.WIRE_KEYS),
                "exactCollisions": exact["collisionCount"],
                "exactCollisionMembers": exact["collisionMembers"],
                "logicalCollisions": logical["collisionCount"],
                "logicalCollisionMembers": logical["collisionMembers"],
                "exactGroups": exact["groups"],
                "logicalGroups": logical["groups"],
            }
        )
    cross_run = fi.collision_report(all_findings, "logical")
    return {
        "source": "evidence/a1/SARIF.json",
        "sourceSha256": fi.digest_file(A1_SARIF),
        "runs": len(per_run),
        "results": len(all_findings),
        "fingerprintsVerified": len(all_findings) * len(fi.WIRE_KEYS),
        "perRun": per_run,
        "crossRunLogicalCollisions": cross_run["collisionCount"],
        "crossRunLogicalCollisionMembers": cross_run["collisionMembers"],
        "crossRunLogicalGroups": cross_run["groups"],
        "verification": (
            "every result's three recorded fingerprints were recomputed from its own "
            "native logical key, artefact binding and region; a mismatch would have "
            "been refused by sarif_adapter.identity_from_result"
        ),
    }


def build_collisions() -> dict:
    findings = _logical_collision_fixture()
    logical = fi.collision_report(findings, "logical")
    exact = fi.collision_report(findings, "exact")
    fingerprint = findings[0].logical_fingerprint
    assert logical["collisionCount"] == 1
    assert logical["groups"][0]["count"] == 2
    assert exact["collisionCount"] == 0

    without_discriminator: dict
    try:
        fi.attribute(findings, fingerprint, "logical")
    except fi.IdentityRefusal as refusal:
        without_discriminator = {
            "refused": True,
            "code": refusal.code,
            "detail": refusal.detail,
        }
    else:  # pragma: no cover
        raise AssertionError("an ambiguous attribution must be refused")

    resolved = fi.attribute(
        findings,
        fingerprint,
        "logical",
        discriminator=lambda f: f.binding.uri == "src/c.rs",
    )
    still_ambiguous: dict
    try:
        fi.attribute(findings, fingerprint, "logical", discriminator=lambda f: True)
    except fi.IdentityRefusal as refusal:
        still_ambiguous = {
            "refused": True,
            "code": refusal.code,
            "detail": refusal.detail,
        }
    else:  # pragma: no cover
        raise AssertionError("a discriminator that leaves two members must still refuse")

    cross_artefact: dict
    try:
        fi.relate(findings[0], findings[1], "same-occurrence")
    except fi.IdentityRefusal as refusal:
        cross_artefact = {
            "refused": True,
            "code": refusal.code,
            "detail": refusal.detail,
        }
    else:  # pragma: no cover
        raise AssertionError("an exact identity must not transfer across artefacts")

    logical_permit = fi.relate(findings[0], findings[1], "same-logical-finding")
    exact_scope_refused: dict
    try:
        fi.authorise_scope(logical_permit, fi.SCOPE_EXACT)
    except fi.IdentityRefusal as refusal:
        exact_scope_refused = {
            "refused": True,
            "code": refusal.code,
            "detail": refusal.detail,
        }
    else:  # pragma: no cover
        raise AssertionError("a logical permit must not authorise exact-scope reuse")

    return {
        "schema": "openssl-rs/a3/collisions/1",
        "model": fi.MODEL_ID,
        "tool": "evidence/a3/build_evidence.py",
        "policy": fi.COLLISION_POLICY,
        "refusalCondition": (
            "attribution of a claim, suppression, discharge or other conclusion to a "
            "fingerprint is refused unless exactly one member matches; a discriminator "
            "that leaves more than one member does not make the attribution valid"
        ),
        "fixture": {
            "description": (
                "two genuinely different register findings in different artefacts, "
                "sharing one native register id"
            ),
            "members": [finding.as_dict() for finding in findings],
            "logical": logical,
            "exact": exact,
            "attributionWithoutDiscriminator": without_discriminator,
            "attributionWithDiscriminator": {
                "resolved": True,
                "member": resolved.as_dict(),
                "discriminator": "binding.uri == 'src/c.rs'",
            },
            "attributionWithNonDiscriminatingFilter": still_ambiguous,
            "sameOccurrenceAcrossArtefacts": cross_artefact,
            "logicalPermit": logical_permit.as_dict(),
            "exactScopeUseOfLogicalPermit": exact_scope_refused,
        },
        "recorded": _recorded_scan(),
        "nonClaims": [
            "a collision is not a defect in a finding; it is a limit on attribution",
            "a zero collision count is a statement about this population, not about "
            "the hash function",
            "the a1/v1 refutation key records 16 hex characters (64 bits), so its "
            "collision domain is smaller than the other key classes; the recorded "
            "values are preserved and collision detection is load-bearing",
        ],
    }


def _fingerprint_stream(document: dict) -> list[tuple]:
    rows = []
    for run in document["runs"]:
        record = run["properties"]["a1"]["record"]["path"]
        for result in run["results"]:
            prints = result["partialFingerprints"]
            rows.append(
                (
                    record,
                    result["ruleId"],
                    result["properties"]["a1"]["logicalKey"],
                    prints.get("a1Rule/v1"),
                    prints.get("a1Logical/v1"),
                    prints.get("a1Exact/v1"),
                )
            )
    return rows


def build_migration() -> dict:
    old = json.loads(A1_SARIF.read_text(encoding="utf-8"))
    new = adapter.build_document(REPO_ROOT)

    old_rows = _fingerprint_stream(old)
    new_rows = _fingerprint_stream(new)
    assert len(old_rows) == len(new_rows)

    mismatches = []
    differing = 0
    for old_row, new_row in zip(old_rows, new_rows):
        recorded = {
            "rule": old_row[3],
            "logical": old_row[4],
            "exact": old_row[5],
        }
        recomputed = {
            "rule": new_row[3],
            "logical": new_row[4],
            "exact": new_row[5],
        }
        if recorded != recomputed:
            differing += sum(1 for key in recorded if recorded[key] != recomputed[key])
            mismatches.append(
                {
                    "record": old_row[0],
                    "ruleId": old_row[1],
                    "logicalKey": old_row[2],
                    "recorded": recorded,
                    "recomputed": recomputed,
                }
            )

    old_stream = fi.digest_bytes(fi.canonical_json(sorted(old_rows)).encode("utf-8"))
    new_stream = fi.digest_bytes(fi.canonical_json(sorted(new_rows)).encode("utf-8"))

    old_adapter = sorted(
        {run["properties"]["a1"]["adapter"]["sha256"] for run in old["runs"]}
    )
    new_adapter = fi.digest_file(TOOLS / "sarif_adapter.py")

    # Every run-level property except the adapter's own digest must be unchanged.
    run_differences = []
    for old_run, new_run in zip(old["runs"], new["runs"]):
        old_props = json.loads(json.dumps(old_run["properties"]))
        new_props = json.loads(json.dumps(new_run["properties"]))
        old_props["a1"]["adapter"]["sha256"] = "masked"
        new_props["a1"]["adapter"]["sha256"] = "masked"
        if old_props != new_props:
            run_differences.append(old_run["properties"]["a1"]["record"]["path"])

    result_differences = []
    for old_run, new_run in zip(old["runs"], new["runs"]):
        if old_run["results"] != new_run["results"]:
            result_differences.append(old_run["properties"]["a1"]["record"]["path"])

    return {
        "schema": "openssl-rs/a3/migration/1",
        "model": fi.MODEL_ID,
        "tool": "evidence/a3/build_evidence.py",
        "artefact": {
            "path": "evidence/a1/SARIF.json",
            "sha256": fi.digest_file(A1_SARIF),
            "bytes": A1_SARIF.stat().st_size,
            "runs": len(old["runs"]),
            "results": len(old_rows),
            "producer": (
                "the narrow SARIF adapter before the identity model was extracted"
            ),
        },
        "oldScheme": {
            "model": fi.MODEL_ID,
            "producer": "forensics/tools/sarif_adapter.py",
            "producerSha256": old_adapter,
        },
        "generalisedModule": {
            "path": "forensics/tools/finding_identity.py",
            "sha256": fi.digest_file(TOOLS / "finding_identity.py"),
        },
        "method": (
            "the identity model was substituted for the adapter's private fingerprint "
            "functions, the A1 sources were re-projected in memory, and every result's "
            "three fingerprints were compared with the recorded values at the same "
            "position; the recorded artefact was read only"
        ),
        "fingerprintsCompared": len(old_rows) * len(fi.WIRE_KEYS),
        "fingerprintsReproduced": len(old_rows) * len(fi.WIRE_KEYS) - differing,
        "fingerprintMismatchCount": differing,
        "mismatches": mismatches,
        "streamSha256Old": old_stream,
        "streamSha256New": new_stream,
        "streamsEqual": old_stream == new_stream,
        "documentDifferences": [
            {
                "field": "runs[*].properties.a1.adapter.sha256",
                "old": old_adapter,
                "new": new_adapter,
                "why": (
                    "the adapter's own digest changed because its source changed; no "
                    "fingerprint is computed over it"
                ),
            }
        ],
        "runPropertyDifferencesExcludingAdapterDigest": run_differences,
        "resultObjectDifferences": result_differences,
        "outcome": "reproduced"
        if not mismatches and old_stream == new_stream
        else "migrated",
        "recordedValuesPreserved": True,
        "artefactRegenerated": False,
        "notes": [
            "the committed evidence/a1/SARIF.json was not rewritten; the recorded "
            "fingerprints remain the recorded values",
            "the adapter digest recorded in the artefact names the pre-extraction "
            "producer, which is a fact about the artefact, not a fingerprint",
            "a mismatch in any fingerprint would be recorded here as a migration with "
            "the old value retained, not silently replaced",
        ],
    }


def _write(path: Path, document: dict) -> None:
    payload = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(REPO_ROOT / "evidence" / "a3"))
    args = parser.parse_args(argv)
    out = Path(args.out)

    code_motion = build_code_motion()
    collisions = build_collisions()
    migration = build_migration()

    _write(out / "CODE-MOTION.json", code_motion)
    _write(out / "COLLISIONS.json", collisions)
    _write(out / "MIGRATION.json", migration)

    print(
        f"code motion: {code_motion['caseCount']} cases, "
        f"{code_motion['variantCount']} variants, all match",
        file=sys.stderr,
    )
    print(
        "collisions: recorded exact="
        f"{sum(r['exactCollisions'] for r in collisions['recorded']['perRun'])}, "
        f"logical={sum(r['logicalCollisions'] for r in collisions['recorded']['perRun'])}, "
        f"cross-run logical={collisions['recorded']['crossRunLogicalCollisions']}",
        file=sys.stderr,
    )
    print(
        f"migration: {migration['fingerprintsCompared']} fingerprints compared, "
        f"{len(migration['mismatches'])} mismatches, outcome={migration['outcome']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
