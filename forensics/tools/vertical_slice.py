#!/usr/bin/env python3
"""vertical_slice.py -- one real finding through every stage of the assurance chain.

Why this tool exists
--------------------
Every item in the assurance chain has its own controls, and each control proves
that one stage refuses one wrong conclusion. None of them proves that stage N's
output is what stage N+1 consumes. A per-stage test can pass while the seam
between two stages is absent: a statement may cite a shard digest nobody
produced, an envelope may frame a statement the verifier never saw, and a policy
may be evaluated over records that are not the ones the slice traversed.

This tool traverses one real artefact through the whole chain and records, for
every stage, the digest it consumed, the digest it produced, its status and its
code. It stops where the chain stops, names the record that establishes the stop,
and marks every later stage ``NOT_REACHED`` rather than omitting it. It does not
decide whether any stage's claim is true: it establishes that the chain is
connected, and where it ends. A recorded stop is a valid completion of the
*slice*; it is never a pass of the release.

The rule
--------
1. **The trace is digest-chained.** Stage N's ``outputDigest`` is stage N+1's
   ``inputDigest``. A break is ``VS_REFUSED_TRACE_BROKEN``, never a warning.
2. **A stage is never omitted.** A stage that is not reached is
   ``NOT_REACHED`` with the reason and the stop that prevented it.
3. **A stop carries its record.** A ``STOP`` without the record that establishes
   it is ``VS_REFUSED_STOP_NOT_RECORDED``.
4. **A stage may not report a stronger state than its source record.** An
   asserted value that the record does not carry is ``VS_REFUSED_STAGE_OVERCLAIM``.
5. **No admission without an independent root.** A trace that reaches
   ``ADMIT``/``AUTHORISED`` while independent verification is zero is
   ``VS_REFUSED_ADMIT_WITHOUT_ROOT``.
6. **A summary is not a stage's evidence.** A stage that reads an A21 summary in
   place of the record it is supposed to consume is
   ``VS_REFUSED_SUMMARY_AS_EVIDENCE``.

What this tool does not do
--------------------------
It does not re-derive any stage's cryptographic or semantic claim; it reads the
records each item produced and checks the *links* between them. It does not
implement post-A12 consumers: this slice has no per-artefact authorisation,
threshold, bundle, key-lifecycle, correction, omission, policy or summary stage,
so a chain that does not stop at A12 refuses rather than inventing one. It does
not claim that the policy counterfactual was evaluated at this candidate: it
reports the committed A20 decision and verifies that the decision names the same
source records this slice traversed.

Usage
-----
    python3 forensics/tools/vertical_slice.py run   [--slice PATH] [--out PATH] [--json]
    python3 forensics/tools/vertical_slice.py trace [--slice PATH]
    python3 forensics/tools/vertical_slice.py stop  [--slice PATH]

Exit status: 0 when the chain completes without an unrecorded break (a recorded
stop at A12 is a valid completion of the slice); 1 when a stage refuses or the
trace is broken; 2 on a usage error. The code is always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import finding_identity  # noqa: E402

MODEL_ID = "a27/v1"
SLICE_SCHEMA = "openssl-rs/a27/slice/1"
STOPS_SCHEMA = "openssl-rs/a27/stops/1"
CONTROLS_SCHEMA = "openssl-rs/a27/controls/1"

BASE_COMMIT = "8354cf34626292474b3d28203b8478f69ee1f634"
BASE_COMMIT_SHORT = "8354cf346"

DEFAULT_SLICE = REPO_ROOT / "evidence/a27/SLICE.json"

# --------------------------------------------------------------------------
# Refusals. A code is stable: the document, the receipt and the tests cite it.
# --------------------------------------------------------------------------
VS_REFUSED_TRACE_BROKEN = "VS_REFUSED_TRACE_BROKEN"
VS_REFUSED_STAGE_SKIPPED = "VS_REFUSED_STAGE_SKIPPED"
VS_REFUSED_OUTPUT_MISSING = "VS_REFUSED_OUTPUT_MISSING"
VS_REFUSED_ARTEFACT_UNBOUND = "VS_REFUSED_ARTEFACT_UNBOUND"
VS_REFUSED_STAGE_OVERCLAIM = "VS_REFUSED_STAGE_OVERCLAIM"
VS_REFUSED_ADMIT_WITHOUT_ROOT = "VS_REFUSED_ADMIT_WITHOUT_ROOT"
VS_REFUSED_SUMMARY_AS_EVIDENCE = "VS_REFUSED_SUMMARY_AS_EVIDENCE"
VS_REFUSED_STOP_NOT_RECORDED = "VS_REFUSED_STOP_NOT_RECORDED"
VS_REFUSED_USAGE = "VS_REFUSED_USAGE"

# A stop is not a refusal: the chain completed honestly and has no next stage.
VS_STOP_NO_INDEPENDENT_VERIFICATION = "VS_STOP_NO_INDEPENDENT_VERIFICATION"

REFUSAL_CODES = (
    VS_REFUSED_TRACE_BROKEN,
    VS_REFUSED_STAGE_SKIPPED,
    VS_REFUSED_OUTPUT_MISSING,
    VS_REFUSED_ARTEFACT_UNBOUND,
    VS_REFUSED_STAGE_OVERCLAIM,
    VS_REFUSED_ADMIT_WITHOUT_ROOT,
    VS_REFUSED_SUMMARY_AS_EVIDENCE,
    VS_REFUSED_STOP_NOT_RECORDED,
)
STOP_CODES = (VS_STOP_NO_INDEPENDENT_VERIFICATION,)
INVOCATION_CODES = (VS_REFUSED_USAGE,)

STATUS_PASS = "PASS"
STATUS_STOP = "STOP"
STATUS_REFUSED = "REFUSED"
STATUS_NOT_REACHED = "NOT_REACHED"

HEX64 = re.compile(r"^[0-9a-f]{64}$")

# --------------------------------------------------------------------------
# The artefact. It is one A1 SARIF result; its identity is the A1 finding
# identity of a source row that the A4 location record also locates.
# --------------------------------------------------------------------------
ARTEFACT_SPEC: dict[str, Any] = {
    "id": "a1-run3-result-2390",
    "kind": "sarif-result",
    "label": "the A1 finding A1-UNSAFE-OBLIGATION-DELEGATED at md32.rs:118 (symbol update)",
    "source": {"record": "evidence/a1/SARIF.json", "run": 3, "resultIndex": 2390},
    "ruleId": "A1-UNSAFE-OBLIGATION-DELEGATED",
    "logicalKey": "src/digest/md32.rs::update::CITED_BY_CALLER",
    "exact": "9387bcba07a02821e3b0190b1a414ab266de6b50c16bf788faf34e70218898b1",
    "logical": "d423fed03da544cf95e80d07dd9db33156bfa030fda634bf2fa025e5211513e3",
    "rule": "a85943c7f0f99e379153074145963b9a1a994f3815bf479e55cd40575659cdf2",
    "a4Instance": "L3-md32-update",
    "population": "a1-sarif-results",
    "why": (
        "It has a recorded exact identity (A1), a recorded location rule (A4 "
        "L3-md32-update locates the same path, line and symbol), a containing "
        "population with identified members (A5 a1-sarif-results, COMPLETE, 4245 "
        "distinct), a delta disposition (A7 STILL_PRESENT) and a shard membership "
        "at the same run and result index (A8). No stage had to be given a "
        "different artefact to make it consume one."
    ),
}

# --------------------------------------------------------------------------
# The chain declaration: ordered, each stage names the tool it invokes (or the
# record it reads), what it consumes and what it produces.
# --------------------------------------------------------------------------
CHAIN: tuple[dict[str, Any], ...] = (
    {
        "stage": "A3",
        "item": "finding identity",
        "tool": "forensics/tools/finding_identity.py",
        "reads": ("evidence/a1/SARIF.json",),
        "consumes": "the artefact binding (exact occurrence identity)",
        "produces": "the identity record: rule, logical and exact fingerprints",
        "contract": "the recorded fingerprints are recomputed from the recorded fields",
    },
    {
        "stage": "A4",
        "item": "location fidelity",
        "tool": "forensics/tools/location_fidelity.py",
        "reads": ("evidence/a4/INSTANCES.json", "evidence/etp-t4/SAFETY-SITES.json"),
        "consumes": "the identity record (A3 output)",
        "produces": "the location rule this site supports, and its limitations",
        "contract": "the instance locates the same path, line and symbol; no precision is added",
    },
    {
        "stage": "A5",
        "item": "population admission",
        "tool": "forensics/tools/completeness.py",
        "reads": ("evidence/a5/POPULATIONS.json", "evidence/a5/ADMISSION.json",
                  "evidence/a1/SARIF.json"),
        "consumes": "the location record (A4 output)",
        "produces": "the admission state of the containing population and the member's presence",
        "contract": "the population is admitted at the state its facts support and the member is present",
    },
    {
        "stage": "A6",
        "item": "suppression disposition",
        "tool": "forensics/tools/suppression_governance.py",
        "reads": ("evidence/a6/SUPPRESSIONS.json",),
        "consumes": "the population admission (A5 output)",
        "produces": "the disposition of this finding: suppressed or not, with the register's refusals",
        "contract": "only an actionable record naming this identity disposes of it",
    },
    {
        "stage": "A7",
        "item": "baseline delta",
        "tool": "forensics/tools/baseline.py",
        "reads": ("evidence/a7/DELTA.json", "evidence/a7/BASELINES.json"),
        "consumes": "the suppression disposition (A6 output)",
        "produces": "the per-identity delta disposition and what the delta actually compares",
        "contract": "the disposition is the one the delta records and no resolution is claimed",
    },
    {
        "stage": "A8",
        "item": "export shard and union",
        "tool": "forensics/tools/code_scanning_export.py",
        "reads": ("evidence/a8/MANIFEST.json", "evidence/a8/SHARD-000.sarif"),
        "consumes": "the delta disposition (A7 output)",
        "produces": "the shard artefact digest and the member's coordinates in it",
        "contract": "the shard is a subset whose union equals the parent and the member is present",
    },
    {
        "stage": "A9",
        "item": "in-toto statement",
        "tool": "forensics/tools/intoto.py",
        "reads": ("evidence/a9/STATEMENTS.json", "evidence/a9/STATEMENTS/a8-shard-000.json"),
        "consumes": "the shard digest (A8 output)",
        "produces": "the statement digest over that shard",
        "contract": "the statement names the shard at the digest its bytes have and asserts no more than it records",
    },
    {
        "stage": "A10",
        "item": "DSSE envelope",
        "tool": "forensics/tools/dsse.py",
        "reads": ("evidence/a10/ENVELOPES.json", "evidence/a10/ENVELOPES/a8-shard-000.json"),
        "consumes": "the statement digest (A9 output)",
        "produces": "the envelope digest over that statement",
        "contract": "the envelope payload is the statement's bytes and the PAE is recomputed from them",
    },
    {
        "stage": "A12",
        "item": "independent verification",
        "tool": "forensics/tools/independent_verify.py",
        "reads": ("evidence/a12/VERIFICATION.json",),
        "consumes": "the envelope digest (A10 output)",
        "produces": "the verification outcome for that envelope",
        "contract": "the outcome is the one recorded for this envelope and the aggregate agrees with it",
    },
    {
        "stage": "A14",
        "item": "authorisation",
        "tool": "forensics/tools/authorisation.py",
        "reads": ("evidence/a14/AUTHORISATION.json",),
        "consumes": "an independent verification outcome (A12 output)",
        "produces": "a role authorisation decision",
        "contract": "not implemented in this slice: no per-artefact action consumes this member",
    },
    {
        "stage": "A15",
        "item": "threshold",
        "tool": "forensics/tools/thresholds.py",
        "reads": ("evidence/a15/EVALUATION.json",),
        "consumes": "the authorisation decision (A14 output)",
        "produces": "a distinct-trust-domain threshold evaluation",
        "contract": "not implemented in this slice",
    },
    {
        "stage": "A16",
        "item": "Sigstore bundle",
        "tool": "forensics/tools/sigstore_bundle.py",
        "reads": ("evidence/a16/INVENTORY.json",),
        "consumes": "the threshold evaluation (A15 output)",
        "produces": "an offline bundle validation",
        "contract": "not implemented in this slice",
    },
    {
        "stage": "A18",
        "item": "key lifecycle",
        "tool": "forensics/tools/key_lifecycle.py",
        "reads": ("evidence/a18/INVENTORY.json",),
        "consumes": "the bundle validation (A16 output)",
        "produces": "a key-survivability evaluation",
        "contract": "not implemented in this slice",
    },
    {
        "stage": "A19",
        "item": "correction status",
        "tool": "forensics/tools/corrections.py",
        "reads": ("evidence/a19/PROPAGATION.json",),
        "consumes": "the key-lifecycle evaluation (A18 output)",
        "produces": "the correction status of the records consumed",
        "contract": "not implemented in this slice",
    },
    {
        "stage": "A17",
        "item": "omission closure",
        "tool": "forensics/tools/omission.py",
        "reads": ("evidence/a17/STATUS.json", "evidence/a17/FREEZE-forward.json"),
        "consumes": "the correction status (A19 output)",
        "produces": "the omission and forward-freeze closure",
        "contract": "not implemented in this slice",
    },
    {
        "stage": "A20",
        "item": "policy",
        "tool": "forensics/tools/policy_engine.py",
        "reads": ("evidence/a20/POLICY.json", "evidence/a20/DECISION.json"),
        "consumes": "the omission closure (A17 output)",
        "produces": "the policy decision",
        "contract": "not implemented in this slice",
    },
    {
        "stage": "A21",
        "item": "summary",
        "tool": "forensics/tools/verification_summary.py",
        "reads": ("evidence/a21/SUMMARY.json",),
        "consumes": "the policy decision (A20 output)",
        "produces": "a reconstructible summary",
        "contract": "not implemented in this slice; a summary is never another stage's evidence",
    },
)

STAGE_ORDER = tuple(entry["stage"] for entry in CHAIN)
STAGE_BY_ID = {entry["stage"]: entry for entry in CHAIN}
IMPLEMENTED_STAGES = ("A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A12")


class SliceRefusal(Exception):
    """A stage refused. The code is stable and the detail names the condition."""

    def __init__(self, code: str, detail: str, stage: str | None = None) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.stage = stage


# --------------------------------------------------------------------------
# Canonical bytes and digests
# --------------------------------------------------------------------------


def canonical(value: Any) -> str:
    """The one canonical form used for every digest in this tool."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def _load(root: Path, relative: str, overrides: dict[str, Any] | None = None) -> Any:
    if overrides is not None and relative in overrides:
        return overrides[relative]
    return json.loads((root / relative).read_text(encoding="utf-8"))


def _record_sha(root: Path, relative: str, overrides: dict[str, Any] | None = None) -> str:
    """The digest cited for a record.

    With an override the cited digest is the digest of the mutated in-memory
    value, so a control does not silently claim the committed bytes.
    """
    if overrides is not None and relative in overrides:
        return digest_value(overrides[relative])
    return digest_file(root / relative)


def _require(condition: bool, code: str, detail: str, stage: str) -> None:
    if not condition:
        raise SliceRefusal(code, detail, stage)


def _first(rows: Iterable[dict[str, Any]], key: str, value: Any) -> dict[str, Any] | None:
    for row in rows:
        if row.get(key) == value:
            return row
    return None


def _entry(
    stage: str,
    previous: str,
    output: str | None,
    status: str,
    codes: Iterable[str],
    detail: dict[str, Any],
) -> dict[str, Any]:
    declaration = STAGE_BY_ID[stage]
    return {
        "stage": stage,
        "item": declaration["item"],
        "tool": declaration["tool"],
        "reads": list(declaration["reads"]),
        "inputDigest": previous,
        "outputDigest": output,
        "status": status,
        "codes": list(codes),
        "detail": detail,
    }


# --------------------------------------------------------------------------
# Binding the artefact: all four preconditions, before the chain starts
# --------------------------------------------------------------------------


def bind_artefact(root: Path, spec: dict[str, Any] | None = None) -> dict[str, Any]:
    """Establish that the artefact has an identity, a location, a population and a shard.

    A precondition that cannot be established is ``VS_REFUSED_ARTEFACT_UNBOUND``:
    the slice will not start from an artefact that one of its stages cannot
    consume, and it will not silently switch to a different artefact.
    """
    spec = dict(ARTEFACT_SPEC if spec is None else spec)
    source = spec.get("source") or {}
    record = source.get("record")
    _require(
        isinstance(record, str) and (root / record).exists(),
        VS_REFUSED_ARTEFACT_UNBOUND,
        f"the artefact's source record {record!r} is not present",
        "A3",
    )
    document = _load(root, record)
    try:
        result = document["runs"][int(source["run"])]["results"][int(source["resultIndex"])]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise SliceRefusal(
            VS_REFUSED_ARTEFACT_UNBOUND,
            f"no result at run {source.get('run')} index {source.get('resultIndex')} in {record}",
            "A3",
        ) from exc

    try:
        a1 = result["properties"]["a1"]
        binding = a1["artifact"]
        native = a1["native"]
        region = result["locations"][0]["physicalLocation"]["region"]
        recorded = result["partialFingerprints"]
        symbol = native["fields"]["symbol"]
    except (KeyError, IndexError, TypeError) as exc:
        raise SliceRefusal(
            VS_REFUSED_ARTEFACT_UNBOUND,
            f"the result does not carry the fields an identity requires: {exc}",
            "A3",
        ) from exc

    _require(
        recorded.get("a1Exact/v1") == spec["exact"],
        VS_REFUSED_ARTEFACT_UNBOUND,
        f"the recorded exact identity {recorded.get('a1Exact/v1')!r} is not the declared {spec['exact']!r}",
        "A3",
    )
    _require(
        result.get("ruleId") == spec["ruleId"],
        VS_REFUSED_ARTEFACT_UNBOUND,
        f"the recorded rule {result.get('ruleId')!r} is not the declared {spec['ruleId']!r}",
        "A3",
    )
    _require(
        a1.get("logicalKey") == spec["logicalKey"],
        VS_REFUSED_ARTEFACT_UNBOUND,
        f"the recorded logical key {a1.get('logicalKey')!r} is not the declared one",
        "A3",
    )
    _require(
        symbol == "update",
        VS_REFUSED_ARTEFACT_UNBOUND,
        f"the result's native symbol {symbol!r} is not the site the A4 instance locates",
        "A4",
    )

    # 1. the identity is derivable, not merely recorded
    finding = finding_identity.Finding(
        rule_id=result["ruleId"],
        logical_key=a1["logicalKey"],
        binding=finding_identity.Binding(
            uri=binding["uri"],
            digest=binding["digest"],
            digest_scope=binding["digestScope"],
        ),
        region=finding_identity.Region("source", line=int(region["startLine"])),
        candidate=a1.get("candidate"),
        native_locator=str(native.get("locator", "")),
    )
    derived = finding.fingerprints
    _require(
        derived == {key: recorded.get(key) for key in derived},
        VS_REFUSED_ARTEFACT_UNBOUND,
        "the recorded fingerprints are not those the identity model derives from the recorded fields",
        "A3",
    )

    # 2. the location record locates the same site
    instances = _load(root, "evidence/a4/INSTANCES.json")
    instance = _first(instances.get("instances", []), "id", spec["a4Instance"])
    _require(
        instance is not None,
        VS_REFUSED_ARTEFACT_UNBOUND,
        f"the A4 instance {spec['a4Instance']!r} is absent",
        "A4",
    )
    assert instance is not None
    joint = [
        row
        for row in instance.get("provenance", [])
        if row.get("kind") == "indexed-site-row"
        and row.get("expect", {}).get("path") == binding["uri"]
        and row.get("expect", {}).get("line") == int(region["startLine"])
        and row.get("expect", {}).get("symbol") == symbol
    ]
    _require(
        bool(joint),
        VS_REFUSED_ARTEFACT_UNBOUND,
        "the A4 instance's provenance does not locate the finding's path, line and symbol",
        "A4",
    )

    # 3. the containing population is admitted and identifies its members
    populations = _load(root, "evidence/a5/POPULATIONS.json")
    admissions = _load(root, "evidence/a5/ADMISSION.json")
    population = _first(populations.get("populations", []), "id", spec["population"])
    admission = _first(admissions.get("populations", []), "id", spec["population"])
    _require(
        population is not None and admission is not None,
        VS_REFUSED_ARTEFACT_UNBOUND,
        f"the population {spec['population']!r} is absent from A5",
        "A5",
    )
    assert population is not None and admission is not None
    _require(
        admission.get("state") == "COMPLETE"
        and admission.get("membersRecorded") is True
        and admission.get("refusal") is None
        and population.get("present") is True,
        VS_REFUSED_ARTEFACT_UNBOUND,
        f"the population {spec['population']!r} is not admitted COMPLETE with identified members",
        "A5",
    )
    # A population is a set of fingerprints, not of runs; collect every member.
    exacts = [
        result_row["partialFingerprints"]["a1Exact/v1"]
        for run in document["runs"]
        for result_row in run.get("results", [])
    ]
    _require(
        spec["exact"] in set(exacts),
        VS_REFUSED_ARTEFACT_UNBOUND,
        "the exact identity is not a member of the containing population",
        "A5",
    )

    # 4. the artefact has a shard membership
    manifest = _load(root, "evidence/a8/MANIFEST.json")
    member_coordinates = None
    for shard_row in manifest.get("shards", []):
        shard_path = f"evidence/a8/{shard_row['file']}"
        _require(
            (root / shard_path).exists(),
            VS_REFUSED_ARTEFACT_UNBOUND,
            f"the manifest names shard {shard_row['file']!r} but the file is absent",
            "A8",
        )
        shard = _load(root, shard_path)
        for run_index, run in enumerate(shard.get("runs", [])):
            for result_index, result_row in enumerate(run.get("results", [])):
                if result_row.get("partialFingerprints", {}).get("a1Exact/v1") == spec["exact"]:
                    member_coordinates = {
                        "shard": shard_path,
                        "shardIndex": shard_row["index"],
                        "run": run_index,
                        "resultIndex": result_index,
                    }
    _require(
        member_coordinates is not None,
        VS_REFUSED_ARTEFACT_UNBOUND,
        "the exact identity has no shard membership",
        "A8",
    )

    artefact = {
        "id": spec["id"],
        "kind": spec["kind"],
        "label": spec["label"],
        "why": spec["why"],
        "ruleId": spec["ruleId"],
        "logicalKey": a1["logicalKey"],
        "symbol": symbol,
        "candidate": a1.get("candidate"),
        "binding": {
            "uri": binding["uri"],
            "digest": binding["digest"],
            "digestScope": binding["digestScope"],
        },
        "region": {"kind": "source", "line": int(region["startLine"]),
                   "key": finding.region.key()},
        "exact": derived["a1Exact/v1"],
        "logical": derived["a1Logical/v1"],
        "rule": derived["a1Rule/v1"],
        "fingerprints": derived,
        "nativeLocator": native.get("locator"),
        "a4Instance": spec["a4Instance"],
        "population": spec["population"],
        "source": {
            "record": record,
            "sha256": digest_file(root / record),
            "run": int(source["run"]),
            "resultIndex": int(source["resultIndex"]),
        },
        "shardMembership": member_coordinates,
    }
    artefact["bindingDigest"] = digest_value(
        {key: value for key, value in artefact.items() if key != "bindingDigest"}
    )
    return artefact


# --------------------------------------------------------------------------
# The implemented stages. Each returns a payload, a status, codes and a digest.
# --------------------------------------------------------------------------


def _stage_identity(root: Path, artefact: dict[str, Any], previous: str,
                    overrides: dict[str, Any] | None) -> dict[str, Any]:
    document = _load(root, "evidence/a1/SARIF.json", overrides)
    source = artefact["source"]
    result = document["runs"][source["run"]]["results"][source["resultIndex"]]
    a1 = result["properties"]["a1"]
    recorded = result["partialFingerprints"]
    finding = finding_identity.Finding(
        rule_id=result["ruleId"],
        logical_key=a1["logicalKey"],
        binding=finding_identity.Binding(
            uri=a1["artifact"]["uri"],
            digest=a1["artifact"]["digest"],
            digest_scope=a1["artifact"]["digestScope"],
        ),
        region=finding_identity.Region(
            "source", line=int(result["locations"][0]["physicalLocation"]["region"]["startLine"])
        ),
        candidate=a1.get("candidate"),
        native_locator=str(a1["native"].get("locator", "")),
    )
    derived = finding.fingerprints
    _require(
        derived == {key: recorded.get(key) for key in derived},
        VS_REFUSED_STAGE_OVERCLAIM,
        "the recorded fingerprints are stronger than the identity model derives",
        "A3",
    )
    native_record = a1["native"].get("record")
    native_sha = a1["native"].get("recordSha256")
    if native_record and native_sha:
        _require(
            (root / native_record).exists() and digest_file(root / native_record) == native_sha,
            VS_REFUSED_STAGE_OVERCLAIM,
            f"the finding's provenance record {native_record} is not the bytes it cites",
            "A3",
        )
    provenance = {
        "record": native_record,
        "sha256": native_sha,
        "rehashed": bool(native_record and native_sha),
    }
    payload = {
        "summary": f"identity {artefact['exact'][:12]} recomputed from the recorded fields",
        "consumes": previous,
        "artefact": artefact["id"],
        "ruleId": result["ruleId"],
        "logicalKey": a1["logicalKey"],
        "binding": a1["artifact"],
        "region": finding.region.key(),
        "fingerprints": derived,
        "nativeLocator": a1["native"].get("locator"),
        "provenance": provenance,
        "source": {
            "record": "evidence/a1/SARIF.json",
            "sha256": _record_sha(root, "evidence/a1/SARIF.json", overrides),
            "run": source["run"],
            "resultIndex": source["resultIndex"],
            "recordSha256": a1["native"].get("recordSha256"),
        },
        "asserts": "identity",
    }
    return {"status": STATUS_PASS, "codes": [], "payload": payload,
            "outputDigest": digest_value(payload)}


def _stage_location(root: Path, artefact: dict[str, Any], previous: str,
                    overrides: dict[str, Any] | None) -> dict[str, Any]:
    instances = _load(root, "evidence/a4/INSTANCES.json", overrides)
    instance = _first(instances.get("instances", []), "id", artefact["a4Instance"])
    _require(instance is not None, VS_REFUSED_OUTPUT_MISSING,
             f"the A4 instance {artefact['a4Instance']!r} is absent", "A4")
    assert instance is not None
    emitted = instance.get("emitted") or {}
    limitations = list(emitted.get("limitations") or [])
    _require(bool(emitted.get("location")), VS_REFUSED_OUTPUT_MISSING,
             "the A4 instance emits no location", "A4")
    joint = [
        row
        for row in instance.get("provenance", [])
        if row.get("kind") == "indexed-site-row"
        and row.get("expect", {}).get("path") == artefact["binding"]["uri"]
        and row.get("expect", {}).get("line") == artefact["region"]["line"]
        and row.get("expect", {}).get("symbol") == artefact["symbol"]
    ]
    _require(bool(joint), VS_REFUSED_OUTPUT_MISSING,
             "the A4 instance does not locate the finding's site", "A4")
    provenance = joint[0]
    provenance_sha = provenance.get("recordSha256")
    if provenance.get("path") and provenance_sha:
        _require(
            (root / provenance["path"]).exists()
            and digest_file(root / provenance["path"]) == provenance_sha,
            VS_REFUSED_STAGE_OVERCLAIM,
            f"the A4 provenance record {provenance['path']} is not the bytes it cites",
            "A4",
        )
    payload = {
        "summary": (
            "line-only at md32.rs:118 for the finding; function-offset-and-extent "
            "for the site's machine-code instance"
        ),
        "consumes": previous,
        "instance": artefact["a4Instance"],
        "class": instance.get("class"),
        "precision": emitted.get("precision"),
        "emitted": emitted.get("location"),
        "limitations": limitations,
        "findingLocation": artefact["region"],
        "joint": joint[0]["expect"],
        "addsSourcePrecision": False,
        "seam": (
            "A4 locates the site's machine-code instance; the finding's own "
            "location stays the source line A1 records. The two are joined by "
            "path, line and symbol, not by identity, so A4 adds a location rule "
            "and no source precision."
        ),
        "source": {
            "record": "evidence/a4/INSTANCES.json",
            "sha256": _record_sha(root, "evidence/a4/INSTANCES.json", overrides),
            "provenanceRecord": provenance.get("path"),
            "provenanceRow": provenance.get("row"),
            "provenanceSha256": provenance_sha,
        },
        "asserts": "location",
    }
    return {"status": STATUS_PASS, "codes": [], "payload": payload,
            "outputDigest": digest_value(payload)}


def _stage_population(root: Path, artefact: dict[str, Any], previous: str,
                      overrides: dict[str, Any] | None) -> dict[str, Any]:
    populations = _load(root, "evidence/a5/POPULATIONS.json", overrides)
    admissions = _load(root, "evidence/a5/ADMISSION.json", overrides)
    population = _first(populations.get("populations", []), "id", artefact["population"])
    admission = _first(admissions.get("populations", []), "id", artefact["population"])
    _require(population is not None and admission is not None,
             VS_REFUSED_OUTPUT_MISSING,
             f"A5 carries no population {artefact['population']!r}", "A5")
    assert population is not None and admission is not None
    _require(
        admission.get("state") == "COMPLETE"
        and admission.get("membersRecorded") is True
        and admission.get("refusal") is None,
        VS_REFUSED_STAGE_OVERCLAIM,
        f"A5 admits {artefact['population']!r} at {admission.get('state')!r}, not COMPLETE",
        "A5",
    )
    document = _load(root, "evidence/a1/SARIF.json", overrides)
    exacts = [
        row["partialFingerprints"]["a1Exact/v1"]
        for run in document["runs"]
        for row in run.get("results", [])
    ]
    _require(
        len(exacts) == int(admission.get("examined", -1))
        == int(population.get("distinctMembers", -2)),
        VS_REFUSED_STAGE_OVERCLAIM,
        "the admitted membership count is not the count the cited record states",
        "A5",
    )
    _require(artefact["exact"] in set(exacts), VS_REFUSED_OUTPUT_MISSING,
             "the artefact is not present in the population the record admits", "A5")
    refused_population = _first(admissions.get("populations", []), "id", "t4-suppressions")
    payload = {
        "summary": (
            f"member of {artefact['population']} ({admission['state']}, "
            f"{admission['examined']} examined, 0 omitted)"
        ),
        "consumes": previous,
        "population": {
            "id": population["id"],
            "kind": population.get("kind"),
            "present": population.get("present"),
            "declared": admission.get("declared"),
            "state": admission.get("state"),
            "examined": admission.get("examined"),
            "expected": population.get("expected"),
            "omitted": admission.get("omitted"),
            "membersRecorded": admission.get("membersRecorded"),
            "distinctMembers": population.get("distinctMembers"),
            "membersBasis": population.get("membersBasis"),
        },
        "membership": {
            "basis": "distinct a1Exact/v1 over the cited record",
            "derivedDistinct": len(set(exacts)),
            "present": True,
            "member": artefact["exact"],
        },
        "alsoRecorded": (
            None if refused_population is None else {
                "id": refused_population["id"],
                "state": refused_population["state"],
                "refusal": refused_population.get("refusal"),
                "detail": refused_population.get("detail"),
            }
        ),
        "seam": (
            "The finding's population is the A1 emission, admitted COMPLETE. The "
            "record the finding cites as provenance also carries a suppression "
            "population (t4-suppressions) that A5 admits only AGGREGATE_ONLY. The "
            "two populations are different, and only the first contains this "
            "member."
        ),
        "source": {
            "admission": "evidence/a5/ADMISSION.json",
            "admissionSha256": _record_sha(root, "evidence/a5/ADMISSION.json", overrides),
            "populations": "evidence/a5/POPULATIONS.json",
            "populationsSha256": _record_sha(root, "evidence/a5/POPULATIONS.json", overrides),
            "memberRecord": "evidence/a1/SARIF.json",
            "memberRecordSha256": _record_sha(root, "evidence/a1/SARIF.json", overrides),
        },
        "asserts": "population",
    }
    return {"status": STATUS_PASS, "codes": [], "payload": payload,
            "outputDigest": digest_value(payload)}


def _stage_suppression(root: Path, artefact: dict[str, Any], previous: str,
                       overrides: dict[str, Any] | None) -> dict[str, Any]:
    register = _load(root, "evidence/a6/SUPPRESSIONS.json", overrides)
    records = list(register.get("records") or [])
    admissions = {row["id"]: row for row in register.get("admissions") or []}
    named = [
        row for row in records
        if artefact["exact"] in (row.get("memberIds") or [])
        or row.get("logicalIdentity") == artefact["logical"]
    ]
    actionable = [
        row for row in named
        if admissions.get(row.get("id"), {}).get("disposition") not in (None, "NON_ACTIONABLE")
    ]
    if actionable:
        disposition = "SUPPRESSED"
        codes = [admissions[row["id"]]["disposition"] for row in actionable]
    elif named:
        disposition = "SUPPRESSION_REFUSED"
        codes = list(admissions.get(named[0]["id"], {}).get("codes") or [])
    else:
        disposition = "NOT_SUPPRESSED"
        codes = []
    register_candidates = sorted({row["candidate"] for row in records if row.get("candidate")})
    finding_candidate = (artefact.get("candidate") or {}).get("commit")
    payload = {
        "summary": (
            "no actionable suppression record names this finding; 0 members disposed"
            if disposition != "SUPPRESSED"
            else "an actionable suppression record names this finding"
        ),
        "consumes": previous,
        "disposition": disposition,
        "codes": codes,
        "matchedRecords": [row.get("id") for row in named],
        "recordsConsidered": len(records),
        "actionableRecords": sum(
            1 for row in records
            if admissions.get(row.get("id"), {}).get("disposition") not in (None, "NON_ACTIONABLE")
        ),
        "membersDisposed": int(register.get("totals", {}).get("membersDisposed", -1)),
        "registerCandidates": register_candidates,
        "findingCandidate": finding_candidate,
        "registerBoundToFindingCandidate": bool(
            finding_candidate and finding_candidate in register_candidates
        ),
        "observedRefusalCounts": dict(register.get("totals", {}).get("byCode") or {}),
        "seam": (
            "The suppression register is recorded at the finding's candidate, but "
            "its admissions were evaluated against a later candidate and every "
            "candidate-bound record is refused stale (SG_REFUSED_STALE_CANDIDATE). "
            "No record is actionable, so no record disposes of this finding."
        ),
        "source": {
            "record": "evidence/a6/SUPPRESSIONS.json",
            "sha256": _record_sha(root, "evidence/a6/SUPPRESSIONS.json", overrides),
            "membersDisposed": register.get("totals", {}).get("membersDisposed"),
        },
        "asserts": "disposition",
    }
    return {"status": STATUS_PASS, "codes": [], "payload": payload,
            "outputDigest": digest_value(payload)}


def _stage_delta(root: Path, artefact: dict[str, Any], previous: str,
                 overrides: dict[str, Any] | None) -> dict[str, Any]:
    document = _load(root, "evidence/a7/DELTA.json", overrides)
    delta = _first(document.get("deltas", []), "before", artefact["population"])
    _require(delta is not None, VS_REFUSED_OUTPUT_MISSING,
             "A7 records no delta over the containing population", "A7")
    assert delta is not None
    disposition = _first(delta.get("dispositions", []), "exact", artefact["exact"])
    _require(disposition is not None, VS_REFUSED_OUTPUT_MISSING,
             "the artefact has no delta disposition", "A7")
    assert disposition is not None
    _require(
        disposition.get("disposition") == "STILL_PRESENT"
        and int(delta.get("counts", {}).get("RESOLVED", -1)) == 0,
        VS_REFUSED_STAGE_OVERCLAIM,
        "the delta's recorded disposition is not the STILL_PRESENT state with zero resolutions",
        "A7",
    )
    baselines = _load(root, "evidence/a7/BASELINES.json", overrides)
    before = _first(baselines.get("baselines", []), "id", delta["before"])
    after = _first(baselines.get("baselines", []), "id", delta["after"])
    _require(before is not None and after is not None,
             VS_REFUSED_OUTPUT_MISSING,
             "A7 does not record both baselines of its delta", "A7")
    assert before is not None and after is not None
    for label, baseline in (("before", before), ("after", after)):
        _require(
            any(member.get("exact") == artefact["exact"] for member in baseline.get("members", [])),
            VS_REFUSED_OUTPUT_MISSING,
            f"the artefact is not a member of the {label} baseline",
            "A7",
        )
    no_baseline = _first(
        document.get("noBaseline", []), "id", f"{artefact['population']}/no-second-population"
    )
    payload = {
        "summary": (
            "STILL_PRESENT between two projections of one emission, not between "
            "two scans at different candidates"
        ),
        "consumes": previous,
        "delta": {"before": delta["before"], "after": delta["after"],
                  "admitted": delta.get("admitted")},
        "disposition": disposition.get("disposition"),
        "reason": disposition.get("reason"),
        "label": disposition.get("label"),
        "counts": delta.get("counts"),
        "baselineComparison": False,
        "beforeTool": before.get("tool"),
        "afterTool": after.get("tool"),
        "noSecondPopulation": (None if no_baseline is None else {
            "id": no_baseline.get("id"),
            "code": no_baseline.get("code"),
            "reason": no_baseline.get("reason"),
        }),
        "seam": (
            "The delta compares the pre-extraction SARIF projection with the "
            "generalised identity model over the same A1 emission. STILL_PRESENT "
            "therefore means the two identity models agree on this member; it is "
            "not a before/after code-change baseline, and A7 itself records that "
            "no second population for this area exists."
        ),
        "source": {
            "record": "evidence/a7/DELTA.json",
            "sha256": _record_sha(root, "evidence/a7/DELTA.json", overrides),
            "baselines": "evidence/a7/BASELINES.json",
            "baselinesSha256": _record_sha(root, "evidence/a7/BASELINES.json", overrides),
        },
        "asserts": "delta",
    }
    return {"status": STATUS_PASS, "codes": [], "payload": payload,
            "outputDigest": digest_value(payload)}


def _stage_export(root: Path, artefact: dict[str, Any], previous: str,
                  overrides: dict[str, Any] | None) -> dict[str, Any]:
    manifest = _load(root, "evidence/a8/MANIFEST.json", overrides)
    membership = artefact["shardMembership"]
    shard_path = membership["shard"]
    shard = _load(root, shard_path, overrides)
    shard_row = _first(manifest.get("shards", []), "file", Path(shard_path).name)
    _require(shard_row is not None, VS_REFUSED_OUTPUT_MISSING,
             "the manifest does not name the shard", "A8")
    assert shard_row is not None
    if overrides is None or shard_path not in overrides:
        _require(digest_file(root / shard_path) == shard_row.get("sha256"),
                 VS_REFUSED_STAGE_OVERCLAIM,
                 "the shard's bytes are not the digest the manifest records", "A8")
    result = shard["runs"][membership["run"]]["results"][membership["resultIndex"]]
    _require(
        result["partialFingerprints"]["a1Exact/v1"] == artefact["exact"],
        VS_REFUSED_OUTPUT_MISSING,
        "the shard's member at those coordinates is not the artefact", "A8",
    )
    union = manifest.get("union") or {}
    parent = manifest.get("parent") or {}
    _require(
        union.get("equalsParent") is True
        and int(union.get("missing", -1)) == 0
        and int(union.get("duplicates", -1)) == 0
        and int(union.get("distinctIdentities", -1)) == int(parent.get("resultCount", -2))
        == int(union.get("shardResultCount", -3)),
        VS_REFUSED_STAGE_OVERCLAIM,
        "the manifest's union does not equal the parent population exactly once",
        "A8",
    )
    _require(parent.get("sha256") == artefact["source"]["sha256"],
             VS_REFUSED_STAGE_OVERCLAIM,
             "the manifest's parent digest is not the artefact's source record", "A8")
    payload = {
        "summary": (
            f"member {membership['run']}/{membership['resultIndex']} of "
            f"{Path(shard_path).name} ({shard_row['sha256'][:12]}); union equals the parent"
        ),
        "consumes": previous,
        "shard": {
            "path": shard_path,
            "index": shard_row.get("index"),
            "sha256": shard_row.get("sha256"),
            "resultCount": shard_row.get("resultCount"),
            "runIndices": shard_row.get("runIndices"),
        },
        "member": {
            "run": membership["run"],
            "resultIndex": membership["resultIndex"],
            "exact": artefact["exact"],
            "sameCoordinatesAsParent": (
                membership["run"] == artefact["source"]["run"]
                and membership["resultIndex"] == artefact["source"]["resultIndex"]
            ),
        },
        "parent": {"path": parent.get("path"), "sha256": parent.get("sha256"),
                   "resultCount": parent.get("resultCount")},
        "union": union,
        "limit": manifest.get("limit"),
        "manifestSha256": _record_sha(root, "evidence/a8/MANIFEST.json", overrides),
        "seam": (
            "The shard is a single file covering all 4245 results, so membership "
            "is the whole population and the coordinates are the parent's. A "
            "multi-shard export would make this member addressable only through "
            "the manifest, not by coordinates."
        ),
        "asserts": "shard",
    }
    return {"status": STATUS_PASS, "codes": [], "payload": payload,
            "outputDigest": shard_row["sha256"]}


def _stage_statement(root: Path, artefact: dict[str, Any], previous: str,
                     overrides: dict[str, Any] | None) -> dict[str, Any]:
    document = _load(root, "evidence/a9/STATEMENTS.json", overrides)
    shard_path = artefact["shardMembership"]["shard"]
    statement = _first(document.get("statements", []), "subject", shard_path)
    _require(statement is not None, VS_REFUSED_OUTPUT_MISSING,
             f"no A9 statement names {shard_path}", "A9")
    assert statement is not None
    _require(statement.get("record", {}).get("sha256") == previous,
             VS_REFUSED_TRACE_BROKEN,
             "the statement's recorded subject digest is not the shard digest A8 produced",
             "A9")
    relative = statement["statement"]
    if not relative.startswith("evidence/"):
        relative = f"evidence/a9/{relative}"
    path = root / relative
    _require(path.exists(), VS_REFUSED_OUTPUT_MISSING,
             f"the statement file {relative} is absent", "A9")
    data = path.read_bytes()
    _require(digest_bytes(data) == statement.get("statementSha256"),
             VS_REFUSED_STAGE_OVERCLAIM,
             "the statement's bytes are not the digest the index records", "A9")
    parsed = json.loads(data.decode("utf-8"))
    _require(parsed.get("_type") == "https://in-toto.io/Statement/v1",
             VS_REFUSED_STAGE_OVERCLAIM,
             "the statement is not an in-toto Statement v1", "A9")
    asserted = statement.get("assertedState") or {}
    recorded_state = statement.get("recordState") or {}
    for key, value in asserted.items():
        _require(
            recorded_state.get(key) == value,
            VS_REFUSED_STAGE_OVERCLAIM,
            f"the statement asserts {key}={value!r} where the record states "
            f"{recorded_state.get(key)!r}",
            "A9",
        )
    _require(asserted.get("subset") is True,
             VS_REFUSED_STAGE_OVERCLAIM,
             "the statement does not record that its subject is a subset", "A9")
    subjects = parsed.get("subject") or []
    _require(
        len(subjects) == 1
        and subjects[0].get("name") == shard_path
        and subjects[0].get("digest", {}).get("sha256") == previous,
        VS_REFUSED_STAGE_OVERCLAIM,
        "the statement's subject is not the shard at the digest A8 produced", "A9",
    )
    payload = {
        "summary": (
            f"statement {statement['statementSha256'][:12]} over the shard; "
            f"asserted state equals the recorded state"
        ),
        "consumes": previous,
        "statement": relative,
        "statementSha256": statement["statementSha256"],
        "subject": statement.get("subject"),
        "predicateType": statement.get("predicateType"),
        "relation": statement.get("relation"),
        "assertedState": asserted,
        "recordState": recorded_state,
        "subset": True,
        "indexSha256": _record_sha(root, "evidence/a9/STATEMENTS.json", overrides),
        "seam": (
            "The statement is about the shard, not about this member. The "
            "member's identity is carried only inside the shard's bytes; from "
            "A8 onward the chain is per-record. The digest link is exact, but "
            "the granularity changes here."
        ),
        "asserts": "statement",
    }
    return {"status": STATUS_PASS, "codes": [], "payload": payload,
            "outputDigest": statement["statementSha256"]}


def _pae(payload_type: str, body: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(body)).encode("ascii")
        + b" "
        + body
    )


def _stage_envelope(root: Path, artefact: dict[str, Any], previous: str,
                    overrides: dict[str, Any] | None) -> dict[str, Any]:
    document = _load(root, "evidence/a10/ENVELOPES.json", overrides)
    envelope_row = _first(document.get("envelopes", []), "payloadSha256", previous)
    _require(envelope_row is not None, VS_REFUSED_OUTPUT_MISSING,
             "no A10 envelope frames the statement digest A9 produced", "A10")
    assert envelope_row is not None
    _require(envelope_row.get("statementMatchesPayload") is True,
             VS_REFUSED_STAGE_OVERCLAIM,
             "the envelope does not record that its payload is the statement", "A10")
    relative = envelope_row["envelope"]
    if not relative.startswith("evidence/"):
        relative = f"evidence/a10/{relative}"
    path = root / relative
    _require(path.exists(), VS_REFUSED_OUTPUT_MISSING,
             f"the envelope file {relative} is absent", "A10")
    data = path.read_bytes()
    _require(digest_bytes(data) == envelope_row.get("envelopeSha256"),
             VS_REFUSED_STAGE_OVERCLAIM,
             "the envelope's bytes are not the digest the index records", "A10")
    parsed = json.loads(data.decode("utf-8"))
    try:
        body = base64.b64decode(parsed["payload"], validate=True)
    except (KeyError, ValueError) as exc:
        raise SliceRefusal(VS_REFUSED_OUTPUT_MISSING,
                           f"the envelope payload does not decode: {exc}", "A10") from exc
    _require(digest_bytes(body) == previous, VS_REFUSED_TRACE_BROKEN,
             "the envelope payload is not the statement bytes A9 produced", "A10")
    pae = _pae(parsed["payloadType"], body)
    _require(digest_bytes(pae) == envelope_row.get("paeSha256"),
             VS_REFUSED_STAGE_OVERCLAIM,
             "the recomputed PAE is not the PAE the record states", "A10")
    _require(len(body) == int(envelope_row.get("payloadBytes", -1)),
             VS_REFUSED_STAGE_OVERCLAIM,
             "the payload byte length is not the length the record states", "A10")
    payload = {
        "summary": (
            f"envelope {envelope_row['envelopeSha256'][:12]} frames the statement "
            f"bytes; PAE recomputed"
        ),
        "consumes": previous,
        "envelope": relative,
        "envelopeSha256": envelope_row["envelopeSha256"],
        "payloadSha256": envelope_row["payloadSha256"],
        "payloadBytes": len(body),
        "payloadType": parsed["payloadType"],
        "paeSha256": digest_bytes(pae),
        "keyid": envelope_row.get("keyid"),
        "signatureCheckedBy": "A12 check 7 (the signature is not re-verified here)",
        "indexSha256": _record_sha(root, "evidence/a10/ENVELOPES.json", overrides),
        "seam": (
            "This stage proves framing and PAE, not authenticity: the keyid is an "
            "unauthenticated hint and the signature is A12's check."
        ),
        "asserts": "envelope",
    }
    return {"status": STATUS_PASS, "codes": [], "payload": payload,
            "outputDigest": envelope_row["envelopeSha256"]}


def _stage_verification(root: Path, artefact: dict[str, Any], previous: str,
                        overrides: dict[str, Any] | None) -> dict[str, Any]:
    document = _load(root, "evidence/a12/VERIFICATION.json", overrides)
    verification = _first(document.get("verifications", []), "envelopeSha256", previous)
    _require(verification is not None, VS_REFUSED_OUTPUT_MISSING,
             "no A12 verification names the envelope digest A10 produced", "A12")
    assert verification is not None
    entries = document.get("verifications") or []
    observed_count = sum(1 for row in entries if row.get("independentlyVerified") is True)
    aggregate = document.get("aggregate") or {}
    _require(
        observed_count == int(aggregate.get("independentlyVerified", -1))
        == int(document.get("independentlyVerified", -2))
        == int(document.get("counts", {}).get("independentlyVerified", -3)),
        VS_REFUSED_STAGE_OVERCLAIM,
        "the A12 aggregate does not equal the per-envelope outcomes it summarises",
        "A12",
    )
    outcome = verification.get("outcome")
    _require(
        verification.get("independentlyVerified") is (outcome == "INDEPENDENTLY_VERIFIED"),
        VS_REFUSED_STAGE_OVERCLAIM,
        "the outcome and the verification flag disagree",
        "A12",
    )
    _require(
        verification.get("statementSha256") == artefact_statement_sha(root, artefact, overrides),
        VS_REFUSED_STAGE_OVERCLAIM,
        "the verification names a different statement than the envelope frames",
        "A12",
    )
    payload = {
        "summary": (
            f"{outcome}: {observed_count} of {len(entries)} envelopes are independently verified"
        ),
        "consumes": previous,
        "envelope": verification.get("envelope"),
        "envelopeSha256": verification.get("envelopeSha256"),
        "statementSha256": verification.get("statementSha256"),
        "outcome": outcome,
        "independentlyVerified": bool(verification.get("independentlyVerified")),
        "codes": list(verification.get("codes") or []),
        "checks": verification.get("checks"),
        "root": {
            "keyid": (verification.get("root") or {}).get("keyid"),
            "algorithm": (verification.get("root") or {}).get("algorithm"),
            "symmetric": (verification.get("root") or {}).get("symmetric"),
            "selfIssued": (verification.get("root") or {}).get("selfIssued"),
            "trustDomain": (verification.get("root") or {}).get("trustDomain"),
            "independenceBasis": (verification.get("root") or {}).get("independenceBasis"),
        },
        "aggregate": {
            "envelopes": len(entries),
            "independentlyVerified": observed_count,
            "selfIssued": int(aggregate.get("selfIssued", -1)),
            "notRun": int(aggregate.get("notRun", -1)),
            "statement": aggregate.get("statement"),
        },
        "source": {
            "record": "evidence/a12/VERIFICATION.json",
            "sha256": _record_sha(root, "evidence/a12/VERIFICATION.json", overrides),
            "locator": f"/verifications[name={verification.get('name')}]",
        },
        "seam": (
            "SELF_ISSUED is the honest outcome: the verifier holds the signer's "
            "secret and every root is inside the candidate. No external party "
            "vouched for these bytes, so the chain has no independent root to "
            "authorise and stops here."
        ),
        "asserts": "verification",
    }
    stopping = outcome != "INDEPENDENTLY_VERIFIED"
    return {
        "status": STATUS_STOP if stopping else STATUS_PASS,
        "codes": list(verification.get("codes") or []),
        "payload": payload,
        "outputDigest": digest_value(payload),
        "stopCode": VS_STOP_NO_INDEPENDENT_VERIFICATION if stopping else None,
        "establishedBy": {
            "record": "evidence/a12/VERIFICATION.json",
            "sha256": _record_sha(root, "evidence/a12/VERIFICATION.json", overrides),
            "locator": f"/verifications[name={verification.get('name')}]",
            "observed": {
                "outcome": outcome,
                "independentlyVerified": bool(verification.get("independentlyVerified")),
                "envelopes": len(entries),
                "independentlyVerifiedEnvelopes": observed_count,
                "codes": list(verification.get("codes") or []),
            },
        } if stopping else None,
    }


def artefact_statement_sha(root: Path, artefact: dict[str, Any],
                           overrides: dict[str, Any] | None) -> str:
    """The A9 statement digest the A12 record must name for this artefact."""
    statements = _load(root, "evidence/a9/STATEMENTS.json", overrides)
    statement = _first(
        statements.get("statements", []), "subject", artefact["shardMembership"]["shard"]
    )
    if statement is None:
        raise SliceRefusal(VS_REFUSED_OUTPUT_MISSING,
                           "no A9 statement names the shard", "A12")
    return statement["statementSha256"]


STAGE_FUNCTIONS = {
    "A3": _stage_identity,
    "A4": _stage_location,
    "A5": _stage_population,
    "A6": _stage_suppression,
    "A7": _stage_delta,
    "A8": _stage_export,
    "A9": _stage_statement,
    "A10": _stage_envelope,
    "A12": _stage_verification,
}


# --------------------------------------------------------------------------
# Running the chain
# --------------------------------------------------------------------------


def run_chain(
    root: Path | None = None,
    artefact: dict[str, Any] | None = None,
    overrides: dict[str, Any] | None = None,
    chain: tuple[dict[str, Any], ...] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Traverse the chain. Returns the full trace and every validation code."""
    root = REPO_ROOT if root is None else root
    chain = CHAIN if chain is None else chain
    if artefact is None:
        artefact = bind_artefact(root)
    trace: list[dict[str, Any]] = []
    previous: str | None = artefact["bindingDigest"]
    terminal: tuple[str, str] | None = None

    for declaration in chain:
        stage = declaration["stage"]
        if terminal is not None:
            trace.append(
                _entry(
                    stage,
                    previous or "",
                    None,
                    STATUS_NOT_REACHED,
                    [],
                    {
                        "reason": (
                            f"the chain stopped at {terminal[0]} ({terminal[1]}); "
                            f"{stage} was not executed"
                        ),
                        "after": terminal[0],
                        "afterCode": terminal[1],
                    },
                )
            )
            continue
        function = STAGE_FUNCTIONS.get(stage)
        if function is None:
            raise SliceRefusal(
                VS_REFUSED_OUTPUT_MISSING,
                f"{stage} has no consumer contract in this slice; a chain that "
                "does not stop at A12 cannot continue here",
                stage,
            )
        assert previous is not None
        try:
            outcome = function(root, artefact, previous, overrides)
        except SliceRefusal as refusal:
            trace.append(
                _entry(
                    stage,
                    previous,
                    None,
                    STATUS_REFUSED,
                    [refusal.code],
                    {"summary": refusal.detail, "refusal": {
                        "code": refusal.code, "detail": refusal.detail}},
                )
            )
            terminal = (stage, refusal.code)
            continue
        codes = list(outcome["codes"])
        stopping = outcome["status"] == STATUS_STOP
        if stopping:
            if outcome.get("stopCode"):
                codes.append(outcome["stopCode"])
            detail = dict(outcome["payload"])
            detail["stopCode"] = outcome.get("stopCode")
            detail["establishedBy"] = outcome.get("establishedBy")
            trace.append(
                _entry(stage, previous, outcome["outputDigest"], STATUS_STOP, codes, detail)
            )
            terminal = (stage, outcome.get("stopCode") or VS_REFUSED_STOP_NOT_RECORDED)
        else:
            trace.append(
                _entry(stage, previous, outcome["outputDigest"], STATUS_PASS, codes,
                       outcome["payload"])
            )
        previous = outcome["outputDigest"]

    return trace, validate_trace(trace, chain)


def run(
    artefact: dict[str, Any] | None = None,
    chain: tuple[dict[str, Any], ...] | None = None,
    root: Path | None = None,
) -> list[dict[str, Any]]:
    """Traverse the chain and return the trace.

    The spec-shaped entry point. ``run_chain`` is the richer function: it returns
    the trace and the validation codes together, which is what the command line
    and the producer use.
    """
    trace, _codes = run_chain(root=root, artefact=artefact, chain=chain)
    return trace


def _is_summary_record(root: Path, relative: str,
                       overrides: dict[str, Any] | None) -> bool:
    try:
        document = _load(root, relative, overrides)
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(document, dict):
        return False
    return (
        document.get("schema") == "openssl-rs/a21/summary/1"
        or document.get("topLevel") == "summary"
        or "replacesEvidence" in document
    )


def validate_trace(
    trace: list[dict[str, Any]],
    chain: tuple[dict[str, Any], ...] | None = None,
    root: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> list[str]:
    """Every way this trace is not a complete, digest-chained slice.

    The codes are returned in a fixed precedence so a control can assert that
    the condition it introduced is the condition that fired.
    """
    root = REPO_ROOT if root is None else root
    chain = CHAIN if chain is None else chain
    expected = [entry["stage"] for entry in chain]
    observed = [entry.get("stage") for entry in trace]
    if observed != expected:
        return [VS_REFUSED_STAGE_SKIPPED]

    codes: list[str] = []
    for entry in trace:
        if entry.get("status") in (STATUS_PASS, STATUS_STOP):
            if not isinstance(entry.get("outputDigest"), str) or not HEX64.match(
                str(entry.get("outputDigest"))
            ):
                codes.append(VS_REFUSED_OUTPUT_MISSING)
                break
    if codes:
        return codes

    for entry in trace:
        if entry.get("status") != STATUS_STOP:
            continue
        established = entry.get("detail", {}).get("establishedBy")
        if not isinstance(established, dict):
            return [VS_REFUSED_STOP_NOT_RECORDED]
        if not isinstance(established.get("record"), str) or not established["record"]:
            return [VS_REFUSED_STOP_NOT_RECORDED]
        if not isinstance(established.get("sha256"), str) or not HEX64.match(
            str(established.get("sha256"))
        ):
            return [VS_REFUSED_STOP_NOT_RECORDED]
        if not isinstance(established.get("locator"), str) or not established["locator"]:
            return [VS_REFUSED_STOP_NOT_RECORDED]
    if codes:
        return codes

    terminal_seen = False
    for entry in trace:
        status = entry.get("status")
        if status in (STATUS_STOP, STATUS_REFUSED):
            terminal_seen = True
            continue
        if status == STATUS_NOT_REACHED and not terminal_seen:
            return [VS_REFUSED_STAGE_SKIPPED]
        if status != STATUS_NOT_REACHED and terminal_seen:
            return [VS_REFUSED_TRACE_BROKEN]
    if codes:
        return codes

    for left, right in zip(trace, trace[1:]):
        if right.get("status") == STATUS_NOT_REACHED:
            continue
        if left.get("outputDigest") != right.get("inputDigest"):
            return [VS_REFUSED_TRACE_BROKEN]
    if codes:
        return codes

    executed = [entry for entry in trace if entry.get("status") in (STATUS_PASS, STATUS_STOP)]
    for entry in executed:
        if entry["stage"] == "A21":
            continue
        for relative in entry.get("reads") or []:
            if _is_summary_record(root, relative, overrides):
                return [VS_REFUSED_SUMMARY_AS_EVIDENCE]

    verification = _first([entry for entry in executed], "stage", "A12")
    if verification is not None:
        observed_zero = int(
            verification.get("detail", {}).get("aggregate", {}).get(
                "independentlyVerified", 0
            )
        )
        if observed_zero < 1:
            for entry in executed:
                if entry["stage"] not in ("A14", "A15", "A16", "A18", "A19", "A17", "A20"):
                    continue
                asserted = str(entry.get("detail", {}).get("asserts", "")).upper()
                if asserted in ("ADMIT", "AUTHORISED", "MET", "BUNDLE_VERIFIED_OFFLINE"):
                    return [VS_REFUSED_ADMIT_WITHOUT_ROOT]
    return []


def check_stop_binding(root: Path, trace: list[dict[str, Any]]) -> list[str]:
    """The stop's record must exist and its digest must be that file's digest."""
    codes: list[str] = []
    for entry in trace:
        if entry.get("status") != STATUS_STOP:
            continue
        established = (entry.get("detail") or {}).get("establishedBy") or {}
        record = established.get("record")
        sha = established.get("sha256")
        if not isinstance(record, str) or not (root / record).exists():
            codes.append(VS_REFUSED_STOP_NOT_RECORDED)
            continue
        if not isinstance(sha, str) or digest_file(root / record) != sha:
            codes.append(VS_REFUSED_STOP_NOT_RECORDED)
    return codes


def first_stop(trace: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The first STOP and the record that establishes it, or None."""
    for entry in trace:
        if entry.get("status") != STATUS_STOP:
            continue
        established = (entry.get("detail") or {}).get("establishedBy")
        if not isinstance(established, dict) or not established.get("record"):
            return {
                "stage": entry["stage"],
                "code": VS_REFUSED_STOP_NOT_RECORDED,
                "establishedBy": None,
                "detail": entry.get("detail"),
            }
        return {
            "stage": entry["stage"],
            "code": entry.get("detail", {}).get("stopCode"),
            "outcome": entry.get("detail", {}).get("outcome"),
            "establishedBy": established,
            "detail": entry.get("detail"),
        }
    return None


# --------------------------------------------------------------------------
# The records
# --------------------------------------------------------------------------


def policy_counterfactual(root: Path) -> dict[str, Any]:
    """What the committed A20 decision says, and whether it names this slice's records.

    This is *not* a stage of the trace. The chain stops at A12, and the A20
    record was produced by its own item at its own candidate. The check here is
    narrower: does the decision name the same source records this slice
    traversed, and does it deny?
    """
    policy = _load(root, "evidence/a20/POLICY.json")
    decision = _load(root, "evidence/a20/DECISION.json")
    checked = []
    mismatched = []
    for obligation in decision.get("obligations", []):
        source = obligation.get("source") or {}
        record = source.get("record")
        recorded_sha = obligation.get("recordSha256")
        actual = digest_file(root / record) if record and (root / record).exists() else None
        row = {
            "id": obligation.get("id"),
            "record": record,
            "state": obligation.get("state"),
            "required": obligation.get("required"),
            "recordSha256": recorded_sha,
            "matchesCurrentRecord": actual == recorded_sha,
        }
        checked.append(row)
        if actual != recorded_sha:
            mismatched.append(row["id"])
    attestation = _first(decision.get("obligations", []), "id", "A12.independent-attestation")
    return {
        "record": "evidence/a20/DECISION.json",
        "sha256": digest_file(root / "evidence/a20/DECISION.json"),
        "policyRecord": "evidence/a20/POLICY.json",
        "policySha256": digest_file(root / "evidence/a20/POLICY.json"),
        "policyId": decision.get("policyId"),
        "policyVersion": decision.get("policyVersion"),
        "decision": decision.get("decision"),
        "default": decision.get("default"),
        "action": decision.get("action"),
        "candidate": decision.get("candidate"),
        "obligationCount": decision.get("obligationCount"),
        "met": decision.get("met"),
        "unmet": decision.get("unmet"),
        "notApplicable": decision.get("notApplicable"),
        "unknown": decision.get("unknown"),
        "attestation": None if attestation is None else {
            "state": attestation.get("state"),
            "detail": attestation.get("detail"),
            "observed": attestation.get("observed"),
            "recordSha256": attestation.get("recordSha256"),
        },
        "sourceRecordsMatchCurrentTree": not mismatched,
        "sourceRecordsMismatched": mismatched,
        "evaluatedByThisSlice": False,
        "note": (
            "The A20 decision is the record's own decision at the record's own "
            "candidate. This slice reads it and checks that it names the same "
            "source records; it does not re-evaluate the policy at the slice's "
            "base commit."
        ),
    }


def build_slice(root: Path | None = None) -> dict[str, Any]:
    """The real slice: bind, run, validate, and record the stop and the counterfactual."""
    root = REPO_ROOT if root is None else root
    artefact = bind_artefact(root)
    trace, codes = run_chain(root, artefact)
    if codes:
        raise SliceRefusal(codes[0], f"the real trace does not validate: {codes}", "trace")
    binding = check_stop_binding(root, trace)
    if binding:
        raise SliceRefusal(binding[0], "the stop is not bound to its record", "A12")
    stop = first_stop(trace)
    if stop is None:
        raise SliceRefusal(VS_REFUSED_STOP_NOT_RECORDED,
                           "the chain completed with no recorded stop", "trace")
    if stop["stage"] != "A12":
        raise SliceRefusal(VS_REFUSED_STAGE_OVERCLAIM,
                           f"the chain stopped at {stop['stage']}, not A12", stop["stage"])
    if stop["code"] != VS_STOP_NO_INDEPENDENT_VERIFICATION:
        raise SliceRefusal(VS_REFUSED_STAGE_OVERCLAIM,
                           f"the A12 stop code is {stop['code']!r}", "A12")

    counts = {
        "stages": len(trace),
        "passed": sum(1 for entry in trace if entry["status"] == STATUS_PASS),
        "stopped": sum(1 for entry in trace if entry["status"] == STATUS_STOP),
        "refused": sum(1 for entry in trace if entry["status"] == STATUS_REFUSED),
        "notReached": sum(1 for entry in trace if entry["status"] == STATUS_NOT_REACHED),
        "codes": len(codes),
    }
    document = {
        "schema": SLICE_SCHEMA,
        "model": MODEL_ID,
        "candidate": {
            "branch": "staging",
            "baseCommit": BASE_COMMIT,
            "baseCommitShort": BASE_COMMIT_SHORT,
            "recordedAt": "2026-11-24",
        },
        "artefact": artefact,
        "chain": [
            {key: (list(value) if isinstance(value, tuple) else value)
             for key, value in entry.items()}
            for entry in CHAIN
        ],
        "trace": trace,
        "stop": {
            "stage": stop["stage"],
            "code": stop["code"],
            "outcome": stop.get("outcome"),
            "establishedBy": stop["establishedBy"],
            "detail": {
                "summary": stop["detail"].get("summary"),
                "aggregate": stop["detail"].get("aggregate"),
                "root": stop["detail"].get("root"),
                "seam": stop["detail"].get("seam"),
            },
        },
        "wouldBe": {"policy": policy_counterfactual(root)},
        "counts": counts,
        "nonClaims": [
            "a slice connects stages; it does not establish that any stage's claim is true",
            "the A20 counterfactual is the committed decision read, not a re-evaluation at this candidate",
            "the post-stop stages are recorded by their own items and were not consumed here",
            "SELF_ISSUED is not a pass, and zero independent verifications is not repaired by relabelling it",
            "the artefact is one member of a mixed-candidate population; nothing here is a census",
            "a recorded stop is a valid completion of this slice, not a pass of the release",
        ],
    }
    return document


def build_stops(slice_document: dict[str, Any]) -> dict[str, Any]:
    """Every stop with the record that establishes it, and every stage after it."""
    trace = slice_document["trace"]
    stops = [
        {
            "stage": entry["stage"],
            "code": entry["detail"].get("stopCode"),
            "outcome": entry["detail"].get("outcome"),
            "establishedBy": entry["detail"].get("establishedBy"),
            "summary": entry["detail"].get("summary"),
        }
        for entry in trace
        if entry["status"] == STATUS_STOP
    ]
    refused = [
        {
            "stage": entry["stage"],
            "code": entry["codes"][0] if entry["codes"] else None,
            "summary": entry["detail"].get("summary"),
        }
        for entry in trace
        if entry["status"] == STATUS_REFUSED
    ]
    terminal = None
    for entry in trace:
        if entry["status"] in (STATUS_STOP, STATUS_REFUSED):
            terminal = entry
            break
    not_reached = [
        {
            "stage": entry["stage"],
            "item": entry["item"],
            "reason": entry["detail"].get("reason"),
            "after": entry["detail"].get("after"),
            "afterCode": entry["detail"].get("afterCode"),
        }
        for entry in trace
        if entry["status"] == STATUS_NOT_REACHED
    ]
    return {
        "schema": STOPS_SCHEMA,
        "model": MODEL_ID,
        "slice": "evidence/a27/SLICE.json",
        "artefact": slice_document["artefact"]["id"],
        "stopCount": len(stops),
        "stops": stops,
        "refusals": refused,
        "terminal": None if terminal is None else {
            "stage": terminal["stage"],
            "status": terminal["status"],
            "code": (terminal["detail"].get("stopCode")
                     if terminal["status"] == STATUS_STOP
                     else (terminal["codes"][0] if terminal["codes"] else None)),
        },
        "notReached": not_reached,
        "notReachedCount": len(not_reached),
        "consequence": (
            "No stage after A12 has an independent verification to consume. The "
            "release cannot be authorised, thresholded, bundled, key-lifecycle-"
            "checked, corrected, omission-closed, decided or summarised on this "
            "chain. The committed A20 decision denies; this slice records that "
            "record and does not re-evaluate it."
        ),
    }


def build_controls(root: Path | None = None) -> dict[str, Any]:
    """One in-memory control per refusal code. A control is not a source change."""
    root = REPO_ROOT if root is None else root
    artefact = bind_artefact(root)
    trace, codes = run_chain(root, artefact)
    if codes:
        raise SliceRefusal(codes[0], f"the real trace does not validate: {codes}", "trace")

    def trace_by_stage(rows: list[dict[str, Any]], stage: str) -> dict[str, Any]:
        row = _first(rows, "stage", stage)
        assert row is not None
        return row

    controls: list[dict[str, Any]] = []

    def add(control_id: str, code: str, mutated: str, mutated_trace: list[dict[str, Any]],
            runner) -> None:
        observed = runner(mutated_trace)
        controls.append({
            "id": control_id,
            "controlOnly": True,
            "code": code,
            "expectedCode": code,
            "mutated": mutated,
            "observedCodes": observed,
            "fired": bool(observed) and observed[0] == code,
        })

    # 1. a broken digest link
    broken = copy.deepcopy(trace)
    trace_by_stage(broken, "A7")["outputDigest"] = "0" * 63 + "1"
    add("trace-broken", VS_REFUSED_TRACE_BROKEN,
        "A7's output digest is replaced, so A8's input no longer equals it",
        broken, lambda rows: validate_trace(rows, root=root))

    # 2. a skipped stage
    skipped = [entry for entry in copy.deepcopy(trace) if entry["stage"] != "A6"]
    add("stage-skipped", VS_REFUSED_STAGE_SKIPPED,
        "A6 is removed from the trace entirely", skipped,
        lambda rows: validate_trace(rows, root=root))

    # 3. a stage whose output is absent
    missing = copy.deepcopy(trace)
    trace_by_stage(missing, "A9")["outputDigest"] = None
    add("output-missing", VS_REFUSED_OUTPUT_MISSING,
        "A9 reports PASS but produces no output digest", missing,
        lambda rows: validate_trace(rows, root=root))

    # 4. an overclaimed stage: A9 asserts a stronger state than its record
    statements = _load(root, "evidence/a9/STATEMENTS.json")
    mutated_statements = copy.deepcopy(statements)
    statement_row = _first(mutated_statements["statements"], "subject",
                           "evidence/a8/SHARD-000.sarif")
    assert statement_row is not None
    statement_row["assertedState"]["results"] = int(statement_row["recordState"]["results"]) + 1
    overrides = {"evidence/a9/STATEMENTS.json": mutated_statements}
    overclaim_trace, _ = run_chain(root, artefact, overrides=overrides)
    overclaim_entry = _first(overclaim_trace, "stage", "A9")
    assert overclaim_entry is not None
    overclaim_codes = list(overclaim_entry.get("codes") or [])
    add("stage-overclaim", VS_REFUSED_STAGE_OVERCLAIM,
        "A9's asserted result count is one more than its record state",
        overclaim_trace, lambda rows: overclaim_codes)

    # 5. an ADMIT with zero independent verification
    admitted = copy.deepcopy(trace)
    verification = trace_by_stage(admitted, "A12")
    verification["status"] = STATUS_PASS
    verification["codes"] = []
    previous = verification["outputDigest"]
    for stage in ("A14", "A15", "A16", "A18", "A19", "A17"):
        entry = trace_by_stage(admitted, stage)
        entry["status"] = STATUS_PASS
        entry["inputDigest"] = previous
        entry["outputDigest"] = digest_value({"synthetic": stage, "after": previous})
        entry["codes"] = []
        entry["detail"] = {"summary": f"synthetic continuation at {stage}", "asserts": stage}
        previous = entry["outputDigest"]
    policy_entry = trace_by_stage(admitted, "A20")
    policy_entry["status"] = STATUS_PASS
    policy_entry["inputDigest"] = previous
    policy_entry["outputDigest"] = digest_value({"synthetic": "A20", "after": previous})
    policy_entry["codes"] = []
    policy_entry["detail"] = {"summary": "synthetic ADMIT", "asserts": "ADMIT"}
    previous = policy_entry["outputDigest"]
    summary_entry = trace_by_stage(admitted, "A21")
    summary_entry["status"] = STATUS_PASS
    summary_entry["inputDigest"] = previous
    summary_entry["outputDigest"] = digest_value({"synthetic": "A21", "after": previous})
    summary_entry["codes"] = []
    summary_entry["detail"] = {"summary": "synthetic summary", "asserts": "SUMMARY"}
    add("admit-without-root", VS_REFUSED_ADMIT_WITHOUT_ROOT,
        "the trace is completed to A20 with ADMIT while A12 records zero independent verifications",
        admitted, lambda rows: validate_trace(rows, root=root))

    # 6. a summary used as evidence
    summary_as_evidence = copy.deepcopy(trace)
    verification = trace_by_stage(summary_as_evidence, "A12")
    verification["reads"] = list(verification["reads"]) + ["evidence/a21/SUMMARY.json"]
    add("summary-as-evidence", VS_REFUSED_SUMMARY_AS_EVIDENCE,
        "A12 cites the A21 summary as the record it verified instead of the verification record",
        summary_as_evidence, lambda rows: validate_trace(rows, root=root))

    # 7. a stop with no record
    unrecorded = copy.deepcopy(trace)
    trace_by_stage(unrecorded, "A12")["detail"].pop("establishedBy", None)
    add("stop-unrecorded", VS_REFUSED_STOP_NOT_RECORDED,
        "A12 is recorded as a STOP with no establishing record", unrecorded,
        lambda rows: validate_trace(rows, root=root))

    # 8. an artefact that is not bound to the chain
    unbound_spec = dict(ARTEFACT_SPEC)
    unbound_spec["exact"] = "0" * 64
    try:
        bind_artefact(root, unbound_spec)
        unbound_codes: list[str] = []
    except SliceRefusal as refusal:
        unbound_codes = [refusal.code]
    controls.append({
        "id": "artefact-unbound",
        "controlOnly": True,
        "code": VS_REFUSED_ARTEFACT_UNBOUND,
        "expectedCode": VS_REFUSED_ARTEFACT_UNBOUND,
        "mutated": "the declared exact identity is a digest no result carries",
        "observedCodes": unbound_codes,
        "fired": unbound_codes[:1] == [VS_REFUSED_ARTEFACT_UNBOUND],
    })

    # 9. a malformed invocation
    usage_codes = _usage_control()
    controls.append({
        "id": "malformed-invocation",
        "controlOnly": True,
        "code": VS_REFUSED_USAGE,
        "expectedCode": VS_REFUSED_USAGE,
        "mutated": "the command line names no known command",
        "observedCodes": usage_codes,
        "fired": usage_codes[:1] == [VS_REFUSED_USAGE],
    })

    covered = {row["code"] for row in controls if row["fired"]}
    required = set(REFUSAL_CODES) | set(INVOCATION_CODES)
    failing = [row["id"] for row in controls if not row["fired"]]
    positive = [
        {
            "id": "real-trace-validates",
            "controlOnly": True,
            "expects": "no validation code",
            "observedCodes": validate_trace(trace, root=root),
        },
        {
            "id": "real-stop-is-recorded",
            "controlOnly": True,
            "expects": "no VS_REFUSED_STOP_NOT_RECORDED",
            "observedCodes": check_stop_binding(root, trace),
        },
        {
            "id": "real-chain-has-no-omission",
            "controlOnly": True,
            "expects": "every stage appears exactly once",
            "observedCodes": [] if [entry["stage"] for entry in trace] == list(STAGE_ORDER)
            else [VS_REFUSED_STAGE_SKIPPED],
        },
    ]
    for row in positive:
        row["fired"] = not row["observedCodes"]
    return {
        "schema": CONTROLS_SCHEMA,
        "model": MODEL_ID,
        "controlOnly": True,
        "refusalCodes": list(REFUSAL_CODES),
        "invocationCodes": list(INVOCATION_CODES),
        "stopCodes": list(STOP_CODES),
        "codesCovered": sorted(covered),
        "codesMissing": sorted(required - covered),
        "coversEveryCode": required.issubset(covered),
        "failing": failing,
        "controls": controls,
        "positiveControls": positive,
        "note": (
            "Each row mutates an in-memory trace or an in-memory record, or an "
            "invocation, and asserts the exact code that fires. No row changes a "
            "committed record, and a control is not evidence that a stage is "
            "correct."
        ),
    }


def _usage_control() -> list[str]:
    """Run the CLI with no valid command and read the code it prints."""
    import contextlib
    import io

    buffer = io.StringIO()
    try:
        with contextlib.redirect_stderr(buffer), contextlib.redirect_stdout(buffer):
            main(["no-such-command"])
    except SystemExit:
        pass
    text = buffer.getvalue()
    return [code for code in INVOCATION_CODES if code in text]


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised by a control
        self.print_usage(sys.stderr)
        print(f"code={VS_REFUSED_USAGE} detail={message}", file=sys.stderr)
        raise SystemExit(2)


def _serialise(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_json(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_bytes(_serialise(document))
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _print_trace(trace: list[dict[str, Any]]) -> None:
    for entry in trace:
        input_digest = (entry.get("inputDigest") or "none")[:12]
        output_digest = (entry.get("outputDigest") or "none")[:12]
        codes = ",".join(entry.get("codes") or []) or "NONE"
        print(
            f"stage={entry['stage']} status={entry['status']} "
            f"input={input_digest} output={output_digest} codes={codes}"
        )


def _codes_after(trace: list[dict[str, Any]]) -> list[str]:
    codes: list[str] = []
    for entry in trace:
        for code in entry.get("codes") or []:
            if code not in codes:
                codes.append(code)
    return codes


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="one real artefact through the assurance chain")
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run", help="run the chain and print the trace")
    run_parser.add_argument("--out", default=None)
    run_parser.add_argument("--json", action="store_true")
    trace_parser = commands.add_parser("trace", help="print the committed trace")
    trace_parser.add_argument("--slice", default=str(DEFAULT_SLICE))
    stop_parser = commands.add_parser("stop", help="print the first stop and the stages not reached")
    stop_parser.add_argument("--slice", default=str(DEFAULT_SLICE))
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    try:
        if args.command == "run":
            document = build_slice(REPO_ROOT)
            codes = list(validate_trace(document["trace"], root=REPO_ROOT))
            codes += check_stop_binding(REPO_ROOT, document["trace"])
            if args.out:
                write_json(Path(args.out), document)
            if args.json:
                print(json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False))
            else:
                print(
                    f"artefact={document['artefact']['id']} "
                    f"exact={document['artefact']['fingerprints']['a1Exact/v1']}"
                )
                _print_trace(document["trace"])
                observed = document["stop"]["establishedBy"]["observed"]
                print(
                    f"stop={document['stop']['stage']} code={document['stop']['code']} "
                    f"outcome={document['stop']['outcome']} "
                    f"independent={observed['independentlyVerifiedEnvelopes']}/{observed['envelopes']}"
                )
            print(f"codes={','.join(codes) if codes else 'NONE'}")
            return 0 if not codes else 1

        if args.command in ("trace", "stop"):
            path = Path(args.slice)
            if not path.exists():
                print(f"code={VS_REFUSED_OUTPUT_MISSING} detail={path} is absent")
                return 1
            document = json.loads(path.read_text(encoding="utf-8"))
            codes = validate_trace(document["trace"], root=REPO_ROOT)
            codes += check_stop_binding(REPO_ROOT, document["trace"])
            if args.command == "trace":
                _print_trace(document["trace"])
                print(
                    f"stages={len(document['trace'])} "
                    f"passed={document['counts']['passed']} "
                    f"stopped={document['counts']['stopped']} "
                    f"notReached={document['counts']['notReached']}"
                )
            else:
                stop = first_stop(document["trace"])
                if stop is None:
                    print(f"code={VS_REFUSED_STOP_NOT_RECORDED} detail=no stop in the trace")
                    return 1
                print(
                    f"stop={stop['stage']} code={stop['code']} "
                    f"outcome={stop['outcome']} "
                    f"record={stop['establishedBy']['record']} "
                    f"sha256={stop['establishedBy']['sha256']} "
                    f"locator={stop['establishedBy']['locator']}"
                )
                for entry in document["trace"]:
                    if entry["status"] == STATUS_NOT_REACHED:
                        print(
                            f"not_reached={entry['stage']} "
                            f"after={entry['detail']['after']} "
                            f"code={entry['detail']['afterCode']} "
                            f"reason={entry['detail']['reason']}"
                        )
            print(f"codes={','.join(codes) if codes else 'NONE'}")
            return 0 if not codes else 1
    except SliceRefusal as refusal:
        print(f"code={refusal.code} stage={refusal.stage} detail={refusal.detail}")
        return 1

    parser.print_usage(sys.stderr)
    print(f"code={VS_REFUSED_USAGE} detail=unknown command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
