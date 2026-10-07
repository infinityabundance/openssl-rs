#!/usr/bin/env python3
"""openssl-rs — the directional, dimension-specific compatibility edges (Phase 23.12).

Phase 23.12 lands the **compatibility edges**: for each release/authority pair the committed
evidence supports, a set of stratified, *directional*, *dimension-specific* facts about
compatibility ([`compatibility_edge`] in `forensics/tools/multitrack_schemas.py`). Each edge
names the two sides, the direction it is read in, one facet and the coarse schema dimension
that facet is of, a verdict (`PASS` / `FAIL` / `UNKNOWN`), and the content-addressed evidence
each side carries -- never one boolean, and never a verdict from numeric ordering.

Why an edge is directional and dimension-specific
-------------------------------------------------
A compatibility fact is about a **reading**: a consumer built against one side binds to a
surface the other side offers, and the two readings need not agree. `direction` is
`reference_to_candidate` when the edge is read from the reference side toward the candidate
side, and `candidate_to_reference` when it is read the other way; the same pair and the same
facet can carry different verdicts in the two directions. The six facets the plan names --
API source, ABI link, ABI load, layout, semantic and CLI-config compatibility -- are finer
than the schema's closed `COMPAT_DIMENSIONS`, so, exactly as the 23.6 delta engine and the
23.9 views keep a fine vocabulary beside the coarse one (`docs/PHASE-23-MULTITRACK-SUBPHASES.md`
section 4.9), an edge carries a coarse `dimension` **and** a fine `facet` that lives with this
generator rather than in the shared schema. It is never a single boolean: the schema refuses a
`version_order` evidence kind by name, and the court refuses a bare `compatible` flag.

Where the verdicts come from, and what is honestly not established
------------------------------------------------------------------
Two pairs are established, and only from committed evidence:

  * **`openssl-3.6.3-historical` <-> `openssl-3.6.4-production`** -- the one canonical edge
    delta the 23.6 engine has committed (`forensics/deltas/openssl-3.6.3--openssl-3.6.4.json`).
    Each facet is derived from the delta receipt for its coarse dimension: a facet whose
    constitutive fine dimensions the delta measured and found unchanged is `PASS`, a removal or
    a contract-bearing change in the reading direction is `FAIL`, and a facet whose constitutive
    dimensions were not measured is `UNKNOWN` with the reason. The two directions are the delta
    read forward and read backward (an addition in one direction is a removal in the other), so
    the pair genuinely differs by direction.
  * **`openssl-rs` (the candidate) <-> `openssl-3.6.4-production` (its reference authority)** --
    the Phase-2 ABI courts (`ABI-MATRIX`, `ABI-LINK`, `ABI-SUBSTITUTION`, `ABI-LOAD`,
    `ABI-LAYOUT`, `ABI-CONSTANTS`, `ABI-INSTALL-LAYOUT`) and the 23.9 compatibility views. The
    semantic facet is `UNKNOWN`: no committed candidate-to-authority semantic measurement exists
    in this evidence set, so it is recorded unmeasured rather than passed.

A dimension or pair the evidence cannot support is recorded `UNKNOWN` with its reason -- never
`PASS` by default. Every evidence entry names the side it belongs to (`from_side` / `to_side` /
`pair`) and, for a side, that side's own authority identity and a content-addressed path +
sha256; **a side's evidence is never inherited from the other** (the general form of D533, the
rule the 23.9 court also carries).

Outputs
-------
  forensics/multitrack/compatibility-edges.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    InputRef,
    REPO_ROOT,
    envelope,
    rel,
    sha256_file,
    write_json,
)

import multitrack_schemas  # noqa: E402

OUT = REPO_ROOT / "forensics" / "multitrack" / "compatibility-edges.json"
GENERATOR = "forensics/tools/compat_edges.py"

# The committed evidence every edge is derived from. Nothing here is typed twice: an edge cites
# the artefact it was derived from and that artefact's sha256.
AUTHORITY_NODES = REPO_ROOT / "forensics" / "authority-nodes.json"
ENTITY_LINEAGE = REPO_ROOT / "forensics" / "multitrack" / "entity-lineage.json"
COMPAT_VIEWS = REPO_ROOT / "forensics" / "multitrack" / "compatibility-views.json"
DELTAS = REPO_ROOT / "forensics" / "deltas"
PRODUCTION_ATLAS = REPO_ROOT / "forensics" / "atlas" / "openssl-3.6.4-production"
SHELL_MANIFEST = REPO_ROOT / "artifacts" / "phase2" / "SHELL_MANIFEST.json"
ABI_COURTS = REPO_ROOT / "artifacts" / "phase2" / "courts"

# The two sides the plane establishes, and the roles they play.
CANDIDATE = "openssl-rs"
REFERENCE_AUTHORITY = "openssl-3.6.4-production"
DELTA_FROM = "openssl-3.6.3-historical"
DELTA_TO = "openssl-3.6.4-production"

# The fine facets the plan names, the coarse schema dimension each is of, and the fine delta
# dimensions that constitute its evidence. A facet is derived only from the fine dimensions its
# coarse dimension buckets (authority_delta.DELTA_DIMENSIONS), so a facet cannot cite a
# measurement that is not about it.
FACETS: dict[str, dict] = {
    "api_source": {
        "dimension": "source_api",
        "delta": ("api_presence", "api_declaration", "prototype", "macro_value", "enum_value",
                  "typedef"),
    },
    "abi_link": {
        "dimension": "abi",
        "delta": ("abi_symbol_presence", "abi_symbol_version"),
    },
    "abi_load": {
        "dimension": "abi",
        "delta": ("abi_symbol_version",),
    },
    "layout": {
        "dimension": "abi",
        "delta": ("public_layout",),
    },
    "semantic": {
        "dimension": "semantic",
        "delta": ("security_policy", "deprecation_state", "documentation_claims"),
    },
    "cli_config": {
        "dimension": "cli_config",
        "delta": ("configuration", "cli", "environment", "filesystem_distribution"),
    },
}

# The fine facets must map onto the schema's closed dimension vocabulary; a facet that did not
# would be a compatibility claim the schema cannot check.
for _facet, _spec in FACETS.items():
    if _spec["dimension"] not in multitrack_schemas.COMPAT_DIMENSIONS:
        raise SystemExit(
            f"compat_edges: facet {_facet!r} names dimension {_spec['dimension']!r}, which is not "
            f"one of the schema's COMPAT_DIMENSIONS {multitrack_schemas.COMPAT_DIMENSIONS}"
        )

# The verdict vocabulary and its projection onto the schema's closed status vocabulary. The
# verdict is the compatibility fact; `status` is the schema field it is projected onto, and the
# two are required to agree by the court.
VERDICTS: tuple[str, ...] = ("PASS", "FAIL", "UNKNOWN")
STATUS_OF_VERDICT: dict[str, str] = {
    "PASS": "compatible",
    "FAIL": "incompatible",
    "UNKNOWN": "unknown",
}

# The Phase-2 ABI courts, per facet. These are the candidate-to-authority measurements the
# brief's §13/§33 boundary names; a facet with no committed court or view is `UNKNOWN`.
P2_FACET_COURTS: dict[str, tuple[str, ...]] = {
    "api_source": ("ABI-CONSTANTS.json", "ABI-MATRIX.json"),
    "abi_link": ("ABI-MATRIX.json", "ABI-LINK.json", "ABI-SUBSTITUTION.json"),
    "abi_load": ("ABI-LOAD.json", "ABI-SUBSTITUTION.json"),
    "layout": ("ABI-LAYOUT.json",),
    "cli_config": ("ABI-INSTALL-LAYOUT.json",),
    "semantic": (),
}
# The 23.9 view facets that corroborate a candidate-to-authority facet, where the view exists.
P2_FACET_VIEWS: dict[str, tuple[str, ...]] = {
    "cli_config": ("distribution_pkg_config", "distribution_install_layout"),
}

# The explicit non-claims every edge carries. They are the stratum's own (section 0).
NON_CLAIMS: list[str] = [
    "a compatibility edge is a directional, dimension-specific fact about one reading, not a "
    "one-boolean compatibility claim about a release",
    "one platform/profile is not every platform/profile: an edge is bounded to the authorities it "
    "names and the evidence they carry",
    "upstream's ABI promise is not candidate evidence",
    "OpenSSL compatibility is not FIPS validation (docs/FIPS_CLAIMS.md)",
]


def _load(path: Path) -> dict:
    """Read a committed artefact, failing closed when it is absent."""
    if not path.is_file():
        raise SystemExit(
            f"compat_edges: {rel(path)} is absent, so the evidence cannot be read; the read is "
            f"fail-closed rather than a fabricated edge"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _side(authority_id: str, release_id: str, kind: str) -> dict:
    """One side of an edge: its authority identity, the release it is over and its nature.

    `kind` is `authority` for a built authority and `candidate` for the crate's own emitted
    distribution. A side is always named explicitly and singularly; nothing selects it.
    """
    return {"authority_id": authority_id, "release_id": release_id, "kind": kind}


def _entry(side: str, authority_id: str | None, kind: str, path: Path,
           note: str | None = None) -> dict:
    """One content-addressed evidence entry: the side it belongs to and its path + sha256."""
    entry: dict = {
        "side": side,
        "kind": kind,
        "path": rel(path),
        "sha256": sha256_file(path),
    }
    if authority_id is not None:
        entry["authority_id"] = authority_id
    if note:
        entry["note"] = note
    return entry


def _plane_kind(path: Path) -> str:
    """The evidence kind of a per-authority atlas plane.

    A declaration plane (macros, functions, structs, ...) is a `source_manifest` reading; a
    symbol plane is a `build_records` reading. The distinction is the plane, not the caller.
    """
    return "build_records" if Path(path).name.startswith("symbols-") else "source_manifest"


def _breaking(facet: str, classification: str, row: dict) -> bool:
    """Whether a classified delta row, read in the edge's direction, breaks that facet.

    A removal always breaks: the surface the consumer bound to is gone. A change breaks only
    where the facet is about the changed contract -- a declaration, prototype, typedef, enum,
    symbol version or public layout -- and never for the delta engine's `st_size`
    implementation-size observation, which its own adjudication records as *not an ABI contract
    change*. An addition never breaks the reading direction it is read in.
    """
    dim = row["dimension"]
    fine_facet = row.get("facet")
    if facet == "api_source":
        if classification == "removed":
            return True
        return classification == "changed" and dim in ("api_declaration", "prototype", "typedef",
                                                       "enum_value")
    if facet == "abi_link":
        if classification == "removed":
            return True
        if classification == "changed" and dim == "abi_symbol_version":
            return True
        return (classification == "changed" and dim == "abi_symbol_presence"
                and fine_facet != "st_size")
    if facet == "abi_load":
        if classification == "removed":
            return True
        return classification == "changed" and dim == "abi_symbol_version"
    # layout, semantic, cli_config: any removal or change of the measured plane is breaking.
    return classification in ("removed", "changed")


def _delta_facet(delta: dict, facet: str, reverse: bool) -> tuple[str, str | None, list[dict]]:
    """`(verdict, reason, rows)` for a delta-derived facet, read forward or backward."""
    spec = FACETS[facet]
    measured = set(delta.get("measured_dimensions") or [])
    constitutive = tuple(d for d in spec["delta"] if d in measured)
    if not constitutive:
        return (
            "UNKNOWN",
            f"the committed delta measures none of {facet}'s constitutive fine dimensions "
            f"{list(spec['delta'])}, so this facet is not measured for this pair",
            [],
        )
    receipt = next((r for r in delta.get("receipts") or []
                    if r.get("dimension") == spec["dimension"]), None)
    if receipt is None:
        return (
            "UNKNOWN",
            f"the committed delta carries no {spec['dimension']} receipt, so this facet is not "
            f"measured for this pair",
            [],
        )
    rows: list[dict] = []
    for classification in ("added", "removed", "changed"):
        for row in receipt.get(classification) or []:
            if row.get("dimension") not in constitutive:
                continue
            effective = classification
            if reverse:
                effective = {"added": "removed", "removed": "added",
                             "changed": "changed"}[classification]
            rows.append({"classification": effective, "row": row})
    breaking = any(_breaking(facet, item["classification"], item["row"]) for item in rows)
    return ("FAIL" if breaking else "PASS"), None, rows


def _delta_evidence(delta_path: Path, receipt: dict | None, from_side: dict,
                    to_side: dict) -> list[dict]:
    """The content-addressed evidence for a delta-derived edge, split by side.

    The committed delta is the `pair` evidence; each authority's own atlas planes are that
    side's `from_side` / `to_side` evidence, so a side's evidence is never inherited from the
    other.
    """
    entries = [
        _entry("pair", None, "atlas_differential", delta_path,
               "the committed canonical edge delta for this pair"),
        _entry("pair", None, "entity_lineage", ENTITY_LINEAGE,
               "the entity identity plane the delta rows key on"),
    ]
    for raw in (receipt or {}).get("evidence") or []:
        path = REPO_ROOT / raw
        if not path.is_file():
            continue
        if from_side["authority_id"] in raw:
            entries.append(_entry("from_side", from_side["authority_id"], _plane_kind(path), path))
        elif to_side["authority_id"] in raw:
            entries.append(_entry("to_side", to_side["authority_id"], _plane_kind(path), path))
    return entries


def _absence_entry(path: Path, reason: str) -> dict:
    """The single absence entry an `UNKNOWN` edge carries: an adjudication, not a measurement."""
    return _entry("pair", None, "manual_adjudication", path, reason)


def _p2_verdict(facet: str, views_body: dict) -> tuple[str, str | None]:
    """`(verdict, reason)` for a candidate-to-authority facet from its committed evidence."""
    statuses: list[str] = []
    for name in P2_FACET_COURTS.get(facet, ()):
        statuses.append(str(_load(ABI_COURTS / name).get("verdict")))
    for view_facet in P2_FACET_VIEWS.get(facet, ()):
        view = next((v for v in views_body.get("views") or []
                     if v.get("facet") == view_facet and v.get("reference_id") == REFERENCE_AUTHORITY),
                    None)
        statuses.append(str((view or {}).get("status")))
    if not statuses:
        return (
            "UNKNOWN",
            "no committed candidate-to-authority measurement exists for this facet: the Phase-2 "
            "ABI courts do not cover it and the compatibility views record no view for it, so it "
            "is unmeasured rather than compatible",
        )
    if any(s in ("fail", "incompatible", "partial") for s in statuses):
        return "FAIL", None
    if all(s in ("pass", "compatible") for s in statuses):
        return "PASS", None
    return (
        "UNKNOWN",
        f"the committed evidence for this facet is not conclusive (measured statuses "
        f"{sorted(set(statuses))}), so it is unmeasured rather than compatible",
    )


def _p2_evidence(facet: str, from_side: dict, to_side: dict, views_body: dict,
                 reason: str | None) -> list[dict]:
    """The content-addressed evidence for a candidate-to-authority edge, split by side.

    Each side carries its own evidence: a built authority its authority node and measured atlas,
    the candidate its emitted distribution shell. The Phase-2 ABI court records are the `pair`
    evidence, since each is a differential reading of the two.
    """
    entries: list[dict] = []
    if reason is not None:
        return [_absence_entry(COMPAT_VIEWS, reason)]
    for name in P2_FACET_COURTS.get(facet, ()):
        entries.append(_entry("pair", None, "court_transcript", ABI_COURTS / name,
                              "the Phase-2 ABI differential court"))
    for view_facet in P2_FACET_VIEWS.get(facet, ()):
        entries.append(_entry("pair", None, "court_transcript", COMPAT_VIEWS,
                              f"the 23.9 compatibility view {view_facet}"))
    for side in (from_side, to_side):
        if side["kind"] == "authority":
            entries.append(_entry("from_side" if side is from_side else "to_side",
                                  side["authority_id"], "build_records", AUTHORITY_NODES,
                                  "the authority node's build identity"))
            entries.append(_entry("from_side" if side is from_side else "to_side",
                                  side["authority_id"], "upstream_declaration",
                                  PRODUCTION_ATLAS / "symbol-versions.json",
                                  "the authority's measured symbol-version plane"))
        else:
            entries.append(_entry("from_side" if side is from_side else "to_side",
                                  side["authority_id"], "build_records", SHELL_MANIFEST,
                                  "the candidate's emitted distribution shell"))
    return entries


def _edge(from_side: dict, to_side: dict, direction: str, facet: str, verdict: str,
          reason: str | None, evidence_kind: str, evidence: list[dict],
          basis: str) -> dict:
    """Build one `compatibility_edge` record.

    The record is directional (its `direction` names which side is read toward which), one
    dimension and one facet, and carries its verdict, its evidence and its explicit non-claims.
    It never carries a bare `compatible` boolean.
    """
    rec: dict = {
        "edge_id": f"CE-{from_side['authority_id']}--{to_side['authority_id']}--{facet}",
        "from_id": from_side["authority_id"],
        "to_id": to_side["authority_id"],
        "from_authority": from_side["authority_id"],
        "to_authority": to_side["authority_id"],
        "from_release": from_side["release_id"],
        "to_release": to_side["release_id"],
        "from_kind": from_side["kind"],
        "to_kind": to_side["kind"],
        "direction": direction,
        "dimension": FACETS[facet]["dimension"],
        "facet": facet,
        "verdict": verdict,
        "status": STATUS_OF_VERDICT[verdict],
        "evidence_kind": evidence_kind,
        "evidence": evidence,
        "basis": basis,
        "non_claims": list(NON_CLAIMS),
    }
    if reason is not None:
        rec["reason"] = reason
    return rec


def _directions() -> list[dict]:
    """The pair-directions the plane establishes, read both ways.

    The two directions of a pair are the same evidence read toward each endpoint, so a
    direction that is compatible and a direction that is not are both recorded rather than
    collapsed.
    """
    delta_ref = _side(DELTA_FROM, "openssl-3.6.3", "authority")
    delta_cand = _side(DELTA_TO, "openssl-3.6.4", "authority")
    auth = _side(REFERENCE_AUTHORITY, "openssl-3.6.4", "authority")
    candidate = _side(CANDIDATE, "openssl-3.6.4", "candidate")
    return [
        {"pair_id": "release-3.6.3-3.6.4", "direction": "reference_to_candidate",
         "from": delta_ref, "to": delta_cand, "source": "delta"},
        {"pair_id": "release-3.6.3-3.6.4", "direction": "candidate_to_reference",
         "from": delta_cand, "to": delta_ref, "source": "delta"},
        {"pair_id": "candidate-vs-reference", "direction": "reference_to_candidate",
         "from": auth, "to": candidate, "source": "views"},
        {"pair_id": "candidate-vs-reference", "direction": "candidate_to_reference",
         "from": candidate, "to": auth, "source": "views"},
    ]


def _delta_edges(direction: dict, delta: dict, delta_path: Path) -> list[dict]:
    """Every facet edge for a delta-derived pair-direction."""
    from_side, to_side = direction["from"], direction["to"]
    reverse = direction["direction"] == "candidate_to_reference"
    edges: list[dict] = []
    for facet in FACETS:
        verdict, reason, rows = _delta_facet(delta, facet, reverse)
        spec = FACETS[facet]
        measured = set(delta.get("measured_dimensions") or [])
        constitutive = tuple(d for d in spec["delta"] if d in measured)
        if verdict == "UNKNOWN":
            evidence = [_absence_entry(delta_path, reason)]
            evidence_kind = "manual_adjudication"
            basis = (f"UNKNOWN: {reason}")
        else:
            receipt = next((r for r in delta.get("receipts") or []
                            if r.get("dimension") == spec["dimension"]), None)
            evidence = _delta_evidence(delta_path, receipt, from_side, to_side)
            evidence_kind = "atlas_differential"
            counted = {"added": 0, "removed": 0, "changed": 0}
            for item in rows:
                counted[item["classification"]] += 1
            basis = (
                f"the committed 3.6.3->3.6.4 delta measures {facet} on "
                f"{list(constitutive)} and yields {counted['added']} added / "
                f"{counted['removed']} removed / {counted['changed']} changed row(s) read "
                f"{'backward' if reverse else 'forward'}; "
                + ("a removal or contract-bearing change is present, so the reading breaks"
                   if verdict == "FAIL"
                   else "no removal and no contract-bearing change is present, so the reading "
                        "holds")
            )
        edges.append(_edge(from_side, to_side, direction["direction"], facet, verdict, reason,
                           evidence_kind, evidence, basis))
    return edges


def _p2_edges(direction: dict, views_body: dict) -> list[dict]:
    """Every facet edge for a candidate-to-authority pair-direction."""
    from_side, to_side = direction["from"], direction["to"]
    edges: list[dict] = []
    for facet in FACETS:
        verdict, reason = _p2_verdict(facet, views_body)
        evidence = _p2_evidence(facet, from_side, to_side, views_body, reason)
        evidence_kind = "manual_adjudication" if verdict == "UNKNOWN" else "court_transcript"
        if verdict == "UNKNOWN":
            basis = f"UNKNOWN: {reason}"
        else:
            courts = ", ".join(P2_FACET_COURTS.get(facet, ())) or "-"
            views = ", ".join(P2_FACET_VIEWS.get(facet, ())) or "-"
            basis = (
                f"the committed candidate-to-authority evidence for {facet} -- the Phase-2 ABI "
                f"courts [{courts}] and the 23.9 compatibility views [{views}] -- reads "
                f"{verdict.lower()}"
            )
        edges.append(_edge(from_side, to_side, direction["direction"], facet, verdict, reason,
                           evidence_kind, evidence, basis))
    return edges


def derive_body() -> dict:
    """The compatibility-edges plane, a pure function of the committed evidence.

    Deterministic: every list is sorted, no wall-clock or environment value is read, and every
    evidence entry is content-addressed. The court re-derives this body through the same code
    and refuses a committed plane that does not reproduce.
    """
    nodes = {n["authority_id"]: n for n in _body(_load(AUTHORITY_NODES)).get("nodes") or []}
    for required in (DELTA_FROM, DELTA_TO, REFERENCE_AUTHORITY):
        if required not in nodes:
            raise SystemExit(f"compat_edges: {required!r} is not an authority node")
    delta_path = DELTAS / "openssl-3.6.3--openssl-3.6.4.json"
    delta = _body(_load(delta_path))
    if not delta.get("covered"):
        raise SystemExit(
            "compat_edges: the committed 3.6.3->3.6.4 delta is not covered, so no pair edge "
            "can be derived from it"
        )
    views_body = _body(_load(COMPAT_VIEWS))

    edges: list[dict] = []
    for direction in _directions():
        if direction["source"] == "delta":
            edges += _delta_edges(direction, delta, delta_path)
        else:
            edges += _p2_edges(direction, views_body)
    edges.sort(key=lambda e: e["edge_id"])

    by_verdict: dict[str, int] = {}
    by_dimension: dict[str, int] = {}
    by_facet: dict[str, int] = {}
    unknown: list[dict] = []
    for e in edges:
        by_verdict[e["verdict"]] = by_verdict.get(e["verdict"], 0) + 1
        by_dimension[e["dimension"]] = by_dimension.get(e["dimension"], 0) + 1
        by_facet[e["facet"]] = by_facet.get(e["facet"], 0) + 1
        if e["verdict"] == "UNKNOWN":
            unknown.append({"edge_id": e["edge_id"], "pair_id": e["from_id"] + "->" + e["to_id"],
                            "facet": e["facet"], "reason": e["reason"]})

    return {
        "rule": (
            "one directional, dimension-specific compatibility edge per pair-direction and facet, "
            "derived from the committed evidence and never typed. A verdict is PASS, FAIL or "
            "UNKNOWN with the evidence that establishes it; a facet whose evidence is absent is "
            "UNKNOWN with its reason, never PASS by default, and no edge is a single boolean. "
            "Every evidence entry names the side it belongs to and, for a side, that side's own "
            "authority identity and a content-addressed path + sha256, so a side's evidence is "
            "never inherited from the other"
        ),
        "direction_model": (
            "reference_to_candidate reads the edge from the reference side toward the candidate "
            "side; candidate_to_reference reads it the other way. The same pair and facet may "
            "carry different verdicts in the two directions"
        ),
        "verdict_vocabulary": list(VERDICTS),
        "status_projection": dict(STATUS_OF_VERDICT),
        "facets": {f: {"dimension": s["dimension"], "delta_dimensions": list(s["delta"])}
                   for f, s in FACETS.items()},
        "directions": [
            {"pair_id": d["pair_id"], "direction": d["direction"], "from_id": d["from"]["authority_id"],
             "to_id": d["to"]["authority_id"], "from_kind": d["from"]["kind"],
             "to_kind": d["to"]["kind"], "source": d["source"]}
            for d in _directions()
        ],
        "counts": {
            "pairs": len({d["pair_id"] for d in _directions()}),
            "directions": len(_directions()),
            "edges": len(edges),
            "unknown": len(unknown),
            "by_verdict": {k: by_verdict[k] for k in sorted(by_verdict)},
            "by_dimension": {k: by_dimension[k] for k in sorted(by_dimension)},
            "by_facet": {k: by_facet[k] for k in sorted(by_facet)},
        },
        "edges": edges,
        "unknown": unknown,
        "non_claims": list(NON_CLAIMS),
        "boundary": (
            "23.12 derives the directional, dimension-specific compatibility edges for the pairs "
            "the committed evidence supports: the one canonical 3.6.3->3.6.4 edge delta (both "
            "directions) and the candidate's relation to its reference authority 3.6.4-production "
            "(both directions). The facets are API source, ABI link, ABI load, layout, semantic "
            "and CLI-config compatibility. A facet the evidence cannot support is UNKNOWN with "
            "its reason; the semantic facet of the candidate-to-authority pair is unmeasured "
            "because no committed candidate-to-authority semantic observation exists in this "
            "evidence set. No edge is a one-boolean claim and none derives compatibility from "
            "numeric ordering"
        ),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args(argv)

    body = derive_body()

    inputs = [
        InputRef(name="authority-nodes", path=AUTHORITY_NODES),
        InputRef(name="entity-lineage", path=ENTITY_LINEAGE),
        InputRef(name="compatibility-views", path=COMPAT_VIEWS),
        InputRef(name="delta-3.6.3-3.6.4", path=DELTAS / "openssl-3.6.3--openssl-3.6.4.json"),
        InputRef(name="production-symbol-versions", path=PRODUCTION_ATLAS / "symbol-versions.json"),
        InputRef(name="phase2-shell-manifest", path=SHELL_MANIFEST),
        *[InputRef(name=f"abi-court/{p.stem.lower()}", path=p)
          for p in sorted(ABI_COURTS.glob("ABI-*.json"))],
    ]
    doc = envelope(kind="compatibility-edges", authority=REFERENCE_AUTHORITY,
                   inputs=inputs, body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[compat-edges] {c['edges']} edge(s) over {c['pairs']} pair(s) / "
          f"{c['directions']} direction(s); verdicts={c['by_verdict']}; "
          f"{c['unknown']} unknown facet(s)")
    for e in body["edges"]:
        mark = e["verdict"]
        print(f"  {e['from_id']:<30} -> {e['to_id']:<30} {e['direction']:<22} "
              f"{e['facet']:<11} {mark}")
    for u in body["unknown"]:
        print(f"  UNKNOWN {u['edge_id']}: {u['reason']}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
