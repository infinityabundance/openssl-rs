#!/usr/bin/env python3
"""openssl-rs — the assembled compatibility matrix (Phase 23.16).

Phase 23.16 lands the **compatibility matrix**: the one artefact that joins the five
evidence planes the stratum has built -- the directional, dimension-specific
compatibility **views** (23.9), the directional, dimension-specific compatibility
**edges** (23.12), the negative (and positive) **obligations** (23.13), the **security
lineage** (23.14) and the **support status** ladder (23.15) -- over the release
lineage, into a set of cells each of which is a directional, dimension-specific record
with a `PASS` / `FAIL` / `UNKNOWN` / `NOT_MEASURED` verdict and the evidence that
establishes it. The plan row (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2, 23.16)
and its brief sections 33 and 49 name what the matrix must be: the stratum's assembled
claim substrate, every cell directional and dimension-specific, **no cell a single
boolean**.

The matrix references, it does not restate
------------------------------------------
A cell carries **references** to the records it joins -- each source is a
`(plane, record_id)` pair with the reading the join took from it -- rather than a copy
of the record. `RT-COMPATIBILITY-MATRIX` re-reads every source record from the plane it
names and re-derives every reading and every cell verdict, so the matrix **cannot
drift** from its inputs: a hand-edited verdict, a relayed record or a boolean rollup
stops reproducing. The five planes are content-addressed once, in the `planes` block,
and each cell cites them by name.

What a cell is, and what it is not
----------------------------------
A cell is keyed by one **directed relation** over the lineage and one **dimension**. The
relations are read from the planes that establish them (the edge plane's declared
pair-directions, the view plane's candidate-to-authority relations and the obligation
plane's authority scopes), so the matrix is `O(relations x dimensions)`, **never** the
pairwise product of releases: it joins over the lineage edges and the planes that exist,
exactly as the plan requires. Every relation gets a cell for every member of the
schema's closed `COMPAT_DIMENSIONS`, so a dimension a relation has no evidence for is
recorded `NOT_MEASURED` **with its reason**, never `PASS` by default. The verdict is the
join of the readings, not a boolean: a cell passes only when every reading passes, any
failing reading fails the cell, and anything unmeasured or unknown leaves the cell
`UNKNOWN` -- never promoted.

Where a reading comes from
--------------------------
  * **edges** -- `PASS`/`FAIL`/`UNKNOWN` as the edge carries them.
  * **views** -- their `status` (`compatible` -> `PASS`, `partial`/`incompatible` ->
    `FAIL`, `unknown` -> `UNKNOWN`, `not_measured` -> `NOT_MEASURED`).
  * **obligations** -- their `state` (`satisfied` -> `PASS`, `open` -> `FAIL`,
    `unknown` -> `UNKNOWN`), scoped to the relation's reference side.
  * **security** -- the candidate disposition (`never_contained`/`safe_divergence` ->
    `PASS`, `unresolved` -> `UNKNOWN`, `preserve_vulnerable_behaviour` -> `FAIL`),
    joined to the candidate-to-reference-authority relation on the **behavioural**
    dimension, so a cell can never re-adopt a fixed behaviour.
  * **support status** -- the endpoint release's ladder row, joined as **context**
    (not a compatibility reading): it bounds a cell to a release/authority state and
    never turns an unmeasured reading into a pass.

Outputs
-------
  forensics/multitrack/compatibility-matrix.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

import multitrack_schemas  # noqa: E402

OUT = REPO_ROOT / "forensics" / "multitrack" / "compatibility-matrix.json"
GENERATOR = "forensics/tools/compat_matrix.py"

# The five planes the matrix joins, and the artefact each is read from. Nothing here is typed
# twice: a cell cites the plane and the record id, and the court re-reads both.
COMPAT_VIEWS = REPO_ROOT / "forensics" / "multitrack" / "compatibility-views.json"
COMPAT_EDGES = REPO_ROOT / "forensics" / "multitrack" / "compatibility-edges.json"
NEG_OBLIGATIONS = REPO_ROOT / "forensics" / "multitrack" / "negative-obligations.json"
SECURITY_LINEAGE = REPO_ROOT / "forensics" / "multitrack" / "security-lineage.json"
SUPPORT_STATUS = REPO_ROOT / "forensics" / "multitrack" / "support-status.json"
AUTHORITY_NODES = REPO_ROOT / "forensics" / "authority-nodes.json"

# The candidate implementation (the subject of every relation) and the reference authority the
# security lineage reasons about. Both are named explicitly and singularly (D534).
CANDIDATE = "openssl-rs"
REFERENCE_AUTHORITY = "openssl-3.6.4-production"

# The `plane -> (artefact, id key, record list key)` map. The id key is the field a source
# reference resolves against, and the record list key is where the plane keeps its records.
PLANES: dict[str, dict] = {
    "compatibility_views": {"path": COMPAT_VIEWS, "id_key": "view_id", "list_key": "views"},
    "compatibility_edges": {"path": COMPAT_EDGES, "id_key": "edge_id", "list_key": "edges"},
    "negative_obligations": {"path": NEG_OBLIGATIONS, "id_key": "obligation_id",
                             "list_key": "obligations"},
    "security_lineage": {"path": SECURITY_LINEAGE, "id_key": "observation_id",
                         "list_key": "observations"},
    "support_status": {"path": SUPPORT_STATUS, "id_key": "subject_id", "list_key": "records"},
}

# The verdict vocabulary, and the projection of each plane's own reading onto it. A cell's
# verdict is the join of its readings, never a typed value and never a boolean.
MATRIX_VERDICTS: tuple[str, ...] = ("PASS", "FAIL", "UNKNOWN", "NOT_MEASURED")
VIEW_STATUS_TO_VERDICT: dict[str, str] = {
    "compatible": "PASS",
    "incompatible": "FAIL",
    "partial": "FAIL",
    "unknown": "UNKNOWN",
    "not_measured": "NOT_MEASURED",
}
OBLIGATION_STATE_TO_VERDICT: dict[str, str] = {
    "satisfied": "PASS",
    "open": "FAIL",
    "unknown": "UNKNOWN",
}
SECURITY_DISPOSITION_TO_VERDICT: dict[str, str] = {
    "never_contained": "PASS",
    "safe_divergence": "PASS",
    "unresolved": "UNKNOWN",
    "preserve_vulnerable_behaviour": "FAIL",
}

# The security lineage joins the candidate-to-reference-authority relation on this dimension: a
# candidate disposition is a statement about the *behaviour* the candidate implements relative to
# a fixed historical behaviour, so the closed vocabulary's `behavioural` dimension is where it
# belongs (docs/PHASE-23-MULTITRACK-SUBPHASES.md section 3.7).
SECURITY_DIMENSION = "behavioural"

NON_CLAIMS: list[str] = [
    "a matrix cell is a directional, dimension-specific join of the committed planes, not a "
    "one-boolean compatibility claim about a release",
    "a cell references its source records rather than restating them, so the matrix cannot drift "
    "from the planes it joins",
    "a cell with no committed reading is NOT_MEASURED with its reason, never PASS by default",
    "one platform/profile is not every platform/profile: a cell is bounded to the authorities and "
    "releases it names",
    "upstream's ABI promise is not candidate evidence",
    "OpenSSL compatibility is not FIPS validation (docs/FIPS_CLAIMS.md)",
]


def _load(path: Path) -> dict:
    """Read a committed artefact, failing closed when it is absent."""
    if not path.is_file():
        raise SystemExit(
            f"compat_matrix: {rel(path)} is absent, so the matrix cannot be assembled; the read "
            f"is fail-closed rather than a fabricated cell"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _plane_records() -> dict[str, list[dict]]:
    """Every plane's record list, keyed by plane name."""
    return {name: _body(_load(spec["path"])).get(spec["list_key"]) or []
            for name, spec in PLANES.items()}


def _release_of(endpoint: str, auth_to_release: dict[str, str]) -> str | None:
    """The catalogue release an endpoint names, or `None` for the candidate itself.

    An authority resolves through the authority-node registry; a bare release id (a release the
    obligation plane scopes an obligation to) is its own release; the candidate is the crate, not
    a release, and has no ladder row.
    """
    if endpoint == CANDIDATE:
        return None
    if endpoint in auth_to_release:
        return auth_to_release[endpoint]
    if endpoint.startswith("openssl-"):
        return endpoint
    return None


def _relations(edges_body: dict, views_body: dict, obligations_body: dict,
               auth_to_release: dict[str, str]) -> list[dict]:
    """Every directed relation the planes establish, `subject -> reference`, deduplicated.

    The relations are read, never typed: the edge plane's declared pair-directions, the view
    plane's candidate-to-authority relations and the obligation plane's authority/release scopes.
    A relation is the matrix's row axis; the dimensions are its columns.
    """
    rels: dict[tuple[str, str, str], dict] = {}

    def add(subject: str, reference: str, direction: str, pair_id: str, kind: str,
            established_by: str) -> None:
        key = (subject, reference, direction)
        if key in rels:
            if established_by not in rels[key]["established_by"]:
                rels[key]["established_by"].append(established_by)
            return
        rels[key] = {
            "relation_id": f"{pair_id}/{direction}",
            "pair_id": pair_id,
            "subject_id": subject,
            "reference_id": reference,
            "subject_release": _release_of(subject, auth_to_release),
            "reference_release": _release_of(reference, auth_to_release),
            "direction": direction,
            "kind": kind,
            "established_by": [established_by],
        }

    for d in edges_body.get("directions") or []:
        add(d["from_id"], d["to_id"], d["direction"], str(d.get("pair_id")),
            str(d.get("source") or "edge"), "compatibility_edges")
    for v in views_body.get("views") or []:
        add(v["subject_id"], v["reference_id"], v["direction"],
            f"candidate-vs-{v['reference_id']}", "candidate_view", "compatibility_views")
    for o in obligations_body.get("obligations") or []:
        scope = o.get("scope") or {}
        ref = scope.get("authority_id") or scope.get("release_id")
        if ref:
            add(CANDIDATE, ref, "candidate_to_reference", f"candidate-vs-{ref}",
                "obligation", "negative_obligations")

    return sorted(rels.values(), key=lambda r: r["relation_id"])


def _scope_matches(obligation: dict, reference_id: str) -> bool:
    """Whether an obligation is scoped to the relation's reference side."""
    scope = obligation.get("scope") or {}
    return scope.get("authority_id") == reference_id or scope.get("release_id") == reference_id


def _source(plane: str, record_id: str, role: str, reading: str | None,
            **extra: object) -> dict:
    """One source reference: the plane and record it names, and the reading taken from it."""
    entry: dict = {"plane": plane, "record_id": record_id, "role": role}
    if reading is not None:
        entry["reading"] = reading
    entry.update(extra)
    return entry


def _readings(relation: dict, dimension: str, planes: dict[str, list[dict]]) -> list[dict]:
    """Every compatibility reading the five planes carry for a relation and dimension.

    A reading names its source record and the value the join took from it. The record itself is
    not copied: the court re-reads it from the plane and re-derives the value.
    """
    readings: list[dict] = []
    subject, reference, direction = (relation["subject_id"], relation["reference_id"],
                                     relation["direction"])

    for e in planes["compatibility_edges"]:
        if (e.get("from_id") == subject and e.get("to_id") == reference
                and e.get("direction") == direction and e.get("dimension") == dimension):
            readings.append(_source("compatibility_edges", e["edge_id"], "reading",
                                    e.get("verdict"), facet=e.get("facet")))

    if direction == "candidate_to_reference" and subject == CANDIDATE:
        for v in planes["compatibility_views"]:
            if (v.get("subject_id") == subject and v.get("reference_id") == reference
                    and v.get("dimension") == dimension):
                verdict = VIEW_STATUS_TO_VERDICT.get(str(v.get("status")))
                if verdict is not None:
                    readings.append(_source("compatibility_views", v["view_id"], "reading",
                                            verdict, facet=v.get("facet")))

    for o in planes["negative_obligations"]:
        if _scope_matches(o, reference) and o.get("dimension") == dimension:
            verdict = OBLIGATION_STATE_TO_VERDICT.get(str(o.get("state")))
            if verdict is not None:
                readings.append(_source("negative_obligations", o["obligation_id"], "reading",
                                        verdict, obligation_kind=o.get("kind")))

    if dimension == SECURITY_DIMENSION \
            and {subject, reference} == {CANDIDATE, REFERENCE_AUTHORITY}:
        for s in planes["security_lineage"]:
            verdict = SECURITY_DISPOSITION_TO_VERDICT.get(str(s.get("candidate_disposition")))
            if verdict is not None:
                readings.append(_source("security_lineage", s["observation_id"], "reading",
                                        verdict, vulnerability_id=s.get("reference")))

    return readings


def _context(relation: dict, planes: dict[str, list[dict]]) -> list[dict]:
    """The support-status rows of the relation's release endpoints, joined as context.

    Support status is a release/authority state, not a compatibility reading: it bounds the cell
    to the state the ladder records, and never turns an unmeasured reading into a pass.
    """
    rows = {r.get("subject_id"): r for r in planes["support_status"]}
    context: list[dict] = []
    for role, release in (("subject", relation["subject_release"]),
                          ("reference", relation["reference_release"])):
        row = rows.get(release) if release else None
        if row is not None:
            context.append(_source("support_status", release, "context", None, endpoint=role,
                                   status=row.get("status"),
                                   support_role=row.get("support_role")))
    return context


def _verdict(readings: list[dict]) -> str:
    """The join of the readings, never a boolean.

    A cell passes only when every reading passes; any failing reading fails the cell; anything
    unmeasured or unknown leaves the cell `UNKNOWN`, and a cell with no reading at all is
    `NOT_MEASURED`. There is deliberately no path from "some readings passed" to `PASS`.
    """
    if not readings:
        return "NOT_MEASURED"
    values = {str(r.get("reading")) for r in readings}
    if "FAIL" in values:
        return "FAIL"
    if values == {"PASS"}:
        return "PASS"
    if "UNKNOWN" in values or "PASS" in values:
        return "UNKNOWN"
    return "NOT_MEASURED"


def _reason(relation: dict, dimension: str, readings: list[dict], verdict: str) -> str | None:
    """The reason a non-passing cell does not pass, naming the plane(s) responsible."""
    if verdict == "PASS":
        return None
    where = f"{relation['subject_id']} -> {relation['reference_id']} ({relation['direction']})"
    if not readings:
        return (f"no committed view, edge, obligation or security record establishes a "
                f"{dimension} reading for {where}, so the cell is not measured rather than "
                f"passed by default")
    planes = sorted({str(r.get("plane")) for r in readings})
    if verdict == "FAIL":
        failing = sorted({f"{r.get('plane')}:{r.get('record_id')}" for r in readings
                          if r.get("reading") == "FAIL"})
        return (f"the {dimension} reading for {where} has a failing reading "
                f"({', '.join(failing)}), so the cell fails")
    unmeasured = sorted({str(r.get("plane")) for r in readings
                         if r.get("reading") in ("UNKNOWN", "NOT_MEASURED")})
    if verdict == "UNKNOWN":
        return (f"the {dimension} reading for {where} joins {len(readings)} record(s) over "
                f"{planes} with no failure but at least one unmeasured or unknown "
                f"({unmeasured}), so the cell is not promoted to PASS")
    return (f"the {dimension} reading for {where} joins only not-measured record(s) over "
            f"{planes}, so the cell is not measured")


def _cells(relations: list[dict], planes: dict[str, list[dict]]) -> list[dict]:
    """Every `(relation, dimension)` cell, derived from the planes."""
    cells: list[dict] = []
    for relation in relations:
        for dimension in multitrack_schemas.COMPAT_DIMENSIONS:
            readings = _readings(relation, dimension, planes)
            context = _context(relation, planes)
            verdict = _verdict(readings)
            cell = {
                "cell_id": f"CM/{relation['relation_id']}/{dimension}",
                "relation_id": relation["relation_id"],
                "pair_id": relation["pair_id"],
                "subject_id": relation["subject_id"],
                "reference_id": relation["reference_id"],
                "subject_release": relation["subject_release"],
                "reference_release": relation["reference_release"],
                "direction": relation["direction"],
                "dimension": dimension,
                "verdict": verdict,
                "sources": readings + context,
                "non_claims": list(NON_CLAIMS),
            }
            if verdict != "PASS":
                cell["reason"] = _reason(relation, dimension, readings, verdict)
            cells.append(cell)
    return cells


def _plane_block(planes: dict[str, list[dict]]) -> list[dict]:
    """The content-addressed plane block every cell cites, computed once."""
    block: list[dict] = []
    for name in sorted(PLANES):
        spec = PLANES[name]
        block.append({
            "name": name,
            "path": rel(spec["path"]),
            "sha256": sha256_file(spec["path"]),
            "id_key": spec["id_key"],
            "record_count": len(planes[name]),
        })
    return block


def body_hash(cells: list[dict]) -> str:
    """The matrix body's content hash, a function of its committed cells."""
    return content_hash({"rows": cells})


def derive_body() -> dict:
    """The compatibility-matrix body, a pure function of the five committed planes.

    Deterministic: every list is sorted, no wall-clock/environment value is read, and every
    source is a reference (plane + record id) rather than a copy. The court re-derives this body
    through the same code, re-reads every source record, and refuses a cell that does not
    reproduce or that contradicts the plane it joins.
    """
    edges_body = _body(_load(COMPAT_EDGES))
    views_body = _body(_load(COMPAT_VIEWS))
    obligations_body = _body(_load(NEG_OBLIGATIONS))
    auth_to_release = {n["authority_id"]: n["release_id"]
                       for n in _body(_load(AUTHORITY_NODES)).get("nodes") or []}

    planes = _plane_records()
    relations = _relations(edges_body, views_body, obligations_body, auth_to_release)
    cells = _cells(relations, planes)

    by_verdict: dict[str, int] = {}
    by_dimension: dict[str, int] = {}
    by_relation: dict[str, int] = {}
    for cell in cells:
        by_verdict[cell["verdict"]] = by_verdict.get(cell["verdict"], 0) + 1
        by_dimension[cell["dimension"]] = by_dimension.get(cell["dimension"], 0) + 1
        by_relation[cell["relation_id"]] = by_relation.get(cell["relation_id"], 0) + 1

    joined = sorted({str(s["plane"]) for cell in cells for s in cell["sources"]})
    return {
        "matrix_id": "CM-phase23-multitrack-assembled",
        "generated_from": [rel(PLANES[name]["path"]) for name in sorted(PLANES)],
        "rule": (
            "one cell per directed lineage relation and dimension, joining the five multitrack "
            "evidence planes -- the compatibility views, the directional compatibility edges, the "
            "negative and positive obligations, the security lineage and the support-status ladder "
            "-- over the release lineage. A cell is directional and dimension-specific with a "
            "PASS/FAIL/UNKNOWN/NOT_MEASURED verdict that is the join of the readings it references; "
            "a cell with no committed reading is NOT_MEASURED with its reason, never PASS by "
            "default, and no cell is a single boolean. Every cell references the source records it "
            "joins (plane + record id) rather than restating them, so the matrix cannot drift from "
            "its inputs"
        ),
        "scope": (
            "the relations are the edge plane's declared pair-directions, the view plane's "
            "candidate-to-authority relations and the obligation plane's authority/release scopes; "
            "the columns are the schema's closed COMPAT_DIMENSIONS. The matrix is O(relations x "
            "dimensions) -- it joins over the lineage edges and the planes that exist -- and is "
            "never the pairwise product of releases"
        ),
        "subject_id": CANDIDATE,
        "verdicts": list(MATRIX_VERDICTS),
        "verdict_projection": {
            "views": dict(VIEW_STATUS_TO_VERDICT),
            "obligations": dict(OBLIGATION_STATE_TO_VERDICT),
            "security": dict(SECURITY_DISPOSITION_TO_VERDICT),
        },
        "security_dimension": SECURITY_DIMENSION,
        "planes": _plane_block(planes),
        "relations": [
            {k: relation[k] for k in ("relation_id", "pair_id", "subject_id", "reference_id",
                                      "subject_release", "reference_release", "direction", "kind",
                                      "established_by")}
            for relation in relations
        ],
        "counts": {
            "cells": len(cells),
            "relations": len(relations),
            "dimensions": len(multitrack_schemas.COMPAT_DIMENSIONS),
            "by_verdict": {k: by_verdict[k] for k in sorted(by_verdict)},
            "by_dimension": {k: by_dimension[k] for k in sorted(by_dimension)},
            "by_relation": {k: by_relation[k] for k in sorted(by_relation)},
            "planes_joined": len(joined),
        },
        "rows": cells,
        "sources_joined": joined,
        "content_hash": body_hash(cells),
        "non_claims": list(NON_CLAIMS),
        "boundary": (
            "the matrix is the assembled substrate, not a strengthened claim: a PASS cell means "
            "every committed reading that joins it passes, a FAIL cell means a joined reading "
            "fails, and an UNKNOWN or NOT_MEASURED cell is honestly unresolved. The candidate's "
            "relation to each authority is joined where the planes name it; the 3.6.3 <-> 3.6.4 "
            "pair is joined in both directions from the committed edge delta. The security lineage "
            "joins the candidate-to-reference-authority relation on the behavioural dimension, so "
            "a cell can never re-adopt a fixed behaviour. A dimension a relation has no evidence "
            "for is NOT_MEASURED with its reason"
        ),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    body = derive_body()

    problems = multitrack_schemas.validate_compatibility_matrix(body)
    if problems:
        raise SystemExit(f"compat_matrix: the derived matrix is not schema-valid: {problems}")

    inputs = [
        InputRef(name="compatibility-views", path=COMPAT_VIEWS),
        InputRef(name="compatibility-edges", path=COMPAT_EDGES),
        InputRef(name="negative-obligations", path=NEG_OBLIGATIONS),
        InputRef(name="security-lineage", path=SECURITY_LINEAGE),
        InputRef(name="support-status", path=SUPPORT_STATUS),
        InputRef(name="authority-nodes", path=AUTHORITY_NODES),
    ]
    doc = envelope(kind="compatibility-matrix", authority=auth.id, inputs=inputs, body=body,
                   generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[compat-matrix] {c['cells']} cell(s) over {c['relations']} relation(s) x "
          f"{c['dimensions']} dimension(s); verdicts={c['by_verdict']}; "
          f"{c['planes_joined']} plane(s) joined")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
