#!/usr/bin/env python3
"""Freeze b58: re-bind the B53-B57 scoped discharges to content-addressed identity.

Why this file exists
--------------------
CAMPAIGN-STATUS.json#/scoped_boundary_discharges records the B53-B57 scoped
discharges, but it keys each one by a *coordinate* (``src/x509/v3_crld.rs:1333``
and similar).  ``consumer_closure.py`` joins a scoped discharge to a boundary
receipt by ``boundary["id"]``, so none of the B53-B57 rows can ever bind: the
B53 ids are ``B53-ADRS-001`` and B54-B57 carry their entries under ``rows``
(a key ``load_boundaries`` does not read) with ``V1:...`` ids.

This generator does not re-adjudicate anything and changes no verdict.  It reads

  * the ledger row (the verdict authority) from CAMPAIGN-STATUS.json,
  * the recorded row (file/kind/operation/verdict) from the B53-B57 receipts,
  * the content of the operation from the frozen S blob (git commit, never the
    worktree),

and emits one additive site-enumerating receipt whose boundary id is the
ledger's own join key and whose acceptance evidence is the **content hash** of
the operation span at S.  The coordinate is an alias for the ledger row; it is
never the acceptance predicate (``consumer_closure.py`` additionally requires
identity + recorded span hash + a discharging disposition).

Rows are grouped by file, kind and operation so each rebind is a single site.
Every source value is recorded per site so a reviewer can replay it without
reconstructing our reasoning.

Output: forensics/memory-safety/campaign/safe-c33/atlas-refresh/
        r13-coordinate-rebind-sites.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path("/work")
PLANE = REPO / "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json"
BOUNDARY_DIR = (REPO / "forensics/memory-safety/campaign/safe-c33/"
                "atlas-refresh")
CENSUS = REPO / "court/freeze-b58/census-b58.json"
OUT = BOUNDARY_DIR / "r13-coordinate-rebind-sites.json"
RECEIPTS = tuple(f"boundary-sweep-B{n}" for n in (53, 54, 55, 56, 57))

sys.path.insert(0, str(REPO / "forensics/tools"))
import consumer_closure as cc  # noqa: E402  (same span resolver the closure uses)

DISCHARGING_VERDICTS = ("SAFETY_DISCHARGED", "DISPATCH_DISCHARGED")
SINGLE_ITEM = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Which receipt coordinate the ledger row was recorded from.  This is a fact
# about the ledger entry, not a choice: B53/B54 recorded the V1 census `line`
# (B54's ``src/ct/ct_x509v3.rs:70`` is row 70's `line`; the sibling at `line`
# 59 has `line_current` 70), while B55/B56/B57 recorded `line_current`
# (B56's ``src/cms/cms_asn1.rs:534`` is the V1 row 523's `line_current`).
COORD_FIELD = {
    "boundary-sweep-B53": "line",
    "boundary-sweep-B54": "line",
    "boundary-sweep-B55": "line_current",
    "boundary-sweep-B56": "line_current",
    "boundary-sweep-B57": "line_current",
}


def sweep_rows(receipt: str) -> list[dict]:
    doc = json.loads((BOUNDARY_DIR / f"{receipt}.json").read_text())
    rows = []
    for key in ("boundaries", "rows"):
        for b in doc.get(key) or []:
            rows.append((key, b))
    return rows


def kind_of(source_key: str, row: dict) -> str | None:
    if row.get("kind"):
        return row["kind"]
    ident = str(row.get("id") or "")
    suffix = ident.rsplit(":", 1)[-1]
    return suffix or None


def main() -> int:
    census = json.loads(CENSUS.read_text())
    source_commit = (census.get("identity") or {}).get("source_head")
    if not source_commit:
        print("[r13-rebind] no census identity.source_head; refusing", file=sys.stderr)
        return 2

    plane_rows = [r for r in json.loads(PLANE.read_text())
                  .get("scoped_boundary_discharges") or []
                  if r.get("receipt") in RECEIPTS]
    if not plane_rows:
        print("[r13-rebind] no B53-B57 scoped rows in the ledger; refusing",
              file=sys.stderr)
        return 2

    boundaries, unresolved = [], []
    for plane in sorted(plane_rows, key=lambda r: r.get("receipt") or ""):
        receipt = plane["receipt"]
        state = str(plane.get("state") or "")
        if not cc.boundary_disposition_is_discharge(state):
            # The ledger row does not assert a scoped discharge; it is not ours
            # to promote.  Record and skip.
            for coord in plane.get("discharged_boundaries") or []:
                unresolved.append({"ledger_receipt": receipt, "coordinate": coord,
                                   "reason": "ledger-row-state-is-not-a-discharge",
                                   "state": state})
            continue
        rows = sweep_rows(receipt)
        coord_field = COORD_FIELD[receipt]
        for coord in sorted(plane.get("discharged_boundaries") or []):
            file, _, line_text = coord.rpartition(":")
            if not file or not line_text.isdigit():
                unresolved.append({"ledger_receipt": receipt, "coordinate": coord,
                                   "reason": "coordinate-is-not-file:line"})
                continue
            line = int(line_text)
            hits = [(key, row) for key, row in rows
                    if row.get("file") == file and row.get(coord_field) == line]
            if len(hits) != 1:
                unresolved.append({
                    "ledger_receipt": receipt, "coordinate": coord,
                    "reason": f"coordinate-resolves-to-{len(hits)}-receipt-rows",
                    "coordinate_field": coord_field,
                    "rows": [r.get("id") for _k, r in hits]})
                continue
            key, row = hits[0]
            operation = row.get("operation")
            if not operation or not SINGLE_ITEM.fullmatch(str(operation)):
                unresolved.append({
                    "ledger_receipt": receipt, "coordinate": coord,
                    "source_row": row.get("id"),
                    "reason": "operation-is-not-a-single-item-identifier",
                    "operation": operation,
                    "note": ("a profile annotation is not an item identity; the "
                             "item it names has more than one definition, so no "
                             "one span can carry the binding")})
                continue
            kind = kind_of(key, row)
            recorded = str(row.get("verdict") or row.get("disposition") or "")
            if not recorded.startswith(DISCHARGING_VERDICTS):
                unresolved.append({
                    "ledger_receipt": receipt, "coordinate": coord,
                    "source_row": row.get("id"),
                    "reason": "recorded-row-verdict-is-not-a-discharge",
                    "recorded_verdict": recorded})
                continue
            try:
                span = cc.resolve_operation_span(
                    REPO, file, operation, operation,
                    locators=(row.get("line"), row.get("line_current"),
                              row.get("current_line")),
                    source_commit=source_commit)
            except cc.SpanResolutionError as exc:
                unresolved.append({
                    "ledger_receipt": receipt, "coordinate": coord,
                    "source_row": row.get("id"), "operation": operation,
                    "reason": "span-refused:" + exc.classification,
                    "detail": exc.detail})
                continue
            recorded_span = row.get("span_sha256")
            if recorded_span and recorded_span != span["sha256"]:
                unresolved.append({
                    "ledger_receipt": receipt, "coordinate": coord,
                    "source_row": row.get("id"), "operation": operation,
                    "reason": "recorded-span-hash-does-not-match-S",
                    "recorded": recorded_span, "at_S": span["sha256"]})
                continue
            boundaries.append({
                # The ledger's join key.  It is only an alias: acceptance below
                # is the span hash, not this coordinate.
                "id": coord,
                "file": file,
                "line": line,
                "kind": kind,
                "operation": operation,
                "mechanism": (row.get("mechanism")
                              or (plane.get("mechanism") if isinstance(
                                  plane.get("mechanism"), str) else None)),
                "disposition": (
                    "SAFETY_DISCHARGED (scoped to this site by ledger row "
                    f"{receipt}; recorded row verdict {recorded}; the binding is "
                    "the content hash of the operation span at S, not the "
                    f"ledger coordinate)"),
                "recorded_verdict": recorded,
                "ledger_receipt": receipt,
                "ledger_coordinate": coord,
                "source_receipt": receipt,
                "source_row_id": row.get("id"),
                "source_row_key": key,
                "source_row_coordinates": {
                    "line": row.get("line"),
                    "line_current": row.get("line_current"),
                    "current_line": row.get("current_line")},
                "span_sha256": span["sha256"],
                "span_schema": cc.SPAN_HASH_SCHEMA,
                "span_normalisation": cc.SPAN_NORMALISATION,
                "span_claim_scope": cc.SPAN_CLAIM_SCOPE,
                "span_start_line": span["start_line"],
                "span_end_line": span["end_line"],
                "span_qualified_identity": span["qualified_identity"],
                "span_resolution": span["resolution"],
                "span_source_commit": source_commit,
                "span_source_field": coord_field,
            })

    boundaries.sort(key=lambda b: (b["file"], b["line"], b["operation"] or ""))
    doc = {
        "schema": "openssl-rs/campaign/safe-c33/boundary-receipt/v1",
        "kind": cc.SITE_RECEIPT_KIND,
        "receipt": "r13-coordinate-rebind",
        "date": "2026-11-11",
        "campaign": "safe-c33",
        "subphase": "b58-rebind",
        "scope": (
            "the B53/B54/B55/B56/B57 scoped discharges already recorded in "
            "CAMPAIGN-STATUS.json#/scoped_boundary_discharges, re-bound to the "
            "content-addressed operation span at S = " + source_commit[:9]),
        "source": {
            "ledger": "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json"
                      "#/scoped_boundary_discharges",
            "receipts": [f"atlas-refresh/{r}.json" for r in RECEIPTS],
            "span_source": "git blob at census identity.source_head (never the worktree)",
            "source_commit": source_commit,
            "span_schema": cc.SPAN_HASH_SCHEMA,
            "span_normalisation": cc.SPAN_NORMALISATION,
        },
        "rebind_rule": (
            "for each ledger row of the five receipts: locate the single receipt "
            "row whose file and recorded coordinate (line, line_current or "
            "current_line) equal the ledger coordinate; take its operation and "
            "kind (kind also read from the V1 id when the row omits it); resolve "
            "the operation's brace-matched span from the S git blob; require the "
            "row's recorded span hash, when present, to equal it; emit one "
            "boundary whose id is the ledger join key and whose disposition "
            "transcribes the ledger row's SAFETY_DISCHARGED state and the row's "
            "own recorded verdict. No verdict is created, widened or withdrawn."),
        "counts": {
            "ledger_rows": sum(len(r.get("discharged_boundaries") or [])
                               for r in plane_rows),
            "rebound": len(boundaries),
            "unresolved": len(unresolved),
            "by_source_receipt": {
                r: sum(1 for b in boundaries if b["source_receipt"] == r)
                for r in RECEIPTS},
        },
        "boundaries": boundaries,
        "unresolved": unresolved,
        "non_claims": [
            "This receipt supplies a coordinate binding, not a new adjudication. "
            "It neither promotes nor withdraws any verdict.",
            "A boundary id is the ledger's join key; the acceptance predicate is "
            "the operation span's content hash at S plus the closure's identity "
            "and disposition checks.",
            "It does not discharge a site whose ledger row is absent, nor one "
            "whose recorded row verdict is not a discharge.",
            "It does not touch the 14 sslconf-exclusivity ledger coordinates, "
            "which name no receipt in this directory and are outside the "
            "B53-B57 scope.",
        ],
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"[r13-rebind] wrote {OUT.relative_to(REPO)}: "
          f"rebound={len(boundaries)} unresolved={len(unresolved)} "
          f"by_receipt={doc['counts']['by_source_receipt']}")
    for u in unresolved:
        print(f"[r13-rebind] unresolved {u}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
