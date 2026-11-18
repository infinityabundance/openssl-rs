#!/usr/bin/env python3
"""B59: supply the missing receipt for the 14 SSL_CONF/cipher/serverinfo sites.

Why this file exists
--------------------
CAMPAIGN-STATUS.json#/scoped_boundary_discharges carries the
``sslconf-exclusivity-2026-11-10`` adjudication, but it keys the discharge by a
*coordinate* (``ssl_conf.rs:434`` and similar).  ``consumer_closure.py`` joins a
scoped discharge to a boundary receipt by ``boundary["id"]``, so the row could
never bind: no receipt in ``atlas-refresh/`` carries those ids.

This generator transcribes the existing adjudication -- it does not create,
widen or withdraw a verdict.  It reads

  * the ledger row (the verdict authority) from CAMPAIGN-STATUS.json,
  * the recorded boundary (file/kind/operation/line_current) from the B46 and
    B47 sweep receipts, whose ``line_current`` is exactly the ledger coordinate,
  * the operation content from the frozen S blob (git commit, never the
    worktree),

and emits one boundary per ledger coordinate whose id is the ledger's join key
and whose acceptance evidence is the **content hash** of the operation span at
S.  The coordinate is an alias for the ledger row; it is never the acceptance
predicate (``consumer_closure.py`` additionally requires identity + recorded
span hash + a discharging disposition).

Two files are written:

  * ``sslconf-exclusivity-2026-11-10.json`` -- the receipt named by the ledger
    row, carrying the adjudication transcription and the per-site evidence;
  * ``sslconf-exclusivity-2026-11-10-sites.json`` -- the loader-visible
    projection.  ``consumer_closure.load_boundaries`` admits exactly two
    receipt families: ``boundary-sweep-B*.json`` and ``*-sites.json`` declaring
    :data:`consumer_closure.SITE_RECEIPT_KIND`.  The suffix is therefore not a
    choice; the projection exists so the mechanism that already exists can read
    the evidence.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path("/work")
PLANE = REPO / "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json"
BOUNDARY_DIR = (REPO / "forensics/memory-safety/campaign/safe-c33"
                / "atlas-refresh")
CENSUS = REPO / "court/freeze-b58/census-b58.json"
RECEIPT_ID = "sslconf-exclusivity-2026-11-10"
OUT_DETAIL = BOUNDARY_DIR / f"{RECEIPT_ID}.json"
OUT_SITES = BOUNDARY_DIR / f"{RECEIPT_ID}-sites.json"

# The controls the adjudication names.  Transcribed, not re-authored.
CONTROLS = [
    "a_reentrant_dispatch_is_refused_and_leaves_the_context_usable",
    "a_concurrent_entry_from_another_thread_is_refused",
    "every_entry_point_refuses_an_overlap_and_works_when_idle",
]
SOURCE_RECEIPTS = ("boundary-sweep-B46", "boundary-sweep-B47")

sys.path.insert(0, str(REPO / "forensics/tools"))
import consumer_closure as cc  # noqa: E402  (the same span resolver the closure uses)


def recorded_boundaries() -> dict[tuple[str, int], dict]:
    """(basename, line_current) -> B46/B47 boundary record.

    The ledger row keys a site by ``ssl_conf.rs:434`` -- the file's base name,
    not its repository path.  The B46/B47 rows carry the repository path, so the
    join is on (basename, line_current); the full path is taken from the row
    itself and a basename that resolves to more than one path is refused rather
    than guessed.
    """
    out: dict[tuple[str, int], dict] = {}
    ambiguous: set[tuple[str, int]] = set()
    for receipt in SOURCE_RECEIPTS:
        doc = json.loads((BOUNDARY_DIR / f"{receipt}.json").read_text())
        for b in doc.get("boundaries") or []:
            line_current = b.get("line_current")
            file = b.get("file")
            if not isinstance(line_current, int) or not file:
                continue
            key = (file.rsplit("/", 1)[-1], line_current)
            if key in out and out[key].get("file") != file:
                ambiguous.add(key)
            out.setdefault(key, dict(b, receipt=receipt))
    for key in ambiguous:
        out.pop(key, None)
    return out


def main() -> int:
    census = json.loads(CENSUS.read_text())
    source_commit = (census.get("identity") or {}).get("source_head")
    if not source_commit:
        print("[b59] no census identity.source_head; refusing", file=sys.stderr)
        return 2

    plane = next((r for r in json.loads(PLANE.read_text())
                  .get("scoped_boundary_discharges") or []
                  if r.get("receipt") == RECEIPT_ID), None)
    if plane is None:
        print(f"[b59] ledger row {RECEIPT_ID!r} not found; refusing",
              file=sys.stderr)
        return 2
    if not cc.boundary_disposition_is_discharge(plane.get("state")):
        print("[b59] ledger row does not assert a scoped discharge; refusing",
              file=sys.stderr)
        return 2

    recorded = recorded_boundaries()
    coords = sorted(plane.get("discharged_boundaries") or [],
                    key=lambda c: (c.rsplit(":", 1)[0],
                                   int(c.rsplit(":", 1)[1])))
    boundaries, unresolved = [], []
    for coord in coords:
        basename, _, line_text = coord.rpartition(":")
        if not basename or not line_text.isdigit():
            unresolved.append({"coordinate": coord,
                               "reason": "coordinate-is-not-file:line"})
            continue
        line = int(line_text)
        row = recorded.get((basename, line))
        if row is None:
            unresolved.append({"coordinate": coord,
                               "reason": "no B46/B47 boundary at this coordinate"})
            continue
        file = row.get("file")
        operation = row.get("operation")
        kind = row.get("kind")
        if row.get("receipt") not in SOURCE_RECEIPTS:
            unresolved.append({"coordinate": coord,
                               "reason": "source receipt not in scope",
                               "receipt": row.get("receipt")})
            continue
        try:
            span = cc.resolve_operation_span(
                REPO, file, operation, operation,
                locators=(line, row.get("line")), source_commit=source_commit)
        except cc.SpanResolutionError as exc:
            unresolved.append({"coordinate": coord, "operation": operation,
                               "reason": "span-refused:" + exc.classification,
                               "detail": exc.detail})
            continue
        recorded_span = row.get("span_sha256")
        if recorded_span and recorded_span != span["sha256"]:
            unresolved.append({"coordinate": coord, "operation": operation,
                               "reason": "recorded-span-hash-does-not-match-S",
                               "recorded": recorded_span,
                               "at_S": span["sha256"]})
            continue
        boundaries.append({
            # The ledger's join key.  It is only an alias: acceptance below is
            # the span hash, not this coordinate.
            "id": coord,
            "file": file,
            "line": line,
            "kind": kind,
            "operation": operation,
            "mechanism": row.get("mechanism"),
            "disposition": (
                "SAFETY_DISCHARGED (scoped to this site by ledger row "
                f"{RECEIPT_ID}; adjudicated DISCHARGE 14/14; recorded boundary "
                f"{row.get('id')} of {row.get('receipt')}; the binding is the "
                "content hash of the operation span at S, not the ledger "
                "coordinate)"),
            "recorded_verdict": "SAFETY_DISCHARGED",
            "ledger_receipt": RECEIPT_ID,
            "ledger_coordinate": coord,
            "source_receipt": row.get("receipt"),
            "source_boundary_id": row.get("id"),
            "source_boundary_line_current": line,
            "controls": CONTROLS,
            "span_sha256": span["sha256"],
            "span_schema": cc.SPAN_HASH_SCHEMA,
            "span_normalisation": cc.SPAN_NORMALISATION,
            "span_claim_scope": cc.SPAN_CLAIM_SCOPE,
            "span_start_line": span["start_line"],
            "span_end_line": span["end_line"],
            "span_qualified_identity": span["qualified_identity"],
            "span_resolution": span["resolution"],
            "span_source_commit": source_commit,
            "span_source_field": "line_current",
        })

    if unresolved:
        print("[b59] refusing: unresolved ledger coordinates", file=sys.stderr)
        for u in unresolved:
            print("  ", u, file=sys.stderr)
        return 3

    boundaries.sort(key=lambda b: (b["file"], b["line"]))
    adjudication = plane.get("adjudication") or {}
    common = {
        "schema": "openssl-rs/campaign/safe-c33/boundary-receipt/v1",
        "receipt": RECEIPT_ID,
        "date": "2026-11-10",
        "transcribed": "2026-11-12",
        "campaign": "safe-c33",
        "subphase": "b59-close18",
        "candidate": source_commit,
        "source": {
            "ledger": ("forensics/memory-safety/campaign/safe-c33/"
                       "CAMPAIGN-STATUS.json#/scoped_boundary_discharges"
                       f"[receipt={RECEIPT_ID}]"),
            "receipts": [f"atlas-refresh/{r}.json" for r in SOURCE_RECEIPTS],
            "span_source": ("git blob at census identity.source_head "
                            "(never the worktree)"),
            "source_commit": source_commit,
            "span_schema": cc.SPAN_HASH_SCHEMA,
            "span_normalisation": cc.SPAN_NORMALISATION,
        },
        "adjudication": {
            "verdict": adjudication.get("verdict"),
            "reviewer": adjudication.get("reviewer"),
            "control": adjudication.get("control"),
            "controls": CONTROLS,
            "evidence": adjudication.get("evidence"),
            "hidden_obligations": plane.get("hidden_obligations"),
            "retained_state": plane.get("retained_state"),
            "note": plane.get("note"),
            "transcription_rule": (
                "verbatim transcription of the ledger row's adjudication; this "
                "receipt supplies the missing boundary-id join and the "
                "content-addressed span, it does not re-adjudicate"),
        },
        "scope": plane.get("scope"),
        "state": plane.get("state"),
        "boundaries": boundaries,
        "unresolved": [],
        "non_claims": [
            ("This receipt supplies a coordinate-bound boundary id and a "
             "content hash; it creates, widens and withdraws no verdict."),
            ("The hidden obligation the adjudication retains (a second "
             "concurrent free, and an entry point racing the release, remain "
             "external serialisation) is recorded here unchanged and is not "
             "claimed discharged."),
            ("A boundary id is the ledger's join key; the acceptance predicate "
             "is the operation span's content hash at S plus the closure's "
             "identity and disposition checks."),
        ],
    }

    detail = dict(common)
    detail["kind"] = "adjudication-transcription"
    detail["loader_visibility"] = {
        "loaded_by_consumer_closure": False,
        "reason": ("load_boundaries admits boundary-sweep-B*.json and "
                   "*-sites.json only; this file is the named receipt the "
                   "ledger row cites"),
        "loader_projection": f"atlas-refresh/{OUT_SITES.name}",
    }
    OUT_DETAIL.write_text(json.dumps(detail, indent=1) + "\n")

    sites = dict(common)
    sites["kind"] = cc.SITE_RECEIPT_KIND
    sites["detail_receipt"] = f"atlas-refresh/{OUT_DETAIL.name}"
    sites["loader_visibility"] = {
        "loaded_by_consumer_closure": True,
        "reason": ("the site-enumerating family load_boundaries reads; the "
                   "boundary rows are identical to the detail receipt"),
    }
    OUT_SITES.write_text(json.dumps(sites, indent=1) + "\n")

    print(f"[b59] ledger coordinates: {len(coords)}")
    print(f"[b59] boundaries written: {len(boundaries)}")
    print(f"[b59] detail: {OUT_DETAIL.relative_to(REPO)}")
    print(f"[b59] sites:  {OUT_SITES.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
