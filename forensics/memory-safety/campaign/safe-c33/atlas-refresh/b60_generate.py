#!/usr/bin/env python3
"""B60: bind the two `free_lock` obligations by a declared definition set.

Why this file exists
--------------------
`src/runtime/thread.rs` defines `free_lock` twice, selected by complementary
`#[cfg]` predicates (the sized `CRYPTO_zalloc` representation on the measured
profile, the `Box` representation off it).  `boundary-sweep-B56` adjudicated
both definitions separately and both verdicts are `SAFETY_DISCHARGED`, and the
applied ledger row names both coordinates (`src/runtime/thread.rs:679`,
`:700`).  The closure could still not discharge them:

  * `resolve_operation_span` finds two candidates, neither is inside a named
    container, so the qualified-identity rule cannot choose one and it refuses
    `ambiguous-identity` *before* the recorded hash is compared;
  * `locators` is accepted but unused, and no receipt field declared which
    definition a boundary row was about.

B60 adds exactly that field to the instrument (`declared_spans`) and this
generator transcribes the existing verdict.  It invents no verdict: it reads

  * the applied ledger row (the verdict authority) from CAMPAIGN-STATUS.json,
  * the two per-definition rows and their verdicts from boundary-sweep-B56,
  * both definitions, their cfg predicates and their content hashes from the
    frozen S git blob (never the worktree),

and cross-checks every span against the B59 close-18 evidence before writing.
The rule the instrument applies is:

    an operation is bound when every declared definition span matches the
    current blob AND the set of definitions found matches the declared set

so a receipt that names only one of the two live definitions cannot bind.

Files written
-------------
  * ``b60-free-lock-operations.json`` -- the named receipt (adjudication
    transcription, both declaration spans, per-definition verdicts, controls);
  * ``b60-free-lock-operations-sites.json`` -- the loader-visible projection
    (``load_boundaries`` admits ``boundary-sweep-B*.json`` and
    ``*-sites.json`` only, the same pattern b59 used).

``--controls`` runs the adversarial control instead of writing receipts.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

REPO = Path("/work")
CAMPAIGN = REPO / "forensics/memory-safety/campaign/safe-c33"
PLANE = CAMPAIGN / "CAMPAIGN-STATUS.json"
BOUNDARY_DIR = CAMPAIGN / "atlas-refresh"
CENSUS = REPO / "court/freeze-b58/census-b58.json"
B56 = BOUNDARY_DIR / "boundary-sweep-B56.json"
B59 = BOUNDARY_DIR / "b59-close18.json"
RECEIPT_ID = "b60-free-lock-operations"
OUT_DETAIL = BOUNDARY_DIR / f"{RECEIPT_ID}.json"
OUT_SITES = BOUNDARY_DIR / f"{RECEIPT_ID}-sites.json"

LEDGER_RECEIPT = "boundary-sweep-B56"
FILE = "src/runtime/thread.rs"
ITEM = "free_lock"
KIND = "UNSAFE_FN_DEF"
MECHANISM = "RUNTIME_CONCURRENCY"
LEDGER_IDS = ("src/runtime/thread.rs:679", "src/runtime/thread.rs:700")

sys.path.insert(0, str(REPO / "forensics/tools"))
import consumer_closure as cc  # noqa: E402  (the instrument under change)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def blob_text(commit: str, path: str) -> str:
    text, _sha = cc._git_blob_text(REPO, commit, path)
    return text


def cfg_predicate(text: str, span: dict) -> str:
    """The attribute text immediately above the definition, verbatim at S."""
    lines = text.splitlines()
    header = lines[span["start_line"] - 1:span["def_line"] - 1]
    if not header:
        raise SystemExit(f"[b60] definition at {span['def_line']} has no attribute "
                         "header; refusing")
    predicate = "\n".join(x.rstrip() for x in header)
    if not predicate.lstrip().startswith("#[cfg"):
        raise SystemExit(f"[b60] header above line {span['def_line']} is not a "
                         f"#[cfg] predicate: {predicate!r}")
    return predicate


def load_inputs() -> tuple[str, dict, list[dict]]:
    census = json.loads(CENSUS.read_text())
    source_commit = (census.get("identity") or {}).get("source_head")
    if not source_commit:
        raise SystemExit("[b60] no census identity.source_head; refusing")

    plane_doc = json.loads(PLANE.read_text())
    row = next((r for r in plane_doc.get("scoped_boundary_discharges") or []
                if r.get("receipt") == LEDGER_RECEIPT), None)
    if row is None:
        raise SystemExit(f"[b60] ledger row {LEDGER_RECEIPT!r} not found; refusing")
    if not cc.boundary_disposition_is_discharge(row.get("state")):
        raise SystemExit("[b60] ledger row does not assert a scoped discharge; refusing")
    missing = [i for i in LEDGER_IDS
               if i not in (row.get("discharged_boundaries") or [])]
    if missing:
        raise SystemExit(f"[b60] ledger row does not name {missing}; refusing")

    b56 = json.loads(B56.read_text())
    rows = [r for r in b56.get("rows") or []
            if r.get("file") == FILE and r.get("kind") == KIND
            and str(r.get("operation", "")).startswith(ITEM)]
    if len(rows) != 2:
        raise SystemExit(f"[b60] expected 2 B56 rows for {ITEM}, found {len(rows)}")
    for r in rows:
        if r.get("verdict") != "SAFETY_DISCHARGED":
            raise SystemExit(f"[b60] B56 row {r.get('id')} verdict "
                             f"{r.get('verdict')!r} is not a discharge; refusing")
        if r.get("line_current") not in (679, 700):
            raise SystemExit(f"[b60] B56 row {r.get('id')} line_current "
                             f"{r.get('line_current')!r} is not a known definition")
    return source_commit, row, sorted(rows, key=lambda r: r["line_current"])


def build_receipt() -> int:
    source_commit, plane_row, rows = load_inputs()
    text = blob_text(source_commit, FILE)
    b59 = json.loads(B59.read_text())
    recorded_profile_spans = {
        p["definition_line"]: p
        for p in (b59.get("causes", {})
                  .get("thread-free_lock-cfg-duplicate", {})
                  .get("profile_spans") or [])}

    declarations, per_definition = [], []
    for r in rows:
        definition_line = r["line_current"]
        span = cc.resolve_operation_at_line(
            REPO, FILE, ITEM, definition_line, source_commit=source_commit)
        if span["def_line"] != definition_line:
            raise SystemExit(f"[b60] resolved definition {span['def_line']} is not "
                             f"the B56 coordinate {definition_line}; refusing")
        predicate = cfg_predicate(text, span)
        prior = recorded_profile_spans.get(definition_line)
        if prior is None:
            raise SystemExit(f"[b60] B59 records no profile span at "
                             f"{definition_line}; refusing to invent one")
        if (prior.get("span_sha256") != span["sha256"]
                or prior.get("span_start_line") != span["start_line"]
                or prior.get("span_end_line") != span["end_line"]):
            raise SystemExit(f"[b60] B59 profile span at {definition_line} "
                             f"({prior.get('span_start_line')}-"
                             f"{prior.get('span_end_line')}, "
                             f"{str(prior.get('span_sha256'))[:16]}) disagrees with "
                             f"the S blob ({span['start_line']}-{span['end_line']}, "
                             f"{span['sha256'][:16]}); refusing")
        if prior.get("cfg_predicate") != predicate:
            # B59 recorded the predicate flattened onto one line; compare the
            # token streams so the check is about the predicate, not layout.
            squash = lambda s: "".join(str(s).split())  # noqa: E731
            if squash(prior["cfg_predicate"]) != squash(predicate):
                raise SystemExit(f"[b60] B59 cfg predicate at {definition_line} "
                                 "differs from the S blob; refusing")
            predicate_note = "B59 recorded this predicate on one line"
        else:
            predicate_note = None
        declarations.append({
            "cfg": predicate,
            "cfg_source": "git blob, attribute lines verbatim",
            "cfg_prior_rendering": predicate_note,
            "start_line": span["start_line"],
            "end_line": span["end_line"],
            "span_sha256": span["sha256"],
            "def_line": span["def_line"],
            "qualified_identity": span["qualified_identity"],
            "span_schema": cc.SPAN_HASH_SCHEMA,
            "span_normalisation": cc.SPAN_NORMALISATION,
            "span_claim_scope": cc.SPAN_CLAIM_SCOPE,
            "source_commit": source_commit,
        })
        per_definition.append({
            "definition_line": definition_line,
            "span_start_line": span["start_line"],
            "span_end_line": span["end_line"],
            "span_sha256": span["sha256"],
            "cfg": predicate,
            "b56_row_id": r.get("id"),
            "b56_line": r.get("line"),
            "b56_operation": r.get("operation"),
            "verdict": r.get("verdict"),
            "evidence": r.get("evidence"),
            "caller": r.get("caller"),
            "registration": r.get("registration"),
            "obligation": r.get("obligation"),
            "ledger_coordinate": f"{FILE}:{definition_line}",
        })
    declarations.sort(key=lambda d: d["start_line"])

    # The instrument's own binding, computed here as a pre-write check.
    bound = cc.resolve_declared_spans(
        REPO, FILE, ITEM, declarations, source_commit=source_commit)
    if [d["sha256"] for d in bound["definitions"]] != [
            d["span_sha256"] for d in declarations]:
        raise SystemExit("[b60] declared definitions do not bind; refusing")

    controls = [
        "b60-C1: a synthetic multiply-defined item with BOTH declared span "
        "hashes matching binds (DISCHARGED)",
        "b60-C2: the same item with ONE declared span hash mutated to 64 zeros "
        "is REFUSED (BLOCKED, span-hash-mismatch)",
        "b60-C3: the same item with only one of its two live definitions "
        "declared is REFUSED (BLOCKED, ambiguous-identity)",
        "b60-C4: the single-span shape (span_sha256, no declared_spans) is "
        "REFUSED (BLOCKED, ambiguous-identity) -- the pre-change behaviour is "
        "load-bearing",
        "b60-C5: B56's per-definition probe (B56-C4) and its mutation M3 are "
        "transcribed unchanged; this batch does not re-run the Rust court",
    ]

    common = {
        "schema": "openssl-rs/campaign/safe-c33/boundary-receipt/v1",
        "receipt": RECEIPT_ID,
        "date": "2026-11-12",
        "campaign": "safe-c33",
        "subphase": "b60-free-lock-operations",
        "candidate": source_commit,
        "source": {
            "ledger": ("forensics/memory-safety/campaign/safe-c33/"
                       "CAMPAIGN-STATUS.json#/scoped_boundary_discharges"
                       f"[receipt={LEDGER_RECEIPT}]"),
            "verdict_receipt": "atlas-refresh/boundary-sweep-B56.json#/rows",
            "prior_span_evidence": "atlas-refresh/b59-close18.json"
                                   "#/causes/thread-free_lock-cfg-duplicate",
            "span_source": ("git blob at census identity.source_head "
                            "(never the worktree)"),
            "source_commit": source_commit,
            "span_schema": cc.SPAN_HASH_SCHEMA,
            "span_set_schema": cc.SPAN_SET_SCHEMA,
            "span_normalisation": cc.SPAN_NORMALISATION,
            "span_set_hash_rule": cc.SPAN_SET_HASH_RULE,
        },
        "resolution_rule": {
            "instrument": "forensics/tools/consumer_closure.py",
            "function": "resolve_declared_spans",
            "rule": ("an operation is bound when every declared definition span "
                     "matches the current blob AND the set of definitions found "
                     "matches the declared set exactly, one-to-one, with no "
                     "declared extent absent and no live extent undeclared"),
            "generality": ("the field is a boundary-row property, not an "
                           "operation special case: any multiply-defined item may "
                           "carry declared_spans"),
            "cfg_is_metadata": ("the cfg predicates are recorded and reported but "
                                "never evaluated; the instrument does not know "
                                "which profile a consumer binary was built for, so "
                                "every definition must match"),
        },
        "bound_span_set": {
            "item": ITEM,
            "file": FILE,
            "kind": KIND,
            "definition_count": len(declarations),
            "set_sha256": bound["sha256"],
            "definitions": declarations,
        },
        "per_definition_verdicts": per_definition,
        "ledger": {
            "receipt": LEDGER_RECEIPT,
            "state": plane_row.get("state"),
            "discharged_boundaries_named": [
                i for i in (plane_row.get("discharged_boundaries") or [])
                if i in LEDGER_IDS],
            "adjudication": plane_row.get("adjudication"),
        },
        "controls": controls,
        "boundaries": [],
        "unresolved": [],
        "non_claims": [
            ("This receipt transcribes B56's two per-definition verdicts and "
             "supplies the missing declared-definition-set binding. It creates, "
             "widens and withdraws no verdict."),
            ("Both boundary rows declare the same two definition spans because "
             "the resolution rule requires the declared set to equal the live "
             "set. Each row's discharge authority is the ledger row that names "
             "that coordinate; the per-definition verdict for BOTH definitions "
             "is SAFETY_DISCHARGED in B56, so neither row claims a definition "
             "the adjudication did not already discharge."),
            ("The off-profile (`Box`) definition does not compile on the "
             "measured profile; B56 verified it by inspection and its row says "
             "so. That limitation is transcribed, not removed."),
            ("RUNTIME_CONCURRENCY remains OWNERSHIP_RECONSTRUCTED; this batch "
             "promotes no mechanism state."),
        ],
    }

    for definition, r in zip(declarations, per_definition):
        common["boundaries"].append({
            "id": r["ledger_coordinate"],
            "file": FILE,
            "line": definition["def_line"],
            "kind": KIND,
            "operation": ITEM,
            "mechanism": MECHANISM,
            "cfg": definition["cfg"],
            "disposition": (
                "SAFETY_DISCHARGED (scoped to this site by ledger row "
                f"{LEDGER_RECEIPT}; recorded row verdict "
                f"{r['verdict']}; the operation is bound by its complete "
                f"declared definition set, both spans content-matched at S)"),
            "recorded_verdict": r["verdict"],
            "ledger_receipt": LEDGER_RECEIPT,
            "ledger_coordinate": r["ledger_coordinate"],
            "source_receipt": "boundary-sweep-B56",
            "source_row_id": r["b56_row_id"],
            "source_row_key": "rows",
            "source_row_coordinates": {
                "line": r["b56_line"],
                "line_current": r["definition_line"],
                "current_line": None,
            },
            "declared_spans": [
                {"cfg": d["cfg"], "start_line": d["start_line"],
                 "end_line": d["end_line"], "span_sha256": d["span_sha256"],
                 "span_schema": d["span_schema"],
                 "span_normalisation": d["span_normalisation"],
                 "span_claim_scope": d["span_claim_scope"],
                 "source_commit": d["source_commit"],
                 "def_line": d["def_line"]}
                for d in declarations],
            "span_set_sha256": bound["sha256"],
            "span_set_schema": cc.SPAN_SET_SCHEMA,
            "span_set_hash_rule": cc.SPAN_SET_HASH_RULE,
            "span_source_commit": source_commit,
            "controls": controls,
        })

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

    print(f"[b60] definitions bound: {len(declarations)}")
    print(f"[b60] span set sha256: {bound['sha256']}")
    for d in declarations:
        print(f"  {d['start_line']}-{d['end_line']} {d['span_sha256']} "
              f"def_line={d['def_line']} {d['cfg']!r}")
    print(f"[b60] detail: {OUT_DETAIL.relative_to(REPO)}")
    print(f"[b60] sites:  {OUT_SITES.relative_to(REPO)}")
    return 0


# --------------------------------------------------------------------------- #
# adversarial controls: the real adjudicator, synthetic multiply-defined items
# --------------------------------------------------------------------------- #

CONTROL_SOURCE = (
    "#[cfg(all(unix))]\n"
    "pub unsafe fn dup_lock(p: *mut u8) {\n"
    "    let _ = p;\n"
    "}\n"
    "\n"
    "#[cfg(not(all(unix)))]\n"
    "pub unsafe fn dup_lock(p: *mut u8) {\n"
    "    let _ = p;\n"
    "}\n")


def _control_adjudicate(boundary: dict) -> dict:
    obligations_plane = {
        "mechanism_discharges": {},
        "scoped_boundary_discharges": {boundary["id"]: {"receipt": "b60-control"}},
        "err_scope": {},
    }
    obligation = {
        "id": "control:src/ctl/dup.rs:1:UNSAFE_FN_DEF",
        "file": "src/ctl/dup.rs",
        "line": 1,
        "kind": "UNSAFE_FN_DEF",
        "item": "dup_lock",
        "mechanism": "RUNTIME_CONCURRENCY",
        "status": None,
        "discharge_receipt": None,
        "status_reason": None,
    }
    return cc.adjudicate(obligation, {"RUNTIME_CONTROL": {}}, [boundary],
                         obligations_plane, repo=Path(_control_repo.name),
                         allow_worktree_span=True)


def controls() -> int:
    global _control_repo
    _control_repo = tempfile.TemporaryDirectory()
    root = Path(_control_repo.name)
    (root / "src/ctl").mkdir(parents=True)
    (root / "src/ctl/dup.rs").write_text(CONTROL_SOURCE)
    cc.clear_span_cache()

    first = cc.resolve_operation_at_line(root, "src/ctl/dup.rs", "dup_lock", 2,
                                        allow_worktree=True)
    second = cc.resolve_operation_at_line(root, "src/ctl/dup.rs", "dup_lock", 7,
                                         allow_worktree=True)
    pair = [
        {"cfg": "#[cfg(all(unix))]", "start_line": first["start_line"],
         "end_line": first["end_line"], "span_sha256": first["sha256"]},
        {"cfg": "#[cfg(not(all(unix)))]", "start_line": second["start_line"],
         "end_line": second["end_line"], "span_sha256": second["sha256"]},
    ]

    def row(declared_spans=None, span_sha256=None):
        rec = {"id": "CTL-1", "file": "src/ctl/dup.rs", "kind": "UNSAFE_FN_DEF",
               "operation": "dup_lock",
               "disposition": "SAFETY_DISCHARGED (scope: src/ctl/dup.rs:1-9)",
               "disposition_discharges": True,
               "superseded_ids": [], "span_sha256": span_sha256}
        if declared_spans is not None:
            rec["declared_spans"] = declared_spans
        return rec

    mutated = [dict(pair[0]), dict(pair[1])]
    mutated[1]["span_sha256"] = "0" * 64

    cases = [
        ("b60-C1 both declared spans match", row(declared_spans=pair)),
        ("b60-C2 one declared span hash mutated", row(declared_spans=mutated)),
        ("b60-C3 only one live definition declared",
         row(declared_spans=[pair[0]])),
        ("b60-C4 single-span shape, no declared set",
         row(span_sha256=first["sha256"])),
    ]
    failures = 0
    print(f"[b60] synthetic item: 2 live definitions "
          f"{first['start_line']}-{first['end_line']} "
          f"{first['sha256'][:16]}, {second['start_line']}-{second['end_line']} "
          f"{second['sha256'][:16]}")
    for name, boundary in cases:
        result = _control_adjudicate(boundary)
        rejections = result.get("span_discharge_rejections") or []
        classification = rejections[0].get("classification") if rejections else None
        binding = (result.get("span_discharge") or {}).get("binding")
        detail = rejections[0].get("detail") if rejections else None
        print(f"[b60] {name}: status={result['status']} "
              f"classification={classification} binding={binding}")
        if detail:
            print(f"        refusal: {detail}")
    # Independent expectation check, so the control cannot silently pass.
    expect = [
        ("DISCHARGED", None),
        ("BLOCKED", "span-hash-mismatch"),
        ("BLOCKED", "ambiguous-identity"),
        ("BLOCKED", "ambiguous-identity"),
    ]
    for (name, boundary), (want_status, want_class) in zip(cases, expect):
        result = _control_adjudicate(boundary)
        rejections = result.get("span_discharge_rejections") or []
        got = (result["status"],
               rejections[0].get("classification") if rejections else None)
        if got != (want_status, want_class):
            failures += 1
            print(f"[b60] CONTROL FAILED {name}: got {got}, "
                  f"want {(want_status, want_class)}")
    print("[b60] controls: " + ("PASS" if not failures
                                else f"FAILED ({failures})"))
    _control_repo.cleanup()
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--controls" in argv[1:]:
        return controls()
    return build_receipt()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
