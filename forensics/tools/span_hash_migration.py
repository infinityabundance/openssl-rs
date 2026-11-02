#!/usr/bin/env python3
"""Backfill content-addressed span hashes for the OLD scoped-discharge set.

The migration is deliberately narrow: a site is recorded only when the OLD
predicate (stable identity AND the receipt's declared range covers the current
census line) already discharged it at ``--migration-candidate``.  Sites the OLD
predicate refused (including the stale B49-I2R-009) receive no hash and stay
refused as ``unmigrated``.

The output is the logged migration map consulted by ``consumer_closure.py``.
It is not an obligation-ledger edit and does not change a receipt schema.
"""
import argparse
import datetime as _dt
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import consumer_closure as cc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--baseline-closure", required=True,
                    help="closure produced by the pre-change tool at the migration candidate")
    ap.add_argument("--boundary-dir",
                    default="forensics/memory-safety/campaign/safe-c33/atlas-refresh")
    ap.add_argument("--migration-candidate", required=True)
    ap.add_argument("--candidate-tag", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    repo = Path(args.repo).resolve()
    boundary_dir = (repo / args.boundary_dir).resolve()
    baseline = json.loads(Path(args.baseline_closure).read_text())
    by_file, by_id = cc.load_boundaries(boundary_dir)
    del by_file
    candidate = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", args.migration_candidate]
    ).decode().strip()
    blobs = {}

    obligations = baseline.get("obligations") or []
    discharged = [o for o in obligations if o.get("status") == "DISCHARGED"]
    sites = []
    not_backfilled = []
    seen = {}

    for o in discharged:
        attempts = [a for a in o.get("scoped_discharge_attempts") or []
                    if a.get("covers_site")]
        if not attempts:
            not_backfilled.append({
                "site_id": o.get("id"), "file": o.get("file"),
                "item": o.get("item"),
                "classification": "no-covers-site",
                "detail": "the baseline discharged the site without a scoped attempt",
            })
            continue
        attempt = attempts[0]
        boundary_id = attempt.get("boundary")
        records = by_id.get(boundary_id) or []
        rec = next((r for r in records
                    if r.get("file") == o.get("file")
                    and r.get("kind") == o.get("kind")), None)
        if rec is None:
            not_backfilled.append({
                "site_id": o.get("id"), "file": o.get("file"),
                "item": o.get("item"), "boundary_id": boundary_id,
                "classification": "span-unparsable",
                "detail": "no boundary receipt record matches the discharging attempt",
            })
            continue
        try:
            text, content_sha = cc._git_blob_text(repo, candidate, o["file"])
            blob_sha = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse",
                 f"{candidate}:{o['file']}"]
            ).decode().strip()
            span = cc.resolve_operation_span(
                repo, o["file"], rec.get("operation"), o.get("item"),
                source_text=text)
            blobs[o["file"]] = {
                "git_blob_sha1": blob_sha,
                "content_sha256": content_sha,
                "source": f"git show {candidate}:{o['file']}",
            }
        except cc.SpanResolutionError as exc:
            not_backfilled.append({
                "site_id": o.get("id"), "file": o.get("file"),
                "item": o.get("item"), "boundary_id": boundary_id,
                "operation": rec.get("operation"),
                "classification": exc.classification,
                "detail": exc.detail,
            })
            continue
        except subprocess.CalledProcessError as exc:
            not_backfilled.append({
                "site_id": o.get("id"), "file": o.get("file"),
                "item": o.get("item"), "boundary_id": boundary_id,
                "operation": rec.get("operation"),
                "classification": "span-unparsable",
                "detail": f"git blob lookup failed: {exc}",
            })
            continue
        key = f"{rec['receipt']}::{boundary_id}"
        entry = {
            "site_id": o.get("id"),
            "stable_id": o.get("stable_id"),
            "receipt": rec["receipt"],
            "boundary_id": boundary_id,
            "file": o["file"],
            "kind": o.get("kind"),
            "item": o.get("item"),
            "operation": rec.get("operation"),
            "old_coordinate": rec.get("line"),
            "obligation_line": o.get("line"),
            "current_census_line": o.get("current_census_line"),
            "span_start_line": span["start_line"],
            "span_end_line": span["end_line"],
            "span_sha256": span["sha256"],
            "span_resolution": span["resolution"],
        }
        if key in seen and seen[key]["span_sha256"] != entry["span_sha256"]:
            raise SystemExit(
                f"conflicting hashes for {key}: {seen[key]['span_sha256']} vs "
                f"{entry['span_sha256']}")
        if key not in seen:
            sites.append(entry)
            seen[key] = entry
        else:
            # One boundary can discharge several carried-forward obligations.
            seen[key].setdefault("site_ids", [seen[key]["site_id"]])
            if entry["site_id"] not in seen[key]["site_ids"]:
                seen[key]["site_ids"].append(entry["site_id"])

    doc = {
        "schema": "safe-c33/span-hash-migration/v1",
        "kind": "span-hash-migration",
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "migration_candidate": candidate,
        "migration_candidate_tag": args.candidate_tag,
        "candidate_verified": True,
        "candidate_blobs": blobs,
        "hash_binding": ("Every span_sha256 is sha256 over the normalised span "
                         "text read from git show <migration_candidate>:<file>; "
                         "candidate_blobs records each per-file git_blob_sha1 and "
                         "content_sha256.  The live worktree is not used for "
                         "these hashes."),
        "baseline_closure": str(Path(args.baseline_closure)),
        "baseline_closure_counts": baseline.get("counts"),
        "old_predicate": ("identity_match and the receipt's declared range covers "
                          "the current census line; when current_census_line "
                          "is unset the OLD tool falls back to the obligation's "
                          "retained enumeration coordinate"),
        "normalisation": cc.SPAN_NORMALISATION,
        "claim_scope": cc.SPAN_CLAIM_SCOPE,
        "span_schema": cc.SPAN_HASH_SCHEMA,
        "counts": {
            "discharged_sites_in_baseline": len(discharged),
            "boundaries_backfilled": len(sites),
            "not_backfilled": len(not_backfilled),
        },
        "sites": sorted(sites, key=lambda s: (s["file"], s["span_start_line"],
                                              s["boundary_id"])),
        "not_backfilled": not_backfilled,
    }
    out = Path(args.out)
    if not out.is_absolute():
        out = repo / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"[span-hash-migration] wrote {out}")
    print(f"[span-hash-migration] discharged={len(discharged)} "
          f"backfilled={len(sites)} not_backfilled={len(not_backfilled)}")
    return 1 if not_backfilled else 0


if __name__ == "__main__":
    sys.exit(main())
