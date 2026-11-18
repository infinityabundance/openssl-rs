#!/usr/bin/env python3
"""Cheap validation of atlas-refresh/b76-removed-thunk-retirements.json.

1. JSON well-formedness and the loader's kind predicate.
2. The filename glob the loader actually scans ('*-sites.json').
3. Simulation: copy the record under a '*-sites.json' name into a scratch dir
   and prove load_boundaries() parses its boundaries and supersedes.
Does NOT re-run the closure.
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "forensics/tools")
import consumer_closure as cc  # noqa: E402

DIR = Path("forensics/memory-safety/campaign/safe-c33/atlas-refresh")
SRC = DIR / "b76-removed-thunk-retirements.json"
doc = json.loads(SRC.read_text())
assert doc["kind"] == cc.SITE_RECEIPT_KIND, doc["kind"]
print("kind ok:", doc["kind"])
print("filename matches '*-sites.json':", SRC.name.endswith("-sites.json"))

with tempfile.TemporaryDirectory() as td:
    scratch = Path(td) / (SRC.stem + "-sites.json")
    shutil.copyfile(SRC, scratch)
    _by_file, by_id = cc.load_boundaries(Path(td))
    expected = sorted(s["ids"][0] for s in doc["supersedes"])
    for b in doc["boundaries"]:
        rec = next(r for r in (by_id.get(b["id"]) or [])
                   if r["receipt"] == doc["receipt"])
        assert rec["superseded_ids"] == expected, rec["superseded_ids"]
        assert not rec["disposition_discharges"], rec["id"]
    print("loader-admitted under '*\u002dsites.json':", doc["receipt"])
    print("boundaries:", len(doc["boundaries"]),
          "| supersedes attached per boundary:", len(expected))
    print("disposition_discharges: false for all four")
