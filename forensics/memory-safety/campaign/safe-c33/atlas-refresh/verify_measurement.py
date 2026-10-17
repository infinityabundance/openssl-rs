#!/usr/bin/env python3
"""Verification companion for atlas_refresh.py (measurement-tooling only).

This does not write campaign artifacts. It re-runs the scanner and checks:

  1. the candidate.json scan totals equal a fresh recomputation;
  2. the full discovered alloc/release surface reconciles with a *direct* grep
     over comment- and literal-stripped source (definitions subtracted);
  3. the per-site worklist row count equals production alloc + release calls;
  4. item-level cfg(test) reclassification counts are self-consistent;
  5. named sanity cases, including the expanded allocator surface.

Run inside the court container from the repo root:

    python3 forensics/memory-safety/campaign/safe-c33/atlas-refresh/verify_measurement.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAMPAIGN = HERE.parent
ROOT = CAMPAIGN.parents[3]
sys.path.insert(0, str(CAMPAIGN))

import atlas_refresh as a  # noqa: E402


def grep_lines(text: str, pattern: str) -> list[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(text)
        name = fh.name
    try:
        out = subprocess.run(
            ["grep", "-oP", pattern, name],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if out.returncode not in (0, 1):
            raise RuntimeError(out.stderr.decode("utf-8", "replace"))
    finally:
        Path(name).unlink()
    return out.stdout.decode("utf-8", "replace").splitlines()


def grep_count(text: str, pattern: str) -> int:
    return len(grep_lines(text, pattern))


def name_pattern(names) -> str:
    names = sorted(names)
    if not names:
        return r"(?!x)x"
    return r"\b(?P<name>" + "|".join(re.escape(n) for n in names) + r")\s*\("


def def_pattern(names) -> str:
    names = sorted(names)
    if not names:
        return r"(?!x)x"
    return r"\bfn\s+(?:" + "|".join(re.escape(n) for n in names) + r")\s*\("


def main() -> int:
    rel_paths = a.list_src_rs(ROOT)
    per_file, _sha, external_test_files, surface = a.scan_files(ROOT, rel_paths)

    def sites(selector):
        return [s for p in rel_paths for s in selector(per_file[p])]

    prod_alloc = sites(lambda f: f["production_alloc_sites"])
    prod_release = sites(lambda f: f["production_release_sites"])
    test_alloc = sites(
        lambda f: [s for s in f["alloc_sites"] if s["in_test"] and not s["is_seam_file"]]
    )
    test_release = sites(
        lambda f: [s for s in f["release_sites"] if s["in_test"] and not s["is_seam_file"]]
    )
    seam_alloc = sites(
        lambda f: [s for s in f.get("seam_sites", []) if s["kind"] == "alloc"]
    )
    seam_release = sites(
        lambda f: [s for s in f.get("seam_sites", []) if s["kind"] == "release"]
    )

    cand = json.loads((HERE / "candidate.json").read_text(encoding="utf-8"))
    scan = cand["recomputed_source_scan"]
    checks = {
        "production_alloc_calls": len(prod_alloc),
        "production_release_calls": len(prod_release),
        "test_only_alloc_calls": len(test_alloc),
        "test_only_release_calls": len(test_release),
        "seam_file_alloc_calls": len(seam_alloc),
        "seam_file_release_calls": len(seam_release),
    }
    candidate_matches = all(scan[k] == v for k, v in checks.items())
    print("fresh totals:", checks)
    print("candidate.json scan totals match fresh recomputation:", candidate_matches)
    print(
        "discovered surface:",
        f"{len(surface['alloc'])} alloc names, {len(surface['release'])} release names,",
        f"aliases={surface['aliases']}",
    )
    print("  seam files:", ", ".join(surface["seam_files"]))
    print("  alloc names:", ", ".join(sorted(surface["alloc"])))
    print("  release names:", ", ".join(sorted(surface["release"])))

    # Direct grep over stripped, line-normalised source for the FULL surface.
    stripped_blob = "\n".join(
        " ".join(a.strip_comments_and_literals(
            (ROOT / p).read_text(encoding="utf-8", errors="replace")
        ).split("\n"))
        for p in rel_paths
    )
    alloc_pat = name_pattern(surface["alloc"])
    release_pat = name_pattern(surface["release"])
    def_alloc_pat = def_pattern(surface["alloc"])
    def_release_pat = def_pattern(surface["release"])
    grep_alloc = grep_count(stripped_blob, alloc_pat)
    grep_release = grep_count(stripped_blob, release_pat)
    grep_def_alloc = grep_count(stripped_blob, def_alloc_pat)
    grep_def_release = grep_count(stripped_blob, def_release_pat)
    grep_calls = (grep_alloc - grep_def_alloc) + (grep_release - grep_def_release)
    scanner_calls = (
        len(prod_alloc) + len(prod_release) + len(test_alloc) + len(test_release)
        + len(seam_alloc) + len(seam_release)
    )
    print(
        "grep on stripped source (full surface): "
        f"alloc={grep_alloc} (defs {grep_def_alloc}), "
        f"release={grep_release} (defs {grep_def_release}), "
        f"call-like={grep_calls}"
    )
    print(
        "partition reconciliation (prod + test + seam == grep call-like):",
        scanner_calls == grep_calls,
        f"({scanner_calls} vs {grep_calls})",
    )

    worklist = json.loads((HERE / "site-worklist.json").read_text(encoding="utf-8"))
    rows = worklist["sites"]
    worklist_ok = len(rows) == len(prod_alloc) + len(prod_release)
    print(
        "worklist rows == production alloc+release calls:",
        worklist_ok,
        f"({len(rows)} vs {len(prod_alloc) + len(prod_release)})",
    )

    # Item-level cfg(test) reclassification.
    item_sites = [
        s for p in rel_paths
        for s in per_file[p]["alloc_sites"] + per_file[p]["release_sites"]
        + per_file[p]["adopt_sites"]
        if s["in_test_item"] and not s["in_test_module"] and not s["is_seam_file"]
    ]
    item_alloc_release = [s for s in item_sites if s["kind"] in ("alloc", "release")]
    item_range_count = sum(len(per_file[p]["item_test_ranges"]) for p in rel_paths)
    cfg_attr_count = sum(per_file[p]["cfg_attr_cfg_test"] for p in rel_paths)
    item_reclass_ok = (
        len(item_sites) == scan["item_cfg_test_sites_reclassified"]
        and len(item_alloc_release) == scan["item_cfg_test_alloc_release_reclassified"]
        and item_range_count == scan["item_cfg_test_range_count"]
        and cfg_attr_count == scan["cfg_attr_cfg_test_attributes"]
    )
    print(
        "item-level cfg(test):",
        f"ranges={item_range_count}",
        f"sites_reclassified={len(item_sites)}",
        f"alloc_release={len(item_alloc_release)}",
        f"cfg_attr_detected={cfg_attr_count}",
        "->", "OK" if item_reclass_ok else "FAIL",
    )

    # Residual allocator-like names not in the discovered surface.
    broad_names = grep_lines(
        stripped_blob,
        r"\b\K(?:CRYPTO|OPENSSL)_[A-Za-z0-9_]*(?:alloc|free|dup)[A-Za-z0-9_]*(?=\s*\()",
    )
    known = set(surface["alloc"]) | set(surface["release"]) | set(surface["excluded"])
    # ex_data lifecycle helpers are not heap allocator operations.
    known |= {"CRYPTO_free_ex_data", "CRYPTO_free_ex_index"}
    residual_names = sorted(set(n for n in broad_names if n not in known))
    print(
        "allocator-like names outside discovered surface (residual):",
        ", ".join(residual_names) or "none",
    )

    # Family coverage: every discovered name with at least one call site anywhere.
    all_sites = (
        prod_alloc + prod_release + test_alloc + test_release
        + seam_alloc + seam_release
    )
    seen_callees = {s["callee"] for s in all_sites}
    unused_names = sorted(
        (set(surface["alloc"]) | set(surface["release"])) - seen_callees
    )
    print("discovered names with no observed call site:", ", ".join(unused_names) or "none")

    def by_file(rel):
        f = per_file[rel]
        return {
            "production_alloc": len(f["production_alloc_sites"]),
            "production_release": len(f["production_release_sites"]),
            "test_alloc": len([s for s in f["alloc_sites"] if s["in_test"]]),
            "test_release": len([s for s in f["release_sites"] if s["in_test"]]),
            "seam_alloc": len([s for s in f.get("seam_sites", []) if s["kind"] == "alloc"]),
            "module_ranges": len(f["test_module_ranges"]),
            "item_ranges": len(f["item_test_ranges"]),
        }

    print("\nSanity cases:")
    sanity_ok = []
    core = by_file("src/provider/core_dispatch.rs")
    sanity_ok.append(core["production_alloc"] == 0 and core["test_alloc"] == 0)
    print("  core_dispatch.rs:", core, "-> OK" if sanity_ok[-1] else "-> FAIL")

    mem = by_file("src/runtime/mem.rs")
    sanity_ok.append(
        "src/runtime/mem.rs" in a.SEAM_FILES
        and mem["production_alloc"] == 0
        and mem["seam_alloc"] > 0
    )
    print("  runtime/mem.rs (seam):", mem, "-> OK" if sanity_ok[-1] else "-> FAIL")

    secure = by_file("src/runtime/secure.rs")
    sanity_ok.append(
        "src/runtime/secure.rs" in a.SEAM_FILES and secure["production_alloc"] == 0
    )
    print("  runtime/secure.rs (seam):", secure, "-> OK" if sanity_ok[-1] else "-> FAIL")

    d2i = [
        s for s in per_file["src/asn1/d2i.rs"]["production_alloc_sites"]
        if s["callee"] == "CRYPTO_realloc"
    ]
    sanity_ok.append(len(d2i) == 2)
    print(
        "  asn1/d2i.rs CRYPTO_realloc production calls:",
        [(s["line"], s["function"]) for s in d2i],
        "-> OK" if sanity_ok[-1] else "-> FAIL",
    )

    mbstr = by_file("src/asn1/a_mbstr.rs")
    sanity_ok.append(mbstr["production_alloc"] == 0 and mbstr["test_alloc"] == 0)
    print(
        "  asn1/a_mbstr.rs (doc-comment only):", mbstr,
        "-> OK" if sanity_ok[-1] else "-> FAIL",
    )

    intern = by_file("src/bn/intern.rs")
    test_free = [
        (s["line"], s["callee"]) for s in per_file["src/bn/intern.rs"]["release_sites"]
        if s["in_test"]
    ]
    sanity_ok.append(bool(test_free))
    print(
        "  bn/intern.rs (cfg(test) call):", intern, "test release sites:", test_free,
        "-> OK" if sanity_ok[-1] else "-> FAIL",
    )

    expanded = sorted(
        {
            s["callee"]
            for s in all_sites
            if s["family"] in {
                "clear_realloc", "array", "aligned", "secure_alloc", "secure_zalloc",
                "secure_array", "secure_calloc", "secure_release",
                "secure_cleansing_release", "dup", "secure_arena",
            }
        }
    )
    sanity_ok.append(bool(expanded))
    print(
        "  expanded-family calls observed:", ", ".join(expanded) or "none",
        "-> OK" if sanity_ok[-1] else "-> FAIL",
    )

    ok = (
        candidate_matches
        and scanner_calls == grep_calls
        and worklist_ok
        and item_reclass_ok
        and all(sanity_ok)
    )
    print("\nVERIFY_RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
