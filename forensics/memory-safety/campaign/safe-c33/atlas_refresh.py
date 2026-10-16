#!/usr/bin/env python3
"""Safe-33 atlas refresh — a lightweight, candidate-bound measurement.

This generator is *measurement only*. It converts no source, regenerates no
Phase-25 evidence graph, and claims no graduation. It pins the exact current
`src/` tree and reports, honestly, where the nine ownership mechanisms stand
between the 33 already-drop-in-compatible downstream consumers and
`SAFE_COMPATIBLE`.

Design constraints (see the task / AGENTS.md §6, §18):
  * Python standard library only; no crate deps, no network.
  * Fast and low-memory: one streaming pass over `src/**/*.rs` (~30 MB).
  * Candidate-bound: the report records the git HEAD, the crate version and a
    content hash over every `src/**/*.rs` (sorted path + bytes), so the refresh
    is provably tied to one tree.

Everything the tool asserts about mechanism→file association is declared as
data in MECHANISM_PATHS below, derived from CLOSURE.md (the "authority
evidence" prefix column) and the `converted_files_on_branch` file lists in
state.json / PROGRESS.md. Keeping it as data makes the mapping auditable.

Run:  python3 forensics/memory-safety/campaign/safe-c33/atlas_refresh.py
Out:  forensics/memory-safety/campaign/safe-c33/atlas-refresh/{candidate.json,REPORT.md}
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# 1. Declared data: seam tokens, allocator sites, mechanism→path mapping.
# --------------------------------------------------------------------------

# An ownership seam is any of these owning-type/destructor markers. Their
# presence in a file is evidence that at least part of the file's raw
# ownership has been reconstructed behind an owning abstraction.
SEAM_TOKENS = [
    "OwnedCtx",
    "OwnedBuf",
    "OwnedBlock",
    "OwnedStr",
    "PropqSlot",
    "RawCtx",
    "OwnedRaw",
    "CtxDestroy",
    "CipherDestroy",
    "impl Drop",
]

# Raw allocator sites. Seam constructors legitimately contain these, so a raw
# site is *not* by itself a defect; it is a site that must be accounted for.
ALLOC_RE = re.compile(r"\bCRYPTO_(?:malloc|zalloc|calloc|strdup|memdup)\b")
FREE_RE = re.compile(r"\bCRYPTO_(?:free|clear_free)\b")

# A file that *defines* the allocator entry points is the `CRYPTO_*` seam's own
# implementation, not an unconverted interior consumer. Its raw sites are the
# seam being defined and must not be reported as residual.
ALLOC_DEF_RE = re.compile(
    r"\bfn\s+CRYPTO_(?:malloc|zalloc|calloc|strdup|memdup|free|clear_free)\b"
)

# Mechanism → src/ path mapping. A trailing "/" is a directory prefix; a bare
# path is an exact file. Derived from CLOSURE.md §2 "authority evidence"
# (crypto/… and ssl/ prefixes → the crate's directory layout) plus the file
# lists in state.json (`converted_files_on_branch`) and PROGRESS.md. Overlap
# between mechanisms is intentional and expected; the union is deduplicated.
MECHANISM_PATHS = {
    "ERR": [
        "src/runtime/err.rs",
        "src/runtime/err_state.rs",
        "src/runtime/err_sites.rs",
        "src/runtime/err_loaders.rs",
        "src/runtime/err_reasons.rs",
        "src/runtime/err_strings.rs",
        "src/ssl/ssl_err_legacy.rs",
    ],
    "RAND_CMS_STORE_KEYFMT": [
        "src/rand/",
        "src/cms/",
        "src/store/",
        "src/pem/",
        "src/pkcs7/",
        "src/pkcs12/",
        "src/cmp/",
        "src/crmf/",
    ],
    "BIO": [
        "src/runtime/bio/",
        "src/context/core_bio.rs",
    ],
    "EVP_PKEY_PROVIDER": [
        "src/evp/",
        "src/provider/",
        "src/property/",
        "src/params/",
        "src/ec/",
        "src/rsa/",
        "src/dsa/",
        "src/dh/",
        "src/bn/",
        "src/ffc/",
    ],
    "RUNTIME_ALLOC_OWNERSHIP": [
        "src/runtime/mem.rs",
        "src/runtime/secure.rs",
        "src/runtime/buffer.rs",
        "src/runtime/stack.rs",
        "src/runtime/ex_data.rs",
        "src/runtime/init.rs",
        "src/runtime/lhash.rs",
        "src/context/",
    ],
    "ASN1_OCSP": [
        "src/asn1/",
        "src/ocsp/",
        "src/ts/",
        "src/runtime/obj.rs",
        "src/runtime/obj_table.rs",
    ],
    "X509_VERIFY_POLICY": [
        "src/x509/",
    ],
    "RUNTIME_CONCURRENCY": [
        "src/runtime/thread.rs",
        "src/runtime/thread_arch.rs",
        "src/runtime/thread_events.rs",
        "src/runtime/threads_common.rs",
        "src/runtime/init.rs",
    ],
    "SSL_SESSION": [
        "src/ssl/",
    ],
}

# The nine mechanisms, in the CLOSURE.md ranking order used by the ledger.
MECHANISM_ORDER = [
    "ERR",
    "RAND_CMS_STORE_KEYFMT",
    "BIO",
    "EVP_PKEY_PROVIDER",
    "RUNTIME_ALLOC_OWNERSHIP",
    "ASN1_OCSP",
    "X509_VERIFY_POLICY",
    "RUNTIME_CONCURRENCY",
    "SSL_SESSION",
]

CAMPAIGN_DIR = "forensics/memory-safety/campaign/safe-c33"
STATE_PATH = f"{CAMPAIGN_DIR}/state.json"
P1000_PATH = "forensics/downstream/p1000-run.json"
CENSUS_PATH = "artifacts/phase25/source-census.json"
OUT_DIR = f"{CAMPAIGN_DIR}/atlas-refresh"


# --------------------------------------------------------------------------
# 2. Small filesystem / git helpers.
# --------------------------------------------------------------------------

def repo_root() -> Path:
    """Locate the repository root from this file's location."""
    return Path(__file__).resolve().parents[4]


def git(*args: str, root: Path) -> str:
    out = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return out.stdout.decode("utf-8", "replace").strip()


def crate_version(root: Path) -> str:
    toml = (root / "Cargo.toml").read_text(encoding="utf-8", errors="replace")
    m = re.search(r'^version\s*=\s*"([^"]+)"', toml, re.MULTILINE)
    return m.group(1) if m else "UNKNOWN"


def list_src_rs(root: Path) -> list[str]:
    base = root / "src"
    out = []
    for dirpath, _dirs, files in os.walk(base):
        for f in files:
            if f.endswith(".rs"):
                out.append(str((Path(dirpath) / f).relative_to(root)))
    return sorted(out)


def scan_files(root: Path, rel_paths: list[str]):
    """One pass: bytes (for the content hash + census cross-check), a decoded
    view (for token/site counts), per-file sha256."""
    per_file = {}
    content_hash = hashlib.sha256()
    content_hash.update(b"openssl-rs/src-rs/v1\x00")
    for rel in rel_paths:
        raw = (root / rel).read_bytes()
        content_hash.update(rel.encode("utf-8"))
        content_hash.update(b"\x00")
        content_hash.update(raw)
        content_hash.update(b"\x00")
        text = raw.decode("utf-8", "replace")
        raw_sites = len(ALLOC_RE.findall(text)) + len(FREE_RE.findall(text))
        seams = [t for t in SEAM_TOKENS if t in text]
        per_file[rel] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_sites": raw_sites,
            "seams": seams,
            "has_seam": bool(seams),
            "defines_allocator": bool(ALLOC_DEF_RE.search(text)),
        }
    return per_file, content_hash.hexdigest()


def matches_any(rel: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if pat.endswith("/"):
            if rel.startswith(pat):
                return True
        elif rel == pat:
            return True
    return False


# --------------------------------------------------------------------------
# 3. Evidence loading (small summaries only; never echoed whole).
# --------------------------------------------------------------------------

def load_state(root: Path) -> dict:
    with open(root / STATE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def load_p1000_counts(root: Path) -> dict:
    with open(root / P1000_PATH, encoding="utf-8") as fh:
        d = json.load(fh)
    b = d["body"]
    passes = [v for v in b["verdicts"] if v.get("verdict") == "DROP_IN_PASS"]
    return {
        "body_hash": d["body_hash"],
        "counts": b["counts"],
        "ladder_levels": b["ladder"]["levels"],
        "pass_families": sorted(
            (v["family_id"], v.get("candidate_level")) for v in passes
        ),
    }


def load_census_file_hashes(root: Path) -> dict | None:
    """Optional: frozen per-file sha256 from the Phase-25 census, used only as a
    candidate-binding cross-check (how many current closure files differ from
    the frozen census). Silently skipped if the artifact is absent/unreadable."""
    path = root / CENSUS_PATH
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        rows = d["body"]["files"]["rows"]
        cols = d["body"]["files"]["columns"]
        pi, si = cols.index("path"), cols.index("file_sha256")
        return {r[pi]: r[si] for r in rows}
    except Exception:
        return None


# --------------------------------------------------------------------------
# 4. Computation.
# --------------------------------------------------------------------------

def build(root: Path, args) -> dict:
    rel_paths = list_src_rs(root)
    per_file, content_sha = scan_files(root, rel_paths)
    allocator_files = sorted(p for p in rel_paths if per_file[p]["defines_allocator"])

    head = git("rev-parse", "HEAD", root=root)
    branch = git("rev-parse", "--abbrev-ref", "HEAD", root=root)
    version = crate_version(root)

    state = load_state(root)
    p1000 = load_p1000_counts(root)

    # --- Cohort (33). state.json#cohort is authoritative; p1000-run is the
    #     frozen verdict artifact and a cross-check on count + level split.
    cohort = state["cohort"]
    families = cohort["families"]
    fam_rows = []
    for name in sorted(families):
        f = families[name]
        fam_rows.append({
            "family": name,
            "level": f["level"],
            "libssl": f["libssl"],
            "evidence": f["evidence"],
            "rank": f["rank"],
            "mechanisms": list(f["mechanisms"]),
        })

    # --- Mechanisms.
    mech_state = {m["id"]: m for m in state["mechanisms"]}
    mechanism_rows = []
    union_files = set()
    for mid in MECHANISM_ORDER:
        pats = MECHANISM_PATHS[mid]
        closure = [p for p in rel_paths if matches_any(p, pats)]
        union_files.update(closure)
        m = mech_state.get(mid, {})
        seam_files = [p for p in closure if per_file[p]["has_seam"]]
        zero_raw = [p for p in closure if per_file[p]["raw_sites"] == 0]
        alloc_def = [p for p in closure if per_file[p]["defines_allocator"]]
        no_seam_raw = [
            p for p in closure
            if not per_file[p]["has_seam"] and per_file[p]["raw_sites"] > 0
            and not per_file[p]["defines_allocator"]
        ]
        seam_raw = [
            p for p in closure
            if per_file[p]["has_seam"] and per_file[p]["raw_sites"] > 0
            and not per_file[p]["defines_allocator"]
        ]
        closure_raw_sites = sum(per_file[p]["raw_sites"] for p in closure)
        interior_sites = sum(per_file[p]["raw_sites"] for p in no_seam_raw)
        mechanism_rows.append({
            "id": mid,
            "category": m.get("category"),
            "state": m.get("state"),
            "families_total": m.get("families_total"),
            "families_measured": m.get("families_measured"),
            "families_inferred": m.get("families_inferred"),
            "crate_unsafe_operations_frozen": m.get("crate_unsafe_operations"),
            "crate_files_frozen": m.get("crate_files"),
            "converted_files_on_branch": list(m.get("converted_files_on_branch", [])),
            # Recomputed against the CURRENT tree:
            "closure_files_recomputed": len(closure),
            "closure_seam_files": len(seam_files),
            "closure_zero_raw_files": len(zero_raw),
            "closure_no_seam_raw_files": len(no_seam_raw),
            "closure_seam_raw_files": len(seam_raw),
            "closure_allocator_definition_files": sorted(alloc_def),
            "closure_raw_sites": closure_raw_sites,
            "unconverted_interior_files": sorted(no_seam_raw),
            "unconverted_interior_file_count": len(no_seam_raw),
            "unconverted_interior_sites": interior_sites,
        })

    # --- Whole-tree scan totals.
    with_seam = [p for p in rel_paths if per_file[p]["has_seam"]]
    zero_raw = [p for p in rel_paths if per_file[p]["raw_sites"] == 0]
    with_raw = [p for p in rel_paths if per_file[p]["raw_sites"] > 0]
    raw_total = sum(per_file[p]["raw_sites"] for p in rel_paths)

    # --- Closure-restricted scan.
    closure_files = sorted(union_files)
    closure_seam = [p for p in closure_files if per_file[p]["has_seam"]]
    closure_no_seam_raw = [
        p for p in closure_files
        if not per_file[p]["has_seam"] and per_file[p]["raw_sites"] > 0
        and not per_file[p]["defines_allocator"]
    ]
    closure_seam_raw = [
        p for p in closure_files
        if per_file[p]["has_seam"] and per_file[p]["raw_sites"] > 0
        and not per_file[p]["defines_allocator"]
    ]
    closure_raw_total = sum(per_file[p]["raw_sites"] for p in closure_files)
    interior_unresolved = sum(per_file[p]["raw_sites"] for p in closure_no_seam_raw)
    seam_bearing_raw = sum(per_file[p]["raw_sites"] for p in closure_seam_raw)

    # --- Coverage gap: top-level src/ modules named by NO mechanism mapping.
    #     This is honest unknown coverage: the nine-mechanism closure does not
    #     cover every module the conversion touches.
    covered_prefixes = set()
    for pats in MECHANISM_PATHS.values():
        for pat in pats:
            covered_prefixes.add(pat)
    uncovered_dirs: dict[str, int] = {}
    for p in rel_paths:
        if not matches_any(p, list(covered_prefixes)):
            parts = p.split("/")
            key = parts[1] if len(parts) > 2 else p
            uncovered_dirs[key] = uncovered_dirs.get(key, 0) + 1

    # --- Per-consumer mechanism status (metric 5).
    mech_by_recon = {mid: (mech_state[mid]["state"] == "OWNERSHIP_RECONSTRUCTED")
                     for mid in MECHANISM_ORDER}
    per_consumer = []
    SAFE_COMPATIBLE = 0
    for row in fam_rows:
        need = row["mechanisms"]
        recon = [m for m in need if mech_by_recon.get(m)]
        open_ = [m for m in need if not mech_by_recon.get(m)]
        per_consumer.append({
            "family": row["family"],
            "level": row["level"],
            "evidence": row["evidence"],
            "mechanisms_required": len(need),
            "mechanisms_ownership_reconstructed": len(recon),
            "mechanisms_unsafe_open": len(open_),
            "unsafe_open_ids": sorted(open_),
            "safe_compatible_eligible": False,
        })

    # --- Ledger vs seam heuristic: files the ledger lists as converted on this
    #     branch that carry NO recognised seam token. Measures how much the
    #     file-level seam heuristic undercounts reconstruction.
    ledger_missing = []
    ledger_present = 0
    ledger_absent = []
    for mid in MECHANISM_ORDER:
        for f in mech_state.get(mid, {}).get("converted_files_on_branch", []):
            if f not in per_file:
                ledger_absent.append({"mechanism": mid, "file": f})
            elif per_file[f]["has_seam"]:
                ledger_present += 1
            else:
                ledger_missing.append({"mechanism": mid, "file": f})

    # --- Census cross-check (frozen hashes vs current tree).
    crosscheck = None
    frozen = load_census_file_hashes(root)
    if frozen is not None:
        changed = [p for p in closure_files
                   if p in frozen and frozen[p] != per_file[p]["sha256"]]
        unknown = [p for p in closure_files if p not in frozen]
        crosscheck = {
            "source": CENSUS_PATH,
            "closure_files_matched": len(closure_files) - len(changed) - len(unknown),
            "closure_files_changed_since_frozen_census": len(changed),
            "closure_files_absent_from_frozen_census": len(unknown),
            "note": (
                "The census is the FROZEN Phase-25 atlas (earlier candidate). "
                "A changed file is candidate drift since that freeze, not a defect."
            ),
        }

    # --- Unknown coverage vs demonstrated failure (distinguished explicitly).
    demonstrated_failure = []
    for mrow in mechanism_rows:
        if mrow["closure_no_seam_raw_files"] > 0:
            demonstrated_failure.append({
                "mechanism": mrow["id"],
                "unconverted_interior_files": mrow["closure_no_seam_raw_files"],
            })
    unknown_coverage = []
    for mrow in mechanism_rows:
        if (mrow["families_inferred"] or 0) > 0:
            unknown_coverage.append({
                "mechanism": mrow["id"],
                "families_without_symbol_fingerprint": mrow["families_inferred"],
            })

    # --- Next-target ranking: families needing the mechanism (reachability)
    #     weighted by the residual risk proxy (unconverted interior files).
    reach = {mid: 0 for mid in MECHANISM_ORDER}
    for row in fam_rows:
        for mid in row["mechanisms"]:
            reach[mid] += 1
    targets = []
    for mrow in mechanism_rows:
        mid = mrow["id"]
        targets.append({
            "mechanism": mid,
            "state": mrow["state"],
            "families_reaching": reach[mid],
            "unconverted_interior_files": mrow["closure_no_seam_raw_files"],
            "unconverted_interior_sites": mrow["unconverted_interior_sites"],
            "score": reach[mid] * mrow["unconverted_interior_sites"],
        })
    targets.sort(key=lambda t: (-t["score"], t["mechanism"]))

    doc = {
        "schema": "openssl-rs/p25-safe-c33/atlas-refresh/1",
        "kind": "safe-c33-atlas-refresh",
        "generator": f"{CAMPAIGN_DIR}/atlas_refresh.py",
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "candidate": {
            "head_sha": head,
            "branch": branch,
            "crate_name": "openssl-rs",
            "crate_version": version,
            "src_rs_files": len(rel_paths),
            "src_content_sha256": content_sha,
            "src_content_hash_rule": (
                "sha256 over the byte string 'openssl-rs/src-rs/v1\\0' followed, "
                "for each src/**/*.rs in sorted relative-path order, by "
                "relpath\\0filebytes\\0"
            ),
            "inventory_head_sha_frozen": state.get("head_sha"),
            "inventory_base_sha": state.get("base_sha"),
        },
        "cohort": {
            "authoritative_source": (
                "forensics/memory-safety/campaign/safe-c33/state.json#cohort "
                "(cross-checked against forensics/downstream/p1000-run.json "
                "body.counts / verdicts)"
            ),
            "candidate_verdict": cohort["verdict"],
            "count": cohort["count"],
            "levels": cohort["levels"],
            "l7_functional": list(cohort["l7_functional"]),
            "build_link_only": list(cohort["build_link_only"]),
            "fingerprinted": list(cohort["fingerprinted"]),
            "p1000_counts": p1000["counts"],
            "p1000_ladder_levels": p1000["ladder_levels"],
            "p1000_pass_families_match": sorted(
                n.split(":", 1)[1] for n, _lvl in p1000["pass_families"]
            ) == sorted(families.keys()),
            "families": fam_rows,
        },
        "mechanism_file_mapping": {
            "rule": (
                "declared as data in atlas_refresh.py:MECHANISM_PATHS; trailing "
                "'/' = directory prefix, bare path = exact file; derived from "
                "CLOSURE.md 'authority evidence' prefixes + state.json "
                "converted_files_on_branch + PROGRESS.md"
            ),
            "paths": MECHANISM_PATHS,
        },
        "mechanisms": mechanism_rows,
        "recomputed_source_scan": {
            "seam_tokens": SEAM_TOKENS,
            "raw_site_patterns": [ALLOC_RE.pattern, FREE_RE.pattern],
            "files_total": len(rel_paths),
            "files_with_seam": len(with_seam),
            "files_zero_raw_sites": len(zero_raw),
            "files_with_raw_sites": len(with_raw),
            "raw_sites_total": raw_total,
            "allocator_definition_files": allocator_files,
            "allocator_definition_note": (
                "Files defining the CRYPTO_* allocator entry points (the seam "
                "itself); their raw sites are the seam being defined, not "
                "interior residuals, and are excluded from metric 4."
            ),
        },
        "cohort_metrics": {
            "1_unique_closure_files": len(closure_files),
            "2_files_ownership_reconstructed": len(closure_seam),
            "3_files_fully_discharged_obligations": 0,
            "3_note": (
                "Obligations are discharged ONLY at the seal point "
                "(AGENTS.md §7 SAFETY_DISCHARGED, §18). No per-site validity "
                "contract has been proven for any closure file at this "
                "candidate, so this is honestly 0. A present seam is "
                "OWNERSHIP_RECONSTRUCTED, which is not discharge."
            ),
            "4_unresolved_interior_raw_sites": {
                "unconverted_no_seam_files": len(closure_no_seam_raw),
                "unconverted_no_seam_sites": interior_unresolved,
                "seam_bearing_files_with_raw_sites": len(closure_seam_raw),
                "seam_bearing_raw_sites_unclassified": seam_bearing_raw,
                "allocator_definition_files_excluded": sorted(
                    p for p in closure_files if per_file[p]["defines_allocator"]
                ),
                "upper_bound_total": interior_unresolved + seam_bearing_raw,
                "note": (
                    "Sites in no-seam files are unambiguously unconverted "
                    "interior. Sites in seam-bearing files are mixed: they "
                    "include legitimate seam-constructor sites and any "
                    "remaining interior sites — this lightweight pass cannot "
                    "separate them, so they are reported, not claimed clean."
                ),
            },
            "5_consumers_safe_compatible": SAFE_COMPATIBLE,
            "5_note": (
                "0 by construction: no mechanism is SAFETY_DISCHARGED, so no "
                "consumer's dependency closure can be discharged. Functional "
                "re-testing is required before any graduation."
            ),
            "per_consumer": per_consumer,
            "closure_raw_sites_total": closure_raw_total,
        },
        "unknown_vs_demonstrated_failure": {
            "unknown_coverage": unknown_coverage,
            "unknown_coverage_note": (
                "Mechanism dependence is MEASURED (symbol fingerprint) for 6 "
                "families and INFERRED (linkage/surface) for 27; isync and "
                "nginx reach L7 with no fingerprint. The join speaks for 6 of "
                "1000. Absence of a fingerprint is unknown coverage, not a pass."
            ),
            "demonstrated_failure": demonstrated_failure,
            "demonstrated_failure_note": (
                "A closure file with a raw allocator site and NO ownership "
                "seam is a known-unconverted interior site in a mechanism a "
                "consumer needs. This is the only class this refresh asserts "
                "as failure-shaped; it is not a functional regression."
            ),
        },
        "census_crosscheck": crosscheck,
        "ledger_seam_crosscheck": {
            "note": (
                "Files state.json lists as converted_files_on_branch that carry "
                "NO recognised seam token in the current tree. The file-level "
                "seam heuristic therefore UNDERCOUNTS reconstruction for "
                "structural/lock-based conversions that leave no owner token."
            ),
            "ledger_files_total": ledger_present + len(ledger_missing),
            "seam_token_present": ledger_present,
            "missing_seam_token": ledger_missing,
            "file_not_in_tree": ledger_absent,
        },
        "mapping_coverage": {
            "covered_top_level_modules": sorted(
                {p.split("/")[1] for p in closure_files if p.count("/") >= 2}
            ),
            "uncovered_top_level_modules": dict(
                sorted(uncovered_dirs.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
            "note": (
                "src modules named by none of the nine mechanism directory "
                "rules (e.g. mac, sm2, modes, des, sm3). Their conversion "
                "work is real but is OUT of this nine-mechanism closure: a "
                "known coverage gap of this refresh, not a claim they are "
                "unconverted."
            ),
        },
        "next_targets": targets,
        "non_claims": [
            "This refresh measures ownership-reconstruction progress only; it "
            "claims no SAFETY_DISCHARGED and no SAFE_COMPATIBLE.",
            "The 33 historical DROP_IN_PASS verdicts are against an EARLIER "
            "candidate; functional re-testing is required before graduation.",
            "A present seam (OwnedCtx/OwnedBuf/impl Drop/…) is "
            "OWNERSHIP_RECONSTRUCTED, never discharge.",
            "Mechanism→file association is a declared directory mapping, not a "
            "per-symbol proof; it is an upper bound used for reachability.",
            "Raw allocator sites in seam-bearing files are reported, not "
            "claimed converted.",
        ],
    }
    return doc


# --------------------------------------------------------------------------
# 5. Human report.
# --------------------------------------------------------------------------

def render_report(doc: dict) -> str:
    c = doc["candidate"]
    coh = doc["cohort"]
    scan = doc["recomputed_source_scan"]
    cm = doc["cohort_metrics"]
    us = doc["unknown_vs_demonstrated_failure"]
    L = []
    a = L.append

    a("# Safe-33 atlas refresh — candidate-bound ownership-reconstruction status")
    a("")
    a(f"Generated {doc['generated_utc']} by `{doc['generator']}` (stdlib only). "
      "**Measurement only** — no source conversion, no Phase-25 regeneration, "
      "no graduation claimed.")
    a("")
    a("## Candidate pin")
    a("")
    a(f"- HEAD `{c['head_sha']}` on `{c['branch']}`")
    a(f"- crate `{c['crate_name']} {c['crate_version']}`")
    a(f"- `src/**/*.rs`: **{c['src_rs_files']}** files, content sha256 "
      f"`{c['src_content_sha256']}`")
    a(f"- frozen inventory was at `{c['inventory_head_sha_frozen']}` (base "
      f"`{c['inventory_base_sha']}`); this refresh re-pins the current tree")
    a("")
    a("## The frozen 33 (authoritative: `state.json#cohort`)")
    a("")
    a(f"- verdict `{coh['candidate_verdict']}`, **{coh['count']}** families "
      f"({coh['levels']['L7-functional']} L7-functional, "
      f"{coh['levels']['L4-linked']} L4-linked)")
    a(f"- p1000 counts: "
      f"`DROP_IN_PASS={coh['p1000_counts']['verdicts']['DROP_IN_PASS']}`, "
      f"`DROP_IN_FAIL={coh['p1000_counts']['verdicts']['DROP_IN_FAIL']}`, "
      f"`DROP_IN_NOT_APPLICABLE={coh['p1000_counts']['verdicts']['DROP_IN_NOT_APPLICABLE']}`")
    a(f"- 33 names verified against `p1000-run.json`: "
      f"{coh['p1000_pass_families_match']}")
    a("")
    a("| family | level | libssl | evidence |")
    a("|---|---|---|---|")
    for f in coh["families"]:
        a(f"| {f['family']} | {f['level']} | {str(f['libssl']).lower()} | {f['evidence']} |")
    a("")
    a("## Nine mechanisms — ownership-reconstruction status")
    a("")
    a("`state` is from `state.json` (vocabulary: `UNSAFE_OPEN` < "
      "`OWNERSHIP_RECONSTRUCTED` < `SAFETY_DISCHARGED`; **none** is discharged). "
      "`closure` / `seam` / `no-seam+raw` are recomputed against the current tree.")
    a("")
    a("| mechanism | state | families | closure files | seam files | no-seam+raw files | closure raw sites |")
    a("|---|---|---|---|---|---|---|")
    for m in doc["mechanisms"]:
        a(f"| {m['id']} | {m['state']} | {m['families_total']} | "
          f"{m['closure_files_recomputed']} | {m['closure_seam_files']} | "
          f"{m['closure_no_seam_raw_files']} | {m['closure_raw_sites']} |")
    a("")
    a("## Cohort metrics (items 1–5, reported independently)")
    a("")
    a("| # | metric | value |")
    a("|---|---|---|")
    a(f"| 1 | unique source files in the union of the nine closures | **{cm['1_unique_closure_files']}** |")
    a(f"| 2 | files with reconstructed ownership (seam present) | **{cm['2_files_ownership_reconstructed']}** |")
    a(f"| 3 | files with fully discharged obligations | **{cm['3_files_fully_discharged_obligations']}** |")
    a(f"| 4 | unresolved interior raw-allocator sites in the closure | **{cm['4_unresolved_interior_raw_sites']['upper_bound_total']}** (upper bound; {cm['4_unresolved_interior_raw_sites']['unconverted_no_seam_sites']} unambiguous) |")
    a(f"| 5 | consumers eligible for `SAFE_COMPATIBLE` | **{cm['5_consumers_safe_compatible']}** |")
    a("")
    a(f"- **3** is 0 by construction: {cm['3_note']}")
    a(f"- **4** detail: {cm['4_unresolved_interior_raw_sites']['note']}")
    _adeff = cm['4_unresolved_interior_raw_sites']['allocator_definition_files_excluded']
    a(f"- **4** exclusions: the `CRYPTO_*` allocator definitions "
      f"({', '.join('`'+x+'`' for x in _adeff) or 'none'}) are the seam itself, "
      f"not interior residuals, and are excluded from the count above.")
    a("")
    a("### Whole-tree scan (current candidate)")
    a("")
    a(f"- files with a seam: **{scan['files_with_seam']}**")
    a(f"- files with zero raw allocator sites: **{scan['files_zero_raw_sites']}**")
    a(f"- files with raw allocator sites remaining: **{scan['files_with_raw_sites']}**")
    a(f"- raw allocator sites total (incl. legitimate seam ctors): "
      f"**{scan['raw_sites_total']}**")
    a(f"- allocator-definition files (seam itself, excluded from metric 4): "
      f"{', '.join('`'+x+'`' for x in scan['allocator_definition_files']) or 'none'}")
    a("")
    a("Seam tokens counted: " + ", ".join(f"`{t}`" for t in scan["seam_tokens"]) + ".")
    a("")
    a("> Caveat — *seam present* is a **file-level heuristic**: a file is counted as"
      " reconstructed if any seam token appears anywhere, even for an unrelated"
      " inner type. It is an upper bound on reconstructed ownership, used for"
      " reachability, never a per-site proof.")
    a("")
    a("### Mapping coverage (unknown coverage, stated)")
    a("")
    a(doc["mapping_coverage"]["note"])
    a("")
    unc = doc["mapping_coverage"]["uncovered_top_level_modules"]
    a("Top-level modules outside the nine-mechanism closure (files): " +
      ", ".join(f"`{k}`({v})" for k, v in list(unc.items())[:18]) + ".")
    a("")
    a("## Per-consumer mechanism status (metric 5)")
    a("")
    a("`recon` = mechanisms the consumer needs that are `OWNERSHIP_RECONSTRUCTED`; "
      "`open` = `UNSAFE_OPEN`. Eligible = needs **all** its mechanisms discharged.")
    a("")
    a("| family | level | mechs | recon | open | open mechanisms | eligible |")
    a("|---|---|---|---|---|---|---|")
    for p in cm["per_consumer"]:
        om = ", ".join(p["unsafe_open_ids"]) or "—"
        a(f"| {p['family']} | {p['level']} | {p['mechanisms_required']} | "
          f"{p['mechanisms_ownership_reconstructed']} | "
          f"{p['mechanisms_unsafe_open']} | {om} | no |")
    a("")
    a("## Distinguishing unknown coverage from demonstrated failure")
    a("")
    a(f"- **Unknown coverage** — {us['unknown_coverage_note']}")
    a("  - mechanisms with linkage-inferred families: " +
      ", ".join(f"{u['mechanism']} ({u['families_without_symbol_fingerprint']})"
                for u in us["unknown_coverage"]))
    a(f"- **Demonstrated failure** — {us['demonstrated_failure_note']}")
    a("  - mechanisms with unconverted (no-seam) interior files: " +
      (", ".join(f"{d['mechanism']} ({d['unconverted_interior_files']})"
                 for d in us["demonstrated_failure"]) or "none"))
    a("")
    a("## Next engineering target (reachability × residual risk)")
    a("")
    a("`score = families reaching the mechanism × unconverted no-seam interior "
      "sites`. Reachability is the count of the 33 that depend on the mechanism "
      "(upper bound); residual risk is the unambiguous no-seam interior sites.")
    a("")
    a("| rank | mechanism | state | families reaching | no-seam interior files | no-seam interior sites | score |")
    a("|---|---|---|---|---|---|---|")
    for i, t in enumerate(doc["next_targets"], 1):
        a(f"| {i} | {t['mechanism']} | {t['state']} | {t['families_reaching']} | "
          f"{t['unconverted_interior_files']} | {t['unconverted_interior_sites']} | "
          f"{t['score']} |")
    a("")
    if doc["census_crosscheck"]:
        cc = doc["census_crosscheck"]
        a("## Candidate-binding cross-check vs the frozen census")
        a("")
        a(f"- closure files matching frozen census hash: {cc['closure_files_matched']}")
        a(f"- closure files CHANGED since the frozen census: "
          f"{cc['closure_files_changed_since_frozen_census']}")
        a(f"- closure files absent from the frozen census: "
          f"{cc['closure_files_absent_from_frozen_census']}")
        a(f"- {cc['note']}")
        a("")
    ls = doc["ledger_seam_crosscheck"]
    a("## Ledger vs seam heuristic")
    a("")
    a(f"Of **{ls['ledger_files_total']}** files the ledger lists as converted on this "
      f"branch, **{len(ls['missing_seam_token'])}** carry no recognised seam token: "
      + (", ".join('`'+m['file']+'`' for m in ls['missing_seam_token']) or "none") + ".")
    a("")
    a(f"{ls['note']}")
    a("")
    a("## Non-claims")
    a("")
    for n in doc["non_claims"]:
        a(f"- {n}")
    a("")
    return "\n".join(L)


# --------------------------------------------------------------------------
# 6. Entry point.
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=None, help="repository root (default: autodetect)")
    ap.add_argument("--out-dir", default=None, help=f"output dir (default: {OUT_DIR})")
    ap.add_argument("--stdout", action="store_true", help="print report to stdout")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else repo_root()
    out_dir = (root / (args.out_dir or OUT_DIR))
    out_dir.mkdir(parents=True, exist_ok=True)

    doc = build(root, args)

    cand_path = out_dir / "candidate.json"
    cand_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = render_report(doc)
    (out_dir / "REPORT.md").write_text(report, encoding="utf-8")

    if args.stdout:
        sys.stdout.write(report)
    else:
        c = doc["candidate"]
        print(f"wrote {cand_path.relative_to(root)}")
        print(f"wrote {(out_dir / 'REPORT.md').relative_to(root)}")
        print(f"candidate HEAD {c['head_sha']} src sha256 {c['src_content_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
