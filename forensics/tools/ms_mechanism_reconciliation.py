#!/usr/bin/env python3
"""Phase 25.17 -- the vulnerability-mechanism reconciliation.

Reconciles each historical memory-corruption **mechanism** the 25.15 census classified
(`artifacts/phase25/historical-cves.json`) and the 25.16 replay re-ran
(`artifacts/phase25/cve-replay/`) against the current unsafe TCB and the independent evidence,
and records, per mechanism, whether the candidate's corresponding code region still exists and
where the mechanism's precondition stands: **ELIMINATED** (structurally excluded, or a replay
observed a safe refusal, or the operation kind is absent from the region), **RELOCATED_TO_BOUNDARY**
(the operation kind survives only at the crate's explicit FFI boundary), **HIDDEN** (the operation
kind survives inside the candidate's abstraction as an interior unsafe-block operation, and no
replay or reduction establishes the precondition), **PRESENT** (the replay observed the mechanism,
or the operation kind survives at an explicit unsafe site), or **UNRESOLVED** (the committed census
resolves no candidate region, so the correspondence is unjoined).

It is a **pure derivation**: it reads only committed planes -- the 25.15 census (the mechanism set
and the candidate regions), the 25.16 replay (the dispositions it observed), the 25.1 census (the
compiler-derived sites and their unsafe contexts), the 25.2 non-Rust TCB (the region layer), the
25.7 exposure classification (the sites' reachability authority), the 25.8 reduction axis (the
`ELIMINATED` / `RELOCATED_TO_BOUNDARY` / `HIDDEN` vocabulary it taught) and the 25.9-25.12 evidence
planes (Miri, ASan/MSan, TSan, Kani) -- and it executes nothing: no compiler, no tool, no probe. It
is therefore **metadata-only** (the manifest lists it and the guard admits it on any host).

The **axes are never conflated**: an operation that survives inside the candidate is never read as
`ELIMINATED`; a structural exclusion cites the 25.16 replay's own structure; and every non-extinct
mechanism is recorded as an honest residual. Extinction is a mechanism statement, never a
future-CVE-count prediction.

Usage:
  python3 forensics/tools/ms_mechanism_reconciliation.py --measure     # derive and write the plane
  python3 forensics/tools/ms_mechanism_reconciliation.py --check       # re-run the pure checks
  python3 forensics/tools/ms_mechanism_reconciliation.py --self-test   # metadata-only + control
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
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
)

# The Docker-only execution guard, called first. This tool executes nothing, so the manifest lists
# it `metadata_only` and the guard admits it on any host.
import phase25_guard  # noqa: E402

import memory_safety_schemas as schemas  # noqa: E402

import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "mechanisms.json"
GENERATOR = "forensics/tools/ms_mechanism_reconciliation.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_mechanism_reconciliation.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# The committed planes this reconciliation reads.
HISTORICAL_CVES = REPO_ROOT / "artifacts" / "phase25" / "historical-cves.json"
CVE_REPLAY_DIR = REPO_ROOT / "artifacts" / "phase25" / "cve-replay"
CVE_REPLAY_INDEX = CVE_REPLAY_DIR / "index.json"
SOURCE_CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
NON_RUST_TCB = REPO_ROOT / "artifacts" / "phase25" / "non-rust-tcb.json"
EXPOSURE = REPO_ROOT / "artifacts" / "phase25" / "exposure.json"
UNSAFE_REDUCTION = REPO_ROOT / "artifacts" / "phase25" / "unsafe-reduction.json"
MIRI = REPO_ROOT / "artifacts" / "phase25" / "miri.json"
ASAN_MSAN = REPO_ROOT / "artifacts" / "phase25" / "asan-msan.json"
TSAN = REPO_ROOT / "artifacts" / "phase25" / "tsan.json"
KANI = REPO_ROOT / "artifacts" / "phase25" / "kani.json"

HISTORICAL_CVES_REL = rel(HISTORICAL_CVES)
CVE_REPLAY_DIR_REL = rel(CVE_REPLAY_DIR)
CVE_REPLAY_INDEX_REL = rel(CVE_REPLAY_INDEX)
SOURCE_CENSUS_REL = rel(SOURCE_CENSUS)
NON_RUST_TCB_REL = rel(NON_RUST_TCB)
EXPOSURE_REL = rel(EXPOSURE)
UNSAFE_REDUCTION_REL = rel(UNSAFE_REDUCTION)
MIRI_REL = rel(MIRI)
ASAN_MSAN_REL = rel(ASAN_MSAN)
TSAN_REL = rel(TSAN)
KANI_REL = rel(KANI)

# The tool planes, by the schema's sanitizer/formal names, so a row cites the plane it reads.
TOOL_PLANES = {"miri": MIRI, "asan": ASAN_MSAN, "tsan": TSAN, "kani": KANI}

# The closed mechanism-disposition vocabulary. `ELIMINATED` / `RELOCATED_TO_BOUNDARY` / `HIDDEN`
# are the 25.8 axis's three reduction classes (never conflated); `PRESENT` is a reachable survival;
# `UNRESOLVED` is the honest residual where the census resolves no region.
DISPOSITIONS: tuple[str, ...] = (
    "ELIMINATED",
    "RELOCATED_TO_BOUNDARY",
    "HIDDEN",
    "PRESENT",
    "UNRESOLVED",
)

# The 25.16 replay states that eliminate a mechanism, and those that demonstrate its presence.
STRUCTURAL_STATE = "CANDIDATE_STRUCTURALLY_EXCLUDED"
REPLAY_ELIMINATION_STATES = frozenset({
    "CANDIDATE_SAFE_REJECTION",
    "CANDIDATE_FEATURE_NOT_APPLICABLE",
})
MEMORY_FAULT_STATES = frozenset({
    "CANDIDATE_REPRODUCES_MEMORY_FAULT",
    "CANDIDATE_UNSAFE_PATH_REMAINS",
    "UPSTREAM_VULNERABLE_REPRODUCED",
})

# The disposition bases. An `ELIMINATED` row's basis must be one of `ELIMINATION_BASES`, so a
# mechanism whose operation survives is never read as eliminated.
BASIS_STRUCTURAL = "structural_exclusion"
BASIS_REPLAY = "replay_elimination"
BASIS_ABSENT = "operation_absent"
BASIS_BOUNDARY = "explicit_boundary_only"
BASIS_INTERIOR = "interior_operation_survives"
BASIS_EXPLICIT = "explicit_unsafe_operation"
BASIS_OBSERVED = "replay_observation"
BASIS_UNJOINED = "region_unjoined"
ELIMINATION_BASES = frozenset({BASIS_STRUCTURAL, BASIS_REPLAY, BASIS_ABSENT})
REPLAY_ELIMINATION_BASES = frozenset({BASIS_REPLAY, BASIS_ABSENT})

# The compiler-derived unsafe-context kinds (25.1) partitioned into the explicit FFI boundary, the
# interior unsafe block (an operation hidden inside the candidate's abstraction) and the explicit
# unsafe API. A mechanism's surviving operation kind is classified by where it lives.
BOUNDARY_CONTEXT_KINDS = frozenset({"FFI_EXPORT_FN", "EXTERN_BLOCK"})
INTERIOR_CONTEXT_KINDS = frozenset({"UNSAFE_BLOCK"})
EXPLICIT_CONTEXT_KINDS = frozenset({"UNSAFE_FN", "UNSAFE_IMPL"})

# The operation kinds that can realize a memory-corruption mechanism, and, per taxonomy class, the
# subset the mechanism's precondition is realized through. This is the reconciliation's one mapping
# rule; it is recorded in the plane's `rule.kind_by_taxonomy` and re-read by the court.
ALL_MEMORY_OPERATION_KINDS: tuple[str, ...] = (
    "RAW_POINTER_DEREFERENCE", "RAW_POINTER_READ", "RAW_POINTER_WRITE", "TRANSMUTE",
    "UNSAFE_FUNCTION_CALL", "UNSAFE_METHOD_CALL", "UNSAFE_IMPL", "STATIC_MUT_ACCESS",
)
KIND_BY_TAXONOMY: dict[str, tuple[str, ...]] = {
    "HEAP_OOB_READ": ("RAW_POINTER_READ", "RAW_POINTER_DEREFERENCE"),
    "STACK_OOB_READ": ("RAW_POINTER_READ", "RAW_POINTER_DEREFERENCE"),
    "HEAP_OOB_WRITE": ("RAW_POINTER_WRITE", "RAW_POINTER_DEREFERENCE"),
    "STACK_OOB_WRITE": ("RAW_POINTER_WRITE", "RAW_POINTER_DEREFERENCE"),
    "BUFFER_OVERFLOW": ("RAW_POINTER_DEREFERENCE", "RAW_POINTER_READ", "RAW_POINTER_WRITE"),
    "USE_AFTER_FREE": ("RAW_POINTER_DEREFERENCE", "UNSAFE_FUNCTION_CALL"),
    "DOUBLE_FREE": ("UNSAFE_FUNCTION_CALL",),
    "NULL_DEREFERENCE": ("RAW_POINTER_DEREFERENCE",),
    "UNINITIALIZED_READ": ("RAW_POINTER_READ", "UNSAFE_FUNCTION_CALL"),
    "INTEGER_OVERFLOW": ("RAW_POINTER_WRITE", "RAW_POINTER_DEREFERENCE"),
    "INTEGER_UNDERFLOW": ("RAW_POINTER_WRITE", "RAW_POINTER_DEREFERENCE"),
    "TYPE_CONFUSION": ("TRANSMUTE",),
    "UNALIGNED_ACCESS": ("RAW_POINTER_READ", "RAW_POINTER_WRITE", "RAW_POINTER_DEREFERENCE"),
    "RACE_CONDITION": ("STATIC_MUT_ACCESS", "UNSAFE_FUNCTION_CALL"),
    "DATA_RACE": ("STATIC_MUT_ACCESS", "UNSAFE_FUNCTION_CALL"),
    "MEMORY_LEAK": ("UNSAFE_FUNCTION_CALL", "UNSAFE_METHOD_CALL"),
    "IMPROPER_FREE": ("UNSAFE_FUNCTION_CALL",),
}

# The committed evidence planes a reconciliation row may cite.
ALLOWED_EVIDENCE = frozenset({
    HISTORICAL_CVES_REL, CVE_REPLAY_INDEX_REL, SOURCE_CENSUS_REL, NON_RUST_TCB_REL,
    EXPOSURE_REL, UNSAFE_REDUCTION_REL, MIRI_REL, ASAN_MSAN_REL, TSAN_REL, KANI_REL,
})

NON_CLAIMS = (
    "a mechanism disposition is a statement about the candidate's structure and the committed "
    "replay evidence, never a future-CVE-count prediction: a mechanism recorded ELIMINATED is one "
    "whose precondition the candidate's structure or a replay excludes, not a claim that no new "
    "memory-corruption mechanism can exist",
    "`HIDDEN` is not `ELIMINATED`: a mechanism whose operation kind survives as an interior "
    "unsafe-block operation is recorded HIDDEN (the operation survives inside the candidate's "
    "abstraction) and never read as extinct, and every non-extinct mechanism carries an open "
    "residual",
    "`RELOCATED_TO_BOUNDARY` is not a weakening: it names an operation that survives only at the "
    "crate's explicit FFI boundary, the unavoidable crossing the ABI requires, never an operation "
    "merely wrapped so its count shrinks",
    "the taxonomy-to-operation-kind mapping is a structural proxy, not a semantic proof: it says "
    "which compiler-derived operation kinds could realize a mechanism class, never that the "
    "historical mechanism is present or absent",
    "a region match is a name-and-path join read from the committed 25.15 census and the committed "
    "25.1 census; an unjoined region is recorded UNRESOLVED rather than assumed correspondent",
    "the disposition vocabulary is the 25.8 axis's, reused: ELIMINATED, RELOCATED_TO_BOUNDARY and "
    "HIDDEN are the reduction classes and are never conflated with one another or with PRESENT",
)


# --------------------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-mechanism-reconciliation] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-") or "unjoined"


def _non_rust_paths(tcb_body: dict) -> set:
    """The first-party non-Rust source paths 25.2 inventories (C adapters, generated C, asm)."""
    out: set = set()
    for key in ("c_adapters", "generated_c", "assembly"):
        for row in tcb_body.get(key) or []:
            path = row.get("path")
            if path:
                out.add(str(path))
    return out


def load_authority() -> dict:
    """The committed planes this plane reads, loaded once so the generator and the court share bytes.

    The 25.15 census and the 25.16 replay are the mechanism set and its dispositions; the 25.1
    census and its unsafe contexts are the candidate structure; the 25.2 non-Rust TCB names the
    region layer; the 25.7 exposure classification is the sites' reachability authority; the 25.8
    reduction axis is the disposition vocabulary's own record; the 25.9-25.12 evidence planes are
    the independent tool evidence. Every columnar artefact is decoded through the one codec.
    """
    census_doc = _load(SOURCE_CENSUS)
    census_body = ms_census.decode_body(census_doc.get("body", census_doc))
    refs = ms_codec.refs_from_census(census_body)

    def dec(path: Path) -> dict:
        doc = _load(path)
        return ms_codec.decode_body(doc.get("body", doc), refs)

    return {
        "historical_cves": _load(HISTORICAL_CVES),
        "cve_replay": dec(CVE_REPLAY_INDEX),
        "source_census": census_body,
        "non_rust_tcb": dec(NON_RUST_TCB),
        "exposure": dec(EXPOSURE),
        "reduction": dec(UNSAFE_REDUCTION),
        "tools": {"miri": dec(MIRI), "asan": dec(ASAN_MSAN), "tsan": dec(TSAN), "kani": dec(KANI)},
    }


# --------------------------------------------------------------------------------------------
# the derivation
# --------------------------------------------------------------------------------------------

_DERIVE_CACHE: dict = {}


def derive_cached(authority: dict) -> dict:
    """`derive` memoised by the identity of its argument (pure and deterministic)."""
    key = id(authority)
    if key not in _DERIVE_CACHE:
        _DERIVE_CACHE[key] = derive(authority)
    return _DERIVE_CACHE[key]


def _classify(state: str, immune: bool, resolved: bool, class_present: bool, structure: str,
              path, token: str, kinds: tuple, boundary: list, interior: list, explicit: list,
              cve_ids: list) -> tuple:
    """`(disposition, basis, reason)` for one mechanism, in the closed disposition vocabulary.

    The order encodes the evidence precedence: a structural exclusion (the 25.16 replay's own
    structure) beats a replay elimination, which beats a replay observation, which beats the region
    and operation-kind analysis. A surviving operation is never read as eliminated.
    """
    kdesc = ", ".join(kinds)
    cves = ", ".join(cve_ids)
    if immune and structure:
        return "ELIMINATED", BASIS_STRUCTURAL, structure
    if state in REPLAY_ELIMINATION_STATES:
        if state == "CANDIDATE_FEATURE_NOT_APPLICABLE":
            return "ELIMINATED", BASIS_REPLAY, (
                "the 25.16 replay records the historical feature is not applicable to the admitted "
                "candidate, so the mechanism's path is absent")
        return "ELIMINATED", BASIS_REPLAY, (
            f"the 25.16 replay ({cves}) observed the candidate safely refuse the advisory's input "
            f"shape, so the vulnerable path is not reached")
    if state in MEMORY_FAULT_STATES:
        return "PRESENT", BASIS_OBSERVED, (
            f"the 25.16 replay observed the mechanism ({state}); the unsafe path is present")
    if not resolved:
        return "UNRESOLVED", BASIS_UNJOINED, (
            f"the committed census resolves no candidate region for the subsystem token {token!r}, "
            f"so the mechanism's correspondence is unjoined; recorded UNRESOLVED rather than "
            f"eliminated or present")
    if not class_present:
        return "ELIMINATED", BASIS_ABSENT, (
            f"the candidate region {path} carries no compiler-derived {kdesc} operation, so the "
            f"operation that realizes the mechanism is absent from the census")
    if boundary and not interior and not explicit:
        return "RELOCATED_TO_BOUNDARY", BASIS_BOUNDARY, (
            f"the mechanism's operation kind ({kdesc}) survives in {path} only as the crate's "
            f"explicit FFI boundary ({len(boundary)} boundary site(s))")
    if interior:
        return "HIDDEN", BASIS_INTERIOR, (
            f"the mechanism's operation kind ({kdesc}) survives in {path} as {len(interior)} "
            f"compiler-derived interior unsafe-block site(s) (not the explicit boundary), and no "
            f"replay or reduction establishes the precondition's disposition, so the reconciliation "
            f"records HIDDEN -- the operation survives inside the candidate's abstraction -- and "
            f"never ELIMINATED")
    return "PRESENT", BASIS_EXPLICIT, (
        f"the mechanism's operation kind ({kdesc}) survives in {path} at {len(explicit)} explicit "
        f"unsafe site(s), so the unsafe operation is present")


def _mechanism(tax: str, token: str, state: str, rows: list, replay_by_cve: dict,
               sites_by_file: dict, census_files: dict, contexts: dict, non_rust: set,
               reduction_files: list, tools: dict) -> dict:
    cve_ids = sorted(str(r.get("cve_id")) for r in rows)
    region_rows = [r.get("candidate_region") or {} for r in rows]
    resolved = any(bool(cr.get("resolved")) for cr in region_rows)
    path = next((str(cr.get("path")) for cr in region_rows if cr.get("resolved")), None)
    files = sorted({p for cr in region_rows for p in (cr.get("files") or [])})
    census_present = [p for p in files if p in census_files]

    kinds = KIND_BY_TAXONOMY.get(tax, ALL_MEMORY_OPERATION_KINDS)
    kindset = set(kinds)
    mech_sites = [s for p in files for s in sites_by_file.get(p, [])
                  if str(s.get("operation_kind")) in kindset]
    region_ids = [str(s.get("site_id")) for p in files for s in sites_by_file.get(p, [])]

    def ck(s: dict) -> str:
        return str((contexts.get(str(s.get("context_id"))) or {}).get("kind") or "")

    boundary = [s for s in mech_sites if ck(s) in BOUNDARY_CONTEXT_KINDS]
    interior = [s for s in mech_sites if ck(s) in INTERIOR_CONTEXT_KINDS]
    explicit = [s for s in mech_sites if ck(s) in EXPLICIT_CONTEXT_KINDS]

    class_present = bool(resolved and census_present and mech_sites)
    immune = state == STRUCTURAL_STATE
    structure = ""
    for c in cve_ids:
        s = str((replay_by_cve.get(c) or {}).get("structure") or "").strip()
        if s:
            structure = s
            break

    disp, basis, reason = _classify(state, immune, resolved, class_present, structure, path,
                                    token, kinds, boundary, interior, explicit, cve_ids)

    layer = None
    if resolved:
        layer = "non_rust_tcb" if any(p in non_rust for p in files) else "rust"

    evidence, independent = _evidence(cve_ids, region_ids, files, tools, reduction_files)
    return {
        "mechanism_id": "vm-" + _slug(tax) + "-" + _slug(token),
        "taxonomy": tax,
        "class_present": class_present,
        "candidate_structurally_immune": bool(immune),
        "reason": reason,
        "cve_ids": cve_ids,
        "evidence": evidence,
        "disposition": disp,
        "disposition_basis": basis,
        "region": {
            "token": token,
            "resolved": bool(resolved),
            "path": path,
            "file_count": len(census_present),
            "unsafe_operations": sum(census_files.get(p, 0) for p in census_present),
            "layer": layer,
            "present": bool(resolved and census_present),
        },
        "replay": {
            "state": state,
            "structure": structure,
            "harness_ran": any(bool((replay_by_cve.get(c) or {}).get("harness_ran"))
                               for c in cve_ids),
            "control_fired": any(bool((replay_by_cve.get(c) or {}).get("control_fired"))
                                 for c in cve_ids),
        },
        "operation_kinds": sorted(kindset),
        "mechanism_sites": {
            "total": len(mech_sites),
            "at_explicit_boundary": len(boundary),
            "interior_unsafe_block": len(interior),
            "explicit_unsafe": len(explicit),
        },
        "independent_evidence": independent,
    }


def _evidence(cve_ids: list, region_ids: list, files: list, tools: dict,
              reduction_files: list) -> tuple:
    """The committed evidence a row cites, and the independent tool evidence per mechanism.

    The region's sites are joined to each committed tool plane's per-site state (Miri, ASan/MSan,
    TSan), the Kani harnesses are joined by their target file, and the 25.8 reconstruction is
    recorded as applicable when its subsystem intersects the region -- so the disposition is
    corroborated (or its gap named) by an instrument other than the one that produced the census.
    """
    ev = {HISTORICAL_CVES_REL, CVE_REPLAY_INDEX_REL, SOURCE_CENSUS_REL, NON_RUST_TCB_REL,
          EXPOSURE_REL}
    for c in cve_ids:
        ev.add(f"{CVE_REPLAY_DIR_REL}/replays/{c}.json")

    independent: list = []
    for name in ("miri", "asan", "tsan"):
        body = tools.get(name) or {}
        states = body.get("sites") or {}
        if not region_ids or not states:
            continue
        hist = Counter(str((states.get(i) or {}).get("state")) for i in region_ids if i in states)
        if not hist:
            continue
        plane = rel(TOOL_PLANES[name])
        independent.append({"tool": name, "plane": plane, "region_sites": sum(hist.values()),
                            "states": dict(sorted(hist.items()))})
        ev.add(plane)

    kani = tools.get("kani") or {}
    file_set = set(files)
    harnesses = [h for h in (kani.get("harnesses") or [])
                 if str(h.get("target_file")) in file_set]
    if harnesses:
        independent.append({"tool": "kani", "plane": KANI_REL, "harnesses": [
            {"harness_id": str(h.get("harness_id")), "target_file": str(h.get("target_file")),
             "role": str(h.get("role"))}
            for h in sorted(harnesses, key=lambda h: str(h.get("harness_id")))]})
        ev.add(KANI_REL)

    independent.append({"tool": "reconstruction", "plane": UNSAFE_REDUCTION_REL,
                        "applicable": bool(set(files) & set(reduction_files))})
    ev.add(UNSAFE_REDUCTION_REL)
    return sorted(ev), independent


def _counts(mechanisms: list, n_cves: int, n_residuals: int) -> dict:
    by_disp = Counter(m["disposition"] for m in mechanisms)
    by_tax = Counter(m["taxonomy"] for m in mechanisms)
    by_basis = Counter(m["disposition_basis"] for m in mechanisms)
    return {
        "mechanisms": len(mechanisms),
        "memory_safety_cves": n_cves,
        "extinct": sum(1 for m in mechanisms if m["disposition"] == "ELIMINATED"),
        "class_present": sum(1 for m in mechanisms if m["class_present"]),
        "structurally_immune": sum(1 for m in mechanisms if m["candidate_structurally_immune"]),
        "regions_resolved": sum(1 for m in mechanisms if m["region"]["resolved"]),
        "regions_unjoined": sum(1 for m in mechanisms if not m["region"]["resolved"]),
        "by_disposition": {k: by_disp[k] for k in sorted(by_disp)},
        "by_taxonomy": {k: by_tax[k] for k in sorted(by_tax)},
        "by_basis": {k: by_basis[k] for k in sorted(by_basis)},
        "residuals": n_residuals,
    }


def derive(authority: dict) -> dict:
    """The whole reconciliation, derived: the mechanism rows, the counts and the residuals."""
    hist = _body(authority["historical_cves"])
    replay_body = authority["cve_replay"]
    census = authority["source_census"]
    non_rust = _non_rust_paths(authority["non_rust_tcb"])
    tools = authority["tools"]
    reconstruction = authority["reduction"].get("reconstruction") or {}
    reduction_files = list((reconstruction.get("subsystem") or {}).get("files") or [])

    cves = [c for c in (hist.get("cves") or []) if c.get("memory_safety")]
    sites = census.get("sites") or []
    contexts = {str(c.get("context_id")): c for c in (census.get("unsafe_contexts") or [])}
    census_files = {str(f.get("path")): int(f.get("unsafe_operations") or 0)
                    for f in (census.get("files") or [])}
    sites_by_file: dict = {}
    for s in sites:
        sites_by_file.setdefault(str(s.get("file")), []).append(s)
    replay_by_cve = {str(r.get("cve_id")): r for r in (replay_body.get("replays") or [])}

    # A mechanism is a (taxonomy class, subsystem token, replay state): CVEs that share all three
    # are one mechanism, so no row conflates two dispositions.
    groups: dict = {}
    for c in cves:
        tax = str(c.get("taxonomy"))
        token = str((c.get("subsystem") or {}).get("token") or "")
        cve = str(c.get("cve_id"))
        state = str((replay_by_cve.get(cve) or {}).get("state") or "")
        groups.setdefault((tax, token, state), []).append(c)

    mechanisms: list = []
    residuals: list = []
    for key in sorted(groups):
        tax, token, state = key
        rows = sorted(groups[key], key=lambda r: str(r.get("cve_id")))
        m = _mechanism(tax, token, state, rows, replay_by_cve, sites_by_file, census_files,
                       contexts, non_rust, reduction_files, tools)
        mechanisms.append(m)
        if m["disposition"] != "ELIMINATED":
            residuals.append({
                "residual_id": f"res-mech-{m['mechanism_id']}",
                "subject": m["mechanism_id"],
                "class": "mechanism_unreconciled",
                "disposition": "open",
                "detail": (f"{', '.join(m['cve_ids'])}: {m['disposition']} -- the mechanism is not "
                           f"shown extinct; {m['reason']}"),
                "evidence": list(m["evidence"]),
            })
    mechanisms.sort(key=lambda r: r["mechanism_id"])
    residuals.sort(key=lambda r: r["residual_id"])
    return {"mechanisms": mechanisms,
            "counts": _counts(mechanisms, len(cves), len(residuals)),
            "residuals": residuals, "cves": cves}


def _rule(authority: dict) -> dict:
    return {
        "authority": {
            "kind": "memory-safety-mechanism-reconciliation-evidence",
            "paths": [HISTORICAL_CVES_REL, CVE_REPLAY_INDEX_REL, SOURCE_CENSUS_REL, NON_RUST_TCB_REL,
                      EXPOSURE_REL, UNSAFE_REDUCTION_REL, MIRI_REL, ASAN_MSAN_REL, TSAN_REL, KANI_REL],
            "declaration": (
                "the 25.15 historical CVE census names the memory-safety mechanisms and their "
                "candidate regions, the 25.16 replay records each mechanism's disposition against "
                "the admitted candidate, 25.1's compiler-backed census gives the candidate's sites "
                "and unsafe contexts, 25.2's non-Rust TCB gives the region layer, 25.7's exposure "
                "classification is the sites' reachability authority, 25.8's reduction axis is the "
                "ELIMINATED / RELOCATED_TO_BOUNDARY / HIDDEN vocabulary, and the 25.9-25.12 "
                "evidence planes (Miri, ASan/MSan, TSan, Kani) are the independent tool evidence; "
                "no disposition, region or count is typed here"
            ),
        },
        "disposition_vocabulary": list(DISPOSITIONS),
        "disposition_rule": (
            "the disposition precedence: a 25.16 structural exclusion -> ELIMINATED (its own "
            "structure cited); a 25.16 safe rejection or feature-not-applicable -> ELIMINATED (a "
            "replay elimination); a 25.16 observed memory fault -> PRESENT; an unjoined candidate "
            "region -> UNRESOLVED; an absent operation kind -> ELIMINATED; an operation kind that "
            "survives only at the explicit FFI boundary -> RELOCATED_TO_BOUNDARY; an operation kind "
            "that survives as an interior unsafe-block site -> HIDDEN; otherwise -> PRESENT. A "
            "surviving operation is never read as ELIMINATED"
        ),
        "kind_by_taxonomy": {k: list(KIND_BY_TAXONOMY[k]) for k in sorted(KIND_BY_TAXONOMY)},
        "boundary_context_kinds": sorted(BOUNDARY_CONTEXT_KINDS),
        "interior_context_kinds": sorted(INTERIOR_CONTEXT_KINDS),
        "explicit_context_kinds": sorted(EXPLICIT_CONTEXT_KINDS),
        "sort_key": "mechanisms by mechanism_id; residuals by residual_id",
    }


def _property_findings(d: dict) -> list:
    c = d["counts"]
    by_disp = ", ".join(f"{k}={v}" for k, v in sorted(c["by_disposition"].items()))
    not_extinct = [m["mechanism_id"] for m in d["mechanisms"] if m["disposition"] != "ELIMINATED"]
    return [
        f"{c['mechanisms']} memory-corruption mechanism(s) are reconciled over "
        f"{c['memory_safety_cves']} memory-safety CVE(s) from the 25.15 census and the 25.16 "
        f"replay: by disposition {by_disp}; {c['extinct']} are shown extinct and "
        f"{c['mechanisms'] - c['extinct']} are not",
        f"{c['class_present']} of {c['mechanisms']} mechanism(s) still carry their operation kind "
        f"in the candidate structure and {c['structurally_immune']} cite a structural exclusion; "
        f"the two are recorded separately and never conflated, so a surviving operation is never "
        f"read as extinct",
        f"{c['regions_resolved']} of {c['mechanisms']} mechanism(s) join a committed candidate "
        f"region and {c['regions_unjoined']} resolve to no region (recorded UNRESOLVED, an open "
        f"residual) rather than assumed correspondent",
        ("the mechanisms not shown extinct are named rather than dropped: "
         + (", ".join(sorted(not_extinct)) if not_extinct else "none")),
        "the reconciliation is a mechanism statement about the candidate's structure and the "
        "committed replay evidence, never a future-CVE-count prediction; each row is corroborated "
        "by the independent tool evidence (25.9-25.12) and the 25.8 reconstruction axis",
    ]


def build_body(authority: dict) -> dict:
    """The reconciliation body: the rule, the mechanism rows, the counts, the residuals, findings."""
    d = derive_cached(authority)
    return {
        "rule": _rule(authority),
        "mechanisms": d["mechanisms"],
        "counts": d["counts"],
        "residuals": d["residuals"],
        "findings": _property_findings(d),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def reconciliation_findings(body: dict, authority: dict) -> list:
    """Every way the committed reconciliation contradicts the committed evidence.

    Pure over `body` and the authority (the 25.15 census, the 25.16 replay, 25.1's census, 25.2's
    non-Rust TCB, 25.7's exposure, 25.8's reduction and the 25.9-25.12 evidence planes): it is what
    the `MS-MECHANISM-RECONCILIATION` court runs. It establishes that every memory-safety CVE has
    exactly one reconciling row and no row names a CVE the census does not classify; that every row
    validates against the `vulnerability_mechanism` schema and carries a disposition from the closed
    vocabulary with committed evidence; that a present class joins a committed census region; that a
    structural immunity cites the 25.16 replay's own structure; that a surviving operation is never
    read as ELIMINATED; that every non-extinct mechanism is a residual; and that the counts and the
    whole plane equal their derivation.
    """
    problems: list = []
    d = derive_cached(authority)
    mechanisms = body.get("mechanisms") or []
    if not isinstance(mechanisms, list):
        return ["the reconciliation plane's `mechanisms` is not a list"]

    ids = [str(m.get("mechanism_id")) for m in mechanisms]
    if len(set(ids)) != len(ids):
        problems.append("the plane carries a duplicate mechanism_id, so a disposition is ambiguous")

    covered: Counter = Counter()
    for m in mechanisms:
        for c in (m.get("cve_ids") or []):
            covered[str(c)] += 1
    expected = sorted(str(c.get("cve_id")) for c in d["cves"])
    for c in expected:
        if covered.get(c, 0) == 0:
            problems.append(f"no row reconciles the memory-safety CVE {c} (dropped)")
        elif covered.get(c, 0) > 1:
            problems.append(f"the memory-safety CVE {c} is reconciled by more than one row")
    for c in sorted(covered):
        if c not in expected:
            problems.append(f"a row reconciles {c}, which the 25.15 census does not classify as a "
                            f"memory-safety mechanism")

    derived_by_id = {str(r["mechanism_id"]): r for r in d["mechanisms"]}
    for mid in sorted(set(derived_by_id) - set(ids)):
        problems.append(f"the plane omits the derived mechanism {mid} (dropped)")
    for mid in sorted(set(ids) - set(derived_by_id)):
        problems.append(f"the plane records the mechanism {mid}, which the committed evidence does "
                        f"not derive")

    for m in mechanisms:
        mid = str(m.get("mechanism_id"))
        for p in schemas.validate("vulnerability_mechanism", m):
            problems.append(f"{mid}: {p}")
        disp = m.get("disposition")
        if disp not in DISPOSITIONS:
            problems.append(f"{mid}: disposition {disp!r} is not in the closed mechanism-disposition "
                            f"vocabulary")
        ev = m.get("evidence") or []
        if not ev:
            problems.append(f"{mid}: the mechanism cites no committed evidence")
        for e in ev:
            es = str(e)
            if es not in ALLOWED_EVIDENCE and not (es.startswith(CVE_REPLAY_DIR_REL + "/replays/")
                                                   and es.endswith(".json")):
                problems.append(f"{mid}: the cited evidence {es!r} is not a committed evidence plane")

        # A present class must join a committed census region.
        if m.get("class_present") and int((m.get("region") or {}).get("file_count") or 0) == 0:
            problems.append(f"{mid}: claims a present mechanism class but joins no committed census "
                            f"region")

        # A structural immunity cites the 25.16 replay's own structure, verbatim.
        if m.get("candidate_structurally_immune"):
            rp = str((m.get("replay") or {}).get("structure") or "")
            if not str(m.get("reason") or "").strip():
                problems.append(f"{mid}: a structurally-immune mechanism states no reason")
            if str(m.get("reason") or "") != rp:
                problems.append(f"{mid}: the structural immunity does not cite the committed 25.16 "
                                f"replay structure")

        # The elimination discipline: a surviving operation is never read as ELIMINATED.
        if disp == "ELIMINATED" and not (m.get("candidate_structurally_immune")
                                         or m.get("disposition_basis") in ELIMINATION_BASES):
            problems.append(f"{mid}: reads a mechanism whose operation survives as ELIMINATED "
                            f"without a structural exclusion, a replay elimination or an absent "
                            f"operation")
        if disp != "ELIMINATED" and m.get("candidate_structurally_immune"):
            problems.append(f"{mid}: a structurally-immune mechanism carries the non-extinct "
                            f"disposition {disp!r}")

    # Every non-extinct mechanism is a residual, and every residual validates.
    residual_ids = {str(r.get("residual_id")) for r in (body.get("residuals") or [])}
    for m in mechanisms:
        if m.get("disposition") != "ELIMINATED" and \
                f"res-mech-{m.get('mechanism_id')}" not in residual_ids:
            problems.append(f"{m.get('mechanism_id')}: a non-extinct mechanism has no residual")
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}"
                     for p in schemas.validate("residual", r)]

    # The counts and the whole plane equal their derivation.
    if body.get("counts") != d["counts"]:
        problems.append("the committed `counts` is not the derived `counts`")
    if mechanisms != d["mechanisms"]:
        problems.append("the committed `mechanisms` is not the derived `mechanisms`")
    if (body.get("residuals") or []) != d["residuals"]:
        problems.append("the committed `residuals` is not the derived `residuals`")

    # The rule names its authorities and equals its derivation.
    rule = body.get("rule") or {}
    auth_paths = (rule.get("authority") or {}).get("paths") or []
    for want in (HISTORICAL_CVES_REL, CVE_REPLAY_INDEX_REL, SOURCE_CENSUS_REL, UNSAFE_REDUCTION_REL):
        if want not in auth_paths:
            problems.append(f"the reconciliation rule does not name the committed {want} as its "
                            f"authority")
    if rule != _rule(authority):
        problems.append("the committed `rule` is not the derived rule")
    return problems


def reconciliation_sensitivity_control(body: dict, authority: dict) -> dict:
    """Seed six mutations and require each caught, with specificity holding.

    Each is a distinct way the reconciliation could lie: a reconciled mechanism silently dropped; a
    disposition with no evidence; a mechanism whose operation survives read as ELIMINATED; a
    mechanism claiming a present class with no committed census region; a typed count; and a
    disposition outside the closed vocabulary.
    """
    baseline = reconciliation_findings(body, authority)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def clone() -> dict:
        return json.loads(json.dumps(body))

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = reconciliation_findings(mutated, authority)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    # m1: a reconciled mechanism silently dropped.
    def drop_mechanism() -> dict:
        b = clone()
        b["mechanisms"] = b["mechanisms"][1:]
        return b

    m1 = check("mechanism_dropped", drop_mechanism(), "omits the derived mechanism")

    # m2: a disposition with no committed evidence.
    def no_evidence() -> dict:
        b = clone()
        b["mechanisms"][0]["evidence"] = []
        return b

    m2 = check("disposition_without_evidence", no_evidence(), "cites no committed evidence")

    # m3: a mechanism whose operation survives read as ELIMINATED (hidden-unsafe read as eliminated).
    def hidden_as_eliminated() -> dict:
        b = clone()
        row = next((r for r in b["mechanisms"] if not r["candidate_structurally_immune"]),
                   b["mechanisms"][0])
        row["disposition"] = "ELIMINATED"
        row["disposition_basis"] = "interior_operation_survives"
        return b

    m3 = check("hidden_unsafe_read_as_eliminated", hidden_as_eliminated(),
               "reads a mechanism whose operation survives as ELIMINATED")

    # m4: a mechanism claiming a present class with no committed census region.
    def no_region() -> dict:
        b = clone()
        row = next((r for r in b["mechanisms"] if r["class_present"]), b["mechanisms"][0])
        row["region"] = dict(row.get("region") or {})
        row["region"]["file_count"] = 0
        return b

    m4 = check("mechanism_without_census_region", no_region(),
               "joins no committed census region")

    # m5: a typed count (a count not derived from the reconciled rows).
    def typed_count() -> dict:
        b = clone()
        b["counts"]["mechanisms"] = int(b["counts"].get("mechanisms", 0)) + 1
        return b

    m5 = check("typed_count", typed_count(), "not the derived `counts`")

    # m6: a disposition outside the closed vocabulary.
    def outside_vocabulary() -> dict:
        b = clone()
        b["mechanisms"][0]["disposition"] = "MAGIC"
        return b

    m6 = check("disposition_outside_vocabulary", outside_vocabulary(),
               "not in the closed mechanism-disposition vocabulary")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# writing and reading the plane
# --------------------------------------------------------------------------------------------

def _write_plane(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-mechanism-reconciliation-tool", path=TOOL),
        InputRef(name="historical-cves", path=HISTORICAL_CVES),
        InputRef(name="cve-replay", path=CVE_REPLAY_INDEX),
        InputRef(name="source-census", path=SOURCE_CENSUS),
        InputRef(name="non-rust-tcb", path=NON_RUST_TCB),
        InputRef(name="exposure", path=EXPOSURE),
        InputRef(name="unsafe-reduction", path=UNSAFE_REDUCTION),
        InputRef(name="miri", path=MIRI),
        InputRef(name="asan-msan", path=ASAN_MSAN),
        InputRef(name="tsan", path=TSAN),
        InputRef(name="kani", path=KANI),
    ]


def _measure() -> int:
    """Derive the reconciliation from the committed planes, and write it."""
    authority = load_authority()
    body = build_body(authority)
    problems = reconciliation_findings(body, authority)
    control = reconciliation_sensitivity_control(body, authority)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-mechanism-reconciliation", authority=auth.id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    _write_plane(OUT, doc)

    c = body["counts"]
    print(f"[ms-mechanism-reconciliation] {rel(OUT)} -- {c['mechanisms']} mechanism(s) over "
          f"{c['memory_safety_cves']} memory-safety CVE(s); extinct={c['extinct']}")
    for m in body["mechanisms"]:
        print(f"  {m['mechanism_id']:<44} {m['disposition']:<22} "
              f"basis={m['disposition_basis']:<28} sites={m['mechanism_sites']['total']}")
    print("  by disposition: " + ", ".join(f"{k}={v}"
                                           for k, v in sorted(c["by_disposition"].items())))
    print(f"  residuals={c['residuals']} control honest={control['honest']} "
          f"specificity={control['specificity_holds']}")
    print(f"  -> body_hash={doc['body_hash'][:16]} all_checks={not problems}")
    for p in problems[:24]:
        print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without reading a compiler."""
    if not OUT.is_file():
        print(f"[ms-mechanism-reconciliation] {rel(OUT)} is absent; run --measure")
        return 1
    body = _body(_load(OUT))
    authority = load_authority()
    problems = reconciliation_findings(body, authority)
    control = reconciliation_sensitivity_control(body, authority)
    if problems or not control["honest"]:
        print(f"[ms-mechanism-reconciliation] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-mechanism-reconciliation] check ok: {c['mechanisms']} mechanism(s) over "
          f"{c['memory_safety_cves']} memory-safety CVE(s); extinct={c['extinct']}; "
          f"{len(body['residuals'])} residual(s); every check holds")
    return 0


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_authority() -> dict:
    """A tiny, self-consistent set of planes exercising all five dispositions."""
    historical = {"body": {"cves": [
        {"cve_id": "CVE-2020-0001", "taxonomy": "HEAP_OOB_READ", "memory_safety": True,
         "subsystem": {"token": "crypto/alpha"},
         "candidate_region": {"resolved": True, "path": "src/alpha/", "files": ["src/alpha/a.rs"]}},
        {"cve_id": "CVE-2020-0002", "taxonomy": "TYPE_CONFUSION", "memory_safety": True,
         "subsystem": {"token": "crypto/beta"},
         "candidate_region": {"resolved": True, "path": "src/beta/", "files": ["src/beta/b.rs"]}},
        {"cve_id": "CVE-2020-0003", "taxonomy": "NULL_DEREFERENCE", "memory_safety": True,
         "subsystem": {"token": "ssl/gamma"},
         "candidate_region": {"resolved": False, "path": None, "files": []}},
        {"cve_id": "CVE-2020-0004", "taxonomy": "ALGORITHM_COMPLEXITY", "memory_safety": False,
         "subsystem": {"token": "crypto/delta"},
         "candidate_region": {"resolved": True, "path": "src/delta/", "files": ["src/delta/d.rs"]}},
        {"cve_id": "CVE-2020-0005", "taxonomy": "BUFFER_OVERFLOW", "memory_safety": True,
         "subsystem": {"token": "crypto/eps"},
         "candidate_region": {"resolved": True, "path": "src/eps/", "files": ["src/eps/e.rs"]}},
    ]}}
    replay = {"replays": [
        {"cve_id": "CVE-2020-0001", "state": "CANDIDATE_STRUCTURALLY_EXCLUDED",
         "structure": "the candidate parses into a u64", "harness_ran": True, "control_fired": True},
        {"cve_id": "CVE-2020-0002", "state": "UNKNOWN", "structure": None,
         "harness_ran": False, "control_fired": False},
        {"cve_id": "CVE-2020-0003", "state": "UNKNOWN", "structure": None,
         "harness_ran": False, "control_fired": False},
        {"cve_id": "CVE-2020-0004", "state": "CANDIDATE_SAFE_REJECTION", "structure": None,
         "harness_ran": True, "control_fired": True},
        {"cve_id": "CVE-2020-0005", "state": "UNKNOWN", "structure": None,
         "harness_ran": False, "control_fired": False},
    ]}
    census = {"files": [{"path": "src/alpha/a.rs", "unsafe_operations": 2},
                        {"path": "src/beta/b.rs", "unsafe_operations": 1},
                        {"path": "src/eps/e.rs", "unsafe_operations": 1}],
              "unsafe_contexts": [
                  {"context_id": "uc-1", "kind": "FFI_EXPORT_FN"},
                  {"context_id": "uc-2", "kind": "UNSAFE_BLOCK"},
                  {"context_id": "uc-3", "kind": "FFI_EXPORT_FN"}],
              "sites": [
                  {"site_id": "us-a", "file": "src/alpha/a.rs", "operation_kind": "RAW_POINTER_READ",
                   "context_id": "uc-1"},
                  {"site_id": "us-b", "file": "src/beta/b.rs", "operation_kind": "TRANSMUTE",
                   "context_id": "uc-2"},
                  {"site_id": "us-c", "file": "src/eps/e.rs",
                   "operation_kind": "RAW_POINTER_DEREFERENCE", "context_id": "uc-3"}]}
    empty_tool = {"sites": {}, "harnesses": []}
    return {
        "historical_cves": historical,
        "cve_replay": replay,
        "source_census": census,
        "non_rust_tcb": {"c_adapters": [], "generated_c": [], "assembly": []},
        "exposure": {"sites": {}},
        "reduction": {"reconstruction": {"subsystem": {"files": ["src/zeta/z.rs"]}}},
        "tools": {"miri": empty_tool, "asan": empty_tool, "tsan": empty_tool, "kani": empty_tool},
    }


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation is clean and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_mechanism_reconciliation.py", env={},
                                       dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_mechanism_reconciliation.py is not admitted as a metadata-only "
                        "generator on a host")

    authority = _synth_authority()
    body = build_body(authority)
    baseline = reconciliation_findings(body, authority)
    if baseline:
        failures.append(f"the synthetic reconciliation body is not clean: {baseline[:4]}")
    c = body["counts"]
    if (c["mechanisms"], c["memory_safety_cves"]) != (4, 4):
        failures.append(f"the synthetic mechanism counts are wrong: mechanisms={c['mechanisms']} "
                        f"memory_safety={c['memory_safety_cves']}")
    # The synthetic must exercise a structural ELIMINATED, a boundary RELOCATED, a hidden HIDDEN
    # and an unresolved UNRESOLVED -- and must not reconcile the non-memory-safety CVE.
    disp = c["by_disposition"]
    if disp != {"ELIMINATED": 1, "RELOCATED_TO_BOUNDARY": 1, "HIDDEN": 1, "UNRESOLVED": 1}:
        failures.append(f"the synthetic dispositions do not exercise the vocabulary: {disp}")
    if c["structurally_immune"] != 1:
        failures.append(f"the synthetic structural-immunity count is wrong: {c['structurally_immune']}")
    if c["regions_unjoined"] != 1 or c["residuals"] != 3:
        failures.append(f"the synthetic region/residual counts are wrong: unjoined="
                        f"{c['regions_unjoined']} residuals={c['residuals']}")
    covered = {c2 for m in body["mechanisms"] for c2 in m["cve_ids"]}
    if "CVE-2020-0004" in covered:
        failures.append("the synthetic reconciles a CVE the census does not classify memory-safety")

    control = reconciliation_sensitivity_control(body, authority)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-mechanism-reconciliation] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-mechanism-reconciliation] self-test ok: the guard admits it as metadata-only; the "
          "synthetic reconciliation is clean (4 mechanisms over 4 memory-safety CVEs, one each "
          "ELIMINATED / RELOCATED_TO_BOUNDARY / HIDDEN / UNRESOLVED, 1 structurally immune, 1 "
          "unjoined region, 3 residuals); and all six seeded mutations (a dropped mechanism, a "
          "disposition with no evidence, a hidden-unsafe read as eliminated, a mechanism with no "
          "census region, a typed count and a disposition outside the vocabulary) are caught with "
          "specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/mechanisms.json from the committed inputs")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed plane")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the metadata-only admission and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool executes nothing, so the manifest
    # lists it `metadata_only` and the guard admits it on any host.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return _check()
    # The default action is the derivation (and `--measure` names it): `evidence_determinism.py`
    # regenerates every generator with no flags and compares the bytes.
    return _measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
