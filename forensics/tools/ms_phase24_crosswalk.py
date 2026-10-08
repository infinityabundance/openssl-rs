#!/usr/bin/env python3
"""openssl-rs — the Phase-24 downstream crosswalk (Phase 25.6).

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). 25.1 enumerates the compiler-derived unsafe
operations, 25.2 records the non-Rust trusted computing base, 25.3 gives every site an obligation
and 25.4 models the ownership/allocation/callback machinery. 25.5 maps every site to the OpenSSL
public compatibility roots the Phase-22 reachability atlas reaches it from. This subphase is 25.6:
it **maps every compiler-derived unsafe site to the Phase-24 downstream population that reaches
it**, and it does so by reading the committed Phase-24 measurement rather than by typing a
consumer.

The rule, and the authority it reads
------------------------------------
    unsafe site -> its authority translation unit (25.5) -> the OpenSSL public surface the unit
       names -> the Phase-24 consumers whose recorded imports reach that surface

Each step is a fact a committed Phase-24 plane measured, and none of it is typed here:

  * the **authority translation unit** of a site is the 25.5 crosswalk's own resolution
    (`artifacts/phase25/phase22-crosswalk.json`); a site 25.5 could not resolve has no authority
    surface and is recorded `NOT_OBSERVED` with that reason, never dropped;
  * the **OpenSSL public surface** a unit names is the authority entities the Phase-22 atlas
    attributes to it (`units[tu].authority_entities`), canonicalised to Phase-22 entity keys by the
    same name index the closure's resolver builds (`forensics/atlas/phase22/reconciliation.json`), so
    a symbol the consumers import and a node in the atlas are the same entity;
  * the **Phase-24 consumers** are the families with a recorded **usage fingerprint**
    (`forensics/downstream/usage-fingerprints.json`): the imported OpenSSL symbols, the public
    headers and the measured level the 24.3 census recorded. A consumer *reaches* a site when one of
    its imported OpenSSL symbols is a symbol the site's authority unit names — an **import**
    observation, which is downstream evidence and never an execution of the site;
  * a consumer is **runtime-observed** when the committed 24.9 runtime atlas
    (`forensics/downstream/runtime-functional-atlas.json`) records a candidate run at one of the
    atlas's functional levels (`rule.levels`), so the site's library surface was exercised by the
    workload — for the measured workload only, never for the site;
  * the **usage clusters** are 24.12's connected components over the measured consumers
    (`forensics/downstream/reconciliation.json`), read rather than recomputed;
  * the **counted population** is the frozen 1,000 families
    (`forensics/downstream/family-freeze.json`), and the build/link and drop-in evidence are the
    committed 24.6/24.11 atlases (`build-link-atlas.json`, `p1000-run.json`).

The join is the Phase-24 measurement's answer, not a second one
--------------------------------------------------------------
For every site's unit this plane asks the committed usage fingerprints whether an imported symbol is
one the unit names. It reads no source, runs no compiler and drives no workload: the imports, the
levels, the clusters and the population are the Phase-24 measurement's, and a consumer the Phase-24
planes do not measure is not invented to fill a gap.

Partial joins are residuals, never zeros or guesses
---------------------------------------------------
Where the join cannot be closed it is recorded rather than defaulted:

  * an **imported symbol with no clean entity mapping** — not a Phase-22 symbol entity, or an
    ambiguous name — gets an explicit `join_evidence_missing` residual, so the consumer's evidence is
    preserved instead of being read as "reaches nothing";
  * a **runtime-observed family with no usage fingerprint** has a runtime observation but no
    symbol-level import to attribute it to, so it is recorded as a `join_evidence_missing` residual
    rather than guessed onto a site;
  * a **site with no authority unit** is `NOT_OBSERVED` with the reason the 25.5 crosswalk gives.

A pure derivation, so it executes nothing
-----------------------------------------
It reads committed planes and writes a derived plane; it runs no compiler, no tool and no probe, so
`forensics/memory-safety/container.json` lists it `metadata_only` and the Docker-only guard admits it
on any host (it still calls the guard first, so the rule is never optional).

Outputs
-------
  artifacts/phase25/phase24-crosswalk.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
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

# The Docker-only execution guard, called first. This tool executes nothing -- it derives a plane
# from committed planes -- so the manifest lists it `metadata_only` and the guard admits it on any
# host exactly as `ms_phase22_crosswalk.py` is.
import phase25_guard  # noqa: E402

# The residual schema and its closed vocabularies. Imported, never restated.
import memory_safety_schemas as schemas  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "phase24-crosswalk.json"
GENERATOR = "forensics/tools/ms_phase24_crosswalk.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_phase24_crosswalk.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# 25.1's compiler-backed source census: the primary unit and the authority for the sites.
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"

# 25.5's Phase-22 reachability crosswalk: the site -> authority-unit resolution this plane reads.
PHASE22_CROSSWALK = REPO_ROOT / "artifacts" / "phase25" / "phase22-crosswalk.json"

# The Phase-22 entity plane, read for the same name index the closure's own resolver builds, so a
# symbol a consumer imports and a node in the atlas are the same entity.
PHASE22_RECONCILIATION = REPO_ROOT / "forensics" / "atlas" / "phase22" / "reconciliation.json"

# The Phase-24 downstream planes. The committed measurement is the authority this plane reads.
DS = REPO_ROOT / "forensics" / "downstream"
USAGE_FINGERPRINTS = DS / "usage-fingerprints.json"
RECONCILIATION = DS / "reconciliation.json"
RUNTIME_ATLAS = DS / "runtime-functional-atlas.json"
BUILD_LINK_ATLAS = DS / "build-link-atlas.json"
P1000_RUN = DS / "p1000-run.json"
FAMILY_FREEZE = DS / "family-freeze.json"

CENSUS_REL = rel(CENSUS)
PHASE22_CROSSWALK_REL = rel(PHASE22_CROSSWALK)
PHASE22_RECONCILIATION_REL = rel(PHASE22_RECONCILIATION)
USAGE_FINGERPRINTS_REL = rel(USAGE_FINGERPRINTS)
RECONCILIATION_REL = rel(RECONCILIATION)
RUNTIME_ATLAS_REL = rel(RUNTIME_ATLAS)
BUILD_LINK_ATLAS_REL = rel(BUILD_LINK_ATLAS)
P1000_RUN_REL = rel(P1000_RUN)
FAMILY_FREEZE_REL = rel(FAMILY_FREEZE)

# The site dispositions. `NOT_OBSERVED` is a recorded state, never an omission.
STATES: tuple[str, ...] = (
    "DOWNSTREAM_RUNTIME_OBSERVED",
    "DOWNSTREAM_IMPORT_OBSERVED",
    "NOT_OBSERVED",
)

# Why a site is `NOT_OBSERVED`: the closed reasons, so an unobserved site is explained rather than
# merely counted.
NOT_OBSERVED_REASONS: tuple[str, ...] = (
    "no_authority_unit",
    "no_measured_consumer_reaches_the_surface",
)

# The residual class for a partial join: an imported symbol with no clean entity mapping, or a
# runtime-observed family with no usage fingerprint. It is a member of the schema's residual
# vocabulary (added by 25.6; see docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 4.5).
JOIN_RESIDUAL_CLASS = "join_evidence_missing"

NON_CLAIMS = (
    "a downstream import does not prove the site executed, and a runtime observation covers the "
    "measured workload only: a site whose unit a consumer imports is reached by that consumer's "
    "symbol table, not exercised, and a functional run attests the workload ran, not that it "
    "entered the site",
    "the join speaks for the measured population: only the families the 24.3 usage census "
    "fingerprinted carry symbol-level import evidence, so a counted family without a fingerprint "
    "cannot be attributed to a site and is not counted as reaching one",
    "reaching a site downstream is not a memory-safety finding: the join says a measured consumer's "
    "imports point at the site's public surface, and it makes no statement about the site's contract "
    "(25.3), its reachability from a root (25.5) or its soundness",
    "the import evidence is the ELF symbol table the 24.3 census read, so a consumer linked "
    "statically or through a private copy of the library is not observed here, and a symbol resolved "
    "through a dlsym/loader path is not distinguished from one linked at build time",
    "the counted population is a selected population, not a random sample: the 1,000 families chosen "
    "from frozen ranking evidence do not generalise to all downstream software, and the join inherits "
    "that selection",
)


# --------------------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-phase24-crosswalk] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def load_authority() -> dict:
    """The committed planes this plane reads, loaded once so the generator and the court share bytes."""
    return {
        "census": _load(CENSUS),
        "phase22_crosswalk": _load(PHASE22_CROSSWALK),
        "phase22_reconciliation": _load(PHASE22_RECONCILIATION),
        "usage_fingerprints": _load(USAGE_FINGERPRINTS),
        "reconciliation": _load(RECONCILIATION),
        "runtime": _load(RUNTIME_ATLAS),
        "build_link": _load(BUILD_LINK_ATLAS),
        "p1000": _load(P1000_RUN),
        "family_freeze": _load(FAMILY_FREEZE),
    }


def _name_index(rec_doc: dict) -> tuple[set, dict]:
    """`(entity keys, name -> {keys})` from the Phase-22 closure's own entity plane.

    The name index reproduces the closure's resolver: a symbol name with exactly one entity key
    resolves to it, and an ambiguous name falls back to `sym|<name>`, which is not an entity key. The
    same canonicalisation is applied here so a symbol a consumer imports and a symbol a unit names
    are the same entity.
    """
    body = rec_doc.get("body", rec_doc)
    field_map = body.get("field_map") or {}
    kf, nf, sf = field_map.get("key"), field_map.get("name"), field_map.get("space")
    keys: set = set()
    by_name: dict = defaultdict(set)
    for e in body.get("entities") or []:
        k = e.get(kf)
        if k is None:
            continue
        keys.add(k)
        if e.get(sf) == "symbol":
            by_name[e.get(nf)].add(k)
    return keys, by_name


def _canonical(name: str, by_name: dict) -> str | None:
    """The Phase-22 entity key a symbol name resolves to, or `None` when it resolves to none.

    `None` is the honest answer for a symbol with no clean entity mapping -- an ambiguous name or a
    name the Phase-22 entity plane does not carry -- and it becomes a `join_evidence_missing`
    residual rather than a silent miss.
    """
    cands = by_name.get(name)
    if cands and len(cands) == 1:
        return next(iter(cands))
    return None


def _candidate_runs(body: dict) -> list:
    return [r for r in (body.get("runs") or []) if r.get("subject") == "candidate"]


# --------------------------------------------------------------------------------------------
# the consumers, read from the Phase-24 measurement
# --------------------------------------------------------------------------------------------

def _consumers(authority: dict, keys: set, by_name: dict) -> tuple[dict, list]:
    """The measured consumers, and the imported symbols that did not map to an entity.

    Each consumer is a family the 24.3 usage census fingerprinted: it carries the imported OpenSSL
    symbols, the public headers and the level the census recorded. The runtime atlas decides whether
    the family was also observed functionally, the build/link atlas whether its linkage was proven,
    and the drop-in run its verdict -- every one a committed Phase-24 plane.
    """
    fps = authority["usage_fingerprints"].get("body", authority["usage_fingerprints"])
    runtime = authority["runtime"].get("body", authority["runtime"])
    build_link = authority["build_link"].get("body", authority["build_link"])
    p1000 = authority["p1000"].get("body", authority["p1000"])
    counted = {str(f.get("family_id"))
               for f in (authority["family_freeze"].get("body", authority["family_freeze"])
                         .get("p1000") or [])}

    functional = set(runtime.get("rule", {}).get("levels") or [])
    runtime_level: dict = {}
    for r in _candidate_runs(runtime):
        fid = str(r.get("family_id"))
        lvl = r.get("level")
        prev = runtime_level.get(fid)
        if prev is None or (lvl in functional and prev not in functional):
            runtime_level[fid] = lvl
    link_proven: dict = {}
    for r in _candidate_runs(build_link):
        fid = str(r.get("family_id"))
        link_proven[fid] = link_proven.get(fid, False) or bool(r.get("linkage_proven"))
    receipts = {str(r.get("family_id")): r for r in (p1000.get("per_consumer_receipts") or [])}

    consumers: dict = {}
    unmapped: list = []
    for f in fps.get("fingerprints") or []:
        name = str(f.get("canonical_name"))
        fid = str(f.get("family_id"))
        imports = sorted({str(s) for s in (f.get("imported_openssl_symbols") or []) if s})
        mapped: set = set()
        for s in imports:
            k = _canonical(s, by_name)
            if k is None or k not in keys:
                unmapped.append((name, s))
            else:
                mapped.add(k)
        lvl = runtime_level.get(fid)
        rec = receipts.get(fid) or {}
        consumers[name] = {
            "family_id": fid,
            "imported_symbols": imports,
            "mapped_import_keys": mapped,
            "headers": sorted({str(h) for h in (f.get("openssl_headers") or []) if h}),
            "census_level": f.get("max_level"),
            "level": lvl,
            "runtime_observed": bool(lvl in functional),
            "link_proven": bool(link_proven.get(fid)),
            "counted": fid in counted,
            "p1000_result": (rec.get("result") if rec else None),
        }
    return consumers, unmapped


def _clusters(authority: dict) -> tuple[dict, list]:
    """`(consumer -> cluster id, [cluster ids])` from 24.12's usage clusters, read not recomputed."""
    body = authority["reconciliation"].get("body", authority["reconciliation"])
    clusters = (body.get("clusters") or {}).get("clusters") or []
    name_to_cluster: dict = {}
    ids: list = []
    for c in clusters:
        cid = str(c.get("cluster_id"))
        ids.append(cid)
        for m in c.get("members") or []:
            name_to_cluster[str(m)] = cid
    return name_to_cluster, sorted(ids)


# --------------------------------------------------------------------------------------------
# the derivation
# --------------------------------------------------------------------------------------------

_DERIVE_CACHE: dict = {}


def derive_cached(census_body: dict, authority: dict) -> dict:
    """`derive` memoised by the identity of its two arguments (pure and deterministic)."""
    key = (id(census_body), id(authority))
    if key not in _DERIVE_CACHE:
        _DERIVE_CACHE[key] = derive(census_body, authority)
    return _DERIVE_CACHE[key]


def derive(census_body: dict, authority: dict) -> dict:
    """The whole crosswalk, derived: sites, consumers, the inverse view, counts and residuals."""
    xw = authority["phase22_crosswalk"].get("body", authority["phase22_crosswalk"])
    xw_sites = xw.get("sites") or {}
    xw_units = xw.get("units") or {}
    keys, by_name = _name_index(authority["phase22_reconciliation"])
    consumers, unmapped = _consumers(authority, keys, by_name)
    name_to_cluster, cluster_ids = _clusters(authority)

    # Per-unit consumer sets. A consumer reaches a unit when one of its imported symbols is a symbol
    # the unit's authority entities name; it is runtime-observed for the unit when it also has a
    # functional run. Computed once per unit, since tens of thousands of sites share the units.
    unit_direct: dict = {}
    unit_runtime: dict = {}
    for tu, u in xw_units.items():
        ent = set(u.get("authority_entities") or [])
        direct = sorted(n for n, c in consumers.items() if c["mapped_import_keys"] & ent)
        unit_direct[tu] = direct
        unit_runtime[tu] = [n for n in direct if consumers[n]["runtime_observed"]]

    risk = {str(s["site_id"]): s.get("risk_tier") for s in (census_body.get("sites") or [])}
    risk_rank = {t: i for i, t in enumerate(schemas.RISK_TIERS)}

    census_ids = [str(s["site_id"]) for s in (census_body.get("sites") or [])]
    sites: dict = {}
    for sid in census_ids:
        e = xw_sites.get(sid)
        if not e or e.get("residual"):
            sites[sid] = {"unit": None, "consumers": [], "clusters": [],
                          "state": "NOT_OBSERVED", "reason": "no_authority_unit"}
            continue
        tu = e.get("unit")
        direct = unit_direct.get(tu, [])
        if not direct:
            sites[sid] = {"unit": tu, "consumers": [], "clusters": [],
                          "state": "NOT_OBSERVED",
                          "reason": "no_measured_consumer_reaches_the_surface"}
            continue
        runtime = unit_runtime.get(tu, [])
        clusters = sorted({name_to_cluster[n] for n in direct if n in name_to_cluster})
        state = ("DOWNSTREAM_RUNTIME_OBSERVED" if runtime
                 else "DOWNSTREAM_IMPORT_OBSERVED")
        sites[sid] = {
            "unit": tu,
            "consumers": direct,
            "runtime_consumers": runtime,
            "clusters": clusters,
            "state": state,
        }

    # The inverse consumer view: per consumer, the sites it reaches and its bounded top sites. Every
    # count is recomputed from the site map above, never typed.
    inverse: dict = {}
    for name in sorted(consumers):
        c = consumers[name]
        reached = sorted(sid for sid, e in sites.items() if name in (e.get("consumers") or []))
        by_state = Counter(sites[sid]["state"] for sid in reached)
        top = sorted(reached, key=lambda s: (risk_rank.get(risk.get(s), len(risk_rank)), s))[:20]
        inverse[name] = {
            "family_id": c["family_id"],
            "counted": c["counted"],
            "cluster": name_to_cluster.get(name),
            "imported_symbols": len(c["imported_symbols"]),
            "mapped_imports": len(c["mapped_import_keys"]),
            "headers": len(c["headers"]),
            "census_level": c["census_level"],
            "runtime_level": c["level"],
            "runtime_observed": c["runtime_observed"],
            "link_proven": c["link_proven"],
            "p1000_result": c["p1000_result"],
            "reachable_sites": len(reached),
            "reachable_sites_by_state": dict(sorted(by_state.items())),
            "top_sites": top,
        }

    # The residuals. A partial join is recorded, never zeroed or guessed.
    residuals: list = []
    unmapped_by_symbol: dict = defaultdict(list)
    for name, sym in unmapped:
        unmapped_by_symbol[sym].append(name)
    for sym, names in sorted(unmapped_by_symbol.items()):
        names = sorted(set(names))
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"{JOIN_RESIDUAL_CLASS}|symbol|{sym}".encode("utf-8")).hexdigest()[:16],
            "subject": sym,
            "class": JOIN_RESIDUAL_CLASS,
            "disposition": "open",
            "detail": ("the imported OpenSSL symbol has no clean Phase-22 entity mapping (it is not "
                       "a Phase-22 symbol entity, or its name is ambiguous), so the consumer(s) that "
                       "import it cannot be joined to an authority unit; preserved rather than read "
                       "as reaching nothing"),
            "evidence": [USAGE_FINGERPRINTS_REL, PHASE22_RECONCILIATION_REL],
            "symbol": sym,
            "consumers": names,
        })
    # A runtime-observed family with no usage fingerprint has a runtime observation but no
    # symbol-level import to attribute it to; recording it is the honest alternative to a guess.
    fingerprinted = {c["family_id"] for c in consumers.values()}
    runtime_families: dict = {}
    for r in _candidate_runs(authority["runtime"].get("body", authority["runtime"])):
        fid = str(r.get("family_id"))
        lvl = r.get("level")
        functional = set((authority["runtime"].get("body", authority["runtime"])
                          .get("rule", {}) or {}).get("levels") or [])
        if lvl in functional:
            runtime_families[fid] = str(r.get("canonical_name"))
    for fid, name in sorted(runtime_families.items()):
        if fid in fingerprinted:
            continue
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"{JOIN_RESIDUAL_CLASS}|runtime|{fid}".encode("utf-8")).hexdigest()[:16],
            "subject": name,
            "class": JOIN_RESIDUAL_CLASS,
            "disposition": "open",
            "detail": ("the family was observed at runtime at a functional level but carries no "
                       "committed usage fingerprint, so its runtime surface has no symbol-level "
                       "import to attribute to an authority unit; recorded rather than attributed "
                       "to a site"),
            "evidence": [RUNTIME_ATLAS_REL, USAGE_FINGERPRINTS_REL],
            "family_id": fid,
        })
    # The census sites 25.5 could not resolve to an authority unit are one recorded partial join.
    no_unit = sum(1 for e in sites.values() if e["state"] == "NOT_OBSERVED"
                  and e["reason"] == "no_authority_unit")
    if no_unit:
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"evidence_missing|no_authority_unit".encode("utf-8")).hexdigest()[:16],
            "subject": "census sites with no Phase-22 authority unit",
            "class": "evidence_missing",
            "disposition": "open",
            "detail": ("the site's containing module transcribes no authority translation unit in "
                       "the Phase-22 transcription atlas, so it has no OpenSSL public surface for a "
                       "consumer to reach; recorded, never dropped and never defaulted to a "
                       "consumer"),
            "evidence": [PHASE22_CROSSWALK_REL, CENSUS_REL],
            "site_count": no_unit,
        })

    states = {s["state"] for s in sites.values()}
    population = {str(f.get("family_id"))
                  for f in (authority["family_freeze"].get("body", authority["family_freeze"])
                            .get("p1000") or [])}
    counts = {
        "census_sites": len(census_ids),
        "sites_with_authority_unit": sum(1 for e in sites.values() if e["unit"] is not None),
        "sites_without_authority_unit": no_unit,
        "sites_runtime_observed": sum(1 for e in sites.values()
                                      if e["state"] == "DOWNSTREAM_RUNTIME_OBSERVED"),
        "sites_import_observed": sum(1 for e in sites.values()
                                     if e["state"] == "DOWNSTREAM_IMPORT_OBSERVED"),
        "sites_not_observed": sum(1 for e in sites.values() if e["state"] == "NOT_OBSERVED"),
        "not_observed_by_reason": dict(sorted(
            Counter(e["reason"] for e in sites.values()
                    if e["state"] == "NOT_OBSERVED").items())),
        "consumers": len(consumers),
        "consumers_with_imports": sum(1 for c in consumers.values() if c["imported_symbols"]),
        "consumers_runtime_observed": sum(1 for c in consumers.values() if c["runtime_observed"]),
        "consumers_link_proven": sum(1 for c in consumers.values() if c["link_proven"]),
        "counted_families": len(population),
        "consumers_counted": sum(1 for c in consumers.values() if c["counted"]),
        "consumers_outside_the_counted_population": sum(1 for c in consumers.values()
                                                        if not c["counted"]),
        "usage_clusters": len(cluster_ids),
        "imported_symbols": len({s for c in consumers.values() for s in c["imported_symbols"]}),
        "imported_symbols_mapped": len({k for c in consumers.values()
                                        for k in c["mapped_import_keys"]}),
        "imported_symbols_unmapped": len(unmapped_by_symbol),
        "runtime_families_without_a_fingerprint": sum(1 for fid in runtime_families
                                                      if fid not in fingerprinted),
        "reachable_sites": sum(1 for e in sites.values() if e.get("consumers")),
        "states": sorted(states),
    }

    return {
        "sites": sites,
        "consumers": inverse,
        "counts": counts,
        "residuals": residuals,
        "unmapped_symbols": sorted(unmapped_by_symbol),
        "runtime_families": runtime_families,
    }


def _rule(authority: dict) -> dict:
    runtime = authority["runtime"].get("body", authority["runtime"])
    return {
        "authority": {
            "kind": "phase24-downstream-measurement",
            "paths": [USAGE_FINGERPRINTS_REL, RECONCILIATION_REL, RUNTIME_ATLAS_REL,
                      BUILD_LINK_ATLAS_REL, P1000_RUN_REL, FAMILY_FREEZE_REL],
            "declaration": (
                "the committed Phase-24 downstream measurement is the authority this plane reads: the "
                "24.3 usage fingerprints carry the imported OpenSSL symbols, 24.9 the runtime levels, "
                "24.6 the proven linkage, 24.11 the drop-in verdicts, 24.12 the usage clusters and "
                "the family freeze the counted population; no consumer is typed"
            ),
            "functional_levels": list(runtime.get("rule", {}).get("levels") or []),
            "counted_population": FAMILY_FREEZE_REL,
        },
        "mapping_rule": (
            "unsafe site -> its authority translation unit (the 25.5 crosswalk's resolution) -> the "
            "OpenSSL public surface the unit names (its Phase-22 authority entities, canonicalised to "
            "entity keys) -> the Phase-24 measured consumers whose imported OpenSSL symbols are "
            "symbols the unit names"
        ),
        "surface": {
            "rule": (
                "a unit's OpenSSL public surface is the authority entities the Phase-22 atlas "
                "attributes to it; a consumer reaches the unit when one of its imported OpenSSL "
                "symbols canonicalises to one of those entity keys by the closure's own name index, "
                "so a symbol a consumer imports and a node in the atlas are the same entity"
            ),
            "input": PHASE22_CROSSWALK_REL,
        },
        "import_observation": (
            "a reaching consumer is an **import** observation: the consumer's ELF symbol table names "
            "a symbol the site's unit provides, which is downstream evidence and never an execution "
            "of the site"
        ),
        "runtime_observation": {
            "rule": (
                "a consumer is runtime-observed when the committed 24.9 runtime atlas records a "
                "candidate run at one of the atlas's own functional levels; a site is "
                "DOWNSTREAM_RUNTIME_OBSERVED when a runtime-observed consumer reaches it, and "
                "DOWNSTREAM_IMPORT_OBSERVED when only a non-functional consumer reaches it"
            ),
            "input": RUNTIME_ATLAS_REL,
        },
        "usage_clusters": {
            "rule": (
                "the site's usage clusters are the cluster ids of the reaching consumers, read from "
                "24.12's connected components over the measured consumers' imported-symbol sets"
            ),
            "input": RECONCILIATION_REL,
        },
        "site_disposition": (
            "every census site is present in `.sites`: an observed site carries its reaching "
            "consumers, its runtime consumers, its usage clusters and its state, and a site no "
            "measured consumer reaches is `NOT_OBSERVED` with a reason; a site is never dropped"
        ),
        "partial_join": (
            "a partial join is a residual, never a zero or a guess: an imported symbol with no clean "
            "entity mapping and a runtime-observed family with no usage fingerprint are "
            "`join_evidence_missing` residuals, and a site with no authority unit is a recorded "
            "`evidence_missing` residual"
        ),
        "sort_key": ("sites by id; consumers by name; residuals by id; every list sorted"),
    }


def _property_findings(d: dict) -> list:
    c = d["counts"]
    consumers = d["consumers"]
    top = sorted(consumers, key=lambda n: (-consumers[n]["reachable_sites"], n))[:3]
    return [
        f"{c['sites_not_observed']} census site(s) are `NOT_OBSERVED`: "
        f"{c['not_observed_by_reason'].get('no_authority_unit', 0)} have no Phase-22 authority unit "
        f"(the 25.5 residual) and "
        f"{c['not_observed_by_reason'].get('no_measured_consumer_reaches_the_surface', 0)} are "
        f"mapped to a unit no measured consumer imports; recorded, never dropped",
        f"the join speaks for {c['consumers']} measured consumer(s) of {c['counted_families']} "
        f"fingerprinted famil(ies): only the families the 24.3 usage census fingerprinted carry "
        f"symbol-level import evidence, so a counted family without a fingerprint is not counted as "
        f"reaching any site",
        f"the top consumers by reachable-site count are "
        + ", ".join(f"{n}={consumers[n]['reachable_sites']}" for n in top)
        + f"; {c['sites_runtime_observed']} site(s) are DOWNSTREAM_RUNTIME_OBSERVED and "
        f"{c['sites_import_observed']} DOWNSTREAM_IMPORT_OBSERVED",
        f"{c['imported_symbols_unmapped']} imported symbol(s) "
        f"({', '.join(d['unmapped_symbols']) or 'none'}) have no clean Phase-22 entity mapping and "
        f"are recorded as join_evidence_missing residuals; "
        f"{c['runtime_families_without_a_fingerprint']} runtime-observed family/-ies without a "
        f"fingerprint cannot be attributed to a site and are recorded too",
        f"reaching a site is import evidence, not execution: {c['reachable_sites']} site(s) are "
        f"reached by a measured consumer's symbol table, and a runtime observation covers the "
        f"measured workload only",
    ]


def build_body(census_body: dict, authority: dict) -> dict:
    """The crosswalk body: the rule, the sites, the consumers, counts, residuals and findings."""
    d = derive_cached(census_body, authority)
    return {
        "rule": _rule(authority),
        "sites": d["sites"],
        "consumers": d["consumers"],
        "counts": d["counts"],
        "residuals": d["residuals"],
        "findings": _property_findings(d),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def crosswalk_findings(body: dict, census_body: dict, authority: dict) -> list:
    """Every way the committed crosswalk contradicts the census or the Phase-24 measurement.

    Pure over `body`, the census and the Phase-24 authority: it is what the `MS-PHASE24-CROSSWALK`
    court runs. It checks that every census site has a disposition (a state plus its consumers, or
    `NOT_OBSERVED` with a reason); that an observed site's consumers are measured consumers that
    reach it and a runtime-observed site has a runtime-observed consumer; that the inverse view
    reproduces from the forward map; that the site map, the consumer view, the counts and the
    residuals equal their derivation; that every partial join is a residual; and that the plane reads
    the committed Phase-24 measurement rather than a typed one.
    """
    problems: list = []
    d = derive_cached(census_body, authority)

    sites = body.get("sites") or {}
    census_ids = [str(s["site_id"]) for s in (census_body.get("sites") or [])]

    # 1. The census site ids are unique and every one has a disposition.
    if len(set(census_ids)) != len(census_ids):
        problems.append("the census carries a duplicate site_id, so a disposition is ambiguous")
    for sid in sorted(set(census_ids) - set(sites)):
        problems.append(f"the census site {sid} has no crosswalk disposition (dropped)")
    for sid in sorted(set(sites) - set(census_ids)):
        problems.append(f"the crosswalk maps {sid}, which is not a census site")

    # 2. Every site is observed with reaching consumers, or NOT_OBSERVED with a closed reason.
    for sid in sorted(set(census_ids) & set(sites)):
        e = sites[sid]
        state = e.get("state")
        cons = e.get("consumers") or []
        if state not in STATES:
            problems.append(f"{sid}: the state {state!r} is not a downstream disposition")
            continue
        if state == "NOT_OBSERVED":
            if cons:
                problems.append(f"{sid}: NOT_OBSERVED but names reaching consumers {cons}")
            if e.get("reason") not in NOT_OBSERVED_REASONS:
                problems.append(f"{sid}: NOT_OBSERVED without a closed reason")
            continue
        if not cons:
            problems.append(f"{sid}: is {state} but names no reaching consumer")
            continue
        for c in cons:
            if c not in d["consumers"]:
                problems.append(f"{sid}: the consumer {c!r} is not a measured Phase-24 consumer")
        # The runtime distinction is the measurement's: a DOWNSTREAM_RUNTIME_OBSERVED site needs a
        # runtime-observed consumer, and a DOWNSTREAM_IMPORT_OBSERVED site must not have one.
        runtime = [c for c in cons if c in d["consumers"]
                   and d["consumers"][c]["runtime_observed"]]
        if state == "DOWNSTREAM_RUNTIME_OBSERVED" and not runtime:
            problems.append(
                f"{sid}: is DOWNSTREAM_RUNTIME_OBSERVED but its consumer(s) {cons} have no runtime "
                f"row at a functional level"
            )

    # 3. The inverse consumer view reproduces from the forward site map.
    for name, rec in (body.get("consumers") or {}).items():
        want = sum(1 for e in sites.values() if name in (e.get("consumers") or []))
        if rec.get("reachable_sites") != want:
            problems.append(
                f"the inverse consumer view disagrees with the site map: consumer {name} records "
                f"{rec.get('reachable_sites')!r} reaching site(s), the site map has {want}"
            )
        for sid in rec.get("top_sites") or []:
            if name not in ((sites.get(sid) or {}).get("consumers") or []):
                problems.append(
                    f"the inverse consumer view names {sid} for {name}, which the site map does not "
                    f"record as reached by it"
                )

    # 4. Every partial join is a residual: the unmapped symbols and the unattributable families.
    residual_symbols = {r.get("symbol") for r in (body.get("residuals") or []) if r.get("symbol")}
    for sym in d["unmapped_symbols"]:
        if sym not in residual_symbols:
            problems.append(f"the imported symbol {sym} has no clean entity mapping and no residual")
    residual_families = {r.get("family_id") for r in (body.get("residuals") or []) if r.get("family_id")}
    for fid, name in sorted(d["runtime_families"].items()):
        if fid not in {c["family_id"] for c in d["consumers"].values()} and fid not in residual_families:
            problems.append(f"the runtime-observed family {name} has no fingerprint and no residual")

    # 5. Every plane equals its derivation.
    for key in ("sites", "consumers", "counts", "residuals"):
        if body.get(key) != d[key]:
            problems.append(f"the committed `{key}` is not the derived `{key}`")

    # 6. The rule names the Phase-24 measurement, not a typed consumer source.
    rule_authority = (body.get("rule") or {}).get("authority") or {}
    paths = rule_authority.get("paths") or []
    if USAGE_FINGERPRINTS_REL not in paths or RUNTIME_ATLAS_REL not in paths:
        problems.append(
            f"the mapping rule does not name the committed Phase-24 measurement "
            f"({USAGE_FINGERPRINTS_REL}, {RUNTIME_ATLAS_REL}) as its authority; it must not type a "
            f"consumer"
        )

    # 7. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}" for p in schemas.validate("residual", r)]

    return problems


def crosswalk_sensitivity_control(body: dict, census_body: dict, authority: dict) -> dict:
    """Seed five mutations and require each caught, with specificity holding.

    Each is a distinct way the crosswalk could lie: a site silently dropped; a site marked
    runtime-observed with no runtime row; the inverse consumer view disagreeing with the forward
    map; a typed consumer count; and a partial join left without its residual.
    """
    baseline = crosswalk_findings(body, census_body, authority)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = crosswalk_findings(mutated, census_body, authority)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    observed = sorted(sid for sid, e in body["sites"].items() if e.get("consumers"))
    unobserved = sorted(sid for sid, e in body["sites"].items() if e.get("state") == "NOT_OBSERVED")
    consumers = sorted(body["consumers"])

    # m1: a census site silently dropped.
    def drop_site() -> dict:
        b = clone()
        b["sites"].pop(observed[0], None)
        return b

    m1 = check("site_dropped", drop_site(), "no crosswalk disposition")

    # m2: a site marked runtime-observed with no runtime row (no consumer at all).
    def runtime_without_row() -> dict:
        b = clone()
        sid = unobserved[0]
        b["sites"][sid] = {"unit": None, "consumers": [], "runtime_consumers": [], "clusters": [],
                           "state": "DOWNSTREAM_RUNTIME_OBSERVED"}
        return b

    m2 = check("runtime_without_row", runtime_without_row(),
               "is DOWNSTREAM_RUNTIME_OBSERVED but names no reaching consumer")

    # m3: the inverse consumer view disagreeing with the forward map.
    def inverse_disagrees() -> dict:
        b = clone()
        b["consumers"][consumers[0]]["reachable_sites"] += 1
        return b

    m3 = check("inverse_view_disagrees", inverse_disagrees(),
               "inverse consumer view disagrees with the site map")

    # m4: a typed consumer count (a count not derived from the site map).
    def typed_count() -> dict:
        b = clone()
        b["counts"]["sites_runtime_observed"] += 1
        return b

    m4 = check("typed_consumer_count", typed_count(), "not the derived `counts`")

    # m5: a partial join left without its residual (the unmapped symbol's residual removed).
    def residual_omitted() -> dict:
        b = clone()
        b["residuals"] = [r for r in b["residuals"]
                          if r.get("class") != JOIN_RESIDUAL_CLASS or not r.get("symbol")]
        return b

    m5 = check("residual_omitted", residual_omitted(), "no clean entity mapping and no residual")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_authority() -> dict:
    """A tiny, self-consistent set of Phase-24 planes: two units, three consumers, one cluster."""
    fm = {"key": "k", "name": "n", "space": "s", "file": "f"}
    entities = [
        {"k": "sym|IMPL1", "n": "IMPL1", "s": "symbol", "f": "crypto/syn/impl.c"},
        {"k": "sym|IMPL2", "n": "IMPL2", "s": "symbol", "f": "crypto/syn/impl.c"},
        {"k": "sym|IMPL3", "n": "IMPL3", "s": "symbol", "f": "crypto/syn/other.c"},
        {"k": "sym|ROOTFN", "n": "ROOTFN", "s": "symbol", "f": "include/openssl/root.h"},
    ]
    phase22_reconciliation = {"body": {"field_map": fm, "entities": entities}}
    phase22_crosswalk = {"body": {
        "sites": {
            "us-syn-1": {"unit": "crypto/syn/impl.c", "roots": ["source-api"], "kinds": [],
                         "root_member": True},
            "us-syn-2": {"unit": "crypto/syn/impl.c", "roots": ["source-api"], "kinds": [],
                         "root_member": False},
            "us-syn-3": {"module": "src/unmapped.rs", "residual": "evidence_missing"},
            "us-syn-4": {"unit": "crypto/syn/other.c", "roots": ["source-api"], "kinds": [],
                         "root_member": False},
        },
        "units": {
            "crypto/syn/impl.c": {"authority_unit": "crypto/syn/impl.c",
                                  "authority_entities": ["sym|IMPL1", "sym|IMPL2"], "roots": {}},
            "crypto/syn/other.c": {"authority_unit": "crypto/syn/other.c",
                                   "authority_entities": ["sym|IMPL3"], "roots": {}},
        },
    }}
    usage_fingerprints = {"body": {"fingerprints": [
        {"canonical_name": "alpha", "family_id": "family:alpha",
         "imported_openssl_symbols": ["IMPL1"], "openssl_headers": ["openssl/syn.h"],
         "max_level": "L5-loaded"},
        {"canonical_name": "delta", "family_id": "family:delta",
         "imported_openssl_symbols": ["IMPL3"], "openssl_headers": [], "max_level": "L4-linked"},
        {"canonical_name": "gamma", "family_id": "family:gamma",
         "imported_openssl_symbols": ["NOPE"], "openssl_headers": [], "max_level": "L4-linked"},
    ]}}
    reconciliation = {"body": {"clusters": {"clusters": [
        {"cluster_id": "cluster:alpha", "members": ["alpha"], "size": 1},
        {"cluster_id": "cluster:delta", "members": ["delta"], "size": 1},
    ]}}}
    runtime = {"body": {
        "runs": [
            {"subject": "candidate", "family_id": "family:alpha", "canonical_name": "alpha",
             "level": "L7-functional"},
            {"subject": "candidate", "family_id": "family:omega", "canonical_name": "omega",
             "level": "L7-functional"},
        ],
        "rule": {"levels": ["L5-loaded", "L6-runtime", "L7-functional"]},
    }}
    build_link = {"body": {"runs": [
        {"subject": "candidate", "family_id": "family:alpha", "linkage_proven": True},
        {"subject": "candidate", "family_id": "family:delta", "linkage_proven": True},
    ]}}
    p1000 = {"body": {"per_consumer_receipts": [
        {"family_id": "family:alpha", "result": "DROP_IN_PASS"},
        {"family_id": "family:delta", "result": "DROP_IN_PASS"},
    ]}}
    family_freeze = {"body": {"p1000": [
        {"family_id": "family:alpha"}, {"family_id": "family:delta"},
    ]}}
    return {
        "census": None,
        "phase22_crosswalk": phase22_crosswalk,
        "phase22_reconciliation": phase22_reconciliation,
        "usage_fingerprints": usage_fingerprints,
        "reconciliation": reconciliation,
        "runtime": runtime,
        "build_link": build_link,
        "p1000": p1000,
        "family_freeze": family_freeze,
    }


def _synth_census() -> dict:
    return {"sites": [
        {"site_id": "us-syn-1", "risk_tier": "S2"},
        {"site_id": "us-syn-2", "risk_tier": "S3"},
        {"site_id": "us-syn-3", "risk_tier": "S4"},
        {"site_id": "us-syn-4", "risk_tier": "S1"},
    ]}


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation is clean and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_phase24_crosswalk.py", env={},
                                       dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_phase24_crosswalk.py is not admitted as a metadata-only generator on "
                        "a host")

    census = _synth_census()
    authority = _synth_authority()
    body = build_body(census, authority)
    baseline = crosswalk_findings(body, census, authority)
    if baseline:
        failures.append(f"the synthetic crosswalk body is not clean: {baseline[:4]}")
    c = body["counts"]
    if (c["sites_runtime_observed"], c["sites_import_observed"], c["sites_not_observed"]) != (2, 1, 1):
        failures.append(f"the synthetic disposition counts are wrong: {c}")
    if c["consumers"] != 3 or c["usage_clusters"] != 2:
        failures.append(f"the synthetic consumer/cluster counts are wrong: {c}")
    # The synthetic must exercise both a join residual (the unmapped symbol) and the state split.
    classes = {r["class"] for r in body["residuals"]}
    if JOIN_RESIDUAL_CLASS not in classes or "evidence_missing" not in classes:
        failures.append(f"the synthetic residuals do not carry both classes: {sorted(classes)}")
    control = crosswalk_sensitivity_control(body, census, authority)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-phase24-crosswalk] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-phase24-crosswalk] self-test ok: the guard admits it as metadata-only; the "
          "synthetic crosswalk body is clean (2 runtime-observed, 1 import-observed, 1 "
          "not-observed; 3 consumers, 2 clusters; a join and an evidence residual); and all five "
          "seeded mutations (a dropped site, a runtime-observed site with no runtime row, an "
          "inverse view that disagrees, a typed consumer count and a partial join with no residual) "
          "are caught with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_planes(path: Path, doc: dict) -> None:
    """Write the plane compactly, key-sorted and deterministic.

    The plane carries tens of thousands of sites, so pretty-printing would multiply the file without
    adding evidence; determinism is preserved (sorted keys, fixed separators) and `body_hash` covers
    the body.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-phase24-crosswalk-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="phase22-crosswalk", path=PHASE22_CROSSWALK),
        InputRef(name="phase22-reconciliation", path=PHASE22_RECONCILIATION),
        InputRef(name="downstream-usage-fingerprints", path=USAGE_FINGERPRINTS),
        InputRef(name="downstream-reconciliation", path=RECONCILIATION),
        InputRef(name="downstream-runtime-functional-atlas", path=RUNTIME_ATLAS),
        InputRef(name="downstream-build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="downstream-p1000-run", path=P1000_RUN),
        InputRef(name="downstream-family-freeze", path=FAMILY_FREEZE),
    ]


def _measure() -> int:
    """Derive the crosswalk from the committed census and the Phase-24 measurement, and write it."""
    census_body = _load(CENSUS).get("body", {})
    authority = load_authority()
    body = build_body(census_body, authority)
    problems = crosswalk_findings(body, census_body, authority)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-phase24-crosswalk", authority=auth.id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    _write_planes(OUT, doc)

    c = body["counts"]
    print(f"[ms-phase24-crosswalk] {c['sites_runtime_observed']} site(s) DOWNSTREAM_RUNTIME_OBSERVED, "
          f"{c['sites_import_observed']} DOWNSTREAM_IMPORT_OBSERVED, "
          f"{c['sites_not_observed']} NOT_OBSERVED over {c['consumers']} measured consumer(s)")
    print("  top consumers by reachable sites: "
          + ", ".join(f"{n}={body['consumers'][n]['reachable_sites']}"
                      for n in sorted(body["consumers"],
                                      key=lambda n: (-body["consumers"][n]["reachable_sites"], n))[:5]))
    print(f"  clusters: {c['usage_clusters']}; residuals: {len(body['residuals'])} "
          f"({c['imported_symbols_unmapped']} unmapped symbol(s))")
    print(f"  -> {rel(OUT)} all_pass={not problems} (findings={len(body['findings'])})")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed crosswalk, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-phase24-crosswalk] {rel(OUT)} is absent; run --measure")
        return 1
    body = _load(OUT).get("body", {})
    census_body = _load(CENSUS).get("body", {})
    authority = load_authority()
    problems = crosswalk_findings(body, census_body, authority)
    if problems:
        print(f"[ms-phase24-crosswalk] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-phase24-crosswalk] check ok: {c['sites_runtime_observed']} runtime-observed, "
          f"{c['sites_import_observed']} import-observed, {c['sites_not_observed']} not-observed; "
          f"{c['consumers']} consumer(s), {len(body['residuals'])} residual(s); every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/phase24-crosswalk.json from the committed inputs")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed crosswalk")
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
