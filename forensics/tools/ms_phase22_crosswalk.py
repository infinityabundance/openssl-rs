#!/usr/bin/env python3
"""openssl-rs — the Phase-22 reachability crosswalk (Phase 25.5).

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). 25.1 enumerates the compiler-derived unsafe
operations, 25.2 records the non-Rust trusted computing base, 25.3 gives every site an obligation
along the closed dimensions and 25.4 models the ownership/allocation/callback machinery. This
subphase is 25.5: it **maps every compiler-derived unsafe site to the OpenSSL public compatibility
roots that can reach it**, and it does so by reading the Phase-22 whole-program reachability atlas
rather than by building a second call graph.

The rule, and the authority it reads
------------------------------------
    unsafe operation -> containing Rust entity -> candidate implementation entity
       -> OpenSSL authority entity -> Phase-22 typed graph -> public compatibility root

Each step is a fact the atlas already measured, and none of it is typed here:

  * the **containing Rust entity** is the 25.1 census site's own `file`, `module` and `function`
    (the compiler established them; the census is the authority for the site);
  * the **candidate implementation entity** is the crate module the site lives in, and the
    **OpenSSL authority entity** it corresponds to is the authority translation unit the module
    *transcribes* — read from `forensics/atlas/transcription-edges.json`, whose rule is the
    dominant authority unit among the symbols the module defines, measured from the code;
  * the authority entities *of that unit* are the symbols `forensics/atlas/internal-symbols.json`
    and `forensics/atlas/export-defining-units.json` attribute to it, canonicalised to their
    Phase-22 entity keys by the same name index the closure itself uses
    (`forensics/atlas/phase22/reconciliation.json`);
  * the **Phase-22 typed graph** is the committed closure
    `forensics/atlas/phase22/compatibility-closure.json`: its declared roots, its typed edges
    (`DIRECT_CALL`, `ADDRESS_TAKEN`, `CALLBACK_SLOT`, `DISPATCH_SLOT`, `REGISTRATION`,
    `CONFIG_DISPATCH`, `RELOCATION_REFERENCE`, `EXPORTED_AS`, `GENERATED_FROM`, `BUILT_INTO`,
    `ENV_READ`, `CLI_DISPATCH`) and, above all, its own precomputed `by_root` reachability;
  * the **public compatibility root** is one of the seven populated declared root families
    (`source-api`, `binary-abi`, `modules`, `callbacks`, `cli`, `configuration`, `distribution`);
    the atlas's `by_root` is the answer to "which root reaches this entity", and this plane reads
    it rather than recomputing a competing one.

The reachability is the atlas's answer, not a second graph
----------------------------------------------------------
For every site's authority entities this plane asks the committed closure's `by_root` whether the
entity is reachable from each family. The typed edges are read only to *name the kinds that make a
reachability real* — the witness edge kinds on a path from a root member to the entity, so a raw
pointer hidden behind a `CALLBACK_SLOT`, a provider `DISPATCH_SLOT`/`REGISTRATION` or a
`RELOCATION_REFERENCE` is recorded as reachable and the kind that carries it is recorded with it.
As a consistency proof that this is the atlas's graph and not a re-derivation, the plane also walks
the committed typed edges from each family's members and requires the reached entity set to equal
the committed `by_root` set exactly; a disagreement is a finding, never a silent pass.

Unresolved sites are recorded, never defaulted
----------------------------------------------
Where the atlas cannot resolve a site — its module transcribes no authority unit in the
transcription atlas — the site gets an explicit residual with its class, its reason and its
evidence, and is never dropped and never defaulted to a root. The counts say how many.

A pure derivation, so it executes nothing
-----------------------------------------
It reads committed atlases and writes a derived plane; it runs no compiler, no tool and no probe,
so `forensics/memory-safety/container.json` lists it `metadata_only` and the Docker-only guard
admits it on any host (it still calls the guard first, so the rule is never optional).

Outputs
-------
  artifacts/phase25/phase22-crosswalk.json

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
# from committed atlases -- so the manifest lists it `metadata_only` and the guard admits it on any
# host exactly as `ms_obligations.py` and `ms_ownership_planes.py` are.
import phase25_guard  # noqa: E402

# The residual schema and its closed vocabularies. Imported, never restated.
import memory_safety_schemas as schemas  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "phase22-crosswalk.json"
GENERATOR = "forensics/tools/ms_phase22_crosswalk.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_phase22_crosswalk.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# 25.1's compiler-backed source census: the primary unit and the authority for the sites.
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"

# The Phase-22 atlas. The typed reachability closure is the authority this plane reads.
PHASE22 = REPO_ROOT / "forensics" / "atlas" / "phase22"
CLOSURE = PHASE22 / "compatibility-closure.json"
RECONCILIATION = PHASE22 / "reconciliation.json"
CLOSURE_REL = rel(CLOSURE)
RECONCILIATION_REL = rel(RECONCILIATION)

# The Phase-22 prerequisite planes that carry the Rust-module -> authority-entity correspondence.
TRANSCRIPTION = REPO_ROOT / "forensics" / "atlas" / "transcription-edges.json"
INTERNAL = REPO_ROOT / "forensics" / "atlas" / "internal-symbols.json"
EXPORT_UNITS = REPO_ROOT / "forensics" / "atlas" / "export-defining-units.json"
TRANSCRIPTION_REL = rel(TRANSCRIPTION)
INTERNAL_REL = rel(INTERNAL)
EXPORT_UNITS_REL = rel(EXPORT_UNITS)

# Residual classes for a site the atlas cannot resolve, from the schema's closed vocabulary. Each is
# an honest leftover: the site is preserved with its reason rather than dropped or defaulted.
RESIDUAL_DETAIL = {
    "evidence_missing": (
        "the containing Rust module transcribes no authority translation unit in the Phase-22 "
        "transcription atlas, so the typed graph cannot resolve the site's candidate entity; the "
        "site is recorded open and is never defaulted to a root"
    ),
    "unclassified_unsafe_site": (
        "the containing Rust module's authority translation unit has no entity the Phase-22 graph "
        "reaches from any declared compatibility root, so the site has no public root; recorded "
        "open rather than defaulted to one"
    ),
}

NON_CLAIMS = (
    "reachability is the Phase-22 typed graph's answer, not execution: a site reachable from a "
    "public root is not thereby exercised, and the absence of a root is not memory safety",
    "the seven populated compatibility-root families are the atlas's declared, observed surfaces; "
    "the three it leaves unpopulated (runtime-behaviour, protocol, dynamic-loading) are not "
    "observed by any Phase-22 instrument, so a site reached only through a dlsym/loader path is "
    "not distinguished from one reached through the seven families",
    "the resolution is at the module granularity the transcription atlas measures: a site in a "
    "shared helper maps to the authority translation unit its module transcribes, not to a single "
    "authority symbol, so several sites in one module share the module's authority entities and "
    "roots",
    "a mapped site is mapped because the atlas's committed by_root reaches the authority entity; "
    "the plane reads that answer and does not re-derive a call graph",
    "compatibility is not security: reaching a site from a public root says where a caller could "
    "meet it, not that the site's contract is discharged (25.3) or that the operation is unsound",
)


# --------------------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-phase22-crosswalk] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def load_authority() -> dict:
    """The Phase-22 authority this plane reads: the closure, its entity index and its symbol units.

    Returned as one object so the generator and the court read the same bytes and the derivation can
    be memoised by its identity.
    """
    return {
        "closure": _load(CLOSURE),
        "reconciliation": _load(RECONCILIATION),
        "transcription": _load(TRANSCRIPTION),
        "internal": _load(INTERNAL),
        "export_units": _load(EXPORT_UNITS),
    }


def _reconciliation_index(rec_doc: dict) -> tuple[set, dict]:
    """`(entity keys, name -> {keys})` from the closure's own entity plane.

    The name index reproduces the closure's resolver: a symbol name with exactly one entity key
    resolves to it, and an ambiguous name falls back to `sym|<name>`, which is simply not an entity
    key. The same canonicalisation is applied here so a symbol this plane names and the graph's
    `by_root` set are the same thing.
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


def _canonical(name: str, by_name: dict) -> str:
    cands = by_name.get(name)
    if cands and len(cands) == 1:
        return next(iter(cands))
    return "sym|" + name


def _symbols_per_unit(internal_doc: dict, export_doc: dict) -> dict:
    """`translation_unit -> {symbol names}`, the authority symbols a unit defines or exports."""
    out: dict = defaultdict(set)
    for doc in (internal_doc, export_doc):
        for r in (doc.get("body", doc).get("records") or []):
            sym, tu = r.get("symbol"), r.get("translation_unit")
            if sym and tu:
                out[tu].add(sym)
    return out


def _module_units(transcription_doc: dict) -> dict:
    """`crate module -> authority translation unit` from the transcription atlas."""
    out: dict = {}
    for m in (transcription_doc.get("body", transcription_doc).get("modules") or []):
        if m.get("module"):
            out[m["module"]] = m.get("translation_unit")
    return out


def _reachability(closure_doc: dict, entity_keys: set) -> tuple:
    """The atlas's reachability, read and corroborated.

    Returns `(families, parent, by_root, consistent)` where `by_root` is the committed answer used
    as the authority, `parent` records the typed edge each node was first reached by (for the
    witness kinds), and `consistent[f]` requires the walk over the committed typed edges to reach
    exactly the committed `by_root` entity set for family `f` -- the proof that the reachability is
    the atlas's own graph and not a re-derivation.
    """
    body = closure_doc.get("body", closure_doc)
    adj: dict = defaultdict(list)
    for row in body.get("edges") or []:
        kind, src, dst = row.split("\t", 2)
        adj[src].append((dst, kind))
    families = sorted(body.get("roots") or {})
    parent: dict = {}
    by_root: dict = {}
    consistent: dict = {}
    for f in families:
        members = list((body["roots"][f] or {}).get("members") or [])
        p: dict = {}
        seen = set(members)
        stack = list(members)
        while stack:
            n = stack.pop()
            for d, k in adj.get(n, ()):
                if d not in seen:
                    seen.add(d)
                    p[d] = (n, k)
                    stack.append(d)
        br = set(((body.get("by_root") or {}).get(f) or {}).get("reachable") or [])
        parent[f] = p
        by_root[f] = br
        consistent[f] = (seen & entity_keys) == br
    return families, parent, by_root, consistent


def _witness_kinds(parent_f: dict, target: str) -> set:
    """The typed edge kinds on the discovery path from a family member to `target`.

    Empty when `target` is itself a declared member of the family: the root reaches it with no edge.
    """
    kinds: set = set()
    cur = target
    while cur in parent_f:
        cur, kind = parent_f[cur]
        kinds.add(kind)
    return kinds


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
    """The whole crosswalk, derived: sites, units, the inverse root view, counts and residuals."""
    closure = authority["closure"].get("body", authority["closure"])
    entity_keys, by_name = _reconciliation_index(authority["reconciliation"])
    tu_syms = _symbols_per_unit(authority["internal"], authority["export_units"])
    mods = _module_units(authority["transcription"])
    families, parent, by_root, consistent = _reachability(authority["closure"], entity_keys)
    member_sets = {f: set(((closure.get("roots") or {})[f] or {}).get("members") or [])
                   for f in families}
    tu_ent = {tu: sorted({_canonical(s, by_name) for s in syms} & entity_keys)
              for tu, syms in tu_syms.items()}

    risk = {s["site_id"]: s.get("risk_tier") for s in (census_body.get("sites") or [])}

    units: dict = {}

    def unit_for(tu: str) -> dict:
        if tu in units:
            return units[tu]
        ent = tu_ent.get(tu, [])
        roots: dict = {}
        for f in families:
            hit = [k for k in ent if k in by_root[f]]
            if not hit:
                continue
            kinds: set = set()
            as_member = False
            for k in hit:
                if k in member_sets[f]:
                    as_member = True
                else:
                    kinds |= _witness_kinds(parent[f], k)
            roots[f] = {"edge_kinds": sorted(kinds), "as_member": as_member, "reached": len(hit)}
        u = {"authority_unit": tu, "authority_entities": ent, "roots": roots}
        units[tu] = u
        return u

    sites: dict = {}
    residual_groups: dict = {}
    mapped = 0

    def residual(sid: str, module: str, cls: str, function=None, unit=None) -> None:
        entry = {"module": module, "residual": cls}
        if unit is not None:
            entry["unit"] = unit
        if function is not None:
            entry["function"] = function
        sites[sid] = entry
        residual_groups.setdefault((cls, module), []).append(sid)

    for s in census_body.get("sites") or []:
        sid = s["site_id"]
        if sid in sites:
            continue
        module = s.get("file")
        tu = mods.get(module)
        if not tu:
            residual(sid, module, "evidence_missing")
            continue
        u = unit_for(tu)
        if not u["authority_entities"]:
            residual(sid, module, "unclassified_unsafe_site", unit=tu)
            continue
        if not u["roots"]:
            residual(sid, module, "unclassified_unsafe_site", function=s.get("function"), unit=tu)
            continue
        rts = sorted(u["roots"])
        kinds = sorted({k for f in rts for k in u["roots"][f]["edge_kinds"]})
        sites[sid] = {
            "unit": tu,
            "function": s.get("function"),
            "roots": rts,
            "kinds": kinds,
            "root_member": any(u["roots"][f]["as_member"] for f in rts),
        }
        mapped += 1

    # The inverse view: per public root, the sites and the kinds that reach them. Every count is
    # recomputed from the site map above, never typed.
    roots: dict = {}
    for f in families:
        meta = (closure.get("roots") or {}).get(f) or {}
        fam_kinds: Counter = Counter()
        tiers: Counter = Counter()
        units_f: set = set()
        as_member = 0
        n = 0
        for sid, e in sites.items():
            f_roots = e.get("roots") or []
            if f not in f_roots:
                continue
            n += 1
            u = units[e["unit"]]
            units_f.add(e["unit"])
            for k in u["roots"][f]["edge_kinds"]:
                fam_kinds[k] += 1
            if u["roots"][f]["as_member"]:
                as_member += 1
            tiers[risk.get(sid)] += 1
        roots[f] = {
            "declared_members": len(meta.get("members") or []),
            "reachable_entities": len(by_root[f]),
            "provenance": meta.get("provenance"),
            "sites": n,
            "units": len(units_f),
            "as_member_sites": as_member,
            "edge_kinds": dict(sorted(fam_kinds.items())),
            "sites_by_risk_tier": {str(k): v for k, v in sorted(tiers.items(), key=lambda x: str(x[0]))},
        }

    # The per-site edge-kind counts: the number of mapped sites whose union witness kinds include
    # each kind. Distinct from the per-root `edge_kinds`, which count within one family.
    kind_sites: Counter = Counter()
    for e in sites.values():
        for k in e.get("kinds") or []:
            kind_sites[k] += 1

    used_units = {e["unit"] for e in sites.values() if e.get("roots")}
    used_entities: set = set()
    for tu in used_units:
        used_entities |= set(units[tu]["authority_entities"])

    residuals: list = []
    for (cls, module), sids in sorted(residual_groups.items()):
        sids = sorted(sids)
        rid = "rx:" + hashlib.sha256(f"{cls}|{module}".encode("utf-8")).hexdigest()[:16]
        residuals.append({
            "residual_id": rid,
            "subject": module,
            "class": cls,
            "disposition": "open",
            "detail": RESIDUAL_DETAIL.get(cls, "unresolved by the Phase-22 atlas"),
            "evidence": [TRANSCRIPTION_REL, CLOSURE_REL],
            "module": module,
            "site_count": len(sids),
            "site_ids": sids,
        })

    counts = {
        "census_sites": len(census_body.get("sites") or []),
        "sites_mapped": mapped,
        "sites_unresolved": len(sites) - mapped,
        "unresolved_by_class": dict(sorted(
            Counter(cls for (cls, _m) in residual_groups).items())),
        "public_roots": len(families),
        "roots_with_sites": sum(1 for f in families if roots[f]["sites"]),
        "authority_units": len(used_units),
        "authority_entities": len(used_entities),
        "transcription_modules": len(mods),
        "edge_kinds": dict(sorted(kind_sites.items())),
    }

    return {
        "sites": sites,
        "units": units,
        "roots": roots,
        "counts": counts,
        "residuals": residuals,
        "families": families,
        "consistent": consistent,
    }


def _rule(closure: dict, families: list) -> dict:
    return {
        "authority": {
            "kind": "phase22-compatibility-closure",
            "path": CLOSURE_REL,
            "declaration": (
                "the committed Phase-22 whole-program reachability closure is the authority this "
                "plane reads; its `by_root` reachability and its typed edge graph are the answer, "
                "and no second call graph is derived"
            ),
            "edge_vocabulary": closure.get("edge_vocabulary") or [],
            "public_roots": families,
            "unpopulated_families": closure.get("unpopulated") or [],
        },
        "mapping_rule": (
            "unsafe site -> its Rust module -> the authority translation unit the module transcribes "
            "-> that unit's authority symbols (canonicalised to Phase-22 entity keys) -> the "
            "declared public compatibility roots whose committed by_root reaches them"
        ),
        "module_resolution": {
            "input": TRANSCRIPTION_REL,
            "rule": (
                "the transcription atlas maps each crate module to the dominant authority "
                "translation unit among the symbols the module defines; the map is measured "
                "from the code, so a module that defines no authority symbol is unresolved "
                "and is recorded as a residual rather than defaulted"
            ),
        },
        "authority_entity_resolution": {
            "inputs": [INTERNAL_REL, EXPORT_UNITS_REL, RECONCILIATION_REL],
            "rule": (
                "the authority symbols of a translation unit are the internal symbols and exports "
                "the atlas attributes to it; each is canonicalised to its Phase-22 entity key by "
                "the same name index the closure's resolver builds, so a symbol named here and a "
                "node in the graph are the same entity"
            ),
        },
        "reachability": {
            "rule": (
                "a family reaches an entity when the entity is in the closure's committed "
                "`by_root[family].reachable`; the committed typed edges are walked from the family "
                "members to corroborate that answer (the walk's reached entity set must equal the "
                "committed set) and to name the edge kinds on a witness path"
            ),
        },
        "edge_kinds": (
            "the kinds recorded per site are the typed-edge kinds on a witness path from a root "
            "member to the site's authority entity; a reachability carried by CALLBACK_SLOT, "
            "DISPATCH_SLOT, REGISTRATION or RELOCATION_REFERENCE is recorded with that kind, so a "
            "raw-pointer operation hidden behind a callback slot, a provider dispatch slot or a "
            "relocation is still reachable and is recorded as such"
        ),
        "root_member": (
            "as_member marks a family whose root member is itself the authority entity, so the root "
            "reaches it with no edge; it is a declared compatibility surface, not a traversal"
        ),
        "site_disposition": (
            "every census site is present in `.sites`: a mapped site carries its roots and kinds, "
            "and a site the atlas cannot resolve carries an explicit residual class with its reason "
            "in `.residuals`; a site is never dropped and never defaulted to a root"
        ),
        "sort_key": ("sites by id; units by translation unit; roots by family; every list sorted"),
    }



def _property_findings(d: dict) -> list:
    c = d["counts"]
    dist = (d["roots"].get("distribution") or {}).get("sites", 0)
    return [
        f"{c['sites_unresolved']} census site(s) have no authority translation unit in the "
        f"Phase-22 transcription atlas and are recorded as explicit unresolved residuals (class "
        f"{', '.join(c['unresolved_by_class']) or 'none'}); none is dropped and none is defaulted "
        f"to a root",
        f"the `distribution` compatibility root family reaches {dist} of the "
        f"{c['sites_mapped']} mapped census site(s) over the atlas's typed edges: its members are "
        f"installed-file entries, so it is a declared root that no unsafe site's authority entity "
        f"is reached from",
        f"reachability is the Phase-22 graph's answer, not execution: the "
        f"{c['sites_mapped']} mapped site(s) are reachable from a public root through the typed "
        f"edges, not exercised",
        f"{c['authority_entities']} authority implementation entit(ies) across "
        f"{c['authority_units']} translation unit(s) anchor the map to the OpenSSL authority",
    ]


def build_body(census_body: dict, authority: dict) -> dict:
    """The crosswalk body: the rule, the sites, the units, the inverse view, counts and residuals."""
    d = derive_cached(census_body, authority)
    closure = authority["closure"].get("body", authority["closure"])
    return {
        "rule": _rule(closure, d["families"]),
        "sites": d["sites"],
        "units": d["units"],
        "roots": d["roots"],
        "counts": d["counts"],
        "residuals": d["residuals"],
        "findings": _property_findings(d),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def crosswalk_findings(body: dict, census_body: dict, authority: dict) -> list:
    """Every way the committed crosswalk contradicts the census or the Phase-22 atlas.

    Pure over `body`, the census and the Phase-22 authority: it is what the `MS-PHASE22-CROSSWALK`
    court runs. It checks that every census site has a disposition (mapped to at least one root, or
    an explicit unresolved residual with a reason); that the site map, the unit map, the inverse
    root view, the counts and the residuals equal their derivation; that the inverse root view
    reproduces from the site map; that the reachability is the atlas's own answer (the walk over
    the committed typed edges equals the committed `by_root`); and that the plane reads the
    compatibility-closure atlas rather than a re-derived graph.
    """
    problems: list = []
    d = derive_cached(census_body, authority)

    sites = body.get("sites") or {}
    census_ids = [s["site_id"] for s in (census_body.get("sites") or [])]

    # 1. The census site ids are unique and every one has a disposition.
    if len(set(census_ids)) != len(census_ids):
        problems.append("the census carries a duplicate site_id, so a disposition is ambiguous")
    for sid in sorted(set(census_ids) - set(sites)):
        problems.append(f"the census site {sid} has no crosswalk disposition (dropped)")
    for sid in sorted(set(sites) - set(census_ids)):
        problems.append(f"the crosswalk maps {sid}, which is not a census site")

    residual_index = {(r.get("class"), r.get("module")): r for r in body.get("residuals") or []}

    # 2. Every site is mapped to a root the atlas reaches, or carries an explicit residual reason.
    for sid in sorted(set(census_ids) & set(sites)):
        e = sites[sid]
        roots = e.get("roots") or []
        if roots:
            derived_roots = (d["sites"].get(sid) or {}).get("roots") or []
            if (d["sites"].get(sid) or {}).get("residual"):
                problems.append(
                    f"{sid}: the atlas records an unresolved residual for this site, but the "
                    f"crosswalk defaults it to the root(s) {roots}"
                )
                continue
            for f in roots:
                if f not in d["families"]:
                    problems.append(f"{sid}: {f} is not a declared public compatibility root")
                elif f not in derived_roots:
                    problems.append(
                        f"{sid}: the root {f} is recorded, but the Phase-22 atlas does not reach "
                        f"this site's authority entity from it"
                    )
        else:
            cls = e.get("residual")
            if not cls:
                problems.append(f"{sid}: the site has no public root and no residual class, so it "
                                f"is silent about its reachability")
                continue
            r = residual_index.get((cls, e.get("module")))
            if r is None:
                problems.append(f"{sid}: the residual {cls} for module {e.get('module')} has no "
                                f"reason record in `.residuals`")
            elif not r.get("detail"):
                problems.append(f"{sid}: the residual {cls} names no reason")

    # 3. The inverse view reproduces from the forward map.
    for f in d["families"]:
        want = sum(1 for e in sites.values() if f in (e.get("roots") or []))
        got = (body.get("roots") or {}).get(f, {}).get("sites")
        if got != want:
            problems.append(
                f"the inverse root view disagrees with the site map: root {f} records {got!r} "
                f"site(s), the site map has {want}"
            )

    # 4. Every plane equals its derivation.
    for key in ("sites", "units", "roots", "counts", "residuals"):
        if body.get(key) != d[key]:
            problems.append(f"the committed `{key}` is not the derived `{key}`")

    # 5. The reachability is the Phase-22 atlas's own answer, not a re-derived graph.
    rule_authority = ((body.get("rule") or {}).get("authority") or {})
    if rule_authority.get("path") != CLOSURE_REL:
        problems.append(
            f"the mapping rule does not name the Phase-22 compatibility-closure atlas "
            f"({CLOSURE_REL}) as its authority; it must not re-derive a competing graph"
        )
    for f, ok in d["consistent"].items():
        if not ok:
            problems.append(
                f"the walk over the committed typed edges does not reproduce the committed by_root "
                f"reachable set for root {f}, so the reachability is not the atlas's own answer"
            )

    # 6. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}" for p in schemas.validate("residual", r)]

    return problems


def crosswalk_sensitivity_control(body: dict, census_body: dict, authority: dict) -> dict:
    """Seed five mutations and require each caught, with specificity holding.

    Each is a distinct way the crosswalk could lie: a site silently dropped; a site mapped to a
    root the atlas does not reach; the inverse root view disagreeing with the forward map; an
    unresolved site defaulted to a root; and the authority re-pointed away from the Phase-22 atlas.
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

    mapped = sorted(sid for sid, e in body["sites"].items() if e.get("roots"))
    unresolved = sorted(sid for sid, e in body["sites"].items() if e.get("residual"))

    # m1: a census site silently dropped.
    def drop_site() -> dict:
        b = clone()
        b["sites"].pop(mapped[0], None)
        return b

    m1 = check("site_dropped", drop_site(), "no crosswalk disposition")

    # m2: a site mapped to a root the atlas does not reach (a declared family it is not reached
    # from). `distribution` reaches no site on the real tree; the synthetic names one too.
    def root_without_path() -> dict:
        b = clone()
        e = b["sites"][mapped[0]]
        for f in sorted(b["roots"]):
            if f not in e["roots"]:
                e["roots"] = sorted(e["roots"] + [f])
                break
        return b

    m2 = check("root_without_path", root_without_path(),
               "does not reach this site's authority entity")

    # m3: the inverse root view disagreeing with the forward map.
    def inverse_disagrees() -> dict:
        b = clone()
        for f in sorted(b["roots"]):
            if b["roots"][f]["sites"]:
                b["roots"][f]["sites"] += 1
                break
        return b

    m3 = check("inverse_view_disagrees", inverse_disagrees(),
               "inverse root view disagrees with the site map")

    # m4: an unresolved site defaulted to a root.
    def default_unresolved_to_root() -> dict:
        b = clone()
        sid = unresolved[0]
        b["sites"][sid] = {"unit": "crypto/fabricated.c", "function": "fabricated",
                           "roots": ["source-api"], "kinds": [], "root_member": False}
        return b

    m4 = check("unresolved_defaulted_to_root", default_unresolved_to_root(),
               "defaults it to the root")

    # m5: the authority re-pointed away from the Phase-22 atlas.
    def authority_not_atlas() -> dict:
        b = clone()
        b["rule"]["authority"]["path"] = "forensics/atlas/phase22/reconciliation.json"
        return b

    m5 = check("authority_not_atlas", authority_not_atlas(),
               "does not name the Phase-22 compatibility-closure atlas")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_authority() -> dict:
    """A tiny, self-consistent Phase-22 authority: one TU, a direct call and a dispatch slot."""
    fm = {"key": "k", "name": "n", "space": "s", "file": "f"}
    entities = [
        {"k": "sym|ROOTFN", "n": "ROOTFN", "s": "symbol", "f": "include/openssl/root.h"},
        {"k": "sym|IMPL1", "n": "IMPL1", "s": "symbol", "f": "crypto/syn/impl.c"},
        {"k": "sym|IMPL2", "n": "IMPL2", "s": "symbol", "f": "crypto/syn/impl.c"},
        {"k": "sym|HIDDEN", "n": "HIDDEN", "s": "symbol", "f": "crypto/syn/impl.c"},
        {"k": "sym|REGTBL", "n": "REGTBL", "s": "symbol", "f": "crypto/syn/reg.c"},
        {"k": "sym|CLIONLY", "n": "CLIONLY", "s": "symbol", "f": "apps/other.c"},
    ]
    reconciliation = {"body": {"field_map": fm, "entities": entities}}
    transcription = {"body": {"modules": [{"module": "src/syn.rs",
                                           "translation_unit": "crypto/syn/impl.c"}]}}
    internal = {"body": {"records": [
        {"symbol": "IMPL1", "translation_unit": "crypto/syn/impl.c"},
        {"symbol": "IMPL2", "translation_unit": "crypto/syn/impl.c"},
        {"symbol": "HIDDEN", "translation_unit": "crypto/syn/impl.c"},
    ]}}
    export_units = {"body": {"records": [{"symbol": "IMPL1",
                                          "translation_unit": "crypto/syn/impl.c"}]}}
    closure = {"body": {
        "roots": {
            "source-api": {"members": ["sym|ROOTFN"], "provenance": "synthetic"},
            "modules": {"members": ["sym|REGTBL"], "provenance": "synthetic"},
            "cli": {"members": ["sym|CLIONLY"], "provenance": "synthetic"},
        },
        "by_root": {
            "source-api": {"reachable": ["sym|ROOTFN", "sym|IMPL1", "sym|IMPL2"]},
            "modules": {"reachable": ["sym|REGTBL", "sym|HIDDEN"]},
            "cli": {"reachable": ["sym|CLIONLY"]},
        },
        "edges": [
            "DIRECT_CALL\tsym|ROOTFN\tsym|IMPL1",
            "DIRECT_CALL\tsym|IMPL1\tsym|IMPL2",
            "DISPATCH_SLOT\tsym|REGTBL\tsym|HIDDEN",
        ],
        "edge_vocabulary": [{"kind": "DIRECT_CALL"}, {"kind": "DISPATCH_SLOT"}],
        "unpopulated": [],
    }}
    return {"closure": closure, "reconciliation": reconciliation, "transcription": transcription,
            "internal": internal, "export_units": export_units}


def _synth_census() -> dict:
    return {"sites": [
        {"site_id": "us-syn-1", "file": "src/syn.rs", "module": "syn", "function": "impl1",
         "risk_tier": "S2"},
        {"site_id": "us-syn-2", "file": "src/syn.rs", "module": "syn", "function": "impl2",
         "risk_tier": "S3"},
        {"site_id": "us-syn-3", "file": "src/unmapped.rs", "module": "unmapped",
         "function": "plain", "risk_tier": "S4"},
    ]}


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation is clean and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_phase22_crosswalk.py", env={},
                                       dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_phase22_crosswalk.py is not admitted as a metadata-only generator on "
                        "a host")

    census = _synth_census()
    authority = _synth_authority()
    body = build_body(census, authority)
    baseline = crosswalk_findings(body, census, authority)
    if baseline:
        failures.append(f"the synthetic crosswalk body is not clean: {baseline[:4]}")
    # The synthetic must exercise both a direct call and a dispatch-slot kind, and both dispositions.
    if body["counts"]["sites_mapped"] != 2 or body["counts"]["sites_unresolved"] != 1:
        failures.append(f"the synthetic body's disposition counts are wrong: {body['counts']}")
    kinds = body["sites"]["us-syn-2"]["kinds"] if "us-syn-2" in body["sites"] else []
    if "DISPATCH_SLOT" not in kinds:
        failures.append(f"the synthetic body does not record the DISPATCH_SLOT witness kind: {kinds}")
    control = crosswalk_sensitivity_control(body, census, authority)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-phase22-crosswalk] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-phase22-crosswalk] self-test ok: the guard admits it as metadata-only; the "
          "synthetic crosswalk body is clean (2 mapped, 1 unresolved, a DIRECT_CALL and a "
          "DISPATCH_SLOT witness kind); and all five seeded mutations (a dropped site, a root the "
          "atlas does not reach, an inverse view that disagrees, an unresolved site defaulted to a "
          "root and an authority re-pointed away from the atlas) are caught with specificity "
          "holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_planes(path: Path, doc: dict) -> None:
    """Write the plane compactly, key-sorted and deterministic.

    The plane carries tens of thousands of sites, so pretty-printing would multiply the file
    without adding evidence; determinism is preserved (sorted keys, fixed separators) and
    `body_hash` covers the body.
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
        InputRef(name="ms-phase22-crosswalk-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="phase22-compatibility-closure", path=CLOSURE),
        InputRef(name="phase22-reconciliation", path=RECONCILIATION),
        InputRef(name="transcription-edges", path=TRANSCRIPTION),
        InputRef(name="internal-symbols", path=INTERNAL),
        InputRef(name="export-defining-units", path=EXPORT_UNITS),
    ]


def _measure() -> int:
    """Derive the crosswalk from the committed census and the Phase-22 atlas, and write it."""
    census_body = _load(CENSUS).get("body", {})
    authority = load_authority()
    body = build_body(census_body, authority)
    problems = crosswalk_findings(body, census_body, authority)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-phase22-crosswalk", authority=auth.id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    _write_planes(OUT, doc)

    c = body["counts"]
    print(f"[ms-phase22-crosswalk] {c['sites_mapped']} site(s) mapped to a public root, "
          f"{c['sites_unresolved']} unresolved residual(s), over {c['public_roots']} public root(s)")
    print(f"  sites by root: "
          + ", ".join(f"{f}={body['roots'][f]['sites']}" for f in sorted(body["roots"])))
    print(f"  edge kinds (sites): {c['edge_kinds']}")
    print(f"  authority: {c['authority_units']} translation unit(s), "
          f"{c['authority_entities']} entit(ies)")
    print(f"  -> {rel(OUT)} all_pass={not problems} (findings={len(body['findings'])})")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed crosswalk, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-phase22-crosswalk] {rel(OUT)} is absent; run --measure")
        return 1
    body = _load(OUT).get("body", {})
    census_body = _load(CENSUS).get("body", {})
    authority = load_authority()
    problems = crosswalk_findings(body, census_body, authority)
    if problems:
        print(f"[ms-phase22-crosswalk] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-phase22-crosswalk] check ok: {c['sites_mapped']} mapped, "
          f"{c['sites_unresolved']} unresolved, {c['public_roots']} public root(s); every check "
          f"holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/phase22-crosswalk.json from the committed inputs")
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
