#!/usr/bin/env python3
"""openssl-rs — Phase 23 courts: the multitrack authority machinery courts.

Each court is an instrument that makes the multitrack authority model of
`docs/RELEASE_GATES.md` section 1 mechanical over releases and authorities that are already
admitted, not a differential probe over a symbol set. This stratum owns no exported symbol: it
emits independently-evidenced compatibility *views*, so its evidence is about the model -- the
release nodes and their chronology, the authority nodes and their builds, the lineage and entity
relations between releases, the delta between two nodes, the directional and dimension-specific
compatibility views and edges, the negative obligations, the security lineage, the support status
of each node, and the assembled matrix. The method is Phases 3 through 21's where an artefact
carries the expectation: each court reads the artefact that holds its subject rather than typing the
expectation beside it, so the two cannot disagree, and a court whose control is not honest is
`fail` rather than `pass`.

**One court is registered.** 23.1 lands `RT-RELEASE-CATALOG`, the release catalogue and lineage
court; the other eleven courts are named in `PENDING_COURTS` and land with the subphases that
build the instruments they drive. The registry is the file `run_courts.py` checks is
reproduced, so a court silently dropped is a finding rather than a smaller green run. This is
the reverse of Phase 16's edge: the ledger's contract-unit states are measured from this registry,
so this runner does **not** bind the obligations ledger as an input.

The record kinds these courts will populate are defined and self-tested in
`forensics/tools/multitrack_schemas.py`; the registry records that schema inventory so the record
kinds are a file the evidence points at rather than prose the plan would have to restate.

The twelve courts, and the subphase that lands each
---------------------------------------------------
  * `RT-RELEASE-CATALOG` -- 23.1, the release-node catalogue and its lineage (registered).
  * `RT-AUTHORITY-NODES` -- 23.2, the authority-node registry.
  * `RT-LINEAGE-EDGES` -- 23.3, the lineage edges.
  * `RT-ENTITY-LINEAGE` -- 23.4, the entity lineage.
  * `RT-DELTA-ENGINE` -- 23.5, the delta engine.
  * `RT-COMPATIBILITY-VIEWS` -- 23.6, the compatibility views.
  * `RT-COMPATIBILITY-EDGES` -- 23.7, the directional compatibility edges.
  * `RT-NEGATIVE-OBLIGATIONS` -- 23.8, the negative obligations.
  * `RT-SECURITY-LINEAGE` -- 23.9, the security lineage.
  * `RT-SUPPORT-STATUS` -- 23.10, the support-status ladder.
  * `RT-COMPATIBILITY-MATRIX` -- 23.11, the compatibility matrix.
  * `MULTITRACK-SEAL` -- 23.12, the full matrix, the FRF/Gemel chain and the seal.

Every one but `RT-RELEASE-CATALOG` is `pending`. A passing court is an instrument, not a property
claim, and this stratum makes no one-boolean compatibility claim anywhere: compatibility is
directional and dimension-specific, cross-version receipts are never inherited, and a historical
vulnerability is observed but never reintroduced.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 4.2 is the precondition.
No court is registered in `gen_frf_courts.py`: that registry is the stratum's seal.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
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
    write_json,
)

# The schemas the later subphases validate their records against. Imported rather than restated, so
# the registry's inventory cannot drift from the module the evidence is checked with.
import multitrack_schemas  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase23" / "COURTS.json"
GENERATOR = "forensics/tools/phase23_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-23-MULTITRACK-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "multitrack_schemas.py"
CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
LINEAGE = REPO_ROOT / "forensics" / "authority-lineage.json"
SNAPSHOT = REPO_ROOT / "forensics" / "multitrack" / "release-archaeology.json"

# 23.1's court, and the identity its subject must begin at. The root is upstream's first real
# OpenSSL release (23 December 1998), not a version the catalogue would pick by sorting.
RELEASE_CATALOG = "RT-RELEASE-CATALOG"
ROOT_RELEASE = "openssl-0.9.1c"
CANONICAL_KINDS = ("branch_fork", "chronological_successor", "maintenance_successor")
PRERELEASE_MARKERS = ("alpha", "beta", "rc", "pre")

# The courts this stratum will stage. 23.1 registers `RT-RELEASE-CATALOG`; each later subphase
# appends its court here in the commit that lands its instrument, and a court removed from the
# table leaves the registry and fails `run_courts.py`.
COURTS: list[tuple[str, str]] = [
    (RELEASE_CATALOG, "_release_catalog_court"),
]

# The remaining courts the plan names, each pending with the subphase that lands it. Ordered as the
# plan orders them, so the registry reads as the execution order.
PENDING_COURTS: dict[str, str] = {
    "RT-AUTHORITY-NODES": "23.2 -- the authority-node registry",
    "RT-LINEAGE-EDGES": "23.3 -- the lineage edges",
    "RT-ENTITY-LINEAGE": "23.4 -- the entity lineage",
    "RT-DELTA-ENGINE": "23.5 -- the delta engine",
    "RT-COMPATIBILITY-VIEWS": "23.6 -- the compatibility views",
    "RT-COMPATIBILITY-EDGES": "23.7 -- the directional compatibility edges",
    "RT-NEGATIVE-OBLIGATIONS": "23.8 -- the negative obligations",
    "RT-SECURITY-LINEAGE": "23.9 -- the security lineage",
    "RT-SUPPORT-STATUS": "23.10 -- the support-status ladder",
    "RT-COMPATIBILITY-MATRIX": "23.11 -- the compatibility matrix",
    "MULTITRACK-SEAL": "23.12 -- the full matrix, the FRF/Gemel chain and the seal",
}


def read_json(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"phase23-courts: {rel(path)} is absent")
    doc = json.loads(path.read_text(encoding="utf-8"))
    # The archaeology snapshot is a raw source manifest rather than an envelope; the catalogue and
    # lineage are enveloped artefacts.
    return doc.get("body", doc)


def _snapshot_label(row: dict) -> tuple[str, bool]:
    """The upstream version label of a timeline row, and whether it is an auxiliary branch."""
    name = row["name"]
    if name.startswith("OpenSSL "):
        name = name[len("OpenSSL "):]
    for prefix in ("fips-", "engine-", "FIPS."):
        if name.startswith(prefix):
            return name[len(prefix):], True
    return name, False


def _is_aux_tag(tag: str) -> bool:
    return (tag.startswith("OpenSSL-engine-") or tag.startswith("OpenSSL-fips-")
            or tag.startswith("OpenSSL_FIPS_"))


def expected_mainline_finals(snapshot: dict) -> dict[str, str]:
    """The upstream mainline final release ids the catalogue must carry, read from the snapshot."""
    out: dict[str, str] = {}
    for row in snapshot["timeline"]:
        tag = row["tag"]
        if tag.startswith("SSLeay_") or _is_aux_tag(tag):
            continue
        label, _aux = _snapshot_label(row)
        if any(m in label.lower() for m in PRERELEASE_MARKERS):
            continue
        try:
            multitrack_schemas.parse_version(label)
        except multitrack_schemas.VersionError:
            continue
        out[f"openssl-{label}"] = tag
    return out


def catalog_findings(catalog: dict, lineage: dict, snapshot: dict) -> list[str]:
    """Every way the catalogue and its lineage fail this court's subject.

    A pure function of the three committed bodies, so the sensitivity control can mutate them and
    re-check. It is deliberately wider than "the files parse": it establishes that the graph
    begins at 0.9.1c, that every upstream mainline final is present with no unexplained gap, that
    a pre-release is never promoted to final or to the stable alias, that the lineage is a typed
    DAG rather than a linearisation, that every node is schema-valid with provenance, and that
    SSLeay is provenance only.
    """
    findings: list[str] = []
    nodes = {n["release_id"]: n for n in catalog.get("nodes", [])}
    ids = set(nodes)

    # 1. the graph begins at upstream's first real release, and at a final mainline node.
    root = catalog.get("root")
    if root != ROOT_RELEASE:
        findings.append(f"the catalogue root is {root!r}, not {ROOT_RELEASE!r}")
    if root in nodes:
        if nodes[root]["release_channel"] != "final":
            findings.append(f"the root {root} is not a final release")
        if nodes[root]["mainline_or_auxiliary"] != "mainline":
            findings.append(f"the root {root} is not a mainline release")

    # 2. every upstream mainline final is present, with no unexplained gap.
    expected = expected_mainline_finals(snapshot)
    unresolved_tags = {r["tag"] for r in catalog.get("unresolved", [])}
    catalog_finals = {n["release_id"] for n in catalog.get("nodes", [])
                      if n["mainline_or_auxiliary"] == "mainline"
                      and n["release_channel"] == "final"}
    for rid, tag in sorted(expected.items()):
        if rid not in catalog_finals and tag not in unresolved_tags:
            findings.append(f"mainline final {rid} (upstream tag {tag}) is missing from the "
                            f"catalogue and is not recorded unresolved")
    for rid in sorted(catalog_finals - set(expected)):
        findings.append(f"catalogue mainline final {rid} is not an upstream mainline final")

    # 3. a pre-release is classified as a pre-release, never promoted to final.
    for n in sorted(catalog.get("nodes", []), key=lambda x: x["release_id"]):
        low = n["display_version"].lower()
        if any(m in low for m in PRERELEASE_MARKERS) and n["release_channel"] == "final":
            findings.append(f"{n['release_id']} carries the pre-release label "
                            f"{n['display_version']!r} but is classified final")

    # 4. the stable alias is a final release, and the newest one by version order.
    alias = (catalog.get("aliases") or {}).get("latest-stable")
    if alias not in nodes:
        findings.append(f"latest-stable points at {alias!r}, which is not a release node")
    else:
        node = nodes[alias]
        low = node["display_version"].lower()
        if node["release_channel"] != "final":
            findings.append(f"latest-stable {alias} is not a final release "
                            f"(channel {node['release_channel']!r})")
        if any(m in low for m in PRERELEASE_MARKERS):
            findings.append(f"latest-stable {alias} is a pre-release by its label "
                            f"{node['display_version']!r}")
        candidates = [n for n in catalog.get("nodes", [])
                      if n["mainline_or_auxiliary"] == "mainline"
                      and n["release_channel"] == "final"]
        newest = max(candidates, key=lambda n: multitrack_schemas.parse_version(
            n["display_version"]).order_key()) if candidates else None
        if newest is not None and newest["release_id"] != alias:
            findings.append(f"latest-stable {alias} is not the newest mainline final "
                            f"({newest['release_id']})")

    # 5. every node is schema-valid and carries provenance.
    for n in sorted(catalog.get("nodes", []), key=lambda x: x["release_id"]):
        findings += [f"release node {n['release_id']}: {p}"
                     for p in multitrack_schemas.validate_release_node(n)]
        if not n.get("metadata_provenance"):
            findings.append(f"release node {n['release_id']} carries no metadata provenance")

    # 6. SSLeay is provenance only.
    for n in catalog.get("nodes", []):
        if n["upstream_tag"].startswith("SSLeay_"):
            findings.append(f"SSLeay tag {n['upstream_tag']} is a release node; SSLeay is "
                            f"provenance ancestry, not an OpenSSL release")
    if not catalog.get("ssleay_ancestry"):
        findings.append("the catalogue records no SSLeay provenance ancestry")
    for s in catalog.get("ssleay_ancestry", []):
        if not str(s.get("tag", "")).startswith("SSLeay_"):
            findings.append(f"ssleay_ancestry entry {s.get('tag')!r} is not an SSLeay tag")

    # 7. the lineage is a typed DAG, not a linearisation, and its parent relation is consistent.
    dag = lineage.get("dag") or {}
    if not dag.get("is_dag"):
        findings.append("the canonical-plus-git-ancestry lineage is not a DAG "
                        f"(cyclic nodes {dag.get('cyclic_nodes')})")
    kinds = Counter(e["kind"] for e in lineage.get("edges", []))
    if kinds.get("branch_fork", 0) < 1:
        findings.append("the lineage types no branch_fork edge, so parallel branches are "
                        "linearised")
    canonical = [e for e in lineage.get("edges", []) if e["kind"] in CANONICAL_KINDS]
    for e in canonical:
        if e["from_id"] not in ids or e["to_id"] not in ids:
            findings.append(f"canonical edge {e['edge_id']} names a node outside the catalogue")
    incoming: dict[str, list[str]] = defaultdict(list)
    for e in canonical:
        incoming[e["to_id"]].append(e["from_id"])
    for n in sorted(catalog.get("nodes", []), key=lambda x: x["release_id"]):
        rid = n["release_id"]
        parents = sorted(incoming.get(rid, []))
        if parents != sorted(n.get("known_parent_edges", [])):
            findings.append(f"{rid}: known_parent_edges {sorted(n.get('known_parent_edges', []))} "
                            f"disagree with the canonical edges {parents}")
        if rid != root and len(parents) != 1:
            findings.append(f"{rid} has {len(parents)} canonical parent edge(s), expected exactly 1")

    # 8. the content hash is a function of the committed body.
    recomputed = content_hash({k: catalog.get(k) for k in (
        "root", "aliases", "ssleay_ancestry", "nodes", "unresolved")})
    if recomputed != catalog.get("content_hash"):
        findings.append("the catalogue content_hash does not reproduce from its body")
    return findings


def _reseal(catalog: dict) -> dict:
    """`catalog` with its content hash recomputed, so a mutation is caught on substance alone."""
    out = copy.deepcopy(catalog)
    out["content_hash"] = content_hash({k: out.get(k) for k in (
        "root", "aliases", "ssleay_ancestry", "nodes", "unresolved")})
    return out


def catalog_sensitivity_control(catalog: dict, lineage: dict, snapshot: dict) -> dict:
    """Prove the court can fail: seed four mutations and require each to be caught.

    The honest catalogue must yield **zero** findings (specificity), and each seeded mutation --
    a deleted release, a `final` flipped to `beta`, a repointed parent edge, and `latest-stable`
    pointed at a beta -- must be caught. Each mutated body is re-sealed first, so the detection is
    the semantic check and never the content-hash check firing on an un-recomputed digest.
    """
    base = catalog_findings(catalog, lineage, snapshot)
    specificity = not base

    # (a) delete a mainline final.
    deleted = _reseal({**copy.deepcopy(catalog),
                       "nodes": [n for n in catalog["nodes"]
                                 if n["release_id"] != "openssl-1.0.2u"]})
    deleted_findings = catalog_findings(deleted, lineage, snapshot)
    caught_deleted = any("openssl-1.0.2u" in f and "missing from the catalogue" in f
                         for f in deleted_findings)

    # (b) flip a final to a beta. The alias is untouched, so only the completeness check moves.
    flipped_nodes = []
    for n in copy.deepcopy(catalog)["nodes"]:
        if n["release_id"] == "openssl-1.0.2u":
            n["release_channel"] = "beta"
        flipped_nodes.append(n)
    flipped = _reseal({**copy.deepcopy(catalog), "nodes": flipped_nodes})
    flipped_findings = catalog_findings(flipped, lineage, snapshot)
    caught_flipped = any("openssl-1.0.2u" in f and "missing from the catalogue" in f
                         for f in flipped_findings)

    # (c) repoint a parent edge: the canonical edge into 1.0.2u is moved off 1.0.2t.
    repointed_edges = []
    for e in copy.deepcopy(lineage)["edges"]:
        if e["kind"] in CANONICAL_KINDS and e["to_id"] == "openssl-1.0.2u":
            e["from_id"] = "openssl-1.0.2a"
        repointed_edges.append(e)
    repointed = {**copy.deepcopy(lineage), "edges": repointed_edges}
    repointed_findings = catalog_findings(catalog, repointed, snapshot)
    caught_repointed = any("known_parent_edges" in f and "disagree" in f
                           for f in repointed_findings)

    # (d) point latest-stable at a beta that sorts above the stable release.
    aliased = _reseal({**copy.deepcopy(catalog),
                       "aliases": {**catalog["aliases"],
                                   "latest-stable": "openssl-4.1.0-beta1"}})
    aliased_findings = catalog_findings(aliased, lineage, snapshot)
    caught_aliased = any("latest-stable openssl-4.1.0-beta1" in f for f in aliased_findings)

    return {
        "baseline_findings": len(base),
        "injected_deleted_release": "openssl-1.0.2u",
        "injected_deleted_findings": len(deleted_findings),
        "injected_final_to_beta": "openssl-1.0.2u",
        "injected_final_to_beta_findings": len(flipped_findings),
        "injected_repointed_edge": "L-*-openssl-1.0.2t-openssl-1.0.2u -> openssl-1.0.2a",
        "injected_repointed_findings": len(repointed_findings),
        "injected_stable_beta": "openssl-4.1.0-beta1",
        "injected_stable_beta_findings": len(aliased_findings),
        "specificity_holds": specificity,
        "caught_deleted_release": caught_deleted,
        "caught_final_to_beta": caught_flipped,
        "caught_repointed_edge": caught_repointed,
        "caught_stable_beta": caught_aliased,
        "honest": bool(specificity and caught_deleted and caught_flipped and caught_repointed
                       and caught_aliased),
    }


def _release_catalog_court(name: str) -> dict:
    """`RT-RELEASE-CATALOG`: 23.1's court, the release catalogue and its lineage.

    Stages no probe. It reads the committed catalogue, its lineage and the archaeology snapshot
    they were derived from, and establishes that the graph begins at OpenSSL 0.9.1c, that every
    upstream mainline final is present with no unexplained gap, that a pre-release is never
    promoted to final or to the stable alias, that the lineage is a typed DAG rather than a
    linearisation, that every node is schema-valid with provenance, and that SSLeay is provenance
    ancestry only. Four seeded mutations are each caught with specificity holding on the honest
    catalogue. A passing catalogue is a **catalogue**, not a compatibility claim: no edge here
    says any release is compatible with any other.
    """
    problems: list[str] = []
    for path, label in ((CATALOG, "release catalogue"), (LINEAGE, "authority lineage"),
                        (SNAPSHOT, "archaeology snapshot")):
        if not path.is_file():
            problems.append(f"the {label} {rel(path)} is absent")
    if problems:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": problems, "findings": [], "control": {}}

    catalog = read_json(CATALOG)
    lineage = read_json(LINEAGE)
    snapshot = read_json(SNAPSHOT)
    findings = catalog_findings(catalog, lineage, snapshot)
    control = catalog_sensitivity_control(catalog, lineage, snapshot)

    c = catalog.get("counts", {})
    verdict = "pass" if (not findings and not problems and control["honest"]) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/release-catalog.json and "
            "forensics/authority-lineage.json, both derived from "
            "forensics/multitrack/release-archaeology.json (the official timeline plus the git "
            "tags' commits and nearest-release ancestors), and establishes the graph's root at "
            "OpenSSL 0.9.1c, the presence of every upstream mainline final with no unexplained "
            "gap, the classification of pre-releases and the finality of latest-stable, the "
            "typed DAG with branch_fork edges for the parallel branches, the schema validity and "
            "provenance of every node, and that SSLeay is provenance ancestry rather than a "
            "release node. A deleted release, a final flipped to beta, a repointed parent edge "
            "and a latest-stable pointed at a beta are each detected (docs/PHASE-23-"
            "MULTITRACK-SUBPHASES.md section 3.2)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the catalogue court reads committed release records and stages no "
            "artifacts/phase23/probes/ pair, so it takes no transcript to diff and carries no "
            "FRF declaration"
        ),
        "root": catalog.get("root"),
        "latest_stable": (catalog.get("aliases") or {}).get("latest-stable"),
        "catalog_counts": c,
        "lineage_counts": lineage.get("counts"),
        "content_hash": catalog.get("content_hash"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)

    records: list[dict] = []
    for name, handler in COURTS:
        # The registered courts stage no probe -- this stratum owns no exported symbol, so no
        # differential probe over a symbol set is its evidence -- and each is computed here rather
        # than read back from disk, so no digest cycle forms. The handler is named in the table
        # and resolved here, so a court added to COURTS without a function is a loud failure.
        fn = globals().get(str(handler))
        if fn is None:
            records.append({"court": name, "verdict": "fail", "stage": "handler-missing",
                            "detail": str(handler)})
            continue
        records.append(fn(name))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    failed = sum(1 for r in records if r["verdict"] == "fail")
    body = {
        "all_pass": failed == 0 and len(records) == len(COURTS),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed, "fail": failed},
        "pending_courts": PENDING_COURTS,
        "schemas": multitrack_schemas.inventory(),
        "claim": (
            "`RT-RELEASE-CATALOG` is 23.1's court: the release catalogue and its lineage. It "
            "stages no probe and reads forensics/release-catalog.json and "
            "forensics/authority-lineage.json, both derived from "
            "forensics/multitrack/release-archaeology.json -- the official OpenSSL release "
            "timeline, the git tag each release names and the commit it peels to, and the "
            "nearest release ancestor the git graph gives it. It establishes that the graph "
            "begins at OpenSSL 0.9.1c (23 December 1998), that every upstream mainline final is "
            "present with no unexplained gap, that a pre-release is classified and never promoted "
            "to final or to the `latest-stable` alias merely by sorting higher, that the lineage "
            "is a typed DAG whose parallel branches are branch_fork edges rather than a false "
            "linear mainline, that every node is schema-valid with provenance, and that SSLeay "
            "is provenance ancestry only. A deleted release, a `final` flipped to `beta`, a "
            "repointed parent edge and a `latest-stable` pointed at a beta are each detected "
            "with specificity holding on the honest catalogue. A passing catalogue is a "
            "catalogue, not a compatibility claim: no edge says any release is compatible with "
            "any other. Phase 23 owns no exported symbol, so no differential probe over a symbol "
            "set is its evidence, and its remaining eleven courts -- RT-AUTHORITY-NODES, "
            "RT-LINEAGE-EDGES, RT-ENTITY-LINEAGE, RT-DELTA-ENGINE, RT-COMPATIBILITY-VIEWS, "
            "RT-COMPATIBILITY-EDGES, RT-NEGATIVE-OBLIGATIONS, RT-SECURITY-LINEAGE, "
            "RT-SUPPORT-STATUS, RT-COMPATIBILITY-MATRIX and MULTITRACK-SEAL -- are pending with "
            "the subphases that land them (23.2 through 23.12). The one thing the model forbids "
            "everywhere is a single boolean: compatibility is directional and "
            "dimension-specific, a cross-version receipt is never inherited, an authority is "
            "named explicitly and singularly, and a historical vulnerability is observed but "
            "never reintroduced. docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 1, 2 and 4 "
            "record the measurement and the precondition."
        ),
    }

    inputs = [
        InputRef(name="phase-23-plan", path=PLAN),
        InputRef(name="multitrack-schemas", path=SCHEMAS),
        InputRef(name="release-catalog", path=CATALOG),
        InputRef(name="authority-lineage", path=LINEAGE),
        InputRef(name="release-archaeology", path=SNAPSHOT),
    ]
    doc = envelope(kind="phase23-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass" and r["court"] == RELEASE_CATALOG:
            c = r["control"]
            counts = r["catalog_counts"]
            lc = r["lineage_counts"] or {}
            print(f"  {r['court']:<32} pass   (no probe, root={r['root']}, "
                  f"latest-stable={r['latest_stable']}, {counts.get('nodes')} node(s) "
                  f"{counts.get('channels')}, {counts.get('unresolved')} unresolved; "
                  f"lineage {lc.get('edges')} edge(s) {lc.get('kinds')}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"deleted->{c['injected_deleted_findings']} "
                  f"final->beta->{c['injected_final_to_beta_findings']} "
                  f"repointed->{c['injected_repointed_findings']} "
                  f"stable->beta->{c['injected_stable_beta_findings']} finding(s))")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] != "pass":
            print(f"  {r['court']:<32} FAIL   stage={r.get('stage', 'derive')}")
            for p in (r.get("problems") or [])[:12]:
                print(f"      {p}")
            for f in (r.get("findings") or [])[:12]:
                print(f"      finding: {f}")
    for cname, needs in PENDING_COURTS.items():
        print(f"  {cname:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  schema inventory: {len(body['schemas'])} record kind(s)")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
