#!/usr/bin/env python3
"""openssl-rs — Phase 23 courts: the multitrack authority machinery courts.

Each court is an instrument that makes the multitrack authority model of
`docs/RELEASE_GATES.md` section 1 mechanical over releases and authorities that are already
admitted, not a differential probe over a symbol set. This stratum owns no exported symbol: it
emits independently-evidenced compatibility *views*, so its evidence is about the model -- the
release nodes and their chronology, the authority nodes and their builds, the parameterized atlases
and their byte-identical proof, the lineage and entity relations between releases, the delta between
two nodes, the ABI/history façades, the oracle-to-oracle and candidate-to-authority semantic courts,
the directional and dimension-specific compatibility views and edges, the historical population, the
downstream consumer per compatibility epoch, the negative obligations, the security lineage, the
support status of each node, and the assembled matrix. The method is Phases 3 through 21's where an
artefact
carries the expectation: each court reads the artefact that holds its subject rather than typing the
expectation beside it, so the two cannot disagree, and a court whose control is not honest is
`fail` rather than `pass`.

**Three courts are registered.** 23.1 lands `RT-RELEASE-CATALOG`, the release catalogue and
lineage court, 23.2 lands `RT-AUTHORITY-NODES`, the authority-node registry court, and 23.3 lands
`RT-ATLAS-PARAMETERIZATION`, the parameterized-atlas court; the other fourteen courts are named in
`PENDING_COURTS` and land with the subphases that
build the instruments they drive. The registry is the file `run_courts.py` checks is
reproduced, so a court silently dropped is a finding rather than a smaller green run. This is
the reverse of Phase 16's edge: the ledger's contract-unit states are measured from this registry,
so this runner does **not** bind the obligations ledger as an input.

The record kinds these courts will populate are defined and self-tested in
`forensics/tools/multitrack_schemas.py`; the registry records that schema inventory so the record
kinds are a file the evidence points at rather than prose the plan would have to restate.

The seventeen courts, and the subphase that lands each
------------------------------------------------------
  * `RT-RELEASE-CATALOG` -- 23.1, the release-node catalogue and its lineage (registered).
  * `RT-AUTHORITY-NODES` -- 23.2, the authority-node registry (registered).
  * `RT-ATLAS-PARAMETERIZATION` -- 23.3, the parameterized atlases and the byte-identical proof
    (registered).
  * `RT-LINEAGE-EDGES` -- 23.4, the lineage edges.
  * `RT-ENTITY-LINEAGE` -- 23.5, the entity lineage.
  * `RT-DELTA-ENGINE` -- 23.6, the delta engine.
  * `RT-ABI-HISTORY-FACADES` -- 23.7, the ABI / history façades.
  * `RT-SEMANTIC-COURTS` -- 23.8, the semantic multitrack courts.
  * `RT-COMPATIBILITY-VIEWS` -- 23.9, the compatibility views.
  * `RT-HISTORICAL-POPULATION` -- 23.10, the historical population.
  * `RT-DOWNSTREAM-MULTITRACK` -- 23.11, the downstream multitrack court.
  * `RT-COMPATIBILITY-EDGES` -- 23.12, the directional compatibility edges.
  * `RT-NEGATIVE-OBLIGATIONS` -- 23.13, the negative obligations.
  * `RT-SECURITY-LINEAGE` -- 23.14, the security lineage.
  * `RT-SUPPORT-STATUS` -- 23.15, the support-status ladder.
  * `RT-COMPATIBILITY-MATRIX` -- 23.16, the compatibility matrix.
  * `MULTITRACK-SEAL` -- 23.17, the full matrix, the FRF/Gemel chain and the seal.

Every one but `RT-RELEASE-CATALOG`, `RT-AUTHORITY-NODES` and `RT-ATLAS-PARAMETERIZATION` is
`pending`. A passing court is an instrument, not a property
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
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    default_authority_id,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

# The schemas the later subphases validate their records against. Imported rather than restated, so
# the registry's inventory cannot drift from the module the evidence is checked with.
import multitrack_schemas  # noqa: E402
# The Phase-23.3 parameterized generator, imported so the court re-derives the census in-process
# through the same code path the receipt was produced by (never a second, drifting predicate).
import atlas_authority  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase23" / "COURTS.json"
GENERATOR = "forensics/tools/phase23_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-23-MULTITRACK-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "multitrack_schemas.py"
CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
LINEAGE = REPO_ROOT / "forensics" / "authority-lineage.json"
SNAPSHOT = REPO_ROOT / "forensics" / "multitrack" / "release-archaeology.json"

# 23.2's subject: the authority-node registry and the records it is derived from. The registry
# itself is the committed artefact the court reads; the acquisition and build receipts and the
# admitted-authority registry are the evidence its claims are checked against.
AUTHORITY_NODES = REPO_ROOT / "forensics" / "authority-nodes.json"
AUTHORITY_REGISTRY = REPO_ROOT / "forensics" / "authorities" / "AUTHORITIES.json"
AUTHORITY_SRC = REPO_ROOT / "forensics" / "authorities"
BUILD_RECORDS = REPO_ROOT / "forensics" / "atlas" / "BUILD_RECORDS.json"
HIST_ACQ = REPO_ROOT / "forensics" / "multitrack" / "historical-acquisition.json"
HIST_RECEIPTS = REPO_ROOT / "forensics" / "multitrack" / "historical-build-receipts.json"

# 23.3's subject: the parameterization receipt, the committed default-authority alias and the
# historical authority's plane census. The default authority's committed atlas is the pivot the
# byte-identity proof binds.
PARAM_RECEIPT = REPO_ROOT / "forensics" / "atlas" / "parameterization-receipt.json"
DEFAULT_AUTHORITY_ALIAS = REPO_ROOT / "forensics" / "multitrack" / "default-authority.json"
PARAM_HISTORICAL = "openssl-0.9.8zh-historical"
PRODUCTION_ATLAS = REPO_ROOT / "forensics" / "atlas" / PRODUCTION_AUTHORITY
# The planes the brief names as the decisive absences for an older authority, cross-checked in the
# court against the committed manifest independently of the generator's own predicates.
KEY_ABSENCE_MARKERS = {
    "providers": "providers/",
    "provider-registrations": "util/providers.num",
    "quic": "ssl/quic/",
}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# 23.1's court, and the identity its subject must begin at. The root is upstream's first real
# OpenSSL release (23 December 1998), not a version the catalogue would pick by sorting.
RELEASE_CATALOG = "RT-RELEASE-CATALOG"
AUTHORITY_NODES_COURT = "RT-AUTHORITY-NODES"
ATLAS_PARAMETERIZATION_COURT = "RT-ATLAS-PARAMETERIZATION"
ROOT_RELEASE = "openssl-0.9.1c"
CANONICAL_KINDS = ("branch_fork", "chronological_successor", "maintenance_successor")
PRERELEASE_MARKERS = ("alpha", "beta", "rc", "pre")

# The courts this stratum will stage. 23.1 registers `RT-RELEASE-CATALOG`; each later subphase
# appends its court here in the commit that lands its instrument, and a court removed from the
# table leaves the registry and fails `run_courts.py`.
COURTS: list[tuple[str, str]] = [
    (RELEASE_CATALOG, "_release_catalog_court"),
    (AUTHORITY_NODES_COURT, "_authority_nodes_court"),
    (ATLAS_PARAMETERIZATION_COURT, "_atlas_parameterization_court"),
]

# The remaining courts the plan names, each pending with the subphase that lands it. Ordered as the
# plan orders them, so the registry reads as the execution order.
PENDING_COURTS: dict[str, str] = {
    "RT-LINEAGE-EDGES": "23.4 -- the lineage edges",
    "RT-ENTITY-LINEAGE": "23.5 -- the entity lineage",
    "RT-DELTA-ENGINE": "23.6 -- the delta engine",
    "RT-ABI-HISTORY-FACADES": "23.7 -- the ABI / history façades",
    "RT-SEMANTIC-COURTS": "23.8 -- the semantic multitrack courts",
    "RT-COMPATIBILITY-VIEWS": "23.9 -- the compatibility views",
    "RT-HISTORICAL-POPULATION": "23.10 -- the historical population",
    "RT-DOWNSTREAM-MULTITRACK": "23.11 -- the downstream multitrack court",
    "RT-COMPATIBILITY-EDGES": "23.12 -- the directional compatibility edges",
    "RT-NEGATIVE-OBLIGATIONS": "23.13 -- the negative obligations",
    "RT-SECURITY-LINEAGE": "23.14 -- the security lineage",
    "RT-SUPPORT-STATUS": "23.15 -- the support-status ladder",
    "RT-COMPATIBILITY-MATRIX": "23.16 -- the compatibility matrix",
    "MULTITRACK-SEAL": "23.17 -- the full matrix, the FRF/Gemel chain and the seal",
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


def _reseal_nodes(body: dict) -> dict:
    """`body` with its content hash recomputed, so a mutation is caught on substance alone."""
    out = copy.deepcopy(body)
    out["content_hash"] = content_hash({"nodes": out.get("nodes", []),
                                        "unavailable": out.get("unavailable", [])})
    return out


def authority_nodes_findings(body: dict, catalog: dict, authorities: dict, build_records: dict,
                             hist_acq: dict, hist_receipts: dict) -> list[str]:
    """Every way the authority-node registry and its backing records fail this court's subject.

    A pure function of the committed bodies, so the sensitivity control can mutate them and
    re-check. It establishes that every node is schema-valid, content-addressed and backed by an
    actual receipt; that release identity is proven against the catalogue rather than assumed; that
    the admitted pair still verifies and has a node; and that an unavailable release is recorded as
    unavailable and never counted as runtime-compatible.
    """
    findings: list[str] = []
    nodes = body.get("nodes", [])
    unavailable = body.get("unavailable", [])
    catalog_nodes = {n["release_id"]: n for n in catalog.get("nodes", [])}
    auth_by_id = {a["id"]: a for a in authorities.get("authorities", [])}
    builds_by_id = {b["id"]: b for b in build_records.get("builds", [])}
    receipts_by_release = {r["release_id"]: r for r in hist_receipts.get("receipts", [])}
    acq_by_release = {r["release_id"]: r for r in hist_acq.get("acquisitions", [])}
    acq_unavailable = {r["release_id"]: r for r in hist_acq.get("unavailable", [])}
    receipt_rel = rel(HIST_RECEIPTS)
    build_records_rel = rel(BUILD_RECORDS)

    ids = [n["authority_id"] for n in nodes]
    if len(set(ids)) != len(ids):
        findings.append(f"the registry has {len(ids) - len(set(ids))} duplicate authority node id(s)")

    for n in nodes:
        aid = n["authority_id"]
        rid = n["release_id"]
        # 1. schema validity.
        findings += [f"authority node {aid}: {p}" for p in multitrack_schemas.validate_authority_node(n)]
        cat = catalog_nodes.get(rid)
        if cat is None:
            findings.append(f"authority node {aid}: release {rid} is not a release node in the "
                            f"catalogue")
        else:
            # 2. release identity is the catalogue's, and is kept separate from the profile.
            git = n.get("git") or {}
            if git.get("tag") != cat["upstream_tag"] or git.get("commit") != cat["upstream_commit"]:
                findings.append(f"authority node {aid}: git identity {git} disagrees with the "
                                f"catalogue's {cat['upstream_tag']}@{cat['upstream_commit']}")
        # 3. the source package is proven, not asserted: a verified published digest.
        sp = n.get("source_package") or {}
        if sp.get("checksum_verified") is not True:
            findings.append(f"authority node {aid}: source package checksum is not verified")
        if not sp.get("sha256") or sp.get("sha256") != sp.get("published_sha256"):
            findings.append(f"authority node {aid}: source package sha256 != published sha256, so "
                            f"tag == tarball is asserted without proof")
        if cat is not None and sp.get("artifact") != f"openssl-{cat['display_version']}.tar.gz":
            findings.append(f"authority node {aid}: source artifact {sp.get('artifact')!r} is not "
                            f"the release's own tarball")
        # 4. content-addressed: every binary and installed hash is a real digest.
        for field in ("binary_hashes", "installed_hashes"):
            value = n.get(field)
            if not isinstance(value, dict) or not value:
                findings.append(f"authority node {aid}: {field} is empty, so the node binds nothing")
                continue
            for key, digest in value.items():
                if not (isinstance(digest, str) and _HEX64.match(digest)):
                    findings.append(f"authority node {aid}: {field}[{key!r}] is not a 64-hex "
                                    f"content address ({digest!r})")
        # 5. a built-authority claim is backed by an actual build receipt.
        if n.get("claim") == "built-authority":
            receipt = n.get("build_receipt")
            if not receipt or not (REPO_ROOT / receipt).is_file():
                findings.append(f"authority node {aid}: claims built-authority but its build "
                                f"receipt {receipt!r} is absent")
            elif receipt == receipt_rel:
                rec = receipts_by_release.get(rid)
                if rec is None:
                    findings.append(f"authority node {aid}: no historical build receipt names {rid}")
                else:
                    if rec.get("binary_hashes") != n.get("binary_hashes"):
                        findings.append(f"authority node {aid}: binary hashes disagree with its "
                                        f"build receipt")
                    if rec.get("installed_hashes") != n.get("installed_hashes"):
                        findings.append(f"authority node {aid}: installed hashes disagree with its "
                                        f"build receipt")
                    if rec.get("source_package", {}).get("sha256") != sp.get("sha256"):
                        findings.append(f"authority node {aid}: source digest disagrees with its "
                                        f"build receipt")
            elif receipt == build_records_rel:
                build = builds_by_id.get(aid)
                if build is None:
                    findings.append(f"authority node {aid}: no build record names it")
                elif build.get("profile") != n.get("build_profile"):
                    findings.append(f"authority node {aid}: build profile {n.get('build_profile')!r} "
                                    f"disagrees with its build record {build.get('profile')!r}")
        if n.get("runtime_evidence") == "unavailable":
            findings.append(f"authority node {aid}: is a node but marked runtime-unavailable")

    # 6. every admitted authority still verifies and has a node whose identity reproduces.
    for a in authorities.get("authorities", []):
        rid = f"openssl-{a['version']}"
        node = next((n for n in nodes if n["authority_id"] == a["id"]), None)
        if node is None:
            findings.append(f"admitted authority {a['id']} has no authority node")
            continue
        if (node.get("source_package") or {}).get("sha256") != a["artifact"]["sha256"]:
            findings.append(f"admitted authority {a['id']}: node source digest disagrees with the "
                            f"registry's verified archive digest")
        manifest_path = AUTHORITY_SRC / a["source_tree"]["manifest"]
        if not manifest_path.is_file():
            findings.append(f"admitted authority {a['id']}: source manifest "
                            f"{a['source_tree']['manifest']} is absent")
        else:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("root_hash") != a["source_tree"]["root_hash"]:
                findings.append(f"admitted authority {a['id']}: source manifest root hash does not "
                                f"reproduce the registry's")
            if manifest.get("file_count") != a["source_tree"]["file_count"]:
                findings.append(f"admitted authority {a['id']}: source manifest file count does not "
                                f"reproduce the registry's")
        if rid not in catalog_nodes:
            findings.append(f"admitted authority {a['id']}: its release {rid} is not catalogued")

    # 7. an unavailable release is recorded as unavailable, backed by the acquisition evidence,
    #    and is never also a node -- so it is never counted as runtime-compatible.
    for u in unavailable:
        rid = u.get("release_id")
        if u.get("outcome") != "unavailable":
            findings.append(f"unavailable entry {rid}: outcome is not `unavailable`")
        if not u.get("reason"):
            findings.append(f"unavailable entry {rid}: carries no reason")
        if u.get("runtime_evidence") != "unavailable":
            findings.append(f"unavailable entry {rid}: does not record runtime evidence unavailable")
        if u.get("runtime_compatible") is not False:
            findings.append(f"unavailable entry {rid}: is not recorded runtime-incompatible")
        if rid not in acq_unavailable:
            findings.append(f"unavailable entry {rid}: is not recorded unavailable in the "
                            f"acquisition registry")
        if any(n["release_id"] == rid for n in nodes):
            findings.append(f"unavailable entry {rid}: is also an authority node, so it would be "
                            f"counted as runtime-compatible")
    for rid in acq_unavailable:
        if not any(u.get("release_id") == rid for u in unavailable):
            findings.append(f"acquisition records {rid} unavailable but the registry omits it")

    # 8. every historical build receipt backs exactly one node.
    for rid in receipts_by_release:
        if not any(n["release_id"] == rid for n in nodes):
            findings.append(f"build receipt for {rid} has no authority node")
    for rid in acq_by_release:
        if not any(n["release_id"] == rid for n in nodes):
            findings.append(f"acquired release {rid} has no authority node")

    # 9. the content hash is a function of the committed body.
    recomputed = content_hash({"nodes": nodes, "unavailable": unavailable})
    if recomputed != body.get("content_hash"):
        findings.append("the registry content_hash does not reproduce from its body")
    return findings


def authority_nodes_sensitivity_control(body: dict, catalog: dict, authorities: dict,
                                        build_records: dict, hist_acq: dict,
                                        hist_receipts: dict) -> dict:
    """Prove the court can fail: seed three mutations and require each to be caught.

    The honest registry must yield **zero** findings (specificity), and each seeded mutation -- a
    `built-authority` claim with no receipt, a dropped required identity field, and a source digest
    that asserts `tag == tarball` without proof -- must be caught. Each mutated body is re-sealed
    first, so the detection is the semantic check and never the content-hash check firing on an
    un-recomputed digest.
    """
    base = authority_nodes_findings(body, catalog, authorities, build_records, hist_acq,
                                    hist_receipts)
    specificity = not base

    # (a) claim built-authority for a node whose receipt does not exist.
    no_receipt = copy.deepcopy(body)
    for n in no_receipt["nodes"]:
        if n["authority_id"] == "openssl-0.9.8zh-historical":
            n["build_receipt"] = "forensics/multitrack/does-not-exist.json"
    no_receipt = _reseal_nodes(no_receipt)
    no_receipt_findings = authority_nodes_findings(no_receipt, catalog, authorities, build_records,
                                                   hist_acq, hist_receipts)
    caught_no_receipt = any("claims built-authority" in f and "absent" in f
                            for f in no_receipt_findings)

    # (b) drop a required identity field (the platform).
    dropped = copy.deepcopy(body)
    for n in dropped["nodes"]:
        if n["authority_id"] == "openssl-3.6.4-production":
            n.pop("platform", None)
    dropped = _reseal_nodes(dropped)
    dropped_findings = authority_nodes_findings(dropped, catalog, authorities, build_records,
                                                hist_acq, hist_receipts)
    caught_dropped = any("platform" in f and "missing required field" in f
                         for f in dropped_findings)

    # (c) assert a source digest without proof: sha256 no longer matches the published digest.
    unproven = copy.deepcopy(body)
    for n in unproven["nodes"]:
        if n["authority_id"] == "openssl-3.6.4-production":
            n["source_package"]["sha256"] = "0" * 64
    unproven = _reseal_nodes(unproven)
    unproven_findings = authority_nodes_findings(unproven, catalog, authorities, build_records,
                                                 hist_acq, hist_receipts)
    caught_unproven = any("asserted without proof" in f for f in unproven_findings)

    return {
        "baseline_findings": len(base),
        "injected_built_without_receipt": "openssl-0.9.8zh-historical",
        "injected_built_without_receipt_findings": len(no_receipt_findings),
        "injected_dropped_platform": "openssl-3.6.4-production",
        "injected_dropped_platform_findings": len(dropped_findings),
        "injected_unproven_tarball": "openssl-3.6.4-production source_package.sha256",
        "injected_unproven_tarball_findings": len(unproven_findings),
        "specificity_holds": specificity,
        "caught_built_without_receipt": caught_no_receipt,
        "caught_dropped_platform": caught_dropped,
        "caught_unproven_tarball": caught_unproven,
        "honest": bool(specificity and caught_no_receipt and caught_dropped and caught_unproven),
    }


def _authority_nodes_court(name: str) -> dict:
    """`RT-AUTHORITY-NODES`: 23.2's court, the authority-node registry.

    Stages no probe. It reads `forensics/authority-nodes.json` and the records it is derived from
    -- the release catalogue, the admitted-authority registry, the build records and the historical
    acquisition and build receipts -- and establishes that every node is schema-valid,
    content-addressed and backed by an actual receipt; that release identity is proven against the
    catalogue and kept separate from platform/profile identity; that the admitted pair still
    verifies; and that an unavailable authority is recorded unavailable and never a node. Three
    seeded mutations are each caught with specificity holding. A passing registry is a
    **registry**, not a compatibility claim.
    """
    problems: list[str] = []
    for path, label in ((AUTHORITY_NODES, "authority-node registry"),
                        (CATALOG, "release catalogue"),
                        (AUTHORITY_REGISTRY, "authority registry"),
                        (BUILD_RECORDS, "build records"),
                        (HIST_ACQ, "historical acquisition"),
                        (HIST_RECEIPTS, "historical build receipts")):
        if not path.is_file():
            problems.append(f"the {label} {rel(path)} is absent")
    if problems:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": problems, "findings": [], "control": {}}

    body = read_json(AUTHORITY_NODES)
    catalog = read_json(CATALOG)
    authorities = read_json(AUTHORITY_REGISTRY)
    build_records = read_json(BUILD_RECORDS)
    hist_acq = read_json(HIST_ACQ)
    hist_receipts = read_json(HIST_RECEIPTS)

    findings = authority_nodes_findings(body, catalog, authorities, build_records, hist_acq,
                                        hist_receipts)
    control = authority_nodes_sensitivity_control(body, catalog, authorities, build_records,
                                                  hist_acq, hist_receipts)
    counts = body.get("counts", {})
    verdict = "pass" if (not findings and not problems and control["honest"]) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/authority-nodes.json and the records it is derived "
            "from -- forensics/release-catalog.json, forensics/authorities/AUTHORITIES.json, "
            "forensics/atlas/BUILD_RECORDS.json and the historical acquisition and build receipts "
            "-- and establishes that every node is schema-valid, content-addressed and backed by an "
            "actual build receipt; that release identity (release_id, git) is proven against the "
            "catalogue and kept separate from platform/profile identity; that the admitted pair's "
            "source manifests still reproduce; and that an unavailable authority is recorded "
            "unavailable and is never a node. A built-authority claim with no receipt, a dropped "
            "required identity field, and a source digest asserting tag == tarball without proof "
            "are each detected (docs/PHASE-23-MULTITRACK-SUBPHASES.md section 3.2)"
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the authority-node court reads committed build evidence and stages no "
            "artifacts/phase23/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "nodes": counts.get("nodes"),
        "built": counts.get("built"),
        "unavailable": counts.get("unavailable"),
        "content_hash": body.get("content_hash"),
        "node_identities": [
            {"authority_id": n["authority_id"], "release_id": n["release_id"],
             "profile": n["build_profile"], "claim": n.get("claim"),
             "receipt": n.get("build_receipt")}
            for n in body.get("nodes", [])
        ],
        "unavailable_identities": [
            {"release_id": u["release_id"], "outcome": u.get("outcome"),
             "runtime_evidence": u.get("runtime_evidence")}
            for u in body.get("unavailable", [])
        ],
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _measure_atlas_byte_identity(authority_id: str) -> dict:
    """Re-derive the authority's atlas through the parameterized generators and measure the diff.

    It snapshots every committed file of the authority's atlas directory, runs the
    authority-parameterized regenerators with an explicit `--authority`, records which committed
    bytes moved, then runs the one non-parameterized reconciliation plane (`atlas_parity.py`) to
    *measure* the disclosed pre-existing drift, and finally restores the committed bytes so the
    working tree is left exactly as committed. Nothing here is typed: the parameterized diff and
    the drift are both read from the files themselves.
    """
    atlas_dir = REPO_ROOT / "forensics" / "atlas" / authority_id
    snapshot = {p.resolve(): p.read_bytes() for p in atlas_dir.glob("*") if p.is_file()}

    def run(gen: str) -> int:
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / gen), "--authority", authority_id],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False)
        return res.returncode

    codes = {g: run(g) for g in atlas_authority.REGENERATORS}
    after_param = {p: p.read_bytes() for p in snapshot}
    parameterized_diffs = sorted(rel(p) for p in snapshot if snapshot[p] != after_param[p])

    # The disclosed pre-existing drift: the reconciliation plane that does not reproduce. It is
    # measured, named and then undone, never applied.
    parity_code = run("forensics/tools/atlas_parity.py")
    after_parity = {p: p.read_bytes() for p in snapshot}
    drift = sorted(rel(p) for p in snapshot if snapshot[p] != after_parity[p])

    for p, b in snapshot.items():
        if p.read_bytes() != b:
            p.write_bytes(b)

    return {
        "authority": authority_id,
        "files_checked": len(snapshot),
        "regenerators": list(atlas_authority.REGENERATORS),
        "regenerator_returncodes": codes,
        "parameterized_diffs": parameterized_diffs,
        "parity_returncode": parity_code,
        "pre_existing_drift": drift,
        "disclosed_drift": sorted(atlas_authority.KNOWN_STALE_PATHS),
    }


def _manifest_paths(manifest_relpath: str) -> list[str]:
    doc = json.loads((REPO_ROOT / manifest_relpath).read_text(encoding="utf-8"))
    return [entry["path"] for entry in doc.get("files", [])]


def atlas_parameterization_findings(receipt: dict, alias: dict,
                                   historical_census: dict) -> list[str]:
    """Every way the parameterization receipt and its censuses fail this court's subject.

    A pure function of committed bodies, so the sensitivity control can mutate them and re-check.
    It establishes that the default is the committed alias (never `latest-stable`); that one
    generator and one plane set serve every authority; that each census re-derives from the
    committed source manifest; that every measured absence is a counted zero with provenance and
    independent corroboration in the manifest; and that the 3.6.4 plane is the pivot for the
    byte-identity proof.
    """
    findings: list[str] = [
        f"parameterization receipt: {p}"
        for p in multitrack_schemas.validate("parameterization_receipt", receipt)
    ]
    default_id = PRODUCTION_AUTHORITY
    alias_id = alias.get("authority_id")
    if alias_id != default_id:
        findings.append(f"the default-authority alias names {alias_id!r}, not the maintained "
                        f"authority {default_id!r}")
    if receipt.get("default_authority") != alias_id:
        findings.append(f"the receipt default_authority {receipt.get('default_authority')!r} is "
                        f"not the alias's {alias_id!r}")
    if receipt.get("default_alias") != "forensics/multitrack/default-authority.json":
        findings.append("the receipt does not name the committed default-authority alias")

    code_path = receipt.get("same_code_path") or {}
    if code_path.get("generator") != atlas_authority.GENERATOR:
        findings.append("the receipt's same_code_path does not name the parameterized generator")
    plane_order = list(receipt.get("plane_order") or code_path.get("plane_order") or [])
    if not plane_order:
        findings.append("the receipt names no shared plane order")
    censuses = receipt.get("censuses") or {}
    if default_id not in censuses:
        findings.append(f"the receipt carries no census for the default authority {default_id}")
    if PARAM_HISTORICAL not in censuses:
        findings.append(f"the receipt carries no census for the historical authority "
                        f"{PARAM_HISTORICAL}")

    # The historical plane's census on disk must be the same body the receipt carries (so the
    # per-authority output and the receipt cannot disagree).
    hist_doc = historical_census.get("body", historical_census)
    receipt_hist = censuses.get(PARAM_HISTORICAL)
    if receipt_hist is not None and hist_doc != receipt_hist:
        findings.append("the on-disk historical plane-census disagrees with the receipt's census")

    # One plane set serves both authorities, in the same order.
    for aid, census in sorted(censuses.items()):
        names = [r.get("plane") for r in census.get("planes", [])]
        if plane_order and names != plane_order:
            findings.append(f"census {aid} does not carry the shared plane set in the same order")

    # Every census re-derives from the committed manifest through the same generator.
    for aid in sorted(censuses):
        try:
            rederived = atlas_authority.build_census(aid)
        except SystemExit as exc:  # pragma: no cover - fail closed on a missing manifest
            findings.append(f"census {aid} cannot be re-derived: {exc}")
            continue
        if rederived != censuses[aid]:
            findings.append(f"census {aid} does not reproduce from its committed source manifest")

    # The historical authority's absences are measured, each with a counted zero and provenance,
    # and each is corroborated against the committed manifest independently of the generator.
    hist = censuses.get(PARAM_HISTORICAL) or {}
    hist_rows = {r["plane"]: r for r in hist.get("planes", [])}
    for plane in plane_order:
        row = hist_rows.get(plane)
        if row is None:
            continue
        if row.get("status") == "measured_absence":
            if row.get("count") != 0:
                findings.append(f"{PARAM_HISTORICAL} {plane}: measured absence with count "
                                f"{row.get('count')!r}, not zero")
            ev = row.get("evidence") or {}
            if not ev or not ev.get("detail"):
                findings.append(f"{PARAM_HISTORICAL} {plane}: measured absence carries no "
                                f"provenance")
            if ev.get("chronology") != "predates":
                findings.append(f"{PARAM_HISTORICAL} {plane}: measured absence is not explained by "
                                f"chronology (chronology={ev.get('chronology')!r})")
    for plane, marker in KEY_ABSENCE_MARKERS.items():
        row = hist_rows.get(plane)
        if row is None or row.get("status") != "measured_absence":
            findings.append(f"{PARAM_HISTORICAL} {plane}: the brief's decisive absence is not "
                            f"recorded as a measured absence")
        manifest = (row or {}).get("evidence", {}).get("manifest")
        if manifest:
            paths = _manifest_paths(manifest)
            if any(p.startswith(marker) if marker.endswith("/") else p == marker
                   for p in paths):
                findings.append(f"{PARAM_HISTORICAL} {plane}: the manifest carries {marker!r}, so "
                                f"the recorded absence is contradicted by the source")
    # ENGINE is present in 0.9.8zh: the older authority produces an absence for the provider
    # epoch, not a blanket one, and the court refuses a census that assumes otherwise.
    engines = hist_rows.get("engines")
    if engines is None or engines.get("status") != "produced":
        findings.append(f"{PARAM_HISTORICAL} engines: the release's ENGINE implementation is "
                        f"present but the census does not record it as produced")

    # The default authority is the byte-identity pivot and must have every plane produced.
    default_rows = {r["plane"]: r for r in (censuses.get(default_id) or {}).get("planes", [])}
    for plane in plane_order:
        row = default_rows.get(plane)
        if row is not None and row.get("status") != "produced":
            findings.append(f"{default_id} {plane}: the maintained authority's plane is not "
                            f"produced")
    if (receipt.get("byte_identity") or {}).get("authority_id") != default_id:
        findings.append("the receipt's byte_identity does not bind the default authority")
    return findings


def atlas_parameterization_sensitivity_control(receipt: dict, alias: dict,
                                               historical_census: dict) -> dict:
    """Prove the court can fail, and that a hidden production fallback is caught.

    The honest receipt must yield **zero** findings (specificity). Then: (a) a census for a
    *different* court authority must differ from the default's, so a generator that ignores its
    authority argument and falls back to production is caught; (b) a measured absence with no
    provenance, with a nonzero count, and (c) a census that renames its own authority, are each
    caught.
    """
    base = atlas_parameterization_findings(receipt, alias, historical_census)
    specificity = not base

    # (a) swapping the authority argument changes the produced plane.
    swapped = atlas_authority.build_census("openssl-3.6.3-historical")
    default_census = (receipt.get("censuses") or {}).get(PRODUCTION_AUTHORITY) or {}
    swapped_differs = (swapped.get("authority_id") != default_census.get("authority_id")
                       and swapped.get("source_file_count")
                       != default_census.get("source_file_count"))
    hidden_fallback_caught = bool(swapped_differs)

    def _mutate(mutator) -> list[str]:
        body = copy.deepcopy(receipt)
        mutator(body)
        return atlas_parameterization_findings(body, alias, historical_census)

    def strip_evidence(body: dict) -> None:
        for row in body["censuses"][PARAM_HISTORICAL]["planes"]:
            if row["status"] == "measured_absence":
                row["evidence"] = {}
                return

    def nonzero_absence(body: dict) -> None:
        for row in body["censuses"][PARAM_HISTORICAL]["planes"]:
            if row["status"] == "measured_absence":
                row["count"] = 5  # an absence with a nonzero count is not a measured zero
                return

    def rename_authority(body: dict) -> None:
        row = body["censuses"][PARAM_HISTORICAL]
        row["authority_id"] = "openssl-3.6.4-production"

    absence_without_evidence = _mutate(strip_evidence)
    absence_nonzero = _mutate(nonzero_absence)
    renamed = _mutate(rename_authority)

    caught_no_evidence = any("measured absence with count" in f or "no provenance" in f
                             for f in absence_without_evidence)
    caught_nonzero = any("not zero" in f for f in absence_nonzero)
    caught_renamed = any("does not reproduce" in f or "disagrees" in f for f in renamed)

    return {
        "baseline_findings": len(base),
        "specificity_holds": specificity,
        "swapped_authority": "openssl-3.6.3-historical",
        "swapped_authority_differs": bool(swapped_differs),
        "swapped_authority_census_files": swapped.get("source_file_count"),
        "hidden_production_fallback_caught": hidden_fallback_caught,
        "injected_absence_without_evidence_findings": len(absence_without_evidence),
        "injected_absence_nonzero_findings": len(absence_nonzero),
        "injected_renamed_authority_findings": len(renamed),
        "caught_absence_without_evidence": caught_no_evidence,
        "caught_absence_nonzero": caught_nonzero,
        "caught_renamed_authority": caught_renamed,
        "honest": bool(specificity and hidden_fallback_caught and caught_no_evidence
                       and caught_nonzero and caught_renamed),
    }


def _atlas_parameterization_court(name: str) -> dict:
    """`RT-ATLAS-PARAMETERIZATION`: 23.3's court, the parameterized atlases.

    Stages no probe in `artifacts/phase23/probes/`: its instrument is the generator itself. It
    reads `forensics/atlas/parameterization-receipt.json`, the committed default-authority alias
    and the historical authority's plane census; re-derives every census through the same
    generator; corroborates the historical authority's decisive absences against the committed
    source manifest; and **re-runs the authority-parameterized archaeology generators for the
    3.6.4 production authority**, asserting the committed plane is byte-identical. The one
    pre-existing, disclosed drift (`parity-obligations.json`) is measured live and undone, never
    applied. Swapping the authority argument must change the produced census, so a hidden
    production fallback is caught.
    """
    problems: list[str] = []
    historical_path = REPO_ROOT / "forensics" / "atlas" / PARAM_HISTORICAL / "plane-census.json"
    for path, label in ((PARAM_RECEIPT, "parameterization receipt"),
                        (DEFAULT_AUTHORITY_ALIAS, "default-authority alias"),
                        (historical_path, "historical plane census"),
                        (HIST_ACQ, "historical acquisition")):
        if not path.is_file():
            problems.append(f"the {label} {rel(path)} is absent")
    if problems:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": problems, "findings": [], "control": {}}

    receipt_doc = json.loads(PARAM_RECEIPT.read_text(encoding="utf-8"))
    receipt = receipt_doc.get("body", receipt_doc)
    alias_doc = json.loads(DEFAULT_AUTHORITY_ALIAS.read_text(encoding="utf-8"))
    alias = alias_doc.get("body", alias_doc)
    historical_doc = json.loads(historical_path.read_text(encoding="utf-8"))

    findings = atlas_parameterization_findings(receipt, alias, historical_doc)
    control = atlas_parameterization_sensitivity_control(receipt, alias, historical_doc)

    identity = _measure_atlas_byte_identity(PRODUCTION_AUTHORITY)
    measured = set(identity["parameterized_diffs"]) | set(identity["pre_existing_drift"])
    disclosed = set(identity["disclosed_drift"])
    undisclosed = sorted(measured - disclosed)
    if undisclosed:
        findings.append("the authority-parameterized regeneration moved committed bytes that are "
                        f"not the disclosed pre-existing drift: {undisclosed}")
    raw_codes = identity["regenerator_returncodes"]
    if any(c != 0 for c in raw_codes.values()):
        findings.append(f"an authority-parameterized regenerator failed: {raw_codes}")
    parameterized_reproduced = not undisclosed

    censuses = receipt.get("censuses") or {}
    verdict = "pass" if (not findings and not problems and control["honest"]) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: its instrument is the parameterized generator. It reads "
            "forensics/atlas/parameterization-receipt.json, the committed default-authority alias "
            "and forensics/atlas/openssl-0.9.8zh-historical/plane-census.json; re-derives every "
            "census through the same generator (one code path, one plane set); corroborates the "
            "historical authority's decisive absences (providers, provider registrations, QUIC) "
            "against its committed source manifest; and re-runs the authority-parameterized "
            "archaeology generators for the 3.6.4 production authority and asserts its committed "
            "plane is byte-identical. The default is the committed alias, never the catalogue's "
            "latest-stable (openssl-4.0.3). Swapping the authority argument changes the produced "
            "census, so a hidden production fallback is caught; a measured absence with no "
            "provenance or a nonzero count is refused. The pre-existing, disclosed drift "
            "(parity-obligations.json and the rendered ATLAS.md, stale since cli-commands gained "
            "its option grammar at p16) is measured live and undone, never applied."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the parameterization court reads committed atlas evidence and stages no "
            "artifacts/phase23/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "default_authority": PRODUCTION_AUTHORITY,
        "planes": len(receipt.get("plane_order") or []),
        "authorities": sorted(censuses),
        "produced": {aid: (c.get("counts") or {}).get("produced")
                     for aid, c in sorted(censuses.items())},
        "measured_absence": {aid: v for aid, v in sorted(
            (receipt.get("measured_absences") or {}).items())},
        "byte_identity": {
            "parameterized_reproduced": parameterized_reproduced,
            "files_checked": identity["files_checked"],
            "regenerators": identity["regenerators"],
            "pre_existing_drift": identity["pre_existing_drift"],
            "disclosed_drift": identity["disclosed_drift"],
        },
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
            "any other. `RT-AUTHORITY-NODES` is 23.2's court: the authority-node registry. It "
            "stages no probe and reads forensics/authority-nodes.json and the records it is "
            "derived from -- the release catalogue, the admitted-authority registry, the build "
            "records and the historical acquisition and build receipts -- and establishes that "
            "every node is schema-valid, content-addressed and backed by an actual build receipt; "
            "that release identity (release_id, git) is proven against the catalogue and kept "
            "separate from platform/profile identity; that the admitted pair's source manifests "
            "still reproduce; and that an unavailable authority is recorded unavailable and is "
            "never a node. A built-authority claim with no receipt, a dropped required identity "
            "field, and a source digest asserting tag == tarball without proof are each detected "
            "with specificity holding. `RT-ATLAS-PARAMETERIZATION` is 23.3's court: the "
            "parameterized atlases. Its instrument is the generator itself: it reads "
            "forensics/atlas/parameterization-receipt.json, the committed default-authority alias "
            "and forensics/atlas/openssl-0.9.8zh-historical/plane-census.json, re-derives every "
            "census through the same generator, corroborates the historical authority's decisive "
            "absences (providers, provider registrations, QUIC) against its committed source "
            "manifest, and re-runs the authority-parameterized archaeology generators for the "
            "3.6.4 production authority, asserting its committed plane is byte-identical. The "
            "default is the committed alias, never the catalogue's `latest-stable` "
            "(openssl-4.0.3); swapping the authority argument changes the produced census, so a "
            "hidden production fallback is caught, and a measured absence with no provenance or "
            "a nonzero count is refused. The one pre-existing, disclosed drift "
            "(parity-obligations.json) is measured live and undone, never applied. Phase 23 owns "
            "no exported symbol, so no differential probe "
            "over a symbol set is its evidence, and its remaining fourteen courts -- "
            "RT-LINEAGE-EDGES, RT-ENTITY-LINEAGE, RT-DELTA-ENGINE, "
            "RT-ABI-HISTORY-FACADES, RT-SEMANTIC-COURTS, RT-COMPATIBILITY-VIEWS, "
            "RT-HISTORICAL-POPULATION, RT-DOWNSTREAM-MULTITRACK, RT-COMPATIBILITY-EDGES, "
            "RT-NEGATIVE-OBLIGATIONS, RT-SECURITY-LINEAGE, RT-SUPPORT-STATUS, "
            "RT-COMPATIBILITY-MATRIX and MULTITRACK-SEAL -- are pending with "
            "the subphases that land them (23.4 through 23.17). The one thing the model forbids "
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
        InputRef(name="authority-nodes", path=AUTHORITY_NODES),
        InputRef(name="authority-registry", path=AUTHORITY_REGISTRY),
        InputRef(name="build-records", path=BUILD_RECORDS),
        InputRef(name="historical-acquisition", path=HIST_ACQ),
        InputRef(name="historical-build-receipts", path=HIST_RECEIPTS),
        InputRef(name="parameterization-receipt", path=PARAM_RECEIPT),
        InputRef(name="default-authority", path=DEFAULT_AUTHORITY_ALIAS),
        InputRef(name="historical-plane-census",
                 path=REPO_ROOT / "forensics" / "atlas" / PARAM_HISTORICAL / "plane-census.json"),
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
        elif r["verdict"] == "pass" and r["court"] == AUTHORITY_NODES_COURT:
            c = r["control"]
            print(f"  {r['court']:<32} pass   (no probe, {r['nodes']} node(s) "
                  f"{r['built']} built, {r['unavailable']} unavailable; "
                  f"content_hash={r['content_hash'][:16]}...; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"no-receipt->{c['injected_built_without_receipt_findings']} "
                  f"dropped-platform->{c['injected_dropped_platform_findings']} "
                  f"unproven-tarball->{c['injected_unproven_tarball_findings']} finding(s))")
            for n in r["node_identities"]:
                print(f"      node {n['authority_id']:<32} release={n['release_id']:<18} "
                      f"profile={n['profile']} claim={n['claim']}")
            for u in r["unavailable_identities"]:
                print(f"      unavailable {u['release_id']:<27} outcome={u['outcome']} "
                      f"runtime_evidence={u['runtime_evidence']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == ATLAS_PARAMETERIZATION_COURT:
            c = r["control"]
            bi = r["byte_identity"]
            print(f"  {r['court']:<32} pass   (no probe, {r['planes']} plane(s) over "
                  f"{len(r['authorities'])} authority/ies; default={r['default_authority']}; "
                  f"{len(r['findings'])} finding(s); 3.6.4 re-derived byte-identical="
                  f"{bi['parameterized_reproduced']} over {bi['files_checked']} file(s), "
                  f"disclosed drift={bi['pre_existing_drift']}; control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"swapped-authority-differs={c['swapped_authority_differs']} "
                  f"no-evidence->{c['injected_absence_without_evidence_findings']} "
                  f"nonzero->{c['injected_absence_nonzero_findings']} "
                  f"renamed->{c['injected_renamed_authority_findings']} finding(s))")
            for aid in sorted(r["produced"]):
                absent = r["measured_absence"].get(aid) or []
                print(f"      authority {aid:<32} produced={r['produced'][aid]}/"
                      f"{r['planes']} measured_absence={len(absent)}"
                      + (f" [{', '.join(absent)}]" if absent else ""))
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
