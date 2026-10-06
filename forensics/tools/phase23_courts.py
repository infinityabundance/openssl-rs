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

**Fifteen courts are registered.** 23.1 lands `RT-RELEASE-CATALOG`, the release catalogue and
lineage court, 23.2 lands `RT-AUTHORITY-NODES`, the authority-node registry court, 23.3 lands
`RT-ATLAS-PARAMETERIZATION`, the parameterized-atlas court, 23.4 lands `RT-LINEAGE-EDGES`, the
typed-lineage-edge court, 23.5 lands `RT-ENTITY-LINEAGE`, the entity-lineage court, 23.6 lands
`RT-DELTA-ENGINE`, the semantic compatibility-delta court, 23.7 lands
`RT-ABI-HISTORY-FACADES`, the ABI/history-façade court, 23.8 lands
`RT-SEMANTIC-COURTS`, the oracle-to-oracle and candidate-to-authority semantic court, 23.9 lands
`RT-COMPATIBILITY-VIEWS`, the directional compatibility-view court, 23.10 lands
`RT-HISTORICAL-POPULATION`, the historical-population court, 23.11 lands
`RT-DOWNSTREAM-MULTITRACK`, the unmodified-downstream-consumer court, and 23.12 lands
`RT-COMPATIBILITY-EDGES`, the directional compatibility-edge court, and 23.13 lands
`RT-NEGATIVE-OBLIGATIONS`, the negative/positive-obligation court, and 23.14 lands
`RT-SECURITY-LINEAGE`, the security-lineage court, and 23.15 lands `RT-SUPPORT-STATUS`, the
support-status-ladder court; the other two courts are
named in
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
  * `RT-LINEAGE-EDGES` -- 23.4, the lineage edges (registered).
  * `RT-ENTITY-LINEAGE` -- 23.5, the entity lineage (registered).
  * `RT-DELTA-ENGINE` -- 23.6, the delta engine (registered).
  * `RT-ABI-HISTORY-FACADES` -- 23.7, the ABI / history façades (registered).
  * `RT-SEMANTIC-COURTS` -- 23.8, the semantic multitrack courts (registered).
  * `RT-COMPATIBILITY-VIEWS` -- 23.9, the compatibility views (registered).
  * `RT-HISTORICAL-POPULATION` -- 23.10, the historical population (registered).
  * `RT-DOWNSTREAM-MULTITRACK` -- 23.11, the downstream multitrack court (registered).
  * `RT-COMPATIBILITY-EDGES` -- 23.12, the directional compatibility edges (registered).
  * `RT-NEGATIVE-OBLIGATIONS` -- 23.13, the negative obligations (registered).
  * `RT-SECURITY-LINEAGE` -- 23.14, the security lineage (registered).
  * `RT-SUPPORT-STATUS` -- 23.15, the support-status ladder (registered).
  * `RT-COMPATIBILITY-MATRIX` -- 23.16, the compatibility matrix.
  * `MULTITRACK-SEAL` -- 23.17, the full matrix, the FRF/Gemel chain and the seal.

Every one but `RT-RELEASE-CATALOG`, `RT-AUTHORITY-NODES`, `RT-ATLAS-PARAMETERIZATION`,
`RT-LINEAGE-EDGES`, `RT-ENTITY-LINEAGE`, `RT-DELTA-ENGINE`, `RT-ABI-HISTORY-FACADES`,
`RT-SEMANTIC-COURTS`, `RT-COMPATIBILITY-VIEWS`, `RT-HISTORICAL-POPULATION`,
`RT-DOWNSTREAM-MULTITRACK`, `RT-COMPATIBILITY-EDGES`,
`RT-NEGATIVE-OBLIGATIONS`, `RT-SECURITY-LINEAGE` and `RT-SUPPORT-STATUS` is
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
    sha256_file,
    write_json,
)

# The schemas the later subphases validate their records against. Imported rather than restated, so
# the registry's inventory cannot drift from the module the evidence is checked with.
import multitrack_schemas  # noqa: E402
# The Phase-23.3 parameterized generator, imported so the court re-derives the census in-process
# through the same code path the receipt was produced by (never a second, drifting predicate).
import atlas_authority  # noqa: E402
# The Phase-23.1 catalogue generator, imported for the lineage hash keys the sensitivity control
# re-seals a mutated body with, so the control isolates the semantic check rather than the hash.
import authority_catalog  # noqa: E402
# The Phase-23.5 entity-lineage generator, imported so the court re-derives every entity relation
# from the same identity shapes the committed plane was produced by (never a second, drifting
# predicate), and re-seals a mutated body with the generator's own hash keys.
import entity_lineage  # noqa: E402
# The Phase-23.6 delta engine, imported so the court re-derives every delta row from the committed
# atlases and entity lineage through the same engine the artefact was produced by, and composes a
# path delta from the edge deltas the same way.
import authority_delta  # noqa: E402
# The Phase-23.7 ABI/history-façade generator, imported so the court re-renders the generated
# `src/compat/layout_generated.rs` from the committed measurement through the same code path the
# file was produced by (never a second, drifting predicate), and re-checks its provenance.
import gen_abi_facades  # noqa: E402
# The Phase-23.8 semantic-court generator, imported so the court re-derives every normalized
# observation from the preserved raw transcripts through the same adapter the artefact was produced
# by (never a second, drifting vocabulary) and resolves each classified difference against the
# committed 23.6 delta engine.
import gen_semantic_courts  # noqa: E402
# The Phase-23.9 compatibility-view generator, imported so the court re-derives the whole plane from
# the committed evidence through the same code path the artefact was produced by (never a second,
# drifting predicate) and checks each view's evidence provenance against the authority it names.
import compat_views  # noqa: E402
# The Phase-23.12 compatibility-edge generator, imported so the court re-derives the whole plane
# from the committed delta/lineage/view/ABI evidence through the same code path the artefact was
# produced by (never a second, drifting predicate) and checks each side's evidence provenance
# against the side it names.
import compat_edges  # noqa: E402
# The Phase-23.13 negative-obligation generator, imported so the court re-derives the whole plane
# from the committed censuses, façades, deltas and symbols planes through the same code path the
# artefact was produced by (never a hand-listed obligation), and re-reads each record's named
# evidence through `adjudicate` so a typed state is a finding rather than a plausible value.
import negative_obligations  # noqa: E402
# The Phase-23.10 historical-population generator, imported so the court re-derives every support
# status from the committed catalogue, authority nodes and receipts through the same code path the
# artefact was produced by (never a hand-listed status) and re-derives a mutated epoch's coverage.
import historical_population  # noqa: E402
# The Phase-23.15 support-status generator, imported so the court re-derives the whole ladder plane
# from the 23.10 population through the same code path the artefact was produced by (never a typed
# status) and reconciles every row with its population record rung for rung.
import support_status  # noqa: E402
# The Phase-23.11 downstream-multitrack generator, imported so the court re-derives every consumer
# record from the raw build/run outputs the artefact carries through the same code path the artefact
# was produced by (never a hand-typed outcome) and re-derives the epoch coverage a mutation moves.
import downstream_multitrack  # noqa: E402
# The Phase-23.14 security-lineage generator, imported so the court re-derives the whole plane from
# the committed source, catalogue, default-authority alias and divergence register through the same
# code path the artefact was produced by (never a typed disposition, a hand-listed fix or a
# re-adopted behaviour) and re-reads every cited evidence path.
import security_lineage  # noqa: E402
# The candidate version the Phase-17 corpus names, read from the one manifest knob so the
# distinctness check cannot drift from `Cargo.toml`.
import gen_frf_courts  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase23" / "COURTS.json"
GENERATOR = "forensics/tools/phase23_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-23-MULTITRACK-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "multitrack_schemas.py"
CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
LINEAGE = REPO_ROOT / "forensics" / "authority-lineage.json"
ENTITY_LINEAGE = REPO_ROOT / "forensics" / "multitrack" / "entity-lineage.json"
# 23.6's subject: the canonical edge deltas the delta engine writes, one file per lineage edge.
DELTAS = REPO_ROOT / "forensics" / "deltas"
DIFFERENTIAL_DIR = REPO_ROOT / "forensics" / "atlas" / "differential"
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

# 23.7's subject: the ABI/history façade plane, the generated repr(C) assertions it materialises,
# and the compat sources whose cfg gating keeps the default build clean. The historical plane
# census and the production atlas are the epoch evidence the court cross-checks against.
ABI_FACADES = REPO_ROOT / "forensics" / "multitrack" / "abi-facades.json"
ABI_FACADE_RUST = REPO_ROOT / "src" / "compat" / "layout_generated.rs"
COMPAT_MOD = REPO_ROOT / "src" / "compat" / "mod.rs"
COMPAT_POLICY = REPO_ROOT / "src" / "compat" / "policy.rs"
BUILD_SCRIPT = REPO_ROOT / "build.rs"
HISTORICAL_ATLAS = REPO_ROOT / "forensics" / "atlas" / PARAM_HISTORICAL
HISTORICAL_MANIFEST = REPO_ROOT / "forensics" / "authorities" / "SOURCE_MANIFEST.0.9.8zh.json"
# The planes the brief names as the decisive absences for an older authority, cross-checked in the
# court against the committed manifest independently of the generator's own predicates.
KEY_ABSENCE_MARKERS = {
    "providers": "providers/",
    "provider-registrations": "util/providers.num",
    "quic": "ssl/quic/",
}

# 23.8's subject: the normalized oracle-to-oracle and candidate-to-authority observations, the raw
# transcripts they were re-derived from, the candidate-to-authority disposition and the not-run list.
SEMANTIC_COURTS = REPO_ROOT / "forensics" / "multitrack" / "semantic-courts.json"
SEMANTIC_PROBE = REPO_ROOT / "courts" / "phase23" / "semantic_probe.c"

# 23.9's subject: the directional, dimension-specific compatibility views plane. The court reads it
# and re-derives every view from the authorities' own committed evidence through the same generator.
COMPATIBILITY_VIEWS = REPO_ROOT / "forensics" / "multitrack" / "compatibility-views.json"

# 23.12's subject: the directional, dimension-specific compatibility edges plane. The court reads it
# and re-derives every edge from the committed delta/lineage/view/ABI evidence through the same
# generator, and checks each side's evidence is its own.
COMPATIBILITY_EDGES = REPO_ROOT / "forensics" / "multitrack" / "compatibility-edges.json"

# 23.13's subject: the negative (and positive) obligations plane. The court reads it and re-derives
# every obligation from the committed censuses, façades, deltas and symbols planes through the same
# generator, and re-reads each record's named evidence so a leaked future symbol, a retained removed
# surface or an assumed state is caught.
NEGATIVE_OBLIGATIONS = REPO_ROOT / "forensics" / "multitrack" / "negative-obligations.json"

# 23.10's subject: the historical-population record over the release catalogue, and the records it
# is derived from -- the authority nodes, the acquisition and build receipts, the committed atlases
# and the semantic pair the runtime rung is read from.
HISTORICAL_POPULATION = REPO_ROOT / "forensics" / "multitrack" / "historical-population.json"
SEMANTIC_COURTS = REPO_ROOT / "forensics" / "multitrack" / "semantic-courts.json"
ATLAS_ROOT = REPO_ROOT / "forensics" / "atlas"

# 23.15's subject: the schema-validated support-status ladder plane, one derived row per catalogue
# node. It is derived from the 23.10 population and reconciled with it, so there is one derivation of
# a status rather than a second hand-maintained truth.
SUPPORT_STATUS = REPO_ROOT / "forensics" / "multitrack" / "support-status.json"

# 23.11's subject: the per-epoch unmodified downstream consumer records, the authority nodes they
# are bounded to, and the Phase-17 candidate corpus they must stay distinct from (a candidate
# result is never relabelled as authority evidence).
DOWNSTREAM_MULTITRACK = REPO_ROOT / "forensics" / "multitrack" / "downstream-multitrack.json"
PHASE17_CORPUS = REPO_ROOT / "forensics" / "atlas" / "downstream-corpus.json"
PHASE17_PROGRAMS = ("curl", "git", "haproxy", "nginx", "openssh", "python")

# 23.14's subject: the security-lineage plane, the frozen source snapshot it is derived from, the
# divergence register and policy it references, and the default-authority alias it reasons about
# (that alias is `DEFAULT_AUTHORITY_ALIAS`, defined with 23.3's subject above).
SECURITY_LINEAGE = REPO_ROOT / "forensics" / "multitrack" / "security-lineage.json"
SECURITY_SOURCE = REPO_ROOT / "forensics" / "multitrack" / "security-source.json"
SECURITY_DIVERGENCE = REPO_ROOT / "forensics" / "divergence-obligations.json"
SECURITY_POLICY = REPO_ROOT / "docs" / "SECURITY_DIVERGENCE_POLICY.md"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# 23.1's court, and the identity its subject must begin at. The root is upstream's first real
# OpenSSL release (23 December 1998), not a version the catalogue would pick by sorting.
RELEASE_CATALOG = "RT-RELEASE-CATALOG"
AUTHORITY_NODES_COURT = "RT-AUTHORITY-NODES"
ATLAS_PARAMETERIZATION_COURT = "RT-ATLAS-PARAMETERIZATION"
LINEAGE_EDGES_COURT = "RT-LINEAGE-EDGES"
ENTITY_LINEAGE_COURT = "RT-ENTITY-LINEAGE"
DELTA_ENGINE_COURT = "RT-DELTA-ENGINE"
ABI_HISTORY_FACADES_COURT = "RT-ABI-HISTORY-FACADES"
SEMANTIC_COURTS_COURT = "RT-SEMANTIC-COURTS"
COMPATIBILITY_VIEWS_COURT = "RT-COMPATIBILITY-VIEWS"
COMPATIBILITY_EDGES_COURT = "RT-COMPATIBILITY-EDGES"
NEGATIVE_OBLIGATIONS_COURT = "RT-NEGATIVE-OBLIGATIONS"
SECURITY_LINEAGE_COURT = "RT-SECURITY-LINEAGE"
SUPPORT_STATUS_COURT = "RT-SUPPORT-STATUS"
HISTORICAL_POPULATION_COURT = "RT-HISTORICAL-POPULATION"
DOWNSTREAM_MULTITRACK_COURT = "RT-DOWNSTREAM-MULTITRACK"
ROOT_RELEASE = "openssl-0.9.1c"
CANONICAL_KINDS = ("branch_fork", "chronological_successor", "maintenance_successor")
PRERELEASE_MARKERS = ("alpha", "beta", "rc", "pre")

# 23.4's subject. The kinds whose reading is **defined** to run forward in time (the
# reference/predecessor precedes the subject/successor), so a `direction` that reads a later release
# into an earlier one is refused. `branch_fork` and `git_ancestry` are excluded: a fork base is the
# predecessor series' current final (which can post-date the branch's own first pre-release) and a
# git ancestor is the commit graph's ancestor, not a date order.
DATED_READING_KINDS = (
    "chronological_successor", "maintenance_successor", "declared_abi_compatibility",
    "security_backport", "observed_compatibility",
)
# The parallel supported lines the plan names (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 0),
# each of which must begin with a typed branch_fork rather than be linearised onto its predecessor.
PARALLEL_SUPPORTED_LINES = ("1.0.2", "1.1.1", "3.", "4.")

# The courts this stratum will stage. 23.1 registers `RT-RELEASE-CATALOG`; each later subphase
# appends its court here in the commit that lands its instrument, and a court removed from the
# table leaves the registry and fails `run_courts.py`.
COURTS: list[tuple[str, str]] = [
    (RELEASE_CATALOG, "_release_catalog_court"),
    (AUTHORITY_NODES_COURT, "_authority_nodes_court"),
    (ATLAS_PARAMETERIZATION_COURT, "_atlas_parameterization_court"),
    (LINEAGE_EDGES_COURT, "_lineage_edges_court"),
    (ENTITY_LINEAGE_COURT, "_entity_lineage_court"),
    (DELTA_ENGINE_COURT, "_delta_engine_court"),
    (ABI_HISTORY_FACADES_COURT, "_abi_history_facades_court"),
    (SEMANTIC_COURTS_COURT, "_semantic_courts_court"),
    (COMPATIBILITY_VIEWS_COURT, "_compatibility_views_court"),
    (COMPATIBILITY_EDGES_COURT, "_compatibility_edges_court"),
    (NEGATIVE_OBLIGATIONS_COURT, "_negative_obligations_court"),
    (SECURITY_LINEAGE_COURT, "_security_lineage_court"),
    (HISTORICAL_POPULATION_COURT, "_historical_population_court"),
    (SUPPORT_STATUS_COURT, "_support_status_court"),
    (DOWNSTREAM_MULTITRACK_COURT, "_downstream_multitrack_court"),
]

# The remaining courts the plan names, each pending with the subphase that lands it. Ordered as the
# plan orders them, so the registry reads as the execution order.
PENDING_COURTS: dict[str, str] = {
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


def _edge_read_pair(edge: dict) -> tuple[str, str]:
    """The edge's endpoints in the sense it is read: `(predecessor/reference, successor/subject)`.

    `direction` is the sense the edge is read in and is load-bearing: `forward` reads
    `from_id -> to_id`, `reverse` reads `to_id -> from_id`. A reader that ignored it could silently
    reverse a relationship, which is the mutation the court's control seeds.
    """
    if edge.get("direction", "forward") == "reverse":
        return edge["to_id"], edge["from_id"]
    return edge["from_id"], edge["to_id"]


def _release_order(catalog: dict) -> dict[str, tuple]:
    """Each release's chronology key: `(date, version order, release_id)`.

    The same key `forensics/tools/authority_catalog.py` orders each series by, so the court's
    family base and the generator's agree rather than being two drifting predicates. An unknown
    date sorts first and is never used to claim a chronology.
    """
    out: dict[str, tuple] = {}
    for n in catalog.get("nodes", []):
        date = n["release_date"]
        version = multitrack_schemas.parse_version(n["display_version"]).order_key()
        out[n["release_id"]] = ((date == "unknown", date), version, n["release_id"])
    return out


def _lineage_dag(ids: set[str], edges: list[dict]) -> tuple[list[str], list[str]]:
    """The edges' topological order over `ids`, and the cyclic nodes (empty when it is a DAG).

    Recomputed here from the edges rather than read from the committed `dag` field, so a cycle
    introduced into the edge list is caught on the graph itself.
    """
    adj: dict[str, list[str]] = {i: [] for i in ids}
    indeg: dict[str, int] = {i: 0 for i in ids}
    for e in edges:
        a, b = e.get("from_id"), e.get("to_id")
        if a in adj and b in adj:
            adj[a].append(b)
            indeg[b] += 1
    queue = sorted(i for i in ids if indeg[i] == 0)
    order: list[str] = []
    while queue:
        x = queue.pop(0)
        order.append(x)
        for y in sorted(adj[x]):
            indeg[y] -= 1
            if indeg[y] == 0:
                queue.append(y)
        queue.sort()
    return order, sorted(i for i in ids if i not in set(order))


def lineage_edge_findings(catalog: dict, lineage: dict) -> list[str]:
    """Every way the typed lineage edges fail this court's subject.

    A pure function of the two committed bodies, so the sensitivity control can mutate them and
    re-check. It establishes that every edge is schema-valid, **typed**, **directed** (its stated
    sense follows the evidence's chronology) and provenance-backed; that the graph is a DAG whose
    parallel supported branches are typed `branch_fork` edges rather than a false linear mainline;
    that a date-order (`chronological_successor`) edge is never presented as an ABI-compatibility
    proof; that the one compatibility-ish kind the evidence supports, `declared_abi_compatibility`,
    is marked as a **declaration** and scoped to its declared family; and that every stated absence
    of a kind carries its reason.
    """
    findings: list[str] = []
    nodes = {n["release_id"]: n for n in catalog.get("nodes", [])}
    ids = set(nodes)
    edges = lineage.get("edges", [])
    order = _release_order(catalog)

    # 1. every edge is schema-valid, typed and directed, with a unique id and known endpoints.
    seen_ids: set[str] = set()
    for e in edges:
        eid = e.get("edge_id")
        findings += [f"lineage edge {eid}: {p}" for p in multitrack_schemas.validate_lineage_edge(e)]
        if eid in seen_ids:
            findings.append(f"lineage edge {eid} is duplicated")
        seen_ids.add(eid)
        for field, value in (("from_id", e.get("from_id")), ("to_id", e.get("to_id"))):
            if value is not None and value not in ids:
                findings.append(f"lineage edge {eid}: {field} {value!r} is not a release node")

    # 2. the stated sense follows the evidence's chronology: an edge whose reading is a date order
    #    (a successor or a declared ABI reference) always runs from the earlier release to the later
    #    one. A reversed direction is a relationship read backwards.
    for e in edges:
        if e["kind"] not in DATED_READING_KINDS:
            continue
        pred, succ = _edge_read_pair(e)
        if pred not in order or succ not in order:
            continue
        if order[pred] > order[succ]:
            findings.append(
                f"lineage edge {e.get('edge_id')} reads [{e.get('direction')}] {pred} -> {succ}, "
                f"but {pred} is later than {succ}; the direction does not follow the evidence"
            )

    # 3. the graph is a DAG, recomputed from the edges rather than read from the committed field.
    _, cyclic = _lineage_dag(ids, edges)
    if cyclic:
        findings.append(f"the lineage is not a DAG: cyclic nodes {sorted(cyclic)[:6]}")
    if not (lineage.get("dag") or {}).get("is_dag"):
        findings.append("the committed lineage does not record itself as a DAG")

    # 4. parallel supported branches are typed forks, not a linearised mainline.
    canonical = [e for e in edges if e["kind"] in CANONICAL_KINDS]
    forks = [e for e in edges if e["kind"] == "branch_fork"]
    if not forks:
        findings.append("the lineage types no branch_fork edge, so parallel branches are "
                        "linearised onto their predecessors")
    children: dict[str, set[str]] = defaultdict(set)
    fork_parents: set[str] = set()
    fork_targets: set[str] = set()
    for e in canonical:
        pred, succ = _edge_read_pair(e)
        children[pred].add(succ)
    for e in forks:
        pred, succ = _edge_read_pair(e)
        fork_parents.add(pred)
        fork_targets.add(succ)
    branch_points = [k for k, v in children.items() if len(v) > 1]
    if not branch_points:
        findings.append("no node has two canonical children, so the lineage is one chain, not a DAG")
    elif not any(k in fork_parents for k in branch_points):
        findings.append("no branch point carries a typed branch_fork edge, so the parallel branches "
                        "are linearised")
    fork_target_versions = {nodes[t]["display_version"] for t in fork_targets if t in nodes}
    for line in PARALLEL_SUPPORTED_LINES:
        if not any(v.startswith(line) for v in fork_target_versions):
            findings.append(f"the {line} supported line has no typed branch_fork head, so it is "
                            f"linearised onto its predecessor rather than forked")

    # 5. a date-order edge is not presented as an ABI-compatibility proof.
    if not lineage.get("date_order_is_not_abi"):
        findings.append("the lineage does not state that a date order is not an ABI proof")
    for e in edges:
        if e["kind"] == "chronological_successor" and (e.get("declared") or e.get("dimension")):
            findings.append(f"chronological_successor edge {e.get('edge_id')} carries a "
                            f"compatibility dimension or declaration, presenting a date order as "
                            f"an ABI proof")
    declared = [e for e in edges if e["kind"] == "declared_abi_compatibility"]
    if not declared:
        findings.append("the lineage types no declared_abi_compatibility edge")
    families: dict[str, list[dict]] = defaultdict(list)
    for n in catalog.get("nodes", []):
        if n["release_channel"] == "final" and n["mainline_or_auxiliary"] == "mainline":
            families[n["declared_compatibility_family"]].append(n)
    bases = {fam: min(members, key=lambda n: order[n["release_id"]])["release_id"]
             for fam, members in families.items()}
    for e in declared:
        ep, es = nodes.get(e.get("from_id")), nodes.get(e.get("to_id"))
        if e.get("declared") is not True:
            findings.append(f"declared_abi_compatibility edge {e.get('edge_id')} is not marked "
                            f"`declared`; a declaration must not read as a measurement")
        if e.get("dimension") != "abi":
            findings.append(f"declared_abi_compatibility edge {e.get('edge_id')} is not on the "
                            f"`abi` dimension")
        if ep is None or es is None:
            continue
        if not (ep["release_channel"] == es["release_channel"] == "final"
                and ep["mainline_or_auxiliary"] == es["mainline_or_auxiliary"] == "mainline"):
            findings.append(f"declared_abi_compatibility edge {e.get('edge_id')} binds a release "
                            f"that is not a mainline final")
        if ep["declared_compatibility_family"] != es["declared_compatibility_family"]:
            findings.append(f"declared_abi_compatibility edge {e.get('edge_id')} spans two declared "
                            f"compatibility families")
        elif e["from_id"] != bases.get(ep["declared_compatibility_family"]):
            findings.append(f"declared_abi_compatibility edge {e.get('edge_id')} does not take the "
                            f"family base {bases.get(ep['declared_compatibility_family'])} as its "
                            f"ABI reference")

    # 6. every edge's provenance resolves: a repo-relative path exists, an http(s) URL is a URL.
    for e in edges:
        prov = e.get("metadata_provenance") or []
        for entry in ([prov] if isinstance(prov, str) else prov):
            if entry.startswith(("http://", "https://")):
                continue
            if not (REPO_ROOT / entry).is_file():
                findings.append(f"lineage edge {e.get('edge_id')}: provenance {entry!r} does not "
                                f"resolve")

    # 7. every kind in the vocabulary is either present or recorded absent with a reason.
    present = {e["kind"] for e in edges}
    absent = lineage.get("absent_kinds") or {}
    for kind in multitrack_schemas.LINEAGE_EDGE_KINDS:
        if kind not in present and kind not in absent:
            findings.append(f"edge kind {kind!r} is neither present nor recorded absent")
    for kind, reason in absent.items():
        if kind in present:
            findings.append(f"edge kind {kind!r} is recorded absent but is present")
        if not reason:
            findings.append(f"absent edge kind {kind!r} carries no reason")

    # 8. the content hash is a function of the committed body.
    recomputed = content_hash({k: lineage.get(k) for k in authority_catalog.LINEAGE_HASH_KEYS})
    if recomputed != lineage.get("content_hash"):
        findings.append("the lineage content_hash does not reproduce from its body")
    return findings


def lineage_edges_sensitivity_control(catalog: dict, lineage: dict) -> dict:
    """Prove the court can fail: seed four mutations and require each to be caught.

    The honest lineage must yield **zero** findings (specificity), and each seeded mutation -- a
    reversed edge direction, a date-order edge relabelled `declared_abi_compatibility`, an
    introduced cycle and an edge stripped of its provenance -- must be caught. Each mutated body is
    re-sealed with the generator's own hash keys first, so the detection is the semantic check and
    never the content-hash check firing on an un-recomputed digest.
    """
    base = lineage_edge_findings(catalog, lineage)
    specificity = not base

    def reseal(body: dict) -> dict:
        out = copy.deepcopy(body)
        out["content_hash"] = content_hash(
            {k: out.get(k) for k in authority_catalog.LINEAGE_HASH_KEYS})
        return out

    # (a) reverse an edge's direction without moving its endpoints: the relationship is now read
    #     from the later release into the earlier one.
    reversed_body = copy.deepcopy(lineage)
    reversed_edge = next((e for e in reversed_body["edges"]
                          if e["kind"] == "chronological_successor"), None)
    if reversed_edge is not None:
        reversed_edge["direction"] = "reverse"
    reversed_body = reseal(reversed_body)
    reversed_findings = lineage_edge_findings(catalog, reversed_body)
    caught_reversed = any("does not follow the evidence" in f for f in reversed_findings)

    # (b) relabel a date-order edge as a declared ABI compatibility edge: a chronology dressed as
    #     an ABI promise.
    relabel_body = copy.deepcopy(lineage)
    relabelled = next((e for e in relabel_body["edges"]
                       if e["kind"] == "chronological_successor"), None)
    if relabelled is not None:
        relabelled["kind"] = "declared_abi_compatibility"
        relabelled["declared"] = True
        relabelled["dimension"] = "abi"
    relabel_body = reseal(relabel_body)
    relabel_findings = lineage_edge_findings(catalog, relabel_body)
    caught_relabel = any("declared_abi_compatibility" in f and "spans two declared" in f
                         for f in relabel_findings)

    # (c) introduce a cycle: a canonical edge from the newest mainline final back to the root.
    newest = max((n for n in catalog["nodes"]
                  if n["release_channel"] == "final" and n["mainline_or_auxiliary"] == "mainline"),
                 key=lambda n: _release_order(catalog)[n["release_id"]])["release_id"]
    cycle_body = copy.deepcopy(lineage)
    cycle_body["edges"].append({
        "edge_id": f"L-maintenance_successor-{newest}-{lineage['root']}",
        "kind": "maintenance_successor",
        "from_id": newest,
        "to_id": lineage["root"],
        "direction": "forward",
        "evidence": ["seeded cycle"],
        "metadata_provenance": [rel(LINEAGE)],
    })
    cycle_body = reseal(cycle_body)
    cycle_findings = lineage_edge_findings(catalog, cycle_body)
    caught_cycle = any("not a DAG" in f for f in cycle_findings)

    # (d) drop an edge's provenance: a relationship asserted with nothing to read it from.
    stripped_body = copy.deepcopy(lineage)
    stripped = next((e for e in stripped_body["edges"] if e["kind"] == "maintenance_successor"),
                    None)
    if stripped is not None:
        stripped["metadata_provenance"] = []
    stripped_body = reseal(stripped_body)
    stripped_findings = lineage_edge_findings(catalog, stripped_body)
    caught_stripped = any("metadata_provenance" in f for f in stripped_findings)

    return {
        "baseline_findings": len(base),
        "injected_reversed_direction": (reversed_edge or {}).get("edge_id"),
        "injected_reversed_direction_findings": len(reversed_findings),
        "injected_relabelled_date_order_edge": (relabelled or {}).get("edge_id"),
        "injected_relabelled_date_order_findings": len(relabel_findings),
        "injected_cycle_edge": f"L-maintenance_successor-{newest}-{lineage['root']}",
        "injected_cycle_findings": len(cycle_findings),
        "injected_provenance_drop": (stripped or {}).get("edge_id"),
        "injected_provenance_drop_findings": len(stripped_findings),
        "specificity_holds": specificity,
        "caught_reversed_direction": caught_reversed,
        "caught_relabelled_date_order": caught_relabel,
        "caught_cycle": caught_cycle,
        "caught_provenance_drop": caught_stripped,
        "honest": bool(specificity and caught_reversed and caught_relabel and caught_cycle
                       and caught_stripped),
    }


def _lineage_edges_court(name: str) -> dict:
    """`RT-LINEAGE-EDGES`: 23.4's court, the typed lineage edges.

    Stages no probe. It reads `forensics/release-catalog.json` and `forensics/authority-lineage.json`
    and establishes that every edge is schema-valid, typed and directed, with the stated sense
    following the evidence's chronology and provenance that resolves; that the graph is a DAG whose
    parallel supported branches (1.0.2, 1.1.1, the 3.x series and the 4.x line) are typed
    `branch_fork` edges rather than a false linear mainline; that a date-order
    (`chronological_successor`) edge is never dressed as an ABI-compatibility proof; that the one
    compatibility-ish kind the evidence supports, `declared_abi_compatibility`, is marked as a
    declaration and scoped to its declared family; and that every kind the vocabulary names but the
    evidence cannot yet settle is recorded absent with its reason. Four seeded mutations are each
    caught with specificity holding. A passing edge set is an **instrument**: it types relationships
    between releases and says nothing about whether any release is compatible with any other.
    """
    problems: list[str] = []
    for path, label in ((CATALOG, "release catalogue"), (LINEAGE, "authority lineage")):
        if not path.is_file():
            problems.append(f"the {label} {rel(path)} is absent")
    if problems:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": problems, "findings": [], "control": {}}

    catalog = read_json(CATALOG)
    lineage = read_json(LINEAGE)
    findings = lineage_edge_findings(catalog, lineage)
    control = lineage_edges_sensitivity_control(catalog, lineage)

    kinds = (lineage.get("counts") or {}).get("kinds", {})
    edges = lineage.get("edges", [])
    verdict = "pass" if (not findings and not problems and control["honest"]) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/release-catalog.json and "
            "forensics/authority-lineage.json and establishes that every edge is schema-valid, "
            "typed and directed, with its stated sense following the evidence's chronology and its "
            "provenance resolving; that the graph is a DAG whose parallel supported branches "
            "(1.0.2, 1.1.1, 3.x, 4.x) are typed branch_fork edges rather than a false linear "
            "mainline; that a date-order chronological_successor edge is never presented as an ABI "
            "proof; that the declared_abi_compatibility edges are marked declarations scoped to "
            "their declared family; and that every kind the vocabulary names but the evidence "
            "cannot settle is recorded absent with a reason. A reversed edge direction, a "
            "date-order edge relabelled declared_abi_compatibility, an introduced cycle and an "
            "edge stripped of provenance are each detected with specificity holding "
            "(docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 0, 3.1 and 4.3)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the lineage-edge court reads committed release records and stages no "
            "artifacts/phase23/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "edges": len(edges),
        "kinds": kinds,
        "declared_edges": sum(1 for e in edges if e.get("declared") is True),
        "absent_kinds": lineage.get("absent_kinds"),
        "direction_model": lineage.get("direction_model"),
        "dag": lineage.get("dag"),
        "content_hash": lineage.get("content_hash"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


# The declaration planes the committed differential atlas publishes a `common` count for, and the
# `entity_lineage` kind each corroborates. The differential is produced by a different generator
# from the entity plane, so agreement is corroboration rather than a restatement.
ENTITY_DIFFERENTIAL_PLANES: dict[str, str] = {
    "functions": "function",
    "variables": "variable",
    "structs": "struct",
    "typedefs": "typedef",
    "enums": "enum",
    "macros": "macro",
}

# The relations whose successor is a single entity, so a group of them landing on the same
# successor without a `merged_from` is a silent merge.
RENAME_LIKE: tuple[str, ...] = ("renamed_to", "moved_to", "semantic_successor")


# The extended fields every entity-lineage row must carry beside the base schema's fields, so a row
# names the two releases, both entities, the signals, the provenance and the confidence.
ENTITY_ROW_FIELDS: tuple[str, ...] = (
    "from_release", "to_release", "from_entity", "to_entity", "strong_signals",
    "metadata_provenance", "confidence",
)


def _entity_differential_findings(body: dict) -> list[str]:
    """Corroborate the entity plane against the committed differential atlas.

    The differential is a second, independently generated projection of the same two authorities,
    so its per-plane `common`/`removed`/`added` counts are a check the entity plane cannot pass by
    agreeing with itself. It is what catches an entity *split* by an instrument artefact: a struct
    whose raw shape moved only because the authority-scoped install prefix moved would leave the
    plane's present-in-both count short of the differential's `common`.
    """
    findings: list[str] = []
    pairs = [p for p in (body.get("coverage") or {}).get("pairs") or [] if p.get("covered")]
    if len(pairs) != 1:
        findings.append(f"the plane covers {len(pairs)} pair(s); the differential corroboration is "
                        f"defined for exactly one, so the plane cannot be corroborated")
        return findings
    pair = pairs[0]
    path = DIFFERENTIAL_DIR / f"{pair['from_authority']}-vs-{pair['to_authority']}.json"
    if not path.is_file():
        findings.append(f"the differential atlas {rel(path)} is absent, so the entity plane cannot "
                        f"be corroborated independently")
        return findings
    planes = read_json(path).get("planes") or {}
    relations = body.get("relations") or []
    kind_rows = Counter(r.get("entity_kind") for r in relations)
    kind_removed = Counter(r.get("entity_kind") for r in relations if r.get("relation") == "removed")
    added_kind: Counter = Counter()
    for kinds in ((body.get("counts") or {}).get("added_not_relations") or {}).values():
        added_kind.update(kinds)
    for plane, kind in ENTITY_DIFFERENTIAL_PLANES.items():
        info = planes.get(plane) or {}
        if info.get("common") is None:
            continue
        present = kind_rows.get(kind, 0) - kind_removed.get(kind, 0)
        if present != info["common"]:
            findings.append(f"the {plane} plane: the entity lineage carries {present} "
                            f"present-in-both row(s) but the committed differential counts "
                            f"{info['common']} common; an entity was dropped or split")
        if info.get("removed_count") is not None \
                and kind_removed.get(kind, 0) != info["removed_count"]:
            findings.append(f"the {plane} plane: {kind_removed.get(kind, 0)} removed row(s) but "
                            f"the differential counts {info['removed_count']}")
        if info.get("added_count") is not None \
                and added_kind.get(kind, 0) != info["added_count"]:
            findings.append(f"the {plane} plane: {added_kind.get(kind, 0)} addition(s) recorded "
                            f"but the differential counts {info['added_count']}")
    return findings


def _entity_coverage_findings(body: dict) -> list[str]:
    """The plane must name its coverage boundary: which authorities and pairs it does and does
    not cover, and why."""
    findings: list[str] = []
    coverage = body.get("coverage") or {}
    authorities = {a.get("authority_id"): a for a in coverage.get("authorities") or []}
    built = entity_lineage.built_authorities()
    for node in built:
        aid = node["authority_id"]
        entry = authorities.get(aid)
        if entry is None:
            findings.append(f"the coverage boundary silently omits the built authority {aid}")
            continue
        if entry.get("covered"):
            if not entry.get("declaration_planes"):
                findings.append(f"{aid} is marked covered but carries no declaration plane")
        elif not entry.get("reason"):
            findings.append(f"{aid} is not covered but names no reason")
        if entry.get("covered") != bool(entry.get("declaration_planes")):
            findings.append(f"{aid}: `covered` disagrees with `declaration_planes`")
    pairs = coverage.get("pairs") or []
    for p in pairs:
        if not p.get("reason"):
            findings.append(f"pair {p.get('from_authority')} -> {p.get('to_authority')} states no "
                            f"reason for its coverage")
    have = {(p.get("from_authority"), p.get("to_authority")) for p in pairs}
    ids = [node["authority_id"] for node in built]
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            if (a, b) not in have and (b, a) not in have:
                findings.append(f"the coverage boundary omits the authority pair {a} / {b}")
    if not coverage.get("boundary"):
        findings.append("the plane names no coverage boundary")
    if coverage.get("covered_pairs") != len([p for p in pairs if p.get("covered")]):
        findings.append("the coverage summary's covered_pairs count does not match its pair list")
    return findings


def _entity_absent_findings(body: dict) -> list[str]:
    """Every relation the vocabulary names is either present or recorded absent with a reason."""
    findings: list[str] = []
    present = {r.get("relation") for r in body.get("relations") or []}
    absent = body.get("absent_relations") or {}
    for relation in multitrack_schemas.ENTITY_RELATIONS:
        if relation not in present and relation not in absent:
            findings.append(f"relation {relation!r} is neither present nor recorded absent")
    for relation, reason in absent.items():
        if relation in present:
            findings.append(f"relation {relation!r} is recorded absent but is present")
        if not reason:
            findings.append(f"absent relation {relation!r} carries no reason")
    return findings


def entity_lineage_findings(body: dict, recomputed: dict | None = None,
                           prefix_only: set[str] | None = None) -> list[str]:
    """Every way the entity lineage fails this court's subject.

    A pure function of the committed body and the committed atlases, so the sensitivity control can
    mutate the body and re-check. It establishes that every row is schema-valid, provenanced and
    carries the extended fields; that a **settled** relation (anything but `unknown_relationship`)
    rests on a **strong** signal and never on a fuzzy nomination; that `same_entity` rows really are
    the same entity and reproduce as such from the atlases; that a relation is never settled on a
    struct whose raw difference is only the authority-scoped install prefix moving; that no two
    entities silently merge into one successor and no entity is both renamed and split; that every
    entity the atlases carry in the earlier release has exactly one row; and that the plane names
    its coverage boundary and its absent relations with reasons. A second, committed projection --
    the differential atlas -- corroborates the per-plane counts independently.
    """
    findings: list[str] = []
    if recomputed is None:
        recomputed = entity_lineage.recompute()
    if prefix_only is None:
        prefix_only = entity_lineage.prefix_only_structs()
    strong = set(entity_lineage.STRONG_SIGNALS)
    nomination = set(entity_lineage.NOMINATION_SIGNALS)
    covered = {(p.get("from_release"), p.get("to_release"))
               for p in (body.get("coverage") or {}).get("pairs") or [] if p.get("covered")}
    relations = body.get("relations") or []

    seen: set[tuple] = set()
    for r in relations:
        eid = r.get("entity_id")
        findings += [f"entity row {eid}: {p}"
                     for p in multitrack_schemas.validate_entity_lineage(r)]
        for f in ENTITY_ROW_FIELDS:
            if f not in r:
                findings.append(f"entity row {eid}: missing required field {f!r}")
        key = (r.get("from_release"), eid)
        if key in seen:
            findings.append(f"entity row {eid}: duplicated for pair {r.get('from_release')}")
        seen.add(key)
        prov = r.get("metadata_provenance") or []
        for entry in ([prov] if isinstance(prov, str) else prov):
            if entry.startswith(("http://", "https://")):
                continue
            if not (REPO_ROOT / entry).is_file():
                findings.append(f"entity row {eid}: provenance {entry!r} does not resolve")
        pair = (r.get("from_release"), r.get("to_release"))
        if pair not in covered:
            findings.append(f"entity row {eid}: names pair {pair[0]} -> {pair[1]}, which the "
                            f"coverage boundary does not declare covered")
        relation = r.get("relation")
        signals = set(r.get("strong_signals") or [])
        if relation == "unknown_relationship":
            if r.get("confidence") != "nominated":
                findings.append(f"entity row {eid}: unknown_relationship must read `nominated`")
            if not (signals & nomination):
                findings.append(f"entity row {eid}: unknown_relationship records no nomination")
        else:
            if r.get("confidence") != "established":
                findings.append(f"entity row {eid}: settled relation {relation!r} must read "
                                f"`established`")
            if not signals:
                findings.append(f"entity row {eid}: settled relation {relation!r} carries no "
                                f"strong signal, so a resemblance would read as a relation")
            bad = sorted(signals & nomination)
            if bad:
                findings.append(f"entity row {eid}: settled relation {relation!r} rests on the "
                                f"nomination signal(s) {bad}; it must be unknown_relationship")
            unknown = sorted(signals - strong - nomination)
            if unknown:
                findings.append(f"entity row {eid}: strong signal(s) {unknown} are not in the "
                                f"published vocabulary")
        if relation == "same_entity" and r.get("from_entity") != r.get("to_entity"):
            findings.append(f"entity row {eid}: same_entity claims two different entities "
                            f"{r.get('from_entity')!r} and {r.get('to_entity')!r}")
        expected = recomputed.get((r.get("from_release"), eid))
        if relation == "unknown_relationship":
            if expected is not None:
                findings.append(f"entity row {eid}: recorded unknown_relationship, but the atlases "
                                f"settle it as {expected!r}")
        elif expected is None:
            findings.append(f"entity row {eid}: relation {relation!r} is claimed for an entity the "
                            f"atlases do not carry in the earlier release")
        elif expected != relation:
            findings.append(f"entity row {eid}: relation {relation!r} does not reproduce from the "
                            f"atlases (they say {expected!r})")
        if eid in prefix_only and relation != "same_entity":
            findings.append(f"entity row {eid}: relation {relation!r} rests only on the "
                            f"authority-scoped install prefix moving, not on a real change")

    row_keys = {(r.get("from_release"), r.get("entity_id")) for r in relations}
    missing = sorted(set(recomputed) - row_keys)
    if missing:
        findings.append(f"{len(missing)} entity/ies present in the earlier release have no row, "
                        f"the first being {missing[0]}")
    extra = sorted(row_keys - set(recomputed))
    if extra:
        findings.append(f"{len(extra)} row(s) name an entity the atlases do not carry in the "
                        f"earlier release, the first being {extra[0]}")

    to_one: dict[tuple, set] = defaultdict(set)
    merged: dict[tuple, set] = defaultdict(set)
    for r in relations:
        if r.get("relation") in RENAME_LIKE:
            to_one[(r.get("from_release"), r.get("to_release"), r.get("to_entity"))].add(
                r.get("entity_id"))
        if r.get("relation") == "merged_from":
            merged[(r.get("from_release"), r.get("to_release"), r.get("entity_id"))] |= set(
                r.get("predecessors") or [])
    for key, sources in sorted(to_one.items(), key=lambda kv: repr(kv[0])):
        if len(sources) >= 2 and key not in merged:
            findings.append(f"entities {sorted(sources)} silently merge into {key[2]!r} without a "
                            f"merged_from row")
    renamed = {(r.get("from_release"), r.get("entity_id")) for r in relations
               if r.get("relation") == "renamed_to"}
    split = {(r.get("from_release"), r.get("entity_id")) for r in relations
             if r.get("relation") == "split_into"}
    for key in sorted(renamed & split, key=repr):
        findings.append(f"entity {key[1]} is recorded both renamed_to and split_into")

    findings += _entity_coverage_findings(body)
    findings += _entity_absent_findings(body)
    findings += _entity_differential_findings(body)
    recomputed_hash = content_hash({k: body.get(k) for k in entity_lineage.HASH_KEYS})
    if recomputed_hash != body.get("content_hash"):
        findings.append("the entity-lineage content_hash does not reproduce from its body")
    if (body.get("counts") or {}).get("rows") != len(relations):
        findings.append("the counts.rows does not match the relation list length")
    return findings


def entity_lineage_sensitivity_control(body: dict, recomputed: dict | None = None,
                                       prefix_only: set[str] | None = None) -> dict:
    """Prove the court can fail: seed four mutations and require each to be caught.

    The honest plane must yield **zero** findings (specificity), and each seeded mutation -- a
    `same_entity` claimed off name-only fuzzy similarity, a `renamed_to` that is really a split, a
    settled relation with no strong signal, and two entities silently merged into one successor --
    must be caught. Each mutated body is re-sealed with the generator's own hash keys first, so the
    detection is the semantic check and never the content-hash check firing on an un-recomputed
    digest.
    """
    if recomputed is None:
        recomputed = entity_lineage.recompute()
    if prefix_only is None:
        prefix_only = entity_lineage.prefix_only_structs()
    base = entity_lineage_findings(body, recomputed, prefix_only)
    specificity = not base

    def reseal(mutated: dict) -> dict:
        out = copy.deepcopy(mutated)
        out["content_hash"] = content_hash({k: out.get(k) for k in entity_lineage.HASH_KEYS})
        return out

    functions = [r for r in body.get("relations") or []
                 if r.get("entity_kind") == "function" and r.get("relation") == "same_entity"]
    if len(functions) < 3:
        return {"honest": False, "reason": "too few function rows for the seeded mutations"}
    x, y, z = functions[0], functions[1], functions[2]
    pair = [x["from_release"], x["to_release"]]
    prov = list(x["metadata_provenance"])

    # (a) a `same_entity` claimed off name-only fuzzy similarity: the added macro is present only
    #     in the later release, so a settled `same_entity` for it rests on resemblance alone.
    fuzzy = copy.deepcopy(body)
    fuzzy["relations"].append({
        "entity_id": "macro:SSL_VALUE_QUIC_MAX_PENDING_CONNS",
        "entity_kind": "macro",
        "relation": "same_entity",
        "present_in": pair,
        "from_release": pair[0],
        "to_release": pair[1],
        "from_entity": "SSL_VALUE_QUIC_MAX_PENDING_CONNS",
        "to_entity": "SSL_VALUE_QUIC_MAX_PENDING_CONNS",
        "strong_signals": ["name-similarity"],
        "evidence": ["seeded: the two names resemble one another"],
        "metadata_provenance": prov,
        "confidence": "established",
    })
    fuzzy_findings = entity_lineage_findings(reseal(fuzzy), recomputed, prefix_only)
    caught_fuzzy = any("nomination signal" in f for f in fuzzy_findings)

    # (b) a `renamed_to` that is actually a split: the same common entity is both renamed to one
    #     successor and split into two.
    split = copy.deepcopy(body)
    split["relations"].append({
        "entity_id": x["entity_id"],
        "entity_kind": "function",
        "relation": "renamed_to",
        "present_in": pair,
        "from_release": pair[0],
        "to_release": pair[1],
        "from_entity": x["from_entity"],
        "to_entity": y["from_entity"],
        "successor": y["from_entity"],
        "strong_signals": ["declaration-name-identity", "declaration-header-identity"],
        "evidence": ["seeded rename"],
        "metadata_provenance": prov,
        "confidence": "established",
    })
    split["relations"].append({
        "entity_id": x["entity_id"],
        "entity_kind": "function",
        "relation": "split_into",
        "present_in": pair,
        "from_release": pair[0],
        "to_release": pair[1],
        "from_entity": x["from_entity"],
        "to_entity": None,
        "successors": [y["from_entity"], z["from_entity"]],
        "strong_signals": ["declaration-name-identity", "declaration-header-identity"],
        "evidence": ["seeded split"],
        "metadata_provenance": prov,
        "confidence": "established",
    })
    split_findings = entity_lineage_findings(reseal(split), recomputed, prefix_only)
    caught_split = any("both renamed_to and split_into" in f for f in split_findings)

    # (c) a settled relation with no strong signal at all.
    nostrong = copy.deepcopy(body)
    nostrong["relations"][0]["strong_signals"] = []
    nostrong_findings = entity_lineage_findings(reseal(nostrong), recomputed, prefix_only)
    caught_nostrong = any("carries no strong signal" in f for f in nostrong_findings)

    # (d) a silent merge: two entities both become the same successor without a merged_from.
    merged = copy.deepcopy(body)
    for src in (x, y):
        merged["relations"].append({
            "entity_id": src["entity_id"],
            "entity_kind": "function",
            "relation": "renamed_to",
            "present_in": pair,
            "from_release": pair[0],
            "to_release": pair[1],
            "from_entity": src["from_entity"],
            "to_entity": z["from_entity"],
            "successor": z["from_entity"],
            "strong_signals": ["declaration-name-identity", "declaration-header-identity"],
            "evidence": ["seeded merge"],
            "metadata_provenance": prov,
            "confidence": "established",
        })
    merged_findings = entity_lineage_findings(reseal(merged), recomputed, prefix_only)
    caught_merge = any("silently merge" in f for f in merged_findings)

    return {
        "baseline_findings": len(base),
        "injected_fuzzy_same_entity": "macro:SSL_VALUE_QUIC_MAX_PENDING_CONNS",
        "injected_fuzzy_same_entity_findings": len(fuzzy_findings),
        "injected_rename_that_is_a_split": x["entity_id"],
        "injected_rename_that_is_a_split_findings": len(split_findings),
        "injected_settled_without_strong_signal": (body["relations"][0]["entity_id"]),
        "injected_settled_without_strong_signal_findings": len(nostrong_findings),
        "injected_silent_merge": [x["entity_id"], y["entity_id"]],
        "injected_silent_merge_findings": len(merged_findings),
        "specificity_holds": specificity,
        "caught_fuzzy_same_entity": caught_fuzzy,
        "caught_rename_that_is_a_split": caught_split,
        "caught_settled_without_strong_signal": caught_nostrong,
        "caught_silent_merge": caught_merge,
        "honest": bool(specificity and caught_fuzzy and caught_split and caught_nostrong
                       and caught_merge),
    }


def _entity_lineage_court(name: str) -> dict:
    """`RT-ENTITY-LINEAGE`: 23.5's court, the entity lineage.

    Stages no probe. It reads `forensics/multitrack/entity-lineage.json` and the committed atlases
    it derives from and establishes that every row is schema-valid, provenanced and carries the two
    releases, both entities, the signals and a confidence; that a settled relation rests on a strong
    signal and never on a fuzzy nomination; that `same_entity` rows are the same entity and
    reproduce as such; that no relation is settled on the install prefix moving; that no entity is
    dropped, silently merged or both renamed and split; and that the plane names its coverage
    boundary and its absent relations. The committed differential atlas corroborates the per-plane
    counts independently. Four seeded mutations are each caught with specificity holding. A passing
    entity plane is an **instrument**: it records what became of each entity, not whether any
    release is compatible with any other.
    """
    problems: list[str] = []
    if not ENTITY_LINEAGE.is_file():
        problems.append(f"the entity lineage {rel(ENTITY_LINEAGE)} is absent")
    if problems:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": problems, "findings": [], "control": {}}

    body = read_json(ENTITY_LINEAGE)
    recomputed = entity_lineage.recompute()
    prefix_only = entity_lineage.prefix_only_structs()
    findings = entity_lineage_findings(body, recomputed, prefix_only)
    control = entity_lineage_sensitivity_control(body, recomputed, prefix_only)

    counts = body.get("counts") or {}
    coverage = body.get("coverage") or {}
    verdict = "pass" if (not findings and not problems and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/multitrack/entity-lineage.json and the committed "
            "atlases it derives from, and establishes that every row is schema-valid, provenanced "
            "and names the two releases, both entities, the strong signals and a confidence; that "
            "a settled relation rests on a strong signal and never on a fuzzy nomination; that "
            "same_entity rows are the same entity and reproduce as such; that no relation is "
            "settled on the authority-scoped install prefix moving; that no entity is dropped, "
            "silently merged or both renamed and split; and that the plane names its coverage "
            "boundary and its absent relations. The committed differential atlas corroborates the "
            "per-plane counts. A same_entity off name-only similarity, a renamed_to that is "
            "really a split, a settled relation with no strong signal and a silent merge are each "
            "detected with specificity holding "
            "(docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 3.2 and 4.5)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the entity-lineage court reads committed atlas records and stages no "
            "artifacts/phase23/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "rows": counts.get("rows"),
        "relations": counts.get("relations"),
        "entity_kinds": counts.get("entity_kinds"),
        "added_not_relations": counts.get("added_not_relations"),
        "covered_pairs": coverage.get("covered_pairs"),
        "boundary": coverage.get("boundary"),
        "absent_relations": body.get("absent_relations"),
        "content_hash": body.get("content_hash"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


# --------------------------------------------------------------------------------------------
# the delta-engine court: the semantic compatibility delta over the canonical edges
# --------------------------------------------------------------------------------------------

# The fields every delta row must carry, so a row is directed, dimension-specific, evidenced and
# adjudicated rather than a bare name (docs/PHASE-23-MULTITRACK-SUBPHASES.md section 3.1).
DELTA_ROW_FIELDS: tuple[str, ...] = (
    "row_id", "entity_id", "entity_kind", "classification", "dimension", "facet",
    "from_id", "to_id", "direction", "sense", "before", "after", "evidence",
    "confidence", "adjudication",
)
# The markers a source-line diff would carry, and the suffixes that make an evidence path a diff
# rather than an atlas. A delta that carried any of them would be the substitution the brief
# forbids: a source diff answering a compatibility question.
DELTA_DIFF_MARKERS: tuple[str, ...] = ("@@", "--- a/", "+++ b/", "diff --git")
DELTA_DIFF_SUFFIXES: tuple[str, ...] = (".patch", ".diff")


def _delta_row_key(row: dict) -> tuple:
    return (row.get("row_id"), row.get("classification"), row.get("dimension"),
            row.get("facet"), row.get("before"), row.get("after"))


def _delta_row_problems(body: dict, row: dict, receipt: dict) -> list[str]:
    """Every way one delta row fails: missing fields, a bad dimension, no evidence, a diff."""
    problems: list[str] = []
    rid = row.get("row_id", "<no id>")
    for field in DELTA_ROW_FIELDS:
        if field not in row:
            problems.append(f"delta row {rid}: missing required field {field!r}")
    dimension = row.get("dimension")
    if dimension not in authority_delta.DELTA_DIMENSIONS:
        problems.append(f"delta row {rid}: dimension {dimension!r} is not a brief dimension")
    if row.get("classification") not in ("added", "removed", "changed"):
        problems.append(f"delta row {rid}: classification {row.get('classification')!r} is not "
                        f"added/removed/changed")
    if not row.get("evidence"):
        problems.append(f"delta row {rid}: carries no evidence, so the change is asserted")
    if row.get("from_id") != body.get("from_id") or row.get("to_id") != body.get("to_id"):
        problems.append(f"delta row {rid}: does not name the delta's two authorities")
    if row.get("sense") not in ("forward", "reverse"):
        problems.append(f"delta row {rid}: sense {row.get('sense')!r} is not forward/reverse")
    elif row.get("direction") != authority_delta.direction_for(row.get("sense")):
        problems.append(f"delta row {rid}: direction {row.get('direction')!r} disagrees with its "
                        f"sense {row.get('sense')!r}")
    if dimension in authority_delta.DELTA_DIMENSIONS \
            and authority_delta.DELTA_DIMENSIONS[dimension] != receipt.get("dimension"):
        problems.append(f"delta row {rid}: dimension {dimension!r} does not belong to receipt "
                        f"dimension {receipt.get('dimension')!r}")
    if not row.get("confidence"):
        problems.append(f"delta row {rid}: carries no confidence")
    if not row.get("adjudication"):
        problems.append(f"delta row {rid}: carries no adjudication")
    for entry in row.get("evidence") or []:
        if str(entry).endswith(DELTA_DIFF_SUFFIXES):
            problems.append(f"delta row {rid}: evidence {entry!r} is a source-line diff, not a "
                            f"compatibility delta")
    haystack = f"{row.get('before')} {row.get('after')}"
    for marker in DELTA_DIFF_MARKERS:
        if marker in haystack:
            problems.append(f"delta row {rid}: the row carries the source-diff marker {marker!r}")
    return problems


def delta_recompute_findings(body: dict) -> list[str]:
    """Every way a committed delta disagrees with the atlases and entity lineage it derives from.

    This is the independent predicate: it re-derives every row through `authority_delta` from the
    committed atlases, so a committed row the evidence does not support is a finding rather than a
    restatement of the row.
    """
    problems: list[str] = []
    recomputed = authority_delta.recompute_rows(
        body["from_authority"], body["to_authority"], sense=body.get("sense", "forward"),
        from_id=body.get("from_id"), to_id=body.get("to_id"))
    committed = authority_delta.rows_of(body)
    fresh = {_delta_row_key(r) for r in recomputed}
    recorded = {_delta_row_key(r) for r in committed}
    for key in sorted(fresh - recorded):
        problems.append(f"the delta omits a row the atlases yield: {key}")
    for key in sorted(recorded - fresh):
        problems.append(f"the delta carries a row the atlases do not yield: {key}")
    if body.get("counts") != authority_delta.counts_of(recomputed):
        problems.append("the delta counts do not reproduce from the atlases")
    return problems


def _composition_consistent(edge_row_lists: list[list[dict]], composed_rows: list[dict]) -> bool:
    """Whether a composed body equals the composition of the edge deltas it claims."""
    expected = {_delta_row_key(r) for r in authority_delta.compose_rows(edge_row_lists)}
    return expected == {_delta_row_key(r) for r in composed_rows}


def delta_engine_findings(bodies: list[tuple[Path, dict]]) -> list[str]:
    """Every way the committed edge deltas fail this court's subject.

    A pure function of the committed bodies, so the sensitivity control mutates one and re-checks.
    It establishes that every receipt is a schema-valid `delta_receipt`; that every row is directed
    and dimension-specific with evidence, a confidence and an adjudication; that a row reproduces
    from the atlases and entity lineage; that a measured dimension and an absent one are disjoint
    and complete; that no row asserts a dimension the evidence does not support; and that no row,
    and no evidence path, is a source-line diff standing in for the compatibility delta.
    """
    findings: list[str] = []
    if not bodies:
        findings.append(f"no committed edge delta under {rel(DELTAS)}")
    for path, body in bodies:
        name = rel(path)
        if body.get("covered") is False:
            if not body.get("reason"):
                findings.append(f"{name}: an uncovered delta names no reason")
            continue
        recomputed_hash = content_hash({k: body.get(k) for k in authority_delta.HASH_KEYS})
        if recomputed_hash != body.get("content_hash"):
            findings.append(f"{name}: content_hash does not reproduce from its body")
        measured = set(body.get("measured_dimensions") or [])
        absent = body.get("absent_dimensions") or {}
        for dimension in authority_delta.DELTA_DIMENSIONS:
            if dimension not in measured and dimension not in absent:
                findings.append(f"{name}: dimension {dimension!r} is neither measured nor recorded "
                                f"absent")
        for dimension in sorted(measured & set(absent)):
            findings.append(f"{name}: dimension {dimension!r} is both measured and recorded absent")
        receipt_coarse = {rc.get("dimension") for rc in body.get("receipts") or []}
        for dimension in sorted(measured):
            if authority_delta.DELTA_DIMENSIONS[dimension] not in receipt_coarse:
                findings.append(f"{name}: measured dimension {dimension!r} has no receipt")
        for receipt in body.get("receipts") or []:
            for problem in multitrack_schemas.validate_delta_receipt(receipt):
                findings.append(f"{name}: receipt {receipt.get('receipt_id')}: {problem}")
            if receipt.get("direction") != authority_delta.direction_for(receipt.get("sense")):
                findings.append(f"{name}: receipt {receipt.get('receipt_id')} direction disagrees "
                                f"with its sense")
            for axis in ("added", "removed", "changed"):
                for row in receipt.get(axis) or []:
                    if row.get("classification") != axis:
                        findings.append(f"{name}: row {row.get('row_id')} sits under {axis} but "
                                        f"classifies {row.get('classification')!r}")
                    if row.get("dimension") in absent:
                        findings.append(f"{name}: row {row.get('row_id')} asserts dimension "
                                        f"{row.get('dimension')!r} the evidence does not support")
                    findings += [f"{name}: {p}" for p in _delta_row_problems(body, row, receipt)]
        if any(k in body for k in ("diff", "patch", "hunks")):
            findings.append(f"{name}: the delta body carries a source-diff field")
        findings += [f"{name}: {p}" for p in delta_recompute_findings(body)]
    return findings


def delta_engine_sensitivity_control(bodies: list[tuple[Path, dict]]) -> dict:
    """Prove the court can fail: seed an unclassified change, a disagreeing composition, an
    unevidenced row and a dimension the evidence does not support, and require each caught.

    The honest bodies must yield **zero** findings (specificity); each seeded mutation is re-sealed
    with the delta engine's own hash keys first, so the detection is the semantic check rather than
    the content-hash check firing on an un-recomputed digest.
    """
    base = delta_engine_findings(bodies)
    specificity = not base
    covered = [(p, b) for p, b in bodies if b.get("covered") is not False]
    if not covered:
        return {"honest": False, "reason": "no covered edge delta to mutate"}
    path, body = covered[0]

    def reseal(mutated: dict) -> list[tuple[Path, dict]]:
        out = copy.deepcopy(mutated)
        out["content_hash"] = content_hash({k: out.get(k) for k in authority_delta.HASH_KEYS})
        return [(path, out)]

    template = next((r for rc in body["receipts"]
                     for axis in ("added", "removed", "changed") for r in rc[axis]), None)
    if template is None:
        return {"honest": False, "reason": "the covered delta carries no rows to mutate"}
    target_receipt = next(rc for rc in body["receipts"]
                          if any(r.get("row_id") == template["row_id"]
                                 for axis in ("added", "removed", "changed")
                                 for r in rc[axis]))

    # (a) an unclassified change: a row that classifies as neither added, removed nor changed.
    unclassified = copy.deepcopy(body)
    planted = copy.deepcopy(template)
    planted["row_id"] = template["row_id"] + "-UNCLASSIFIED"
    planted["classification"] = "unclassified"
    for rc in unclassified["receipts"]:
        if rc.get("receipt_id") == target_receipt.get("receipt_id"):
            rc["changed"].append(planted)
    unclassified_findings = delta_engine_findings(reseal(unclassified))
    caught_unclassified = any("is not added/removed/changed" in f
                              for f in unclassified_findings)

    # (b) a composed path that disagrees with its edges: the composition of the committed rows is
    #     mutated, and the consistency check must report the disagreement.
    edge_rows = authority_delta.rows_of(body)
    split = max(1, len(edge_rows) // 2)
    edge_lists = [edge_rows[:split], edge_rows[split:]]
    consistent = _composition_consistent(edge_lists, authority_delta.compose_rows(edge_lists))
    mutated_rows = copy.deepcopy(authority_delta.compose_rows(edge_lists))
    if mutated_rows:
        mutated_rows[0]["classification"] = "removed" if mutated_rows[0]["classification"] != \
            "removed" else "added"
    expected_keys = {_delta_row_key(r) for r in authority_delta.compose_rows(edge_lists)}
    mutated_keys = {_delta_row_key(r) for r in mutated_rows}
    caught_composition = expected_keys != mutated_keys
    composition_mismatch = len(expected_keys ^ mutated_keys)

    # (c) a row with no evidence: the change is asserted rather than measured.
    no_evidence = copy.deepcopy(body)
    planted = copy.deepcopy(template)
    planted["row_id"] = template["row_id"] + "-NO-EVIDENCE"
    planted["evidence"] = []
    for rc in no_evidence["receipts"]:
        if rc.get("receipt_id") == target_receipt.get("receipt_id"):
            {"added": rc["added"], "removed": rc["removed"], "changed": rc["changed"]}[
                template["classification"]].append(planted)
    no_evidence_findings = delta_engine_findings(reseal(no_evidence))
    caught_no_evidence = any("carries no evidence" in f for f in no_evidence_findings)

    # (d) a delta asserting a dimension the evidence does not support: a row carrying an absent
    #     dimension.
    unsupported = copy.deepcopy(body)
    planted = copy.deepcopy(template)
    planted["row_id"] = template["row_id"] + "-UNSUPPORTED"
    planted["dimension"] = "security_policy"
    for rc in unsupported["receipts"]:
        if rc.get("receipt_id") == target_receipt.get("receipt_id"):
            rc["changed"].append(planted)
    unsupported_findings = delta_engine_findings(reseal(unsupported))
    caught_unsupported = any("the evidence does not support" in f for f in unsupported_findings)

    return {
        "baseline_findings": len(base),
        "injected_unclassified_change": template["row_id"],
        "injected_unclassified_change_findings": len(unclassified_findings),
        "injected_disagreeing_composition": len(edge_lists),
        "injected_disagreeing_composition_findings": composition_mismatch,
        "injected_unevidenced_row": template["row_id"],
        "injected_unevidenced_row_findings": len(no_evidence_findings),
        "injected_unsupported_dimension": "security_policy",
        "injected_unsupported_dimension_findings": len(unsupported_findings),
        "specificity_holds": specificity,
        "composition_consistent": consistent,
        "caught_unclassified_change": caught_unclassified,
        "caught_disagreeing_composition": caught_composition,
        "caught_unevidenced_row": caught_no_evidence,
        "caught_unsupported_dimension": caught_unsupported,
        "honest": bool(specificity and consistent and caught_unclassified and caught_composition
                       and caught_no_evidence and caught_unsupported),
    }


def _atlas_records(path: Path, key: str = "records") -> list[dict]:
    """The records list of a committed atlas document, or an empty list."""
    if not path.is_file():
        return []
    return (read_json(path) or {}).get(key) or []


def _abi_facade_provenance(rec: dict, manifest: dict[str, str]) -> list[str]:
    """The provenance links of one public-layout record against the committed source manifest."""
    fid = rec.get("facade_id")
    out: list[str] = []
    header = rec.get("header")
    if header not in manifest:
        out.append(f"{fid}: header {header!r} is not in the committed source manifest")
    elif manifest[header] != rec.get("header_sha256"):
        out.append(f"{fid}: the cited header hash does not match the committed source manifest")
    return out


def abi_facade_findings(body: dict) -> list[str]:
    """Every way the committed ABI/history façade plane fails this court's subject.

    A pure function of the committed plane, so the sensitivity control mutates one and re-checks.
    It establishes that every record is schema-valid; that every record names an **explicit**
    adapter and never a blind cast; that every historical layout's header resolves in the committed
    source manifest with the measured hash; that a historical façade is the transparent pre-1.1.0
    layout its canonical counterpart does **not** define (the opacity transition); that the
    canonical prototype declaration is the production atlas's own; that the ENGINE/Provider and
    init/thread epochs agree with the plane census and the production atlas; that the generated
    `repr(C)` assertions are exactly what the measurement yields; and that the default build is
    unaffected (the façades are cfg-gated behind the non-default compatibility selection, and the
    production surface carries no façade name).
    """
    findings: list[str] = []
    facades = body.get("facades") or []
    if not facades:
        findings.append("the ABI/history façade plane carries no record")

    for rec in facades:
        fid = rec.get("facade_id")
        findings += [f"{fid}: {p}" for p in multitrack_schemas.validate_abi_facade(rec)]
        adapter = str(rec.get("adapter") or "")
        if not adapter or "transmute" in adapter or adapter.strip() in ("cast", "as"):
            findings.append(
                f"{fid}: adapter {adapter!r} is a blind cast, not an explicit adapter over the "
                f"shared implementation"
            )

    # Provenance and the opacity transition, against the historical manifest and the production
    # atlas. A historical layout is transparent; the production authority must mark the same tag
    # opaque, or the record is not a transition this stratum can establish.
    manifest: dict[str, str] = {}
    if HISTORICAL_MANIFEST.is_file():
        manifest = {f["path"]: f["sha256"] for f in read_json(HISTORICAL_MANIFEST)["files"]}
    else:
        findings.append(f"the historical source manifest {rel(HISTORICAL_MANIFEST)} is absent")
    production_structs = {r["name"]: r for r in _atlas_records(PRODUCTION_ATLAS / "structs.json")}
    layouts = [r for r in facades if r.get("facade_kind") == "public_layout"]
    for rec in layouts:
        fid = rec.get("facade_id")
        findings += _abi_facade_provenance(rec, manifest)
        if rec.get("public_layout_epoch") != "transparent_pre_1_1_0":
            findings.append(f"{fid}: a historical façade must be the transparent pre-1.1.0 layout")
        if rec.get("canonical_public_layout_epoch") != "opaque_post_1_1_0":
            findings.append(f"{fid}: the canonical type must be the opaque post-1.1.0 layout")
        tag = rec.get("canonical_c_tag")
        canonical = production_structs.get(tag)
        if canonical is None or canonical.get("complete") is not False:
            findings.append(
                f"{fid}: the production authority does not mark struct {tag!r} opaque, so there "
                f"is no opacity transition to establish"
            )

    # Prototype records: the eras must genuinely differ, and the canonical declaration must be the
    # production atlas's own rather than a restatement.
    functions = {r["name"]: r for r in _atlas_records(PRODUCTION_ATLAS / "functions.json")}
    macros = {r["name"]: r for r in _atlas_records(PRODUCTION_ATLAS / "macros.json")}
    for rec in facades:
        if rec.get("facade_kind") != "prototype":
            continue
        fid = rec.get("facade_id")
        symbol = rec.get("symbol")
        eras = rec.get("eras") or []
        signatures = {(e.get("era"), e.get("declaration"), e.get("kind")) for e in eras}
        if len(signatures) < 2:
            findings.append(f"{fid}: the eras do not declare {symbol} differently")
        canonical = next((e for e in eras if e.get("authority_id") == PRODUCTION_AUTHORITY), None)
        if canonical is None:
            findings.append(f"{fid}: the prototype names no canonical declaration")
        elif canonical.get("kind") == "function":
            atlas = functions.get(symbol)
            if atlas is None:
                findings.append(f"{fid}: {symbol} is not a function in the production atlas")
            elif atlas.get("type", "").split("(")[0].strip() != \
                    str(canonical.get("declaration")).split("(")[0].strip():
                findings.append(
                    f"{fid}: the canonical declaration of {symbol} disagrees with the production "
                    f"atlas ({atlas.get('type')!r})"
                )
        elif symbol not in macros:
            findings.append(f"{fid}: {symbol} is not a macro in the production atlas")

    # The architecture epochs, against the historical plane census.
    census = {r["plane"]: r for r in _atlas_records(HISTORICAL_ATLAS / "plane-census.json",
                                                    "planes")}
    for rec in facades:
        if rec.get("facade_kind") != "architecture":
            continue
        fid = rec.get("facade_id")
        if rec.get("authority_id") == PARAM_HISTORICAL:
            if rec.get("engine_model") != "engine" or rec.get("provider_model") != "no_provider":
                findings.append(f"{fid}: the historical architecture model is not engine/no-provider")
            if census.get("providers", {}).get("status") != "measured_absence":
                findings.append(f"{fid}: the census does not measure providers absent, so a "
                                f"no-provider epoch is not established")
            if census.get("engines", {}).get("status") != "produced":
                findings.append(f"{fid}: the census does not measure engines present")
        elif rec.get("authority_id") == PRODUCTION_AUTHORITY:
            if rec.get("provider_model") != "provider_store":
                findings.append(f"{fid}: the production architecture model is not a provider store")

    # The init/thread epochs.
    for rec in facades:
        if rec.get("facade_kind") != "init_thread":
            continue
        fid = rec.get("facade_id")
        if rec.get("authority_id") == PARAM_HISTORICAL:
            if rec.get("init_model") != "explicit_global_init":
                findings.append(f"{fid}: the historical epoch is not explicit global init")
            if rec.get("thread_model") != "application_locking_callbacks":
                findings.append(f"{fid}: the historical epoch does not use application locking")
            if "CRYPTO_set_locking_callback" not in (rec.get("callbacks") or []):
                findings.append(f"{fid}: the historical epoch does not name its locking callback")
        elif rec.get("authority_id") == PRODUCTION_AUTHORITY:
            if rec.get("init_model") != "automatic_init":
                findings.append(f"{fid}: the production epoch is not automatic init")
            if rec.get("thread_model") != "internal_thread_support":
                findings.append(f"{fid}: the production epoch is not internal thread support")

    # The generated repr(C) assertions must be exactly what the measurement yields.
    try:
        expected = gen_abi_facades.render_rust(body)
    except SystemExit as exc:
        findings.append(f"the generated layout assertions could not be rendered: {exc}")
        expected = None
    if expected is not None:
        committed = ABI_FACADE_RUST.read_text(encoding="utf-8") if ABI_FACADE_RUST.is_file() \
            else ""
        if committed != expected:
            findings.append(
                "the generated layout assertions do not match the measurement (a field offset, "
                "width or the struct size has drifted from forensics/multitrack/abi-facades.json)"
            )

    # The default build is unaffected: every façade module is behind the compatibility-selection
    # cfg, and the cfg itself is guarded by the non-default selection; the production surface
    # carries no façade name.
    if not COMPAT_MOD.is_file():
        findings.append(f"{rel(COMPAT_MOD)} is absent")
    else:
        mod_text = COMPAT_MOD.read_text(encoding="utf-8")
        for module in ("adapters", "arch", "layout_generated", "prototypes"):
            marker = (f"#[cfg(any(test, openssl_rs_compat_facades))]\npub mod {module};".replace(
                "\n", "\n"))
            if marker not in mod_text:
                findings.append(
                    f"the {module} façade module is not gated behind the compatibility-selection "
                    f"cfg, so the default build would carry it"
                )
    if not BUILD_SCRIPT.is_file():
        findings.append(f"{rel(BUILD_SCRIPT)} is absent")
    else:
        build_text = BUILD_SCRIPT.read_text(encoding="utf-8")
        if "default-authority.json" not in build_text:
            findings.append("build.rs does not read the committed default-authority alias")
        guard = build_text.find("if selection != default_authority {")
        cfg = build_text.find("rustc-cfg=openssl_rs_compat_facades")
        if cfg == -1 or guard == -1 or cfg < guard:
            findings.append(
                "build.rs does not guard the façade cfg behind the non-default selection, so "
                "the default build could compile a façade"
            )
    for name in ("symbols-libcrypto.json", "symbols-libssl.json", "functions.json"):
        path = PRODUCTION_ATLAS / name
        if path.is_file() and "Facade" in path.read_text(encoding="utf-8"):
            findings.append(f"the production atlas {name} carries a façade name")

    if not str(body.get("boundary") or "").strip():
        findings.append("the plane names no coverage boundary")
    not_established = body.get("not_established")
    if not isinstance(not_established, list) or not not_established:
        findings.append("partial coverage is not named in not_established with a reason")
    return findings


def abi_facade_sensitivity_control(body: dict) -> dict:
    """Prove the court can fail: perturb a struct layout, put a provider in a pre-provider epoch,
    and blind-cast a façade, and require each caught with specificity holding."""
    base = abi_facade_findings(body)
    specificity = not base
    layouts = [r for r in body.get("facades") or [] if r.get("facade_kind") == "public_layout"]
    architectures = [r for r in body.get("facades") or []
                     if r.get("facade_kind") == "architecture"
                     and r.get("authority_id") == PARAM_HISTORICAL]
    if not layouts or not architectures:
        return {"honest": False, "reason": "the plane lacks a layout or an architecture record"}

    # (a) a perturbed struct offset: the generated assertion set no longer matches the measurement.
    perturbed = copy.deepcopy(body)
    target = next(r for r in perturbed["facades"] if r.get("facade_kind") == "public_layout")
    field = target["fields"][-1]
    field["offset"] = field["offset"] + target.get("alignof", 8)
    perturbed_findings = abi_facade_findings(perturbed)
    caught_offset = any("do not match the measurement" in f or "overlaps" in f
                        or "past sizeof" in f for f in perturbed_findings)

    # (b) a provider symbol in a pre-provider selection: the architecture epoch becomes a lie.
    provider = copy.deepcopy(body)
    arch = next(r for r in provider["facades"] if r.get("facade_kind") == "architecture"
                and r.get("authority_id") == PARAM_HISTORICAL)
    arch["provider_model"] = "provider_store"
    provider_findings = abi_facade_findings(provider)
    caught_provider = any("provider" in f for f in provider_findings)

    # (c) a blind cast: the record no longer names an explicit adapter.
    blind = copy.deepcopy(body)
    layout = next(r for r in blind["facades"] if r.get("facade_kind") == "public_layout")
    layout["adapter"] = "transmute"
    blind_findings = abi_facade_findings(blind)
    caught_blind = any("blind cast" in f for f in blind_findings)

    return {
        "baseline_findings": len(base),
        "injected_struct_offset": target.get("facade_id"),
        "injected_struct_offset_findings": len(perturbed_findings),
        "injected_provider_in_pre_provider_epoch": arch.get("facade_id"),
        "injected_provider_findings": len(provider_findings),
        "injected_blind_cast": layout.get("facade_id"),
        "injected_blind_cast_findings": len(blind_findings),
        "specificity_holds": specificity,
        "caught_struct_offset": caught_offset,
        "caught_provider_in_pre_provider_epoch": caught_provider,
        "caught_blind_cast": caught_blind,
        "honest": bool(specificity and caught_offset and caught_provider and caught_blind),
    }


def _abi_history_facades_court(name: str) -> dict:
    """`RT-ABI-HISTORY-FACADES`: 23.7's court, the ABI / history façades.

    Stages no probe. It reads `forensics/multitrack/abi-facades.json`, the generated
    `src/compat/layout_generated.rs`, the compat sources the build gating lives in, the historical
    plane census and the production atlas, and establishes the record's schema, its explicit
    adapters, its provenance in the committed source manifest, the opacity transition, the
    prototype, architecture and init/thread epoch facts, and that the generated assertions are
    exactly what the measurement yields. Three seeded mutations -- a perturbed struct offset, a
    provider in a pre-provider epoch and a blind-cast façade -- are each caught with specificity
    holding. A passing façade plane is an **instrument**: it establishes a small historical epoch
    and names the boundary of what is not established; it is not a source or binary compatibility
    claim about any release.
    """
    problems: list[str] = []
    if not ABI_FACADES.is_file():
        problems.append(f"the ABI/history façade plane {rel(ABI_FACADES)} is absent")
    body: dict = {}
    if not problems:
        body = read_json(ABI_FACADES)
    findings = abi_facade_findings(body) if body else []
    control = abi_facade_sensitivity_control(body) if body else {"honest": False}
    verdict = "pass" if (not findings and not problems and control.get("honest")) else "fail"

    facades = body.get("facades") or []
    summaries = []
    for rec in facades:
        row = {"facade_id": rec.get("facade_id"), "facade_kind": rec.get("facade_kind"),
               "authority_id": rec.get("authority_id"), "epoch": rec.get("epoch"),
               "adapter": rec.get("adapter")}
        for key in ("struct_name", "sizeof", "alignof", "symbol", "engine_model",
                    "provider_model", "init_model", "thread_model"):
            if key in rec:
                row[key] = rec[key]
        summaries.append(row)
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/multitrack/abi-facades.json, the generated "
            "src/compat/layout_generated.rs and the compat sources the build gating lives in, "
            "re-derives the generated assertions through the same generator, and establishes that "
            "every record is a schema-valid abi_facade naming an explicit adapter; that every "
            "historical layout's header resolves in the committed 0.9.8zh source manifest with the "
            "measured hash; that the production authority marks the same struct opaque (the "
            "opacity transition); that a prototype's eras genuinely differ and its canonical "
            "declaration is the production atlas's own; that the ENGINE/Provider and init/thread "
            "epochs agree with the census; and that the default 3.6.4 production build compiles no "
            "façade (the modules are cfg-gated behind the non-default compatibility selection). A "
            "perturbed struct offset, a provider in a pre-provider epoch and a blind-cast façade "
            "are each detected with specificity holding (docs/PHASE-23-MULTITRACK-SUBPHASES.md "
            "sections 2, 3.4 and 4.10)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the ABI/history-façade court reads committed façade records and generated Rust and "
            "writes no artifacts/phase23/probes/ pair, so it takes no transcript to diff and "
            "carries no FRF declaration"
        ),
        "facades": summaries,
        "boundary": body.get("boundary"),
        "not_established": body.get("not_established"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _semantic_delta_body() -> dict:
    """The committed 23.6 edge delta's body, or an empty mapping when it is absent."""
    return read_json(gen_semantic_courts.DELTA) if gen_semantic_courts.DELTA.is_file() else {}


def semantic_court_findings(body: dict) -> list[str]:
    """Every way the committed semantic-courts plane fails this court's subject.

    A pure function of the committed plane, so the sensitivity control mutates one and re-checks.
    It establishes that every observation is a schema-valid `semantic_observation`; that the raw
    transcripts are present, content-addressed and attributed to the authority they claim; that the
    committed observations **reproduce** from those raw bytes through the same adapter; that a raw
    difference and a recorded divergence agree (the adapter neither erases a difference nor invents
    one); that every divergence is classified and **corroborated** against the committed 23.6 delta
    engine; that the candidate-to-authority dimension names existing passing courts rather than
    being silently dropped; and that a pair that could not be run is recorded not-run with a reason
    and is never also observed.
    """
    findings: list[str] = []
    rows = body.get("observations") or []
    if not rows:
        findings.append("the semantic-courts plane carries no observation")
    raw = body.get("raw_transcripts") or {}

    for rec in rows:
        oid = rec.get("observation_id")
        findings += [f"{oid}: {p}" for p in
                     multitrack_schemas.validate_semantic_observation(rec)]

    # The raw transcripts: present, content-addressed, and attributed to the authority they name.
    parsed: dict[str, dict[str, str]] = {}
    for side in ("authority_a", "authority_b"):
        transcript = raw.get(side)
        if not isinstance(transcript, dict) or not transcript.get("stdout"):
            findings.append(f"the {side} raw transcript is absent, so its observations cannot be "
                            f"re-derived")
            parsed[side] = {}
            continue
        if transcript.get("sha256") != content_hash(transcript["stdout"]):
            findings.append(f"the {side} raw transcript's recorded sha256 is not the sha256 of its "
                            f"own bytes")
        parsed[side] = gen_semantic_courts.parse_transcript(transcript["stdout"])
        expected = body.get(side)
        if parsed[side].get("side.authority") != expected:
            findings.append(
                f"the {side} raw transcript attributes itself to "
                f"{parsed[side].get('side.authority')!r}, not {expected!r}: a probe read against "
                f"the wrong authority"
            )
        release = (body.get("authorities") or {}).get(side, {}).get("release_id")
        if release and parsed[side].get("side.release") != release:
            findings.append(f"the {side} raw transcript's release "
                            f"{parsed[side].get('side.release')!r} is not the record's {release!r}")

    # Re-derive every observation from the raw bytes through the same adapter the plane was built by.
    delta = _semantic_delta_body()
    if not delta:
        findings.append(f"the 23.6 delta engine {rel(gen_semantic_courts.DELTA)} is absent, so no "
                        f"difference can be classified against it")
    else:
        try:
            derived = gen_semantic_courts.derive_observations(raw, delta)
        except (KeyError, TypeError) as exc:
            findings.append("the observations could not be re-derived from the raw transcripts: "
                            f"{exc}")
            derived = None
        if derived is not None and derived != rows:
            findings.append(
                "the committed observations do not reproduce from the preserved raw transcripts "
                "through the same adapter: a normalized reading was altered or a difference erased"
            )

    # A raw difference and a recorded divergence must agree: the adapter may neither erase a
    # difference the raw bytes carry nor invent one they do not.
    for rec in rows:
        key = rec.get("vocabulary")
        ra, rb = parsed["authority_a"].get(key), parsed["authority_b"].get(key)
        if ra is None or rb is None:
            continue
        if (ra != rb) == bool(rec.get("agreement")):
            findings.append(
                f"{rec.get('observation_id')}: the raw transcripts "
                f"{'differ' if ra != rb else 'agree'} on {key} while the observation records "
                f"{'agreement' if rec.get('agreement') else 'divergence'}"
            )

    # Every divergence is a classified release delta, tied to the 23.6 engine's own row or to a
    # dimension the engine records absent with its reason.
    index = gen_semantic_courts.delta_index(delta)
    absent = set(delta.get("absent_dimensions") or {})
    for rec in rows:
        if rec.get("agreement"):
            continue
        oid = rec.get("observation_id")
        ref, absent_dim = rec.get("release_delta"), rec.get("absent_dimension")
        if isinstance(ref, dict) and ref.get("dimension") and ref.get("entity_id"):
            if (ref["dimension"], ref["entity_id"]) not in index:
                findings.append(f"{oid}: release_delta {ref['dimension']}:{ref['entity_id']} does not "
                                f"resolve in the committed 23.6 delta")
        elif absent_dim:
            if absent_dim not in absent:
                findings.append(f"{oid}: absent_dimension {absent_dim!r} is not a dimension the "
                                f"committed 23.6 delta records absent")
        else:
            findings.append(f"{oid}: a divergent observation carries neither a release_delta nor an "
                            f"absent_dimension, so it is not a classified release delta")

    # The candidate-to-authority dimension: a statement naming existing passing courts, verified.
    cat = body.get("candidate_to_authority") or {}
    if not cat.get("statement"):
        findings.append("the candidate-to-authority disposition names no statement")
    for entry in cat.get("existing_courts") or []:
        path = REPO_ROOT / str(entry.get("artefact") or "")
        if not path.is_file():
            findings.append(f"the candidate-to-authority artefact {entry.get('artefact')!r} is "
                            f"absent")
            continue
        verdicts = {c.get("court"): c.get("verdict")
                    for c in (read_json(path).get("courts") or [])}
        for court in entry.get("courts") or []:
            if court not in verdicts:
                findings.append(f"the candidate-to-authority court {court} is not in "
                                f"{entry.get('artefact')}")
            elif verdicts[court] != "pass":
                findings.append(f"the candidate-to-authority court {court} is {verdicts[court]} in "
                                f"{entry.get('artefact')}")

    # A pair that could not run is recorded with a reason and is never also observed.
    not_run = body.get("not_run")
    if not isinstance(not_run, list) or not not_run:
        findings.append("no not-run pair is recorded; a pair a venue cannot execute must be a stated "
                        "distance rather than a court quietly counted as passing")
    else:
        for entry in not_run:
            if not str(entry.get("reason") or "").strip():
                findings.append(f"the not-run pair {entry.get('pair')} carries no reason")
            pair = set(entry.get("pair") or [])
            for rec in rows:
                if {rec.get("authority_a"), rec.get("authority_b")} == pair:
                    findings.append(f"{sorted(pair)} is both not_run and observed; a skipped pair "
                                    f"cannot be counted as evidence")

    if not str(body.get("boundary") or "").strip():
        findings.append("the plane names no coverage boundary")
    return findings


def semantic_courts_sensitivity_control(body: dict) -> dict:
    """Prove the court can fail: erase a difference, swap the authorities, and leave a difference
    unclassified, and require each caught with specificity holding."""
    base = semantic_court_findings(body)
    specificity = not base

    # (a) the adapter normalizes away a real difference: the raw bytes still differ, but the
    # observation now records agreement. The re-derivation must notice.
    erase = copy.deepcopy(body)
    target = next((r for r in erase.get("observations") or []
                   if not r.get("agreement") and r.get("release_delta")), None)
    if target is None:
        return {"honest": False, "reason": "the plane has no divergent observation to erase"}
    target["observed_b"] = target["observed_a"]
    target["agreement"] = True
    target["classification"] = "agreed"
    erase_findings = semantic_court_findings(erase)
    caught_erase = any("erased" in f or "reproduce" in f for f in erase_findings)

    # (b) a probe read against the wrong authority: the two raw transcripts are swapped, so each
    # side's bytes belong to the other authority the record names.
    swap = copy.deepcopy(body)
    transcripts = swap.get("raw_transcripts") or {}
    transcripts["authority_a"], transcripts["authority_b"] = \
        transcripts["authority_b"], transcripts["authority_a"]
    swap_findings = semantic_court_findings(swap)
    caught_wrong_authority = any("wrong authority" in f for f in swap_findings)

    # (c) a difference left unclassified: its classification is emptied, which the schema refuses.
    unclassified = copy.deepcopy(body)
    row = next(r for r in unclassified["observations"] if not r.get("agreement"))
    row["classification"] = ""
    unclassified_findings = semantic_court_findings(unclassified)
    caught_unclassified = any("classification" in f for f in unclassified_findings)

    return {
        "baseline_findings": len(base),
        "injected_erased": target.get("observation_id"),
        "injected_erased_findings": len(erase_findings),
        "injected_swapped_authorities": [body.get("authority_a"), body.get("authority_b")],
        "injected_wrong_authority_findings": len(swap_findings),
        "injected_unclassified": row.get("observation_id"),
        "injected_unclassified_findings": len(unclassified_findings),
        "specificity_holds": specificity,
        "caught_erased_difference": caught_erase,
        "caught_wrong_authority": caught_wrong_authority,
        "caught_unclassified_difference": caught_unclassified,
        "honest": bool(specificity and caught_erase and caught_wrong_authority
                       and caught_unclassified),
    }


def _semantic_courts_court(name: str) -> dict:
    """`RT-SEMANTIC-COURTS`: 23.8's court, the semantic multitrack courts.

    Stages no probe at court time: the probes were executed in the court venue by
    `gen_semantic_courts.py --measure`, which preserved both raw transcripts in the artefact. The
    court reads `forensics/multitrack/semantic-courts.json` and **re-runs the authority-to-authority
    comparison** from those preserved raw bytes through the same adapter, classifies every observed
    difference as a release delta against the committed 23.6 engine, and proves the side-specific
    adapters do not erase the difference under investigation. Three seeded mutations -- an adapter
    that normalizes away a real difference, a probe that would pass against the wrong authority, and
    a difference left unclassified -- are each caught with specificity holding. A passing semantic
    court is an **instrument**: it records the movement between two named authorities and is not a
    compatibility claim about either.
    """
    problems: list[str] = []
    if not SEMANTIC_COURTS.is_file():
        problems.append(f"the semantic-courts plane {rel(SEMANTIC_COURTS)} is absent")
    body: dict = {}
    if not problems:
        body = read_json(SEMANTIC_COURTS)
    findings = semantic_court_findings(body) if body else []
    control = semantic_courts_sensitivity_control(body) if body else {"honest": False}
    verdict = "pass" if (not findings and not problems and control.get("honest")) else "fail"

    summaries = [
        {"observation_id": r.get("observation_id"), "vocabulary": r.get("vocabulary"),
         "dimension": r.get("dimension"), "classification": r.get("classification"),
         "agreement": r.get("agreement"), "observed_a": r.get("observed_a"),
         "observed_b": r.get("observed_b"), "release_delta": r.get("release_delta")}
        for r in body.get("observations") or []
    ]
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe at court time: the shared probe courts/phase23/semantic_probe.c was "
            "compiled and run against both authorities in the court venue by "
            "gen_semantic_courts.py --measure, and the court re-runs the authority-to-authority "
            "comparison from the raw transcripts the artefact preserves. It establishes that every "
            "observation is a schema-valid semantic_observation over the shared normalized "
            "vocabulary; that the raw transcripts are content-addressed and attributed to the "
            "authority they name; that the committed observations reproduce from those raw bytes "
            "through the same adapter; that the side-specific adapters for the declarations that "
            "differ across the pair preserve the difference rather than erasing it; that every "
            "divergence is a classified release delta resolving in the committed 23.6 delta engine "
            "(or in a dimension it records absent); that the candidate-to-authority dimension is "
            "discharged by named, passing existing courts rather than duplicated; and that a pair "
            "the venue cannot execute is recorded not-run with its reason. An adapter that erases a "
            "real difference, a probe read against the wrong authority and an unclassified "
            "difference are each detected with specificity holding "
            "(docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 2, 3.2 and 4.11)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the semantic court compares an authority against an authority (oracle-to-oracle) and "
            "re-runs the comparison from raw transcripts preserved in the committed artefact, so it "
            "stages no artifacts/phase23/probes/<probe>.{authority,candidate} pair a challenge could "
            "locate and diffs no authority-versus-candidate transcript; the candidate-to-authority "
            "dimension is discharged by the existing Phase-2 and Phase-17 courts this plane names"
        ),
        "observations": summaries,
        "classified_differences": body.get("classified_differences"),
        "differs": body.get("differs"),
        "agrees": body.get("agrees"),
        "not_run": body.get("not_run"),
        "candidate_to_authority": body.get("candidate_to_authority"),
        "boundary": body.get("boundary"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def compatibility_view_findings(body: dict) -> list[str]:
    """Every way the committed compatibility-views plane fails this court's subject.

    A pure function of the committed plane, so the sensitivity control mutates one and re-checks.
    It establishes that every view is a schema-valid, directional, dimension-specific
    `compatibility_view` with an explicit `evidence_kind` that is never numeric ordering; that
    every view names an admitted reference authority and a distribution facet; that its reference
    evidence belongs to the authority it names (a view inherits no receipt across an authority);
    that every evidence path is present and content-addressed; that the committed plane reproduces
    from the authorities' own committed evidence through the same generator; and that every
    `COMPAT_DIMENSIONS` member is either the dimension of an emitted view or recorded not-derivable
    with a reason.
    """
    findings: list[str] = []
    views = body.get("views") or []
    not_derivable = body.get("not_derivable") or []
    authorities = body.get("authorities") or []
    if not views:
        findings.append("the compatibility-views plane carries no view")
    if not authorities:
        findings.append("the compatibility-views plane names no authority")

    for v in views:
        vid = v.get("view_id") or "<no view_id>"
        findings += [f"{vid}: {p}" for p in multitrack_schemas.validate_compatibility_view(v)]
        if not v.get("facet"):
            findings.append(f"{vid}: names no distribution facet, so it is not dimension-specific")
        if v.get("reference_id") not in authorities:
            findings.append(
                f"{vid}: reference authority {v.get('reference_id')!r} is not an admitted authority"
            )
        evidence = v.get("evidence") or []
        if not any(e.get("role") == "reference" for e in evidence):
            findings.append(f"{vid}: carries no reference-role evidence, so it is not derived from "
                            f"the authority it names")
        for entry in evidence:
            path, digest = entry.get("path"), entry.get("sha256")
            if entry.get("role") == "reference" and entry.get("authority_id") != v.get("reference_id"):
                findings.append(
                    f"{vid}: reference evidence belongs to {entry.get('authority_id')!r}, not the "
                    f"view's authority {v.get('reference_id')!r}: a view inherits no receipt across "
                    f"an authority"
                )
            p = REPO_ROOT / str(path or "")
            if not p.is_file():
                findings.append(f"{vid}: evidence path {path!r} is absent")
            elif digest != sha256_file(p):
                findings.append(f"{vid}: evidence {path!r} is not content-addressed (recorded "
                                f"sha256 does not match the file)")

    # The committed plane must reproduce from the authorities' own committed evidence through the
    # same generator the artefact was produced by: a relayed evidence path or a hand-edited value
    # stops reproducing.
    try:
        derived = compat_views.derive_body()
    except SystemExit as exc:
        findings.append(f"the compatibility views could not be re-derived: {exc}")
        derived = None
    if derived is not None and derived != body:
        findings.append(
            "the committed views do not reproduce from the authorities' own evidence through the "
            "same generator: a view was altered, relayed from another authority, or inherited"
        )

    # Every dimension is either the dimension of an emitted view for the authority, or a named
    # not-derivable row with a reason -- never silently absent.
    for aid in authorities:
        covered = {v.get("dimension") for v in views if v.get("reference_id") == aid}
        named = {r.get("dimension") for r in not_derivable if r.get("authority_id") == aid}
        for dim in multitrack_schemas.COMPAT_DIMENSIONS:
            if dim not in covered and dim not in named:
                findings.append(
                    f"{aid}: dimension {dim!r} has neither an emitted view nor a not-derivable "
                    f"record with a reason"
                )
    for row in not_derivable:
        if row.get("authority_id") not in authorities:
            findings.append(f"a not-derivable row names {row.get('authority_id')!r}, which is not "
                            f"an admitted authority")
        if not str(row.get("reason") or "").strip():
            findings.append(f"a not-derivable row ({row.get('dimension')!r}) carries no reason")
    return findings


def compatibility_views_sensitivity_control(body: dict) -> dict:
    """Prove the court can fail: relay one authority's evidence into another's view, make a view a
    single boolean, cite numeric ordering as the evidence kind, and drop the reference authority,
    and require each caught with specificity holding."""
    base = compatibility_view_findings(body)
    specificity = not base

    # (a) the load-bearing anti-inheritance rule: relay authority A's reference evidence into a
    # view that names authority B. The view now carries evidence that is not its own.
    relay = copy.deepcopy(body)
    a_view = next((v for v in relay.get("views") or [] if v.get("reference_id") != PRODUCTION_AUTHORITY),
                  None)
    b_view = next((v for v in relay.get("views") or [] if v.get("reference_id") == PRODUCTION_AUTHORITY),
                  None)
    if a_view is None or b_view is None:
        return {"honest": False, "reason": "the plane has no two authorities to relay between"}
    b_view["evidence"] = copy.deepcopy(a_view["evidence"])
    relay_findings = compatibility_view_findings(relay)
    caught_relay = any("inherits no receipt" in f or "belongs to" in f for f in relay_findings)

    # (b) a view collapsed to the one boolean the model forbids.
    boolean = copy.deepcopy(body)
    boolean["views"][0]["compatible"] = True
    boolean_findings = compatibility_view_findings(boolean)
    caught_boolean = any("boolean" in f for f in boolean_findings)

    # (c) a view citing numeric ordering as its evidence kind.
    ordering = copy.deepcopy(body)
    ordering["views"][0]["evidence_kind"] = "version_order"
    ordering_findings = compatibility_view_findings(ordering)
    caught_ordering = any("ordering" in f for f in ordering_findings)

    # (d) a view with no reference authority.
    noref = copy.deepcopy(body)
    noref["views"][0]["reference_id"] = ""
    noref_findings = compatibility_view_findings(noref)
    caught_noref = any("reference_id" in f or "reference authority" in f for f in noref_findings)

    return {
        "baseline_findings": len(base),
        "injected_relayed_authority": [a_view.get("reference_id"), b_view.get("reference_id")],
        "injected_relayed_findings": len(relay_findings),
        "injected_boolean_view": boolean["views"][0].get("view_id"),
        "injected_boolean_findings": len(boolean_findings),
        "injected_ordering_view": ordering["views"][0].get("view_id"),
        "injected_ordering_findings": len(ordering_findings),
        "injected_no_reference_view": noref["views"][0].get("view_id"),
        "injected_no_reference_findings": len(noref_findings),
        "specificity_holds": specificity,
        "caught_relayed_authority": caught_relay,
        "caught_boolean_view": caught_boolean,
        "caught_ordering_evidence": caught_ordering,
        "caught_no_reference": caught_noref,
        "honest": bool(specificity and caught_relay and caught_boolean and caught_ordering
                       and caught_noref),
    }


def _compatibility_views_court(name: str) -> dict:
    """`RT-COMPATIBILITY-VIEWS`: 23.9's court, the directional compatibility views.

    Stages no probe. It reads `forensics/multitrack/compatibility-views.json` and re-derives the
    whole plane from the authorities' own committed evidence through the same generator, and
    establishes that every view is a schema-valid, directional, dimension-specific
    `compatibility_view`; that no view is a boolean and none cites numeric ordering as its evidence
    kind; that every view is derived from the authority it names and carries only that authority's
    reference evidence; that every evidence path is content-addressed; and that a dimension the
    evidence cannot support is recorded not-derivable with its reason. Four seeded mutations --
    relaying authority A's evidence into authority B's view, a view collapsed to a boolean, a view
    citing numeric ordering, and a view with no reference authority -- are each caught with
    specificity holding. A passing view is an **instrument**: it records the distribution/ABI shell
    surface derived from one authority and is not a one-boolean compatibility claim.
    """
    problems: list[str] = []
    if not COMPATIBILITY_VIEWS.is_file():
        problems.append(f"the compatibility-views plane {rel(COMPATIBILITY_VIEWS)} is absent")
    body: dict = {}
    if not problems:
        body = read_json(COMPATIBILITY_VIEWS)
    findings = compatibility_view_findings(body) if body else []
    control = compatibility_views_sensitivity_control(body) if body else {"honest": False}
    verdict = "pass" if (not findings and not problems and control.get("honest")) else "fail"

    per_authority = []
    for aid in sorted(set(body.get("authorities") or [])):
        views = [v for v in body.get("views") or [] if v.get("reference_id") == aid]
        rows = sorted((v.get("facet"), v.get("dimension"), v.get("status")) for v in views)
        not_derivable = sorted(
            (r.get("dimension"), r.get("facet"))
            for r in body.get("not_derivable") or [] if r.get("authority_id") == aid
        )
        per_authority.append({
            "authority_id": aid,
            "support_status": views[0].get("support_status") if views else None,
            "views": [{"facet": f, "dimension": d, "status": s} for f, d, s in rows],
            "not_derivable": [d for d, _f in not_derivable],
        })
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/multitrack/compatibility-views.json and re-derives "
            "the whole plane from the authorities' own committed evidence through the same "
            "generator. It establishes that every view is a schema-valid, directional, "
            "dimension-specific compatibility_view with an explicit evidence_kind that is never "
            "numeric ordering; that no view carries a bare `compatible` boolean; that every view "
            "names an admitted reference authority and a distribution facet and carries only that "
            "authority's reference evidence, so a view inherits no receipt across a version; that "
            "every evidence path is present and content-addressed; that the committed plane "
            "reproduces from the authorities' committed evidence; and that every dimension is "
            "either an emitted view or recorded not-derivable with its reason. Relaying authority "
            "A's evidence into authority B's view, a view collapsed to a boolean, a view citing "
            "numeric ordering and a view with no reference authority are each detected with "
            "specificity holding (docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 2, 3.1, 3.3 and "
            "4.12)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the compatibility-views court reads a committed evidence plane and writes no "
            "artifacts/phase23/probes/<probe>.{authority,candidate} pair, so it stages no "
            "transcript to diff and carries no FRF declaration"
        ),
        "subject_id": body.get("subject_id"),
        "direction_model": body.get("direction_model"),
        "counts": body.get("counts"),
        "per_authority": per_authority,
        "not_derivable": body.get("not_derivable"),
        "boundary": body.get("boundary"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def compatibility_edge_findings(body: dict) -> list[str]:
    """Every way the committed compatibility-edges plane fails this court's subject.

    A pure function of the committed plane, so the sensitivity control mutates one and re-checks.
    It establishes that every edge is a schema-valid, directional, dimension-specific
    `compatibility_edge` whose facet maps onto its coarse dimension; that its verdict is PASS,
    FAIL or UNKNOWN with `status` the schema projection, and never a bare boolean; that its
    evidence kind is never numeric ordering; that every evidence entry is present,
    content-addressed and names the side it belongs to, so a side's evidence is never inherited
    from the other; that a PASS or FAIL cites decisive evidence and an UNKNOWN cites only an
    absence adjudication with a reason; and that every declared pair-direction carries every
    facet.
    """
    findings: list[str] = []
    edges = body.get("edges") or []
    directions = body.get("directions") or []
    facets = body.get("facets") or {}
    if not edges:
        findings.append("the compatibility-edges plane carries no edge")
    if not facets:
        findings.append("the plane declares no facet vocabulary")
    by_key: dict[tuple[str, str, str], dict] = {}

    for e in edges:
        eid = e.get("edge_id") or "<no edge_id>"
        findings += [f"{eid}: {p}" for p in multitrack_schemas.validate_compatibility_edge(e)]
        if not e.get("facet"):
            findings.append(f"{eid}: names no facet, so it is not dimension-specific")
        elif e["facet"] in facets and facets[e["facet"]]["dimension"] != e.get("dimension"):
            findings.append(
                f"{eid}: facet {e['facet']!r} names dimension "
                f"{facets[e['facet']]['dimension']!r}, but the record says {e.get('dimension')!r}"
            )
        if e.get("from_id") == e.get("to_id"):
            findings.append(f"{eid}: both sides of a directional edge are the same node")
        verdict = e.get("verdict")
        if verdict not in ("PASS", "FAIL", "UNKNOWN"):
            findings.append(f"{eid}: verdict {verdict!r} is not PASS/FAIL/UNKNOWN")
        else:
            want = {"PASS": "compatible", "FAIL": "incompatible", "UNKNOWN": "unknown"}[verdict]
            if e.get("status") != want:
                findings.append(
                    f"{eid}: verdict {verdict} projects to status {want!r}, but the record says "
                    f"{e.get('status')!r}"
                )
        for flag in ("compatible", "overall", "is_compatible", "compatible_overall"):
            if flag in e:
                findings.append(
                    f"{eid}: carries a `{flag}` flag: compatibility is not a single boolean"
                )
        if e.get("evidence_kind") == "version_order":
            findings.append(f"{eid}: cites numeric ordering as its evidence kind")

        entries = e.get("evidence") or []
        if not entries:
            findings.append(f"{eid}: cites no evidence")
        decisive = 0
        from_paths: set[str] = set()
        to_paths: set[str] = set()
        for entry in entries:
            side = entry.get("side")
            if side not in ("from_side", "to_side", "pair"):
                findings.append(f"{eid}: evidence entry has side {side!r}")
                continue
            if entry.get("kind") == "version_order":
                findings.append(f"{eid}: an evidence entry cites numeric ordering")
            path = entry.get("path")
            p = REPO_ROOT / str(path or "")
            if not p.is_file():
                findings.append(f"{eid}: evidence path {path!r} is absent")
            elif entry.get("sha256") != sha256_file(p):
                findings.append(f"{eid}: evidence {path!r} is not content-addressed (recorded "
                                f"sha256 does not match the file)")
            if entry.get("kind") != "manual_adjudication":
                decisive += 1
            if side == "from_side":
                if entry.get("authority_id") != e.get("from_authority"):
                    findings.append(
                        f"{eid}: from-side evidence belongs to {entry.get('authority_id')!r}, not "
                        f"the from side's authority {e.get('from_authority')!r}: a side's evidence "
                        f"is not inherited from the other"
                    )
                if path:
                    from_paths.add(str(path))
            elif side == "to_side":
                if entry.get("authority_id") != e.get("to_authority"):
                    findings.append(
                        f"{eid}: to-side evidence belongs to {entry.get('authority_id')!r}, not "
                        f"the to side's authority {e.get('to_authority')!r}: a side's evidence is "
                        f"not inherited from the other"
                    )
                if path:
                    to_paths.add(str(path))
        shared = from_paths & to_paths
        if shared:
            findings.append(
                f"{eid}: the two sides share evidence {sorted(shared)}: a side's evidence is not "
                f"inherited from the other"
            )
        if verdict == "UNKNOWN":
            if not str(e.get("reason") or "").strip():
                findings.append(f"{eid}: is UNKNOWN with no reason")
            if decisive:
                findings.append(
                    f"{eid}: is UNKNOWN but cites decisive evidence, so it is not honestly "
                    f"unmeasured"
                )
        elif verdict in ("PASS", "FAIL"):
            if not decisive:
                findings.append(
                    f"{eid}: is {verdict} but cites no decisive evidence, so the verdict is not "
                    f"established by evidence"
                )
        by_key[(e.get("from_id"), e.get("to_id"), e.get("facet"))] = e

    # every declared pair-direction carries every facet, and no edge is outside them.
    declared = {(d.get("from_id"), d.get("to_id"), d.get("direction")) for d in directions}
    if len(by_key) != len(edges):
        findings.append("the plane carries two edges with the same from/to/facet key")
    for d in directions:
        for facet in facets:
            if (d.get("from_id"), d.get("to_id"), facet) not in by_key:
                findings.append(
                    f"the pair-direction {d.get('from_id')} -> {d.get('to_id')} "
                    f"({d.get('direction')}) has no {facet!r} edge"
                )
    identity = set()
    for e in edges:
        identity.add(e.get("from_id"))
        identity.add(e.get("to_id"))
    for key in by_key:
        edge = by_key[key]
        if (key[0], key[1], edge.get("direction")) not in declared:
            findings.append(
                f"{edge.get('edge_id')}: its direction is not one of the plane's declared "
                f"pair-directions"
            )
        unresolved = {edge.get("from_authority"), edge.get("to_authority")} - identity
        if unresolved:
            findings.append(
                f"{edge.get('edge_id')}: names authority identity {sorted(unresolved)} not among "
                f"the plane's sides"
            )
    return findings


def compatibility_edges_sensitivity_control(body: dict) -> dict:
    """Prove the court can fail: seed five mutations and require each caught.

    The honest plane must yield **zero** findings (specificity), and each seeded mutation -- a
    PASS with no evidence, a dimension collapsed to one boolean, a side's evidence inherited from
    the other, a verdict defaulting to PASS where the evidence does not establish it, and an
    evidence kind of numeric ordering -- must be caught.
    """
    base = compatibility_edge_findings(body)
    specificity = not base

    # (a) a PASS with no evidence: the load-bearing refusal of a default pass.
    no_evidence = copy.deepcopy(body)
    stripped = next((e for e in no_evidence["edges"] if e["verdict"] == "PASS"), None)
    if stripped is None:
        return {"honest": False, "reason": "the plane has no PASS edge to strip"}
    stripped["evidence"] = []
    stripped_id = stripped["edge_id"]
    stripped_findings = compatibility_edge_findings(no_evidence)
    caught_no_evidence = any("cites no evidence" in f for f in stripped_findings)

    # (b) a dimension collapsed to the one boolean the model forbids.
    boolean = copy.deepcopy(body)
    boolean["edges"][0]["compatible"] = True
    boolean_id = boolean["edges"][0]["edge_id"]
    boolean_findings = compatibility_edge_findings(boolean)
    caught_boolean = any("not a single boolean" in f for f in boolean_findings)

    # (c) evidence inherited across the two sides: retag a from-side entry with the to side's
    #     authority, so the from side now carries evidence that is not its own.
    relay = copy.deepcopy(body)
    relay_edge = next((e for e in relay["edges"]
                       if any(x.get("side") == "from_side" for x in e["evidence"])
                       and any(x.get("side") == "to_side" for x in e["evidence"])), None)
    if relay_edge is None:
        return {"honest": False, "reason": "the plane has no edge with both sides' own evidence"}
    relay_entry = next(x for x in relay_edge["evidence"] if x.get("side") == "from_side")
    relay_entry["authority_id"] = relay_edge["to_authority"]
    relay_id = relay_edge["edge_id"]
    relay_findings = compatibility_edge_findings(relay)
    caught_relay = any("not inherited from the other" in f for f in relay_findings)

    # (d) a verdict defaulting to PASS: an UNKNOWN flipped to PASS while its evidence still only
    #     records the absence.
    default_pass = copy.deepcopy(body)
    unknown_edge = next((e for e in default_pass["edges"] if e["verdict"] == "UNKNOWN"), None)
    if unknown_edge is None:
        return {"honest": False, "reason": "the plane has no UNKNOWN edge to flip"}
    unknown_edge["verdict"] = "PASS"
    unknown_edge["status"] = "compatible"
    default_id = unknown_edge["edge_id"]
    default_findings = compatibility_edge_findings(default_pass)
    caught_default = any("cites no decisive evidence" in f for f in default_findings)

    # (e) an evidence kind of numeric ordering.
    ordering = copy.deepcopy(body)
    ordering["edges"][0]["evidence_kind"] = "version_order"
    ordering_id = ordering["edges"][0]["edge_id"]
    ordering_findings = compatibility_edge_findings(ordering)
    caught_ordering = any("numeric ordering" in f for f in ordering_findings)

    return {
        "baseline_findings": len(base),
        "injected_pass_without_evidence": stripped_id,
        "injected_pass_without_evidence_findings": len(stripped_findings),
        "injected_collapsed_boolean": boolean_id,
        "injected_collapsed_boolean_findings": len(boolean_findings),
        "injected_inherited_evidence": relay_id,
        "injected_inherited_evidence_findings": len(relay_findings),
        "injected_verdict_defaulting_to_pass": default_id,
        "injected_verdict_defaulting_to_pass_findings": len(default_findings),
        "injected_ordering_evidence": ordering_id,
        "injected_ordering_evidence_findings": len(ordering_findings),
        "specificity_holds": specificity,
        "caught_pass_without_evidence": caught_no_evidence,
        "caught_collapsed_boolean": caught_boolean,
        "caught_inherited_evidence": caught_relay,
        "caught_verdict_defaulting_to_pass": caught_default,
        "caught_ordering_evidence": caught_ordering,
        "honest": bool(specificity and caught_no_evidence and caught_boolean and caught_relay
                       and caught_default and caught_ordering),
    }


def _compatibility_edges_court(name: str) -> dict:
    """`RT-COMPATIBILITY-EDGES`: 23.12's court, the directional compatibility edges.

    Stages no probe. It reads `forensics/multitrack/compatibility-edges.json` and re-derives the
    whole plane from the committed delta/lineage/view/ABI evidence through the same generator, and
    establishes that every edge is a schema-valid, directional, dimension-specific
    `compatibility_edge`; that each verdict is PASS/FAIL/UNKNOWN with the evidence that establishes
    it and never a bare boolean; that a facet whose evidence is absent is UNKNOWN, not PASS; that
    neither side's evidence is inherited from the other; and that the evidence kind is never
    numeric ordering. Five seeded mutations -- a PASS with no evidence, a dimension collapsed to
    one boolean, evidence inherited across the two sides, a verdict defaulting to PASS, and a
    numeric-ordering evidence kind -- are each caught with specificity holding. A passing edge is
    an **instrument**: it records one directional, dimension-specific reading of one pair, not a
    one-boolean compatibility claim.
    """
    problems: list[str] = []
    if not COMPATIBILITY_EDGES.is_file():
        problems.append(f"the compatibility-edges plane {rel(COMPATIBILITY_EDGES)} is absent")
    body: dict = {}
    if not problems:
        body = read_json(COMPATIBILITY_EDGES)
    findings = compatibility_edge_findings(body) if body else []

    # The committed plane must reproduce from the committed evidence through the same generator:
    # a typed verdict, a relayed evidence path or a hand-edited status stops reproducing.
    if body:
        try:
            derived = compat_edges.derive_body()
        except SystemExit as exc:
            findings.append(f"the compatibility edges could not be re-derived: {exc}")
            derived = None
        if derived is not None and derived != body:
            findings.append(
                "the committed edges do not reproduce from the committed evidence through the "
                "same generator: an edge was altered or a verdict was typed rather than derived"
            )

    control = compatibility_edges_sensitivity_control(body) if body else {"honest": False}
    verdict = "pass" if (not findings and not problems and control.get("honest")) else "fail"

    matrix = [
        {"from_id": e.get("from_id"), "to_id": e.get("to_id"),
         "direction": e.get("direction"), "dimension": e.get("dimension"),
         "facet": e.get("facet"), "verdict": e.get("verdict"),
         "status": e.get("status")}
        for e in body.get("edges") or []
    ]
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/multitrack/compatibility-edges.json and "
            "re-derives the whole plane from the committed edge deltas, the entity lineage, the "
            "compatibility views and the Phase-2 ABI courts through the same generator. It "
            "establishes that every edge is a schema-valid, directional, dimension-specific "
            "compatibility_edge whose facet maps onto its coarse dimension; that each verdict is "
            "PASS/FAIL/UNKNOWN with the evidence that establishes it and never a single boolean; "
            "that a facet whose evidence is absent is UNKNOWN with its reason, never PASS by "
            "default; that every evidence entry is content-addressed and names the side it "
            "belongs to, so neither side's evidence is inherited from the other; and that no "
            "evidence kind is numeric ordering. A PASS with no evidence, a dimension collapsed to "
            "one boolean, evidence inherited across the two sides, a verdict defaulting to PASS "
            "and a numeric-ordering evidence kind are each detected with specificity holding "
            "(docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 2, 3.1, 3.3 and 4.9)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the compatibility-edges court reads a committed evidence plane and writes no "
            "artifacts/phase23/probes/<probe>.{authority,candidate} pair, so it stages no "
            "transcript to diff and carries no FRF declaration"
        ),
        "direction_model": body.get("direction_model"),
        "verdict_vocabulary": body.get("verdict_vocabulary"),
        "counts": body.get("counts"),
        "matrix": matrix,
        "unknown": body.get("unknown"),
        "boundary": body.get("boundary"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def negative_obligation_findings(body: dict) -> list[str]:
    """Every way the committed negative-obligations plane fails this court's subject.

    A pure function of the committed plane, so the sensitivity control mutates one and re-checks.
    It establishes that every obligation is a schema-valid `negative_obligation` whose
    `expected_state` is the polarity its kind asserts; that its scope names an admitted authority or
    a catalogued release; that its evidence is present, content-addressed and the evidence its
    derivation checks actually read, so a negative obligation is checked against the named
    authority/view/plane rather than asserted; that its `state` is the reading `adjudicate` takes
    from that evidence and never assumed -- `open` is a compatibility defect and `unknown` is only
    where no authority or view exists; that both polarities and all six kinds are present; and that
    the committed plane reproduces from the committed evidence through the same generator.
    """
    findings: list[str] = []
    obligations = body.get("obligations") or []
    authorities = set(body.get("authorities") or [])
    releases = set(body.get("releases") or [])
    expected = body.get("expected_state_of_kind") or {}
    if not obligations:
        findings.append("the negative-obligations plane carries no obligation")
    if not authorities:
        findings.append("the plane names no authority")

    view_ids = {v.get("view_id") for v in (read_json(COMPATIBILITY_VIEWS).get("views") or [])} \
        if COMPATIBILITY_VIEWS.is_file() else set()

    ids: set[str] = set()
    kinds_seen: set[str] = set()
    for o in obligations:
        oid = o.get("obligation_id") or "<no obligation_id>"
        findings += [f"{oid}: {p}" for p in multitrack_schemas.validate_negative_obligation(o)]
        if oid in ids:
            findings.append(f"{oid}: duplicate obligation_id")
        ids.add(oid)
        kind = o.get("kind")
        kinds_seen.add(kind)
        if kind in expected and o.get("expected_state") != expected.get(kind):
            findings.append(
                f"{oid}: expected_state {o.get('expected_state')!r} is not the polarity its kind "
                f"{kind!r} asserts ({expected.get(kind)!r})"
            )
        scope = o.get("scope")
        if isinstance(scope, dict):
            aid, rid = scope.get("authority_id"), scope.get("release_id")
            if aid and aid not in authorities:
                findings.append(f"{oid}: scope authority {aid!r} is not among the plane's "
                                f"authorities")
            if rid and rid not in releases:
                findings.append(f"{oid}: scope release {rid!r} is not among the plane's releases")
            if not aid and not rid:
                findings.append(f"{oid}: scope names neither an authority nor a release")
        if o.get("view_id") is not None and o.get("view_id") not in view_ids:
            findings.append(f"{oid}: names view {o.get('view_id')!r}, which is not a committed "
                            f"compatibility view")

        entries = o.get("evidence") or []
        if not entries:
            findings.append(f"{oid}: cites no evidence")
        paths: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                findings.append(f"{oid}: an evidence entry is not an object")
                continue
            if entry.get("role") not in ("authority", "view", "release", "pair", "model"):
                findings.append(f"{oid}: evidence entry has role {entry.get('role')!r}")
            path = entry.get("path")
            paths.add(path)
            p = REPO_ROOT / str(path or "")
            if not p.is_file():
                findings.append(f"{oid}: evidence path {path!r} is absent")
            elif entry.get("sha256") != sha256_file(p):
                findings.append(f"{oid}: evidence {path!r} is not content-addressed (recorded "
                                f"sha256 does not match the file)")

        checks = (o.get("derivation") or {}).get("checks") or []
        if not checks:
            findings.append(f"{oid}: carries no derivation check, so its state is not derived from "
                            f"evidence")
        for check in checks:
            for ep in check.get("evidence") or []:
                if ep not in paths:
                    findings.append(
                        f"{oid}: the check {check.get('rule')!r} reads {ep!r}, which is not among "
                        f"the record's evidence, so the obligation is not checked against it"
                    )
            ca = check.get("authority_id")
            if ca and isinstance(scope, dict) and scope.get("authority_id") \
                    and ca != scope.get("authority_id"):
                findings.append(
                    f"{oid}: the check {check.get('rule')!r} is about {ca!r}, not the obligation's "
                    f"authority {scope.get('authority_id')!r}"
                )

        state, detail = negative_obligations.adjudicate(o)
        if o.get("state") != state:
            findings.append(
                f"{oid}: state {o.get('state')!r} is not the state its evidence establishes "
                f"({state}: {detail})"
            )
        if o.get("state") == "open":
            findings.append(f"{oid}: the obligation is open -- a compatibility defect")
        if o.get("state") == "unknown":
            rules = (o.get("derivation") or {}).get("rules") or []
            if "architecture-future" not in rules:
                findings.append(f"{oid}: reads `unknown` where the named evidence adjudicates")

    for kind in multitrack_schemas.NEGATIVE_OBLIGATION_KINDS:
        if kind not in kinds_seen:
            findings.append(f"the plane carries no {kind} obligation, so it is not a contract")
    if not (kinds_seen & set(negative_obligations.POSITIVE_KINDS)):
        findings.append("the plane carries no positive obligation, so it is only prohibitions")

    # The committed plane must reproduce from the committed evidence through the same generator: a
    # typed state, a hand-listed obligation or a leaked/retained surface stops reproducing.
    try:
        derived = negative_obligations.derive_body()
    except SystemExit as exc:
        findings.append(f"the negative obligations could not be re-derived: {exc}")
        derived = None
    if derived is not None and derived != body:
        findings.append(
            "the committed obligations do not reproduce from the committed evidence through the "
            "same generator: an obligation's state was typed, an obligation was hand-listed, or a "
            "leaked/retained surface was recorded"
        )
    return findings


def negative_obligations_sensitivity_control(body: dict) -> dict:
    """Prove the court can fail: seed five mutations and require each caught.

    The honest plane must yield **zero** findings (specificity), and each seeded mutation -- a
    provider symbol present in a pre-provider authority's view, a post-1.1.0 layout declared
    public, an ENGINE symbol retained in a 4.x view, an obligation with no evidence, and a future
    symbol leaked into an earlier authority's view -- must be caught with specificity holding.
    """
    base = negative_obligation_findings(body)
    specificity = not base

    # (a) a provider symbol present in a pre-provider authority's view: flip the absent provider
    #     store to `must_exist` while it still reads satisfied.
    provider = copy.deepcopy(body)
    prov_rec = next((o for o in provider["obligations"]
                     if o["kind"] == "must_not_exist" and o["subject"] == "provider-store"
                     and o["scope"].get("authority_id") == "openssl-0.9.8zh-historical"), None)
    if prov_rec is None:
        return {"honest": False, "reason": "the plane has no pre-provider provider obligation"}
    prov_rec["kind"] = "must_exist"
    prov_rec["expected_state"] = "present"
    prov_id = prov_rec["obligation_id"]
    prov_findings = negative_obligation_findings(provider)
    caught_provider = any("not the state its evidence establishes" in f for f in prov_findings)

    # (b) a post-1.1.0 layout declared public: flip the canonical opaque layout to `must_be_public`.
    layout = copy.deepcopy(body)
    lay_rec = next((o for o in layout["obligations"]
                    if o["kind"] == "must_be_opaque" and o["subject"] == "EVP_MD_CTX"), None)
    if lay_rec is None:
        return {"honest": False, "reason": "the plane has no canonical opaque layout obligation"}
    lay_rec["kind"] = "must_be_public"
    lay_rec["expected_state"] = "public"
    lay_id = lay_rec["obligation_id"]
    lay_findings = negative_obligation_findings(layout)
    caught_layout = any("not the state its evidence establishes" in f for f in lay_findings)

    # (c) an ENGINE symbol retained in a 4.x view: the 4.x obligation is `unknown` because no 4.x
    #     authority exists; assume it satisfied.
    engine = copy.deepcopy(body)
    eng_rec = next((o for o in engine["obligations"]
                    if o["subject"] == "ENGINE"
                    and o["scope"].get("release_id") == "openssl-4.0.3"), None)
    if eng_rec is None:
        return {"honest": False, "reason": "the plane has no 4.x ENGINE obligation"}
    eng_rec["state"] = "satisfied"
    eng_id = eng_rec["obligation_id"]
    eng_findings = negative_obligation_findings(engine)
    caught_engine = any("not the state its evidence establishes" in f for f in eng_findings)

    # (d) an obligation with no evidence.
    no_evidence = copy.deepcopy(body)
    strip_rec = no_evidence["obligations"][0]
    strip_rec["evidence"] = []
    strip_rec["derivation"]["checks"] = []
    strip_id = strip_rec["obligation_id"]
    strip_findings = negative_obligation_findings(no_evidence)
    caught_no_evidence = any("cites no evidence" in f for f in strip_findings)

    # (e) a future symbol leaked into an earlier authority's view: the 3.6.3 must_not_exist macro
    #     flipped to must_exist while it still reads satisfied.
    leak = copy.deepcopy(body)
    leak_rec = next((o for o in leak["obligations"]
                     if o["kind"] == "must_not_exist"
                     and o["subject"] == "SSL_VALUE_QUIC_MAX_PENDING_CONNS"), None)
    if leak_rec is None:
        return {"honest": False, "reason": "the plane has no added-macro obligation"}
    leak_rec["kind"] = "must_exist"
    leak_rec["expected_state"] = "present"
    leak_id = leak_rec["obligation_id"]
    leak_findings = negative_obligation_findings(leak)
    caught_leak = any("not the state its evidence establishes" in f for f in leak_findings)

    return {
        "baseline_findings": len(base),
        "injected_provider_in_pre_provider_view": prov_id,
        "injected_provider_findings": len(prov_findings),
        "injected_opaque_layout_declared_public": lay_id,
        "injected_opaque_layout_findings": len(lay_findings),
        "injected_engine_retained_in_4x_view": eng_id,
        "injected_engine_findings": len(eng_findings),
        "injected_obligation_without_evidence": strip_id,
        "injected_no_evidence_findings": len(strip_findings),
        "injected_leaked_future_symbol": leak_id,
        "injected_leaked_symbol_findings": len(leak_findings),
        "specificity_holds": specificity,
        "caught_provider_in_pre_provider_view": caught_provider,
        "caught_opaque_layout_declared_public": caught_layout,
        "caught_engine_retained_in_4x_view": caught_engine,
        "caught_obligation_without_evidence": caught_no_evidence,
        "caught_leaked_future_symbol": caught_leak,
        "honest": bool(specificity and caught_provider and caught_layout and caught_engine
                       and caught_no_evidence and caught_leak),
    }


def _negative_obligations_court(name: str) -> dict:
    """`RT-NEGATIVE-OBLIGATIONS`: 23.13's court, the negative (and positive) obligations.

    Stages no probe. It reads `forensics/multitrack/negative-obligations.json` and re-derives the
    whole plane from the committed censuses, façades, deltas and symbols planes through the same
    generator, and establishes that every obligation is a schema-valid `negative_obligation` whose
    expected state is the polarity its kind asserts; that its scope names an admitted authority or a
    catalogued release; that every obligation is checked against the authority/view/plane evidence
    it names; that its state is the reading that evidence establishes and never assumed, so an
    `open` obligation is a compatibility defect and `unknown` is only where no authority or view
    exists; and that both polarities and all six kinds are present. Five seeded mutations -- a
    provider symbol present in a pre-provider authority's view, a post-1.1.0 layout declared public,
    an ENGINE symbol retained in a 4.x view, an obligation with no evidence, and a future symbol
    leaked into an earlier authority's view -- are each caught with specificity holding. A passing
    obligation set is an **instrument**: it records what a named authority or release must (not)
    carry, not a one-boolean compatibility claim.
    """
    problems: list[str] = []
    if not NEGATIVE_OBLIGATIONS.is_file():
        problems.append(f"the negative-obligations plane {rel(NEGATIVE_OBLIGATIONS)} is absent")
    body: dict = {}
    if not problems:
        body = read_json(NEGATIVE_OBLIGATIONS)
    findings = negative_obligation_findings(body) if body else []
    control = negative_obligations_sensitivity_control(body) if body else {"honest": False}
    verdict = "pass" if (not findings and not problems and control.get("honest")) else "fail"

    inventory = []
    for o in body.get("obligations") or []:
        scope = o.get("scope") if isinstance(o.get("scope"), dict) else {}
        inventory.append({
            "obligation_id": o.get("obligation_id"),
            "kind": o.get("kind"),
            "subject": o.get("subject"),
            "authority_id": scope.get("authority_id"),
            "release_id": scope.get("release_id"),
            "state": o.get("state"),
        })
    by_kind: dict[str, int] = {}
    for o in inventory:
        by_kind[o["kind"]] = by_kind.get(o["kind"], 0) + 1
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/multitrack/negative-obligations.json and "
            "re-derives the whole plane from the committed censuses, ABI/history façades, edge "
            "deltas and symbols planes through the same generator. It establishes that every "
            "obligation is a schema-valid negative_obligation whose expected state is the polarity "
            "its kind asserts; that its scope names an admitted authority or a catalogued release; "
            "that everything it names is present and content-addressed and is the evidence the "
            "record's derivation checks actually read, so a negative obligation is checked against "
            "the named authority/view/plane; that its state is the reading that evidence "
            "establishes and never assumed, so `open` is a compatibility defect and `unknown` is "
            "only where no authority or view exists; and that both polarities and all six kinds "
            "are present. A provider symbol present in a pre-provider authority's view, a "
            "post-1.1.0 layout declared public, an ENGINE symbol retained in a 4.x view, an "
            "obligation with no evidence and a future symbol leaked into an earlier authority's "
            "view are each detected with specificity holding "
            "(docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 2 and 3.6)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the negative-obligations court reads a committed evidence plane and writes no "
            "artifacts/phase23/probes/<probe>.{authority,candidate} pair, so it stages no "
            "transcript to diff and carries no FRF declaration"
        ),
        "kinds": body.get("kinds"),
        "states": body.get("states"),
        "expected_state_of_kind": body.get("expected_state_of_kind"),
        "counts": body.get("counts"),
        "authorities": body.get("authorities"),
        "releases": body.get("releases"),
        "by_kind": by_kind,
        "obligations": inventory,
        "boundary": body.get("boundary"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _security_evidence_problems(oid: str, entry: object) -> list[str]:
    """Every way one security evidence entry fails: it is not an object, or it names no source, or
    a repo-relative path is absent or not content-addressed. A URL entry carries the SHA-256 of the
    bytes fetched at acquisition time and is bound by the frozen snapshot, so it is not re-read."""
    if not isinstance(entry, dict):
        return [f"{oid}: an evidence entry is not an object"]
    path = entry.get("path")
    url = entry.get("url")
    if path is not None:
        p = REPO_ROOT / str(path)
        if not p.is_file():
            return [f"{oid}: evidence path {path!r} is absent"]
        if entry.get("sha256") != sha256_file(p):
            return [f"{oid}: evidence {path!r} is not content-addressed (recorded sha256 does not "
                    f"match the file)"]
        return []
    if url is None:
        return [f"{oid}: an evidence entry names neither a repo path nor a URL"]
    return []


def security_lineage_problems(body: dict, catalog: dict, lineage: dict, source: dict,
                              divergence: dict, authority_ids: set[str],
                              authority_node_releases: set[str]) -> list[str]:
    """Every way the committed security-lineage plane fails this court's subject.

    A pure function of the committed evidence, so the sensitivity control mutates one and
    re-checks. It establishes that every vulnerability identity carries an affected range, at
    least one branch fix and a disposition from the closed vocabulary; that every branch-fix
    observation is schema-valid, maps to the maintained branch of the release it fixes, and
    records an unavailable-source identifier as an external reference and **never** as an
    authority; that no disposition re-adopts a fixed behaviour (a `preserve_vulnerable_behaviour`
    disposition, or a `safe_divergence` with no recorded divergence to rest on, is a finding); that
    the `security_backport` edges the observed fixes establish are present in the authority
    lineage with their `security_reference`; that the reference authority is the committed alias;
    and that the whole plane reproduces from the committed evidence through the same generator.
    """
    problems: list[str] = []
    observations = body.get("observations") or []
    vulnerabilities = body.get("vulnerabilities") or []
    by_id = {o.get("observation_id"): o for o in observations}
    if not observations:
        problems.append("the security-lineage plane carries no branch-fix observation")
    if not vulnerabilities:
        problems.append("the security-lineage plane carries no vulnerability identity")

    catalog_by_id = {n["release_id"]: n for n in catalog.get("nodes", [])}
    catalog_by_version = {n["display_version"]: n for n in catalog.get("nodes", [])}
    divergence_ids = {row.get("id") for row in divergence.get("rows", [])}

    # 1. every vulnerability identity: a range, a fix, a disposition that does not reintroduce.
    seen: set[str] = set()
    for v in vulnerabilities:
        vid = v.get("vulnerability_id") or "<no vulnerability_id>"
        if vid in seen:
            problems.append(f"{vid}: duplicate vulnerability identity")
        seen.add(vid)
        ranges = v.get("affected_ranges") or []
        if not ranges:
            problems.append(f"{vid}: carries no affected range")
        for r in ranges:
            if security_lineage.parse_range(r) is None:
                problems.append(f"{vid}: affected range {r!r} is not a `from ... before ...` range")
        fixes = v.get("branch_fixes") or []
        if not fixes:
            problems.append(f"{vid}: carries no branch fix")
        for fid in fixes:
            if fid not in by_id:
                problems.append(f"{vid}: names branch fix {fid!r}, which is not an observation")
        if v.get("severity") not in multitrack_schemas.SECURITY_SEVERITIES:
            problems.append(f"{vid}: severity {v.get('severity')!r} is outside the vocabulary")
        disp = v.get("candidate_disposition")
        basis = v.get("candidate_disposition_basis") or {}
        if disp == security_lineage.FORBIDDEN_DISPOSITION:
            problems.append(f"{vid}: candidate disposition {disp!r} would reintroduce a fixed "
                            f"behaviour -- the no-reintroduction rule is failed")
        elif disp not in multitrack_schemas.SECURITY_DISPOSITIONS:
            problems.append(f"{vid}: candidate disposition {disp!r} is outside the vocabulary")
        if disp == "safe_divergence":
            refs = basis.get("divergence_references") or []
            if not refs:
                problems.append(f"{vid}: a safe divergence is asserted with no recorded "
                                f"divergence to rest on")
            for d in refs:
                if d not in divergence_ids:
                    problems.append(f"{vid}: names divergence {d!r}, which the register does not "
                                    f"carry")
        elif disp == "unresolved" and not basis.get("reason"):
            problems.append(f"{vid}: an unresolved disposition carries no reason")
        elif disp == "never_contained" and (basis.get("divergence_references") or []):
            problems.append(f"{vid}: a never_contained disposition cites a divergence")
        if v.get("reintroduced") is not False:
            problems.append(f"{vid}: reintroduced is not the literal false")

    # 2. every branch fix: schema-valid, the right branch, an external reference or a node.
    for o in observations:
        oid = o.get("observation_id") or "<no observation_id>"
        problems += [f"{oid}: {p}" for p in
                     multitrack_schemas.validate_security_observation(o)]
        vid = o.get("vulnerability_id")
        if vid not in seen:
            problems.append(f"{oid}: vulnerability {vid!r} is not an identity the plane carries")
        if o.get("reference") != vid:
            problems.append(f"{oid}: reference {o.get('reference')!r} disagrees with its "
                            f"vulnerability {vid!r}")
        if o.get("authority_id") is not None:
            problems.append(f"{oid}: a branch fix names an authority {o.get('authority_id')!r}; a "
                            f"fix release is a release reference, not an authority")
        node = catalog_by_id.get(o.get("release_id")) or catalog_by_version.get(o.get("fixed_in"))
        try:
            expected = (security_lineage.branch_of(node["display_version"]) if node
                        else security_lineage.branch_of(str(o.get("fixed_in"))))
        except Exception as exc:  # noqa: BLE001 -- a fixed string the model cannot decode
            problems.append(f"{oid}: fixed_in {o.get('fixed_in')!r} is not a decodable version: "
                            f"{exc}")
            expected = None
        if expected is not None and o.get("branch") != expected:
            problems.append(f"{oid}: branch {o.get('branch')!r} does not map to the maintained "
                            f"branch {expected!r} of fixed release {o.get('fixed_in')!r}")
        rng = security_lineage.parse_range(o.get("affected") or "")
        if rng is None:
            problems.append(f"{oid}: affected {o.get('affected')!r} is not a `from ... before ...` "
                            f"range")
        elif rng[1] != o.get("fixed_in"):
            problems.append(f"{oid}: affected range fixes {rng[1]!r} but the row records "
                            f"fixed_in {o.get('fixed_in')!r}")
        external = node is None
        if o.get("external_release_reference") is not external:
            problems.append(
                f"{oid}: external_release_reference is "
                f"{o.get('external_release_reference')!r} but fixed release "
                f"{o.get('fixed_in')!r} is {'not ' if external else ''}a catalogue node; an "
                f"unavailable-source identifier is an external reference, never admitted as an "
                f"authority")
        if external:
            rid = o.get("release_id")
            if rid in authority_node_releases or rid in authority_ids:
                problems.append(f"{oid}: external identifier {rid!r} is admitted as an authority")
            if o.get("source_available") is not False:
                problems.append(f"{oid}: an external reference records source_available true")
        elif o.get("release_id") != node["release_id"]:
            problems.append(f"{oid}: release_id {o.get('release_id')!r} is not the catalogue node "
                            f"{node['release_id']!r} its fixed version resolves to")
        vrec = next((v for v in vulnerabilities if v.get("vulnerability_id") == vid), None)
        if vrec is not None and o.get("candidate_disposition") != vrec.get("candidate_disposition"):
            problems.append(f"{oid}: candidate disposition disagrees with its vulnerability "
                            f"identity")
        for entry in o.get("evidence") or []:
            problems += _security_evidence_problems(oid, entry)

    # 3. the security_backport edges the observed fixes establish are in the lineage.
    expected_edges = {e["edge_id"]: e for e in security_lineage.security_backport_edges(
        catalog.get("nodes", []))}
    lineage_security = {e["edge_id"]: e for e in lineage.get("edges", [])
                        if e.get("kind") == "security_backport"}
    if set(body.get("backport_edges") or []) != set(expected_edges):
        problems.append("the plane's backport_edges do not reproduce from the committed source "
                        "and catalogue")
    for eid, e in expected_edges.items():
        le = lineage_security.get(eid)
        if le is None:
            problems.append(f"backport edge {eid} the observed fixes establish is absent from the "
                            f"authority lineage")
        elif le.get("security_reference") != e["security_reference"]:
            problems.append(f"backport edge {eid} names security_reference "
                            f"{le.get('security_reference')!r}, not {e['security_reference']!r}")
    for eid in sorted(set(lineage_security) - set(expected_edges)):
        problems.append(f"the lineage carries security_backport edge {eid}, which no observed "
                        f"vulnerability establishes")

    # 4. counts and the reference authority agree with the rows.
    counts = body.get("counts") or {}
    if counts.get("vulnerabilities") != len(vulnerabilities):
        problems.append("counts.vulnerabilities does not match the identity rows")
    if counts.get("branch_fixes") != len(observations):
        problems.append("counts.branch_fixes does not match the observation rows")
    alias = read_json(DEFAULT_AUTHORITY_ALIAS)
    ra = body.get("reference_authority") or {}
    if (ra.get("authority_id") != alias.get("authority_id")
            or ra.get("release_id") != alias.get("maintained_candidate")):
        problems.append("the plane's reference authority is not the committed default-authority "
                        "alias")

    # 5. the whole plane reproduces from the committed evidence through the same generator.
    try:
        derived = security_lineage.derive_body()
    except SystemExit as exc:
        problems.append(f"the security lineage could not be re-derived: {exc}")
        derived = None
    if derived is not None and derived != body:
        problems.append("the committed security lineage does not reproduce from the committed "
                        "evidence through the same generator: a disposition, a fix or a subsystem "
                        "was typed")
    return problems


def security_lineage_property_findings(body: dict, source: dict) -> list[str]:
    """The property findings: every source vulnerability the plane did not bind, and every
    unresolved observation. These are findings about the *property* the unit names -- the whole
    lineage observed and bound -- and they are why a passing `RT-SECURITY-LINEAGE` is an instrument,
    never a statement that the lineage is secure."""
    findings: list[str] = []
    observed = {v.get("vulnerability_id") for v in body.get("vulnerabilities") or []}
    for ref in sorted(set(source["source"]["all_references"]) - observed):
        findings.append(f"unobserved vulnerability {ref}: the source records it and this plane "
                        f"does not bind it")
    for v in body.get("vulnerabilities") or []:
        if v.get("candidate_disposition") == "unresolved":
            basis = v.get("candidate_disposition_basis") or {}
            findings.append(f"vulnerability {v.get('vulnerability_id')} is unresolved: "
                            f"{basis.get('reason', '')}")
    return findings


def security_lineage_sensitivity_control(body: dict, catalog: dict, lineage: dict, source: dict,
                                         divergence: dict, authority_ids: set[str],
                                         authority_node_releases: set[str]) -> dict:
    """Prove the court can fail: seed five mutations and require each caught.

    The honest plane must yield **zero** problems (specificity), and each seeded mutation -- a CVE
    fix mapped to the wrong branch, a vulnerable behaviour marked preserved, a safe divergence
    asserted with no recorded divergence, an extended-support identifier admitted as an authority,
    and a vulnerability with its branch fix dropped -- must be caught.
    """
    def check(b: dict) -> list[str]:
        return security_lineage_problems(b, catalog, lineage, source, divergence, authority_ids,
                                         authority_node_releases)

    base = check(body)
    specificity = not base

    # (a) map a CVE fix to the wrong maintained branch.
    wrong_branch = copy.deepcopy(body)
    obs = next((o for o in wrong_branch["observations"] if o["branch"] == "1.0.2"), None)
    if obs is None:
        obs = wrong_branch["observations"][0]
    obs["branch"] = "3.0" if obs["branch"] != "3.0" else "1.0.2"
    wrong_branch_id = obs["observation_id"]
    wrong_branch_findings = check(wrong_branch)
    caught_branch = any("does not map to the maintained branch" in f for f in wrong_branch_findings)

    # (b) mark a vulnerable behaviour as preserved.
    preserved = copy.deepcopy(body)
    preserved["vulnerabilities"][0]["candidate_disposition"] = \
        security_lineage.FORBIDDEN_DISPOSITION
    preserved_id = preserved["vulnerabilities"][0]["vulnerability_id"]
    preserved_findings = check(preserved)
    caught_preserve = any("would reintroduce a fixed behaviour" in f for f in preserved_findings)

    # (c) assert a safe divergence with no recorded divergence to rest on.
    nodiv = copy.deepcopy(body)
    target = next((v for v in nodiv["vulnerabilities"]
                   if v["candidate_disposition"] == "never_contained"), None)
    if target is None:
        return {"honest": False, "reason": "the plane has no never_contained vulnerability"}
    target["candidate_disposition"] = "safe_divergence"
    target["candidate_disposition_basis"] = {"disposition": "safe_divergence",
                                             "basis": "injected", "reason": "injected",
                                             "divergence_references": []}
    nodiv_id = target["vulnerability_id"]
    nodiv_findings = check(nodiv)
    caught_nodiv = any("no recorded divergence to rest on" in f for f in nodiv_findings)

    # (d) admit an extended-support identifier as an authority.
    admitted = copy.deepcopy(body)
    ext = next((o for o in admitted["observations"] if o["external_release_reference"]), None)
    if ext is None:
        return {"honest": False, "reason": "the plane has no external release reference"}
    ext["authority_id"] = sorted(authority_ids)[0] if authority_ids else "openssl-3.6.4-production"
    admitted_id = ext["observation_id"]
    admitted_findings = check(admitted)
    caught_authority = any("is admitted as an authority" in f or "names an authority" in f
                           for f in admitted_findings)

    # (e) drop a vulnerability's branch fix.
    dropped = copy.deepcopy(body)
    dropped["vulnerabilities"][0]["branch_fixes"] = []
    dropped_id = dropped["vulnerabilities"][0]["vulnerability_id"]
    dropped_findings = check(dropped)
    caught_nofix = any("carries no branch fix" in f for f in dropped_findings)

    return {
        "baseline_problems": len(base),
        "injected_wrong_branch": wrong_branch_id,
        "injected_wrong_branch_findings": len(wrong_branch_findings),
        "injected_preserved_behaviour": preserved_id,
        "injected_preserved_behaviour_findings": len(preserved_findings),
        "injected_safe_divergence_without_record": nodiv_id,
        "injected_safe_divergence_without_record_findings": len(nodiv_findings),
        "injected_external_as_authority": admitted_id,
        "injected_external_as_authority_findings": len(admitted_findings),
        "injected_dropped_branch_fix": dropped_id,
        "injected_dropped_branch_fix_findings": len(dropped_findings),
        "specificity_holds": specificity,
        "caught_wrong_branch": caught_branch,
        "caught_preserved_behaviour": caught_preserve,
        "caught_safe_divergence_without_record": caught_nodiv,
        "caught_external_as_authority": caught_authority,
        "caught_dropped_branch_fix": caught_nofix,
        "honest": bool(specificity and caught_branch and caught_preserve and caught_nodiv
                       and caught_authority and caught_nofix),
    }


def _security_lineage_court(name: str) -> dict:
    """`RT-SECURITY-LINEAGE`: 23.14's court, the historical security lineage.

    Stages no probe. It reads `forensics/multitrack/security-lineage.json`, re-deriving the whole
    plane from the committed source, catalogue, default-authority alias and divergence register
    through the same generator, and establishes that every vulnerability carries an affected
    range, per-branch fixes and a candidate disposition; that each branch fix maps to the correct
    maintained branch; that no disposition re-adopts a fixed behaviour (a preserved vulnerable
    behaviour, or a safe divergence with no recorded divergence, is a finding); that an
    unavailable-source identifier is an external release reference and is never admitted as an
    authority; and that the `security_backport` edges the observed fixes establish are present in
    the authority lineage. Five seeded mutations are each caught with specificity holding. The
    property -- the whole lineage observed and bound -- is NOT_CLAIMED and the unobserved source
    records are named as findings, so a passing `RT-SECURITY-LINEAGE` is an instrument, never a
    statement that the lineage is secure.
    """
    problems: list[str] = []
    for path, label in (
        (SECURITY_LINEAGE, "security-lineage plane"),
        (SECURITY_SOURCE, "security source snapshot"),
        (CATALOG, "release catalogue"),
        (LINEAGE, "authority lineage"),
        (SECURITY_DIVERGENCE, "divergence register"),
        (SECURITY_POLICY, "security divergence policy"),
        (DEFAULT_AUTHORITY_ALIAS, "default authority alias"),
    ):
        if not path.is_file():
            problems.append(f"the {label} {rel(path)} is absent")
    if problems:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": problems, "findings": [], "control": {}}

    body = read_json(SECURITY_LINEAGE)
    catalog = read_json(CATALOG)
    lineage = read_json(LINEAGE)
    source = read_json(SECURITY_SOURCE)
    divergence = read_json(SECURITY_DIVERGENCE)
    authority_ids = {a["id"] for a in read_json(AUTHORITY_REGISTRY).get("authorities", [])}
    authority_node_releases = {n["release_id"]
                               for n in read_json(AUTHORITY_NODES).get("nodes", [])}
    problems += security_lineage_problems(body, catalog, lineage, source, divergence, authority_ids,
                                          authority_node_releases)
    control = security_lineage_sensitivity_control(body, catalog, lineage, source, divergence,
                                                   authority_ids, authority_node_releases)
    findings = security_lineage_property_findings(body, source)
    verdict = "pass" if (not problems and control.get("honest")) else "fail"

    counts = body.get("counts") or {}
    inventory = [{
        "observation_id": o.get("observation_id"),
        "vulnerability_id": o.get("vulnerability_id"),
        "branch": o.get("branch"),
        "fixed_in": o.get("fixed_in"),
        "release_id": o.get("release_id"),
        "external": o.get("external_release_reference"),
    } for o in body.get("observations") or []]
    identities = [{
        "vulnerability_id": v.get("vulnerability_id"),
        "severity": v.get("severity"),
        "branches": v.get("branches"),
        "candidate_disposition": v.get("candidate_disposition"),
        "subsystem": (v.get("subsystem") or {}).get("token"),
        "fips_impact": (v.get("fips_impact") or {}).get("impact"),
        "branch_fixes": len(v.get("branch_fixes") or []),
    } for v in body.get("vulnerabilities") or []]
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/multitrack/security-lineage.json and re-derives "
            "the whole plane from the frozen source snapshot, the release catalogue, the "
            "default-authority alias and the divergence register through the same generator. It "
            "establishes that every vulnerability identity carries an affected range, per-branch "
            "fixes and a candidate disposition; that a branch fix maps to the correct maintained "
            "branch; that no disposition re-adopts a fixed behaviour, so a preserved vulnerable "
            "behaviour or a safe divergence with no recorded divergence is a finding; that an "
            "unavailable-source (extended-support) identifier is an external release reference "
            "and is never admitted as an authority; and that the security_backport edges the "
            "observed fixes establish are present in the authority lineage. A CVE fix mapped to "
            "the wrong branch, a vulnerable behaviour marked preserved, a safe divergence with "
            "no recorded divergence, an extended-support identifier admitted as an authority and "
            "a dropped branch fix are each detected with specificity holding "
            "(docs/SECURITY_DIVERGENCE_POLICY.md sections 1 and 3; "
            "docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 0, 3.7 and 4.6)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the security-lineage court reads a committed evidence plane and stages no "
            "artifacts/phase23/probes/<probe>.{authority,candidate} pair, so it takes no "
            "transcript to diff and carries no FRF declaration"
        ),
        "reference_authority": body.get("reference_authority"),
        "counts": counts,
        "coverage": body.get("coverage"),
        "dispositions": body.get("dispositions"),
        "identities": identities,
        "observations": inventory,
        "backport_edges": body.get("backport_edges"),
        "boundary": body.get("boundary"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _reseal_population(body: dict) -> dict:
    """`body` with its content hash recomputed, so a mutation is caught on substance alone."""
    out = copy.deepcopy(body)
    out["content_hash"] = historical_population.body_hash(
        out.get("records") or [], out.get("epochs") or [], out.get("unavailable") or [])
    return out


def population_findings(body: dict, catalog: dict, authority_nodes: dict, authorities: dict,
                        build_records: dict, hist_acq: dict, hist_receipts: dict,
                        views: dict, semantic: dict, default_alias: dict) -> list[str]:
    """Every way the historical-population record and its backing evidence fail this court.

    A pure function of the committed bodies, so the sensitivity control can mutate them and
    re-check. It establishes that every catalogue node has exactly one schema-valid record; that a
    `built-authority` rung is backed by an actual receipt; that an unavailable release is never
    counted runtime-compatible; that `runtime_compatible` holds only where the rung says; that each
    major ABI epoch has a built representative; that the counts and content hash reproduce; and
    that every evidence path is content-addressed.
    """
    findings: list[str] = []
    records = body.get("records") or []
    epochs = body.get("epochs") or []
    unavailable = body.get("unavailable") or []
    catalog_nodes = {n["release_id"]: n for n in catalog.get("nodes", [])}
    auth_nodes = {n["release_id"]: n for n in authority_nodes.get("nodes", [])}
    builds = {b["id"]: b for b in build_records.get("builds", [])}
    acq_unavail = {r["release_id"]: r for r in hist_acq.get("unavailable", [])}
    receipts = {r["release_id"]: r for r in hist_receipts.get("receipts", [])}
    receipt_rel = rel(HIST_RECEIPTS)
    build_records_rel = rel(BUILD_RECORDS)

    # 1. schema validity, including the load-bearing `runtime_compatible` refusal.
    for r in records:
        rid = r.get("release_id", "<none>")
        findings += [f"population record {rid}: {p}" for p in
                     multitrack_schemas.validate_population_record(r)]

    # 2. every catalogue node has exactly one record, and no record is extra.
    ids = [r.get("release_id") for r in records]
    if len(set(ids)) != len(ids):
        findings.append(f"the population has {len(ids) - len(set(ids))} duplicate record id(s)")
    for rid in sorted(set(catalog_nodes) - set(ids)):
        findings.append(f"catalogue release {rid} has no population record, so it is silently "
                        f"omitted")
    for rid in sorted(set(ids) - set(catalog_nodes)):
        findings.append(f"population record {rid} names no catalogue release")

    # 3. a `built-authority` rung is backed by an actual receipt that names the release.
    for r in records:
        rid = r.get("release_id")
        rungs = r.get("rungs_attained") or []
        if "built-authority" not in rungs:
            continue
        node = auth_nodes.get(rid)
        if node is None or node.get("claim") != "built-authority":
            findings.append(f"population record {rid} attained built-authority but no authority "
                            f"node backs it with a receipt")
            continue
        receipt = node.get("build_receipt")
        if not receipt or not (REPO_ROOT / receipt).is_file():
            findings.append(f"population record {rid}: built-authority but its build receipt "
                            f"{receipt!r} is absent")
        elif receipt == receipt_rel and rid not in receipts:
            findings.append(f"population record {rid}: no historical build receipt names it")
        elif receipt == build_records_rel and node["authority_id"] not in builds:
            findings.append(f"population record {rid}: no build record names its authority")
        cited = {e.get("path") for e in (r.get("evidence") or [])}
        if not (cited & {receipt_rel, build_records_rel}):
            findings.append(f"population record {rid}: its evidence cites no build receipt, so "
                            f"built-authority is asserted without proof")

    # 4. an unavailable release is studied and never counted runtime-compatible.
    for u in unavailable:
        rid = u.get("release_id")
        if u.get("runtime_compatible") is not False:
            findings.append(f"unavailable entry {rid}: is not recorded runtime-incompatible")
        if not u.get("reason"):
            findings.append(f"unavailable entry {rid}: carries no reason")
        if rid not in acq_unavail:
            findings.append(f"unavailable entry {rid}: is not in the acquisition registry")
    for rid in sorted(acq_unavail):
        if rid not in catalog_nodes:
            continue
        rec = next((r for r in records if r.get("release_id") == rid), None)
        if rec is None:
            findings.append(f"acquisition records {rid} unavailable but the population omits it")
            continue
        if rec.get("runtime_compatible") is not False:
            findings.append(f"unavailable release {rid} is counted runtime-compatible")
        if rec.get("status") != "archaeological-only":
            findings.append(f"unavailable release {rid} is not archaeological-only")
        if not any(u.get("release_id") == rid for u in unavailable):
            findings.append(f"unavailable release {rid} is not carried in the unavailable list")

    # 5. `runtime_compatible` holds exactly where the runtime rung does.
    for r in records:
        rungs = r.get("rungs_attained") or []
        if bool(r.get("runtime_compatible")) != ("runtime-evidenced" in rungs):
            findings.append(f"population record {r.get('release_id')}: runtime_compatible disagrees "
                            f"with its rungs_attained")

    # 6. each epoch is consistent with the records, and every major epoch has a representative.
    epoch_names = {e.get("epoch") for e in epochs}
    for name in historical_population.MAJOR_EPOCHS:
        if name not in epoch_names:
            findings.append(f"major ABI epoch {name} is not carried in the population")
    for e in epochs:
        members = [r for r in records if r.get("epoch") == e.get("epoch")]
        if e.get("members") != len(members):
            findings.append(f"epoch {e.get('epoch')}: member count does not reproduce from the "
                            f"records")
        built = sorted(r.get("release_id") for r in members
                       if "built-authority" in (r.get("rungs_attained") or []))
        if sorted(e.get("built_representatives") or []) != built:
            findings.append(f"epoch {e.get('epoch')}: built_representatives does not reproduce "
                            f"from the records")
        if e.get("epoch") in historical_population.MAJOR_EPOCHS and not e.get("covered"):
            findings.append(f"major ABI epoch {e.get('epoch')} has no built representative")
    for r in records:
        if r.get("epoch") not in epoch_names:
            findings.append(f"population record {r.get('release_id')} names an epoch no row carries")

    # 7. the counts reproduce from the records.
    recomputed = _population_counts(records, epochs, unavailable)
    if body.get("counts") != recomputed:
        findings.append("the population counts do not reproduce from its records")

    # 8. the content hash is a function of the committed records.
    if historical_population.body_hash(records, epochs, unavailable) != body.get("content_hash"):
        findings.append("the population content_hash does not reproduce from its body")

    # 9. every evidence path is present and content-addressed.
    for r in records:
        for entry in r.get("evidence") or []:
            path, digest = entry.get("path"), entry.get("sha256")
            p = REPO_ROOT / str(path or "")
            if not p.is_file():
                findings.append(f"population record {r.get('release_id')}: evidence path {path!r} "
                                f"is absent")
            elif digest != sha256_file(p):
                findings.append(f"population record {r.get('release_id')}: evidence {path!r} is "
                                f"not content-addressed")
    return findings


def _population_counts(records: list[dict], epochs: list[dict], unavailable: list[dict]) -> dict:
    """The population counts, recomputed from the records (never read from the body)."""
    by_status: dict[str, int] = {}
    by_rung: dict[str, int] = {}
    by_epoch: dict[str, int] = {}
    for r in records:
        status = r.get("status", "<none>")
        epoch = r.get("epoch", "<none>")
        by_status[status] = by_status.get(status, 0) + 1
        by_epoch[epoch] = by_epoch.get(epoch, 0) + 1
        for rung in r.get("rungs_attained") or []:
            by_rung[rung] = by_rung.get(rung, 0) + 1
    return {
        "nodes": len(records),
        "by_status": {k: by_status[k] for k in sorted(by_status)},
        "by_rung": {k: by_rung[k] for k in sorted(by_rung)},
        "by_epoch": {k: by_epoch[k] for k in sorted(by_epoch)},
        "built": sum(1 for r in records if "built-authority" in (r.get("rungs_attained") or [])),
        "unavailable": len(unavailable),
        "runtime_compatible": sum(1 for r in records if r.get("runtime_compatible")),
        "epochs": len(historical_population.MAJOR_EPOCHS),
        "epochs_covered": sum(1 for e in epochs
                              if e.get("epoch") in historical_population.MAJOR_EPOCHS
                              and e.get("covered")),
    }


def population_sensitivity_control(body: dict, catalog: dict, authority_nodes: dict,
                                  authorities: dict, build_records: dict, hist_acq: dict,
                                  hist_receipts: dict, views: dict, semantic: dict,
                                  default_alias: dict) -> dict:
    """Prove the court can fail: seed four mutations and require each caught.

    The honest record must yield **zero** findings (specificity), and each seeded mutation -- a
    release marked built with no receipt, an unavailable release marked runtime-compatible, a
    release with no status, and an epoch with no representative -- must be caught. Each mutated
    body is re-sealed first, so the detection is a semantic check and never the content-hash check
    firing on an un-recomputed digest.
    """
    def findings_of(b, an=authority_nodes):
        return population_findings(b, catalog, an, authorities, build_records, hist_acq,
                                   hist_receipts, views, semantic, default_alias)

    base = findings_of(body)
    specificity = not base

    # (a) a built record with no receipt: drop the backing authority node from the inputs.
    no_receipt_inputs = copy.deepcopy(authority_nodes)
    no_receipt_inputs["nodes"] = [n for n in no_receipt_inputs["nodes"]
                                  if n["release_id"] != "openssl-1.0.2u"]
    no_receipt = _reseal_population(body)
    no_receipt_findings = findings_of(no_receipt, no_receipt_inputs)
    caught_no_receipt = any("built-authority" in f and "receipt" in f
                            for f in no_receipt_findings)

    # (b) an unavailable release marked runtime-compatible.
    overclaim = copy.deepcopy(body)
    for r in overclaim["records"]:
        if r["release_id"] == "openssl-0.9.1c":
            r["status"] = "runtime-evidenced"
            r["rungs_attained"] = ["catalogued", "admitted-source", "built-authority",
                                   "atlas-complete", "candidate-view", "runtime-evidenced"]
            r["runtime_compatible"] = True
    overclaim = _reseal_population(overclaim)
    overclaim_findings = findings_of(overclaim)
    caught_overclaim = any("runtime-compatible" in f for f in overclaim_findings)

    # (c) a release with no status.
    naked = copy.deepcopy(body)
    naked["records"][0].pop("status", None)
    naked = _reseal_population(naked)
    naked_findings = findings_of(naked)
    caught_naked = any("missing required field 'status'" in f for f in naked_findings)

    # (d) an epoch with no representative: clear the 1.0.x epoch and its only built record.
    empty_epoch = copy.deepcopy(body)
    for e in empty_epoch["epochs"]:
        if e["epoch"] == "1.0.x":
            e["built_representatives"] = []
            e["covered"] = False
    for r in empty_epoch["records"]:
        if r["release_id"] == "openssl-1.0.2u":
            r["rungs_attained"] = ["catalogued", "admitted-source"]
            r["status"] = "admitted-source"
            r["outcome"] = "acquired"
    empty_epoch = _reseal_population(empty_epoch)
    empty_epoch_findings = findings_of(empty_epoch)
    caught_empty_epoch = any("no built representative" in f for f in empty_epoch_findings)

    return {
        "baseline_findings": len(base),
        "injected_built_without_receipt": "openssl-1.0.2u (authority node dropped)",
        "injected_built_without_receipt_findings": len(no_receipt_findings),
        "injected_unavailable_runtime_compatible": "openssl-0.9.1c",
        "injected_unavailable_runtime_compatible_findings": len(overclaim_findings),
        "injected_missing_status": naked["records"][0].get("release_id"),
        "injected_missing_status_findings": len(naked_findings),
        "injected_epoch_without_representative": "1.0.x",
        "injected_epoch_without_representative_findings": len(empty_epoch_findings),
        "specificity_holds": specificity,
        "caught_built_without_receipt": caught_no_receipt,
        "caught_unavailable_runtime_compatible": caught_overclaim,
        "caught_missing_status": caught_naked,
        "caught_epoch_without_representative": caught_empty_epoch,
        "honest": bool(specificity and caught_no_receipt and caught_overclaim and caught_naked
                       and caught_empty_epoch),
    }


def _historical_population_court(name: str) -> dict:
    """`RT-HISTORICAL-POPULATION`: 23.10's court, the historical population.

    Stages no probe. It reads `forensics/multitrack/historical-population.json` and re-derives the
    whole record from the committed catalogue, authority nodes and receipts through the same
    generator, and establishes that every catalogue node has exactly one schema-valid status; that
    a `built-authority` rung is backed by an actual receipt; that an unavailable release is never
    counted runtime-compatible; that `runtime_compatible` holds only where the runtime rung does;
    that each major ABI epoch has at least one built representative; that the counts and content
    hash reproduce; and that every evidence path is content-addressed. Four seeded mutations -- a
    release marked built with no receipt, an unavailable release marked runtime-compatible, a
    release with no status, and an epoch with no representative -- are each caught with specificity
    holding. A passing population is an **instrument**: it records how far each node reached and is
    not a compatibility claim about any release.
    """
    problems: list[str] = []
    for path, label in ((HISTORICAL_POPULATION, "historical-population record"),
                        (CATALOG, "release catalogue"),
                        (AUTHORITY_NODES, "authority-node registry"),
                        (AUTHORITY_REGISTRY, "authority registry"),
                        (BUILD_RECORDS, "build records"),
                        (HIST_ACQ, "historical acquisition"),
                        (HIST_RECEIPTS, "historical build receipts"),
                        (COMPATIBILITY_VIEWS, "compatibility-views plane"),
                        (SEMANTIC_COURTS, "semantic-courts plane"),
                        (DEFAULT_AUTHORITY_ALIAS, "default-authority alias")):
        if not path.is_file():
            problems.append(f"the {label} {rel(path)} is absent")
    if problems:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": problems, "findings": [], "control": {}}

    body = read_json(HISTORICAL_POPULATION)
    catalog = read_json(CATALOG)
    authority_nodes = read_json(AUTHORITY_NODES)
    authorities = read_json(AUTHORITY_REGISTRY)
    build_records = read_json(BUILD_RECORDS)
    hist_acq = read_json(HIST_ACQ)
    hist_receipts = read_json(HIST_RECEIPTS)
    views = read_json(COMPATIBILITY_VIEWS)
    semantic = read_json(SEMANTIC_COURTS)
    default_alias = read_json(DEFAULT_AUTHORITY_ALIAS)

    findings = population_findings(body, catalog, authority_nodes, authorities, build_records,
                                   hist_acq, hist_receipts, views, semantic, default_alias)

    # No status is typed: the committed record must reproduce from the committed evidence through
    # the same generator, so a hand-edited status stops reproducing.
    try:
        derived = historical_population.derive_body()
    except SystemExit as exc:
        findings.append(f"the historical population could not be re-derived: {exc}")
        derived = None
    if derived is not None and derived != body:
        findings.append(
            "the committed population does not reproduce from the committed evidence through the "
            "same generator: a status was typed rather than derived"
        )

    control = population_sensitivity_control(body, catalog, authority_nodes, authorities,
                                             build_records, hist_acq, hist_receipts, views,
                                             semantic, default_alias)
    counts = body.get("counts", {})
    verdict = "pass" if (not findings and not problems and control["honest"]) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/multitrack/historical-population.json and "
            "re-derives the whole record from the committed release catalogue, authority nodes, "
            "acquisition and build receipts, atlases, compatibility views and semantic pair "
            "through the same generator. It establishes that every catalogue node has exactly one "
            "schema-valid support status; that a built-authority rung is backed by an actual "
            "receipt; that an unavailable release is recorded unavailable and is never counted "
            "runtime-compatible; that runtime_compatible holds only where the runtime rung does; "
            "that each major ABI epoch has at least one built representative; that no status was "
            "typed; that the counts and content hash reproduce; and that every evidence path is "
            "content-addressed. A release marked built with no receipt, an unavailable release "
            "marked runtime-compatible, a release with no status and an epoch with no "
            "representative are each detected with specificity holding "
            "(docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 2, 3.2 and 4)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the historical-population court reads a committed evidence record and writes no "
            "artifacts/phase23/probes/<probe>.{authority,candidate} pair, so it stages no "
            "transcript to diff and carries no FRF declaration"
        ),
        "counts": counts,
        "epochs": body.get("epochs"),
        "unavailable": [{"release_id": r.get("release_id"), "reason": r.get("reason")}
                        for r in body.get("unavailable") or []],
        "runtime_compatible": [r.get("release_id") for r in body.get("records") or []
                               if r.get("runtime_compatible")],
        "content_hash": body.get("content_hash"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _support_status_reseal(body: dict) -> dict:
    """`body` with its content hash recomputed, so a mutation is caught on substance alone."""
    out = copy.deepcopy(body)
    out["content_hash"] = support_status.body_hash(out.get("records") or [])
    return out


def _support_status_counts(records: list[dict]) -> dict:
    """The support-status counts, recomputed from the rows (never read from the body)."""
    by_status: dict[str, int] = {}
    by_rung: dict[str, int] = {}
    by_role: dict[str, int] = {}
    by_scope: dict[str, int] = {}
    for r in records:
        status = r.get("status", "<none>")
        role = r.get("support_role", "<none>")
        scope = r.get("scope", "<none>")
        by_status[status] = by_status.get(status, 0) + 1
        by_role[role] = by_role.get(role, 0) + 1
        by_scope[scope] = by_scope.get(scope, 0) + 1
        for rung in r.get("rungs_attained") or []:
            by_rung[rung] = by_rung.get(rung, 0) + 1
    return {
        "nodes": len(records),
        "by_status": {k: by_status[k] for k in sorted(by_status)},
        "by_rung": {k: by_rung[k] for k in sorted(by_rung)},
        "by_support_role": {k: by_role[k] for k in sorted(by_role)},
        "by_scope": {k: by_scope[k] for k in sorted(by_scope)},
        "support_targets": by_role.get("support-target", 0),
        "archaeology": by_role.get("archaeology", 0),
        "runtime_compatible": sum(1 for r in records if r.get("runtime_compatible")),
    }


def support_status_findings(body: dict, population: dict, catalog: dict, authority_nodes: dict,
                            authorities: dict, build_records: dict, hist_acq: dict,
                            hist_receipts: dict, views: dict, semantic: dict, downstream: dict,
                            default_alias: dict) -> list[str]:
    """Every way the support-status plane and its backing evidence fail this court.

    A pure function of the committed bodies, so the sensitivity control can mutate them and
    re-check. It establishes that one schema-valid row names every catalogue node; that every row
    reconciles node-for-node and rung-for-rung with its 23.10 population record; that each rung a
    node attained is backed by the evidence that establishes it (a `built-authority` by an actual
    receipt, a `downstream-evidenced` by a passing consumer, ...); that each rung not attained
    carries a reason; that `archaeological-only` is never counted a support target; that the
    statuses are derived and carry no competing `PARITY_VERIFIED`; and that the counts and content
    hash reproduce and every evidence path is content-addressed.
    """
    findings: list[str] = []
    records = body.get("records") or []
    catalog_nodes = {n["release_id"]: n for n in catalog.get("nodes", [])}
    auth_nodes = {n["release_id"]: n for n in authority_nodes.get("nodes", [])}
    builds = {b["id"] for b in build_records.get("builds", [])}
    acquisitions = {r["release_id"] for r in hist_acq.get("acquisitions", [])}
    admitted = {f"openssl-{a['version']}" for a in authorities.get("authorities", [])}
    receipts = {r["release_id"] for r in hist_receipts.get("receipts", [])}
    compatible = {v.get("reference_id") for v in views.get("views", [])
                  if v.get("status") == "compatible"}
    runtime = {semantic.get("authority_a"), semantic.get("authority_b")} - {None}
    passed = {r.get("authority_id") for r in downstream.get("records", [])
              if r.get("outcome") == "passed"}
    maintained = str(default_alias.get("maintained_candidate") or "")
    receipt_rel, build_records_rel = rel(HIST_RECEIPTS), rel(BUILD_RECORDS)

    def rung_problem(rung: str, rid: str, aid: str | None, rungs: list[str]) -> str | None:
        """Why the named rung is not established by the evidence, or `None` when it is."""
        if rung == "catalogued":
            return None if rid in catalog_nodes else "it names no catalogue release"
        if rung == "admitted-source":
            return None if (rid in acquisitions or rid in admitted) \
                else "no acquisition record and no admitted-authority record names it"
        if rung == "built-authority":
            node = auth_nodes.get(rid)
            if node is None or node.get("claim") != "built-authority":
                return "no authority node backs it with a built-authority claim"
            receipt = node.get("build_receipt")
            if not receipt or not (REPO_ROOT / receipt).is_file():
                return "its build receipt is absent"
            if receipt == receipt_rel and rid not in receipts:
                return "no historical build receipt names it"
            if receipt == build_records_rel and node["authority_id"] not in builds:
                return "no build record names its authority"
            return None
        if rung == "atlas-complete":
            return None if (aid and historical_population.atlas_anchor(aid)) \
                else "the authority carries no committed atlas"
        if rung == "candidate-view":
            return None if (aid and aid in compatible) \
                else "no compatible candidate-to-reference view names the authority"
        if rung == "runtime-evidenced":
            return None if (aid and aid in runtime) \
                else "the authority is not one side of the executed semantic pair"
        if rung == "downstream-evidenced":
            return None if (aid and aid in passed) \
                else "no passing unmodified downstream consumer exercised the authority"
        if rung == "maintained":
            return None if (rid == maintained and "built-authority" in rungs) \
                else "it is not the maintained candidate the default-authority alias names"
        return f"{rung!r} is not a ladder rung"

    # 1. schema validity -- ordering, no duplicate, no skipped core rung, highest-rung status.
    for r in records:
        rid = r.get("subject_id", "<none>")
        findings += [f"support-status row {rid}: {p}" for p in
                     multitrack_schemas.validate_support_status(r)]

    # 2. exactly one row per catalogue node, and no row is extra.
    ids = [r.get("subject_id") for r in records]
    if len(set(ids)) != len(ids):
        findings.append(f"the support-status plane has {len(ids) - len(set(ids))} duplicate row "
                        f"id(s)")
    for rid in sorted(set(catalog_nodes) - set(ids)):
        findings.append(f"catalogue release {rid} has no support-status row, so it is silently "
                        f"omitted")
    for rid in sorted(set(ids) - set(catalog_nodes)):
        findings.append(f"support-status row {rid} names no catalogue release")

    # 3. every row reconciles with its 23.10 population record -- the anti-duplication proof.
    pop = {r["release_id"]: r for r in population.get("records") or []}
    for r in records:
        rid = r.get("subject_id")
        p = pop.get(rid)
        if p is None:
            findings.append(f"support-status row {rid} has no population record to reconcile with")
            continue
        if r.get("status") != p.get("status"):
            findings.append(f"support-status row {rid}: status {r.get('status')!r} does not "
                            f"reconcile with the population's {p.get('status')!r}")
        if list(r.get("rungs_attained") or []) != list(p.get("rungs_attained") or []):
            findings.append(f"support-status row {rid}: rungs_attained {r.get('rungs_attained')!r} "
                            f"do not reconcile with the population's "
                            f"{p.get('rungs_attained')!r}")
        if r.get("scope") != p.get("scope"):
            findings.append(f"support-status row {rid}: scope does not reconcile with the "
                            f"population")
        if bool(r.get("runtime_compatible")) != bool(p.get("runtime_compatible")):
            findings.append(f"support-status row {rid}: runtime_compatible does not reconcile with "
                            f"the population")
    if (body.get("counts") or {}).get("by_status") \
            != (population.get("counts") or {}).get("by_status"):
        findings.append("the support-status by_status histogram does not reconcile with the "
                        "population's")

    # 4. each attained rung is backed by the evidence that establishes it, and cited in the row.
    for r in records:
        rid = r.get("subject_id")
        rungs = r.get("rungs_attained") or []
        node = auth_nodes.get(rid)
        aid = node.get("authority_id") if node else None
        by_rung = r.get("evidence_by_rung") or {}
        row_paths = {e.get("path") for e in (r.get("evidence") or [])}
        for rung in rungs:
            why = rung_problem(rung, rid, aid, rungs)
            if why is not None:
                findings.append(f"support-status row {rid}: attained {rung} but {why}")
            entry = by_rung.get(rung)
            if entry is None:
                findings.append(f"support-status row {rid}: attained {rung} with no "
                                f"evidence_by_rung entry")
            elif entry.get("path") not in row_paths:
                findings.append(f"support-status row {rid}: evidence_by_rung[{rung}] cites "
                                f"{entry.get('path')!r}, which is not in the row's evidence")

    # 4b. each rung not attained carries a reason, and the set is exactly the ladder minus attained.
    for r in records:
        rid = r.get("subject_id")
        not_attained = r.get("not_attained") or {}
        expected = {rung for rung in multitrack_schemas.SUPPORT_LADDER
                    if rung not in (r.get("rungs_attained") or [])}
        if set(not_attained) != expected:
            findings.append(f"support-status row {rid}: not_attained {sorted(not_attained)} is not "
                            f"exactly the ladder rungs not attained {sorted(expected)}")
        for rung, reason in not_attained.items():
            if not isinstance(reason, str) or not reason.strip():
                findings.append(f"support-status row {rid}: not_attained[{rung}] carries no reason")

    # 5. archaeological-only is archaeology, climbs no rung, and is never counted a support target.
    for r in records:
        rid = r.get("subject_id")
        archaeology = r.get("status") == "archaeological-only"
        role = r.get("support_role")
        if role not in ("support-target", "archaeology"):
            findings.append(f"support-status row {rid}: support_role {role!r} is not one of "
                            f"support-target/archaeology")
        elif archaeology != (role == "archaeology"):
            findings.append(f"support-status row {rid}: support_role {role!r} disagrees with status "
                            f"{r.get('status')!r}")
        if archaeology and (r.get("rungs_attained") or []):
            findings.append(f"support-status row {rid}: an archaeological-only node has climbed a "
                            f"rung")

    # 5b. the counts reproduce, and the support/archaeology split is exact.
    recomputed = _support_status_counts(records)
    if body.get("counts") != recomputed:
        findings.append("the support-status counts do not reproduce from its rows")
    elif recomputed["support_targets"] + recomputed["archaeology"] != recomputed["nodes"]:
        findings.append("the support-target and archaeology counts do not account for every node")

    # 6. the statuses do not compete with the parity dimensions: no PARITY_VERIFIED, no boolean.
    for r in records:
        rid = r.get("subject_id")
        for key in r:
            if key in ("compatible", "parity", "parity_verified"):
                findings.append(f"support-status row {rid} carries a competing {key!r} field")
        if r.get("status") not in multitrack_schemas.SUPPORT_STATUSES:
            findings.append(f"support-status row {rid}: status {r.get('status')!r} is not a ladder "
                            f"status")

    # 7. the content hash is a function of the committed rows.
    if support_status.body_hash(records) != body.get("content_hash"):
        findings.append("the support-status content_hash does not reproduce from its rows")

    # 8. every evidence path is present and content-addressed.
    for r in records:
        for entry in r.get("evidence") or []:
            path, digest = entry.get("path"), entry.get("sha256")
            p = REPO_ROOT / str(path or "")
            if not p.is_file():
                findings.append(f"support-status row {r.get('subject_id')}: evidence path {path!r} "
                                f"is absent")
            elif digest != sha256_file(p):
                findings.append(f"support-status row {r.get('subject_id')}: evidence {path!r} is "
                                f"not content-addressed")
    return findings


def support_status_sensitivity_control(body: dict, population: dict, catalog: dict,
                                       authority_nodes: dict, authorities: dict,
                                       build_records: dict, hist_acq: dict, hist_receipts: dict,
                                       views: dict, semantic: dict, downstream: dict,
                                       default_alias: dict) -> dict:
    """Prove the court can fail: seed four mutations and require each caught.

    The honest plane must yield **zero** findings (specificity), and each seeded mutation -- a node
    claiming a higher rung with no evidence, a node skipping a core rung, an archaeological-only node
    counted a support target, and a status typed rather than derived -- must be caught. Each mutated
    body is re-sealed first, so the detection is a semantic check and never the content-hash check
    firing on an un-recomputed digest.
    """
    def findings_of(b, p=population):
        return support_status_findings(b, p, catalog, authority_nodes, authorities, build_records,
                                       hist_acq, hist_receipts, views, semantic, downstream,
                                       default_alias)

    base = findings_of(body)
    specificity = not base

    def ladder_prefix(n: int) -> list[str]:
        return list(multitrack_schemas.SUPPORT_LADDER[:n])

    def reasons_for(rungs: list[str], archaeology: bool, reason: str) -> dict[str, str]:
        if archaeology:
            return {rung: reason for rung in multitrack_schemas.SUPPORT_LADDER}
        return {rung: support_status.NON_ATTAINMENT[rung] for rung in multitrack_schemas.SUPPORT_LADDER
                if rung not in rungs}

    # (a) a node claiming a higher rung with no evidence: 1.0.0 claims runtime-evidenced.
    higher = copy.deepcopy(body)
    for r in higher["records"]:
        if r["subject_id"] == "openssl-1.0.0":
            r["status"] = "runtime-evidenced"
            r["rungs_attained"] = ladder_prefix(6)
            r["not_attained"] = reasons_for(r["rungs_attained"], False, r["reason"])
    higher = _support_status_reseal(higher)
    higher_findings = findings_of(higher)
    caught_higher = any("attained runtime-evidenced but" in f for f in higher_findings)

    # (b) a node skipping a core rung: 3.6.4 attains built-authority without admitted-source.
    skipped = copy.deepcopy(body)
    for r in skipped["records"]:
        if r["subject_id"] == "openssl-3.6.4":
            r["rungs_attained"] = ["catalogued", "built-authority"]
            r["status"] = "built-authority"
            r["not_attained"] = reasons_for(r["rungs_attained"], False, r["reason"])
    skipped = _support_status_reseal(skipped)
    skipped_findings = findings_of(skipped)
    caught_skipped = any("skip a core rung" in f for f in skipped_findings)

    # (c) an archaeological-only node counted a support target.
    archaeology = copy.deepcopy(body)
    for r in archaeology["records"]:
        if r["support_role"] == "archaeology":
            r["support_role"] = "support-target"
            break
    archaeology = _support_status_reseal(archaeology)
    archaeology_findings = findings_of(archaeology)
    caught_archaeology = any("support_role" in f and "disagrees with status" in f
                             for f in archaeology_findings)

    # (d) a status typed rather than derived: 3.6.4 lowered to downstream-evidenced, internally
    # consistent, so only the reconciliation and re-derivation checks can catch it.
    typed = copy.deepcopy(body)
    typed_rid = None
    for r in typed["records"]:
        if r["subject_id"] == "openssl-3.6.4":
            typed_rid = r["subject_id"]
            r["status"] = "downstream-evidenced"
            r["rungs_attained"] = ["catalogued", "admitted-source", "built-authority",
                                   "atlas-complete", "downstream-evidenced"]
            r["evidence_by_rung"] = {k: v for k, v in r["evidence_by_rung"].items()
                                     if k in r["rungs_attained"]}
            r["not_attained"] = reasons_for(r["rungs_attained"], False, r["reason"])
    typed = _support_status_reseal(typed)
    typed_findings = findings_of(typed)
    caught_typed = any("does not reconcile with the population" in f for f in typed_findings)
    caught_typed = caught_typed and (support_status.derive_body() != typed)

    return {
        "baseline_findings": len(base),
        "injected_higher_rung_without_evidence": "openssl-1.0.0 -> runtime-evidenced",
        "injected_higher_rung_without_evidence_findings": len(higher_findings),
        "injected_skipped_rung": "openssl-3.6.4 -> [catalogued, built-authority]",
        "injected_skipped_rung_findings": len(skipped_findings),
        "injected_archaeology_counted_supported": "openssl-0.9.1c (support_role flipped)",
        "injected_archaeology_counted_supported_findings": len(archaeology_findings),
        "injected_typed_status": typed_rid,
        "injected_typed_status_findings": len(typed_findings),
        "specificity_holds": specificity,
        "caught_higher_rung_without_evidence": caught_higher,
        "caught_skipped_rung": caught_skipped,
        "caught_archaeology_counted_supported": caught_archaeology,
        "caught_typed_status": caught_typed,
        "honest": bool(specificity and caught_higher and caught_skipped and caught_archaeology
                       and caught_typed),
    }


def _support_status_court(name: str) -> dict:
    """`RT-SUPPORT-STATUS`: 23.15's court, the support-status ladder.

    Stages no probe. It reads `forensics/multitrack/support-status.json` and re-derives the whole
    ladder plane from the 23.10 historical population through the same generator, and establishes
    that every catalogue node has exactly one schema-valid row; that every row reconciles node-for-
    node and rung-for-rung with its population record; that each rung a node attained is backed by
    the evidence that establishes it (a `built-authority` by a receipt, a `downstream-evidenced` by
    a passing consumer, ...); that each rung not attained carries a reason; that `archaeological-
    only` climbs no rung and is never counted a support target; that the statuses are derived rather
    than typed and carry no competing `PARITY_VERIFIED`; and that the counts and content hash
    reproduce and every evidence path is content-addressed. Four seeded mutations -- a node claiming
    a higher rung with no evidence, a node skipping a core rung, an archaeological-only node counted
    a support target, and a status typed rather than derived -- are each caught with specificity
    holding. A passing ladder is an **instrument**: it records how far each release node reached and
    is not a compatibility claim about any release.
    """
    problems: list[str] = []
    for path, label in ((SUPPORT_STATUS, "support-status plane"),
                        (HISTORICAL_POPULATION, "historical-population record"),
                        (CATALOG, "release catalogue"),
                        (AUTHORITY_NODES, "authority-node registry"),
                        (AUTHORITY_REGISTRY, "authority registry"),
                        (BUILD_RECORDS, "build records"),
                        (HIST_ACQ, "historical acquisition"),
                        (HIST_RECEIPTS, "historical build receipts"),
                        (COMPATIBILITY_VIEWS, "compatibility-views plane"),
                        (SEMANTIC_COURTS, "semantic-courts plane"),
                        (DOWNSTREAM_MULTITRACK, "downstream-multitrack plane"),
                        (DEFAULT_AUTHORITY_ALIAS, "default-authority alias")):
        if not path.is_file():
            problems.append(f"the {label} {rel(path)} is absent")
    if problems:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": problems, "findings": [], "control": {}}

    body = read_json(SUPPORT_STATUS)
    catalog = read_json(CATALOG)
    authority_nodes = read_json(AUTHORITY_NODES)
    authorities = read_json(AUTHORITY_REGISTRY)
    build_records = read_json(BUILD_RECORDS)
    hist_acq = read_json(HIST_ACQ)
    hist_receipts = read_json(HIST_RECEIPTS)
    views = read_json(COMPATIBILITY_VIEWS)
    semantic = read_json(SEMANTIC_COURTS)
    downstream = read_json(DOWNSTREAM_MULTITRACK)
    default_alias = read_json(DEFAULT_AUTHORITY_ALIAS)
    population = read_json(HISTORICAL_POPULATION)

    findings = support_status_findings(body, population, catalog, authority_nodes, authorities,
                                       build_records, hist_acq, hist_receipts, views, semantic,
                                       downstream, default_alias)

    # No status is typed: the committed plane must reproduce from the 23.10 population through the
    # same generator, and that population must itself reproduce from the committed evidence.
    try:
        derived = support_status.derive_body()
    except SystemExit as exc:
        findings.append(f"the support-status plane could not be re-derived: {exc}")
        derived = None
    if derived is not None and derived != body:
        findings.append(
            "the committed support-status plane does not reproduce from the 23.10 population "
            "through the same generator: a status was typed rather than derived"
        )
    try:
        if historical_population.derive_body() != population:
            findings.append("the committed historical population does not reproduce from its "
                            "evidence, so the ladder it feeds cannot be trusted")
    except SystemExit as exc:
        findings.append(f"the historical population could not be re-derived: {exc}")

    control = support_status_sensitivity_control(body, population, catalog, authority_nodes,
                                                 authorities, build_records, hist_acq,
                                                 hist_receipts, views, semantic, downstream,
                                                 default_alias)
    counts = body.get("counts", {})
    verdict = "pass" if (not findings and not problems and control["honest"]) else "fail"
    records = body.get("records") or []
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/multitrack/support-status.json and re-derives the "
            "whole ladder plane from the 23.10 historical population through the same generator. It "
            "establishes that every catalogue node has exactly one schema-valid support-status row; "
            "that every row reconciles node-for-node and rung-for-rung with its population record, "
            "so there is one derivation rather than two; that each rung a node attained is backed by "
            "the evidence that establishes it (a built-authority by a receipt, a downstream-"
            "evidenced by a passing consumer, a candidate-view by a compatible view, ...); that each "
            "rung not attained carries its reason; that archaeological-only climbs no rung and is "
            "never counted a support target; that the statuses are derived rather than typed and "
            "carry no competing PARITY_VERIFIED; and that the counts and content hash reproduce and "
            "every evidence path is content-addressed. A node claiming a higher rung with no "
            "evidence, a node skipping a core rung, an archaeological-only node counted a support "
            "target and a status typed rather than derived are each detected with specificity "
            "holding (docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 2, 3.2 and 4)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the support-status court reads a committed evidence record and writes no "
            "artifacts/phase23/probes/<probe>.{authority,candidate} pair, so it stages no "
            "transcript to diff and carries no FRF declaration"
        ),
        "counts": counts,
        "status_histogram": counts.get("by_status"),
        "support_targets": counts.get("support_targets"),
        "archaeological_only": [r.get("subject_id") for r in records
                                if r.get("support_role") == "archaeology"],
        "content_hash": body.get("content_hash"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _downstream_reseal(body: dict) -> dict:
    """`body` with its content hash recomputed, so a mutation is caught on substance alone."""
    out = copy.deepcopy(body)
    out["content_hash"] = downstream_multitrack.body_hash(
        out.get("records") or [], out.get("not_run") or [], out.get("failed") or [],
        out.get("epochs") or [])
    return out


def downstream_multitrack_findings(body: dict, authority_nodes: dict, phase17: dict,
                                   candidate_version: str, specs: dict[str, dict],
                                   major_epochs: tuple[str, ...]) -> list[str]:
    """Every way the downstream-multitrack record and its backing evidence fail this court.

    A pure function of the committed bodies plus the authored trial spec, so the sensitivity
    control can mutate them and re-check. It establishes that every record is a schema-valid
    `downstream_epoch`; that every major epoch is covered by exactly one passing primary consumer
    and the epoch rows reproduce; that a passing consumer actually built and ran against the
    authority it names (its raw `ldd` output links that authority's prefix and its own SONAMEs and
    never the candidate shell, and its version banner names the authority's OpenSSL); that a
    record is never relabelled across authorities (its authority is the one its trial is about and
    the one in the authority-node registry); that a `not_run` (or `failed`) record carries its
    reason, claims no passing build or run, and is never counted as covering an epoch; that the
    counts and content hash reproduce; and that the Phase-17 candidate corpus is still green and is
    distinct from this authority evidence rather than relabelled into it.
    """
    findings: list[str] = []
    records = body.get("records") or []
    not_run = body.get("not_run") or []
    failed = body.get("failed") or []
    epochs = body.get("epochs") or []
    all_records = records + not_run + failed
    nodes = {n["authority_id"]: n for n in authority_nodes.get("nodes") or []}

    # 1. schema validity, including the load-bearing refusal of a pass with no build or run.
    for r in all_records:
        tid = r.get("trial_id", "<none>")
        findings += [f"downstream record {tid}: {p}"
                     for p in multitrack_schemas.validate_downstream_epoch(r)]

    # 2. a trial id is unique, and a passed record is not also a not-run one.
    ids = [r.get("trial_id") for r in all_records]
    if len(set(ids)) != len(ids):
        findings.append(f"the downstream plane names {len(ids) - len(set(ids))} duplicate trial "
                        f"id(s)")
    for r in records:
        if r.get("outcome") != "passed":
            findings.append(f"downstream trial {r.get('trial_id')} is in the passed list but its "
                            f"outcome is {r.get('outcome')!r}")
    for r in not_run:
        if r.get("outcome") != "not_run":
            findings.append(f"downstream trial {r.get('trial_id')} is in the not-run list but its "
                            f"outcome is {r.get('outcome')!r}")
    for r in failed:
        findings.append(f"downstream trial {r.get('trial_id')} is `failed`, which is an instrument "
                        f"defect rather than a pass or an honest unavailability")

    # 3. every major epoch is covered by exactly one passing primary consumer, and the epoch rows
    #    reproduce from the records (never typed).
    if tuple(downstream_multitrack.MAJOR_EPOCHS) != tuple(major_epochs):
        findings.append("the downstream epoch list and the historical-population epoch list have "
                        "drifted apart")
    if {e.get("epoch") for e in epochs} != set(major_epochs):
        findings.append("the downstream epoch rows do not name exactly the major ABI epochs")
    for name in major_epochs:
        primary = [r for r in records if r.get("epoch") == name and r.get("role") == "primary"]
        if len(primary) != 1:
            findings.append(f"major ABI epoch {name} has {len(primary)} passing primary consumer(s), "
                            f"not exactly one")
    for e in epochs:
        members = sorted(r.get("trial_id") for r in records if r.get("epoch") == e.get("epoch"))
        primary = [r for r in records if r.get("epoch") == e.get("epoch")
                   and r.get("role") == "primary"]
        covered = len(primary) == 1
        if bool(e.get("covered")) != covered:
            findings.append(f"epoch {e.get('epoch')}: covered={e.get('covered')} does not reproduce "
                            f"from the passed records")
        if sorted(e.get("records") or []) != members:
            findings.append(f"epoch {e.get('epoch')}: records do not reproduce from the passed "
                            f"records")
        if covered and e.get("authority_id") != primary[0].get("authority_id"):
            findings.append(f"epoch {e.get('epoch')}: authority does not reproduce from its "
                            f"passing primary record")

    # 4. a passing consumer is a real artifact against the authority it names, never relabelled.
    for r in records:
        tid = r.get("trial_id")
        spec = specs.get(tid)
        if spec is None:
            findings.append(f"downstream record {tid} names no known trial")
            continue
        node = nodes.get(r.get("authority_id"))
        if node is None:
            findings.append(f"downstream record {tid} names no authority node")
            continue
        if r.get("authority_id") != spec["authority_id"]:
            findings.append(f"downstream record {tid} is relabelled to authority "
                            f"{r.get('authority_id')} but its trial is about {spec['authority_id']}")
        if r.get("release_id") != node["release_id"]:
            findings.append(f"downstream record {tid}: release {r.get('release_id')} does not match "
                            f"its authority node {node['release_id']}")
        auth = r.get("authority") or {}
        for f in ("build_profile", "platform"):
            if auth.get(f) != node.get(f):
                findings.append(f"downstream record {tid}: authority.{f} does not match the "
                                f"authority node")
        if not r.get("evidence"):
            findings.append(f"downstream record {tid} passes but cites no evidence")
        raw = r.get("raw")
        if not isinstance(raw, dict) or not raw:
            findings.append(f"downstream record {tid} claims a pass with no raw build/run artifact")
            continue
        ldd = raw.get("ldd_output") or ""
        prefix_frag = f"forensics/authorities/prefix/{node['authority_id']}/"
        if prefix_frag not in ldd:
            findings.append(f"downstream record {tid} passes but its `ldd` output does not link "
                            f"the authority prefix {prefix_frag}")
        if "artifacts/phase2/install" in ldd:
            findings.append(f"downstream record {tid} links the candidate distribution shell, so it "
                            f"is not authority evidence")
        for soname in (node.get("binary_hashes") or {}):
            if soname not in ldd:
                findings.append(f"downstream record {tid} does not link the authority's {soname}")
        token = node["release_id"].removeprefix("openssl-")
        if f"OpenSSL/{token}" not in (raw.get("version_output") or ""):
            findings.append(f"downstream record {tid} version banner does not name the authority's "
                            f"OpenSSL {token}")

    # 5. a not-run record is honest unavailability: it carries its reason, claims no pass, and is
    #    never the coverage of an epoch.
    for r in not_run:
        tid = r.get("trial_id")
        if not r.get("reason"):
            findings.append(f"downstream not_run record {tid} carries no reason")
        spec = specs.get(tid)
        if spec is not None and r.get("authority_id") != spec["authority_id"]:
            findings.append(f"downstream not_run record {tid} is relabelled to authority "
                            f"{r.get('authority_id')} but its trial is about {spec['authority_id']}")
        build = r.get("build") or {}
        run = r.get("run") or {}
        if build.get("ok") is True or run.get("ok") is True:
            findings.append(f"downstream not_run record {tid} claims a passing build or run")

    # 6. the counts and the content hash reproduce from the committed records.
    if body.get("counts") != downstream_multitrack.counts_of(records, not_run, failed, epochs):
        findings.append("the downstream counts do not reproduce from its records")
    if downstream_multitrack.body_hash(records, not_run, failed, epochs) != body.get("content_hash"):
        findings.append("the downstream content_hash does not reproduce from its body")

    # 7. the existing Phase-17 candidate corpus remains green and distinct: it still records the
    #    six programs against the candidate, and no downstream record is relabelled as candidate or
    #    as a Phase-17 record.
    programs = {r.get("program"): r for r in phase17.get("programs") or []}
    for program in PHASE17_PROGRAMS:
        p = programs.get(program)
        if p is None:
            findings.append(f"the Phase-17 candidate corpus no longer carries {program}")
            continue
        if (p.get("functional") or {}).get("ok") is not True:
            findings.append(f"the Phase-17 candidate corpus records {program} as not functional")
        if p.get("candidate") != candidate_version:
            findings.append(f"the Phase-17 candidate corpus records {program} against candidate "
                            f"{p.get('candidate')}, not the current {candidate_version}")
    for r in records + not_run:
        if r.get("consumer") == candidate_version or r.get("authority_id") in (
                "openssl-rs", candidate_version):
            findings.append(f"downstream record {r.get('trial_id')} is relabelled as candidate "
                            f"evidence")
    return findings


def downstream_sensitivity_control(body: dict, authority_nodes: dict, phase17: dict,
                                   candidate_version: str, specs: dict[str, dict],
                                   major_epochs: tuple[str, ...]) -> dict:
    """Prove the court can fail: seed three mutations and require each caught.

    The honest record must yield **zero** findings (specificity), and each seeded mutation -- a
    consumer claiming a build with no artifact, an epoch counted passing while its consumer is
    `not_run`, and a result relabelled across authorities -- must be caught. Each mutated body is
    re-sealed first, so the detection is a semantic check and never the content-hash check firing
    on an un-recomputed digest.
    """
    def findings_of(b: dict) -> list[str]:
        return downstream_multitrack_findings(b, authority_nodes, phase17, candidate_version,
                                              specs, major_epochs)

    base = findings_of(body)
    specificity = not base

    # (a) a consumer claiming a build with no artifact: drop the raw build/run output of a pass.
    no_artifact = copy.deepcopy(body)
    stripped = no_artifact["records"][0]
    stripped["raw"] = {}
    stripped_tid = stripped["trial_id"]
    no_artifact = _downstream_reseal(no_artifact)
    no_artifact_findings = findings_of(no_artifact)
    caught_no_artifact = any("no raw build/run artifact" in f for f in no_artifact_findings)

    # (b) an epoch counted passing while its consumer is not_run: move the 1.0.x primary record to
    #     the not-run list while the 1.0.x epoch row still claims coverage.
    passing_while_not_run = copy.deepcopy(body)
    moved = next(r for r in passing_while_not_run["records"]
                 if r["epoch"] == "1.0.x" and r["role"] == "primary")
    passing_while_not_run["records"] = [r for r in passing_while_not_run["records"]
                                         if r is not moved]
    moved["outcome"] = "not_run"
    moved["reason"] = "simulated: counted passing while the consumer is not_run"
    passing_while_not_run["not_run"] = passing_while_not_run["not_run"] + [moved]
    passing_while_not_run = _downstream_reseal(passing_while_not_run)
    passing_while_not_run_findings = findings_of(passing_while_not_run)
    caught_passing_while_not_run = any("not exactly one" in f or "does not reproduce" in f
                                       for f in passing_while_not_run_findings)

    # (c) a result relabelled across authorities: the 3.6.4 pass claimed against 0.9.8zh.
    relabelled = copy.deepcopy(body)
    target = next(r for r in relabelled["records"] if r["trial_id"] == "3.6+/4.x--curl-8.22.0")
    target["authority_id"] = "openssl-0.9.8zh-historical"
    target["release_id"] = "openssl-0.9.8zh"
    target["authority"] = dict(target["authority"], authority_id="openssl-0.9.8zh-historical",
                              release_id="openssl-0.9.8zh")
    relabelled = _downstream_reseal(relabelled)
    relabelled_findings = findings_of(relabelled)
    caught_relabelled = any("relabelled to authority" in f or "does not match" in f
                            for f in relabelled_findings)

    return {
        "baseline_findings": len(base),
        "injected_pass_without_artifact": stripped_tid,
        "injected_pass_without_artifact_findings": len(no_artifact_findings),
        "injected_epoch_passing_while_not_run": "1.0.x",
        "injected_epoch_passing_while_not_run_findings": len(passing_while_not_run_findings),
        "injected_result_relabelled_across_authorities": "3.6+/4.x--curl-8.22.0",
        "injected_result_relabelled_across_authorities_findings": len(relabelled_findings),
        "specificity_holds": specificity,
        "caught_pass_without_artifact": caught_no_artifact,
        "caught_epoch_passing_while_not_run": caught_passing_while_not_run,
        "caught_result_relabelled": caught_relabelled,
        "honest": bool(specificity and caught_no_artifact and caught_passing_while_not_run
                       and caught_relabelled),
    }


def _downstream_multitrack_court(name: str) -> dict:
    """`RT-DOWNSTREAM-MULTITRACK`: 23.11's court, the unmodified downstream consumer per epoch.

    Stages no probe. It reads `forensics/multitrack/downstream-multitrack.json` and re-derives the
    whole record from the raw build/run outputs it carries through the same generator, and
    establishes that every major ABI epoch is covered by exactly one unmodified real downstream
    consumer built against that epoch's built authority; that a passing consumer genuinely built
    and ran (its raw `ldd` links the authority's prefix and SONAMEs and never the candidate shell,
    and its banner names the authority); that a record is never relabelled across authorities; that
    a `not_run` pair is honest unavailability that is never counted as passing; and that the
    Phase-17 candidate corpus is still green and distinct. Three seeded mutations -- a consumer
    claiming a build with no artifact, an epoch counted passing while its consumer is `not_run`,
    and a result relabelled across authorities -- are each caught with specificity holding. A
    passing downstream plane is an **instrument**: it records what one consumer did against one
    authority on one platform/profile, and is not a compatibility claim about any other.
    """
    problems: list[str] = []
    for path, label in ((DOWNSTREAM_MULTITRACK, "downstream-multitrack record"),
                        (AUTHORITY_NODES, "authority-node registry"),
                        (PHASE17_CORPUS, "Phase-17 candidate downstream corpus")):
        if not path.is_file():
            problems.append(f"the {label} {rel(path)} is absent")
    if problems:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": problems, "findings": [], "control": {}}

    body = read_json(DOWNSTREAM_MULTITRACK)
    authority_nodes = read_json(AUTHORITY_NODES)
    phase17 = read_json(PHASE17_CORPUS)
    candidate_version = gen_frf_courts.CANDIDATE_VERSION
    specs = {t["trial_id"]: t for t in downstream_multitrack.TRIALS}
    major_epochs = historical_population.MAJOR_EPOCHS

    findings = downstream_multitrack_findings(body, authority_nodes, phase17, candidate_version,
                                              specs, major_epochs)

    # No outcome is typed: the committed record must reproduce from its own raw outputs through the
    # same generator, so a hand-edited outcome stops reproducing.
    try:
        fresh = downstream_multitrack.rederive_body(body)
    except SystemExit as exc:
        findings.append(f"the downstream record could not be re-derived: {exc}")
        fresh = None
    if fresh is not None and fresh != body:
        findings.append(
            "the committed downstream record does not reproduce from the raw build/run outputs it "
            "carries through the same generator: an outcome was typed rather than derived"
        )

    control = downstream_sensitivity_control(body, authority_nodes, phase17, candidate_version,
                                             specs, major_epochs)
    counts = body.get("counts", {})
    verdict = "pass" if (not findings and not problems and control["honest"]) else "fail"

    def _row(r: dict) -> dict:
        return {
            "trial_id": r.get("trial_id"), "epoch": r.get("epoch"), "role": r.get("role"),
            "consumer": r.get("consumer"), "consumer_version": r.get("consumer_version"),
            "authority_id": r.get("authority_id"), "release_id": r.get("release_id"),
            "build_profile": (r.get("authority") or {}).get("build_profile"),
            "platform": (r.get("authority") or {}).get("platform"),
            "outcome": r.get("outcome"),
            "build_ok": (r.get("build") or {}).get("ok"),
            "run_ok": (r.get("run") or {}).get("ok"),
            "http_code": (r.get("run") or {}).get("http_code"),
            "tls": (r.get("run") or {}).get("tls"),
            "observation": r.get("observation"),
            "reason": r.get("reason"),
        }

    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/multitrack/downstream-multitrack.json and "
            "re-derives every consumer record from the raw build/run outputs the artefact carries "
            "through the same generator. It establishes that every major ABI epoch -- pre-1.0, "
            "1.0.x, 1.1.x, 3.x and 3.6+/4.x -- is covered by exactly one unmodified real downstream "
            "consumer built against that epoch's built authority and exercised against the "
            "authority's own s_server; that a passing consumer genuinely built and ran (its raw "
            "`ldd` output links the authority's prefix and its own SONAMEs and never the candidate "
            "distribution shell, and its version banner names the authority's OpenSSL); that a "
            "record is never relabelled across authorities; that a `not_run` pair is honest "
            "unavailability carrying its measured reason and is never counted as passing; that no "
            "outcome was typed; and that the Phase-17 candidate corpus is still green and distinct. "
            "A consumer claiming a build with no artifact, an epoch counted passing while its "
            "consumer is `not_run`, and a result relabelled across authorities are each detected "
            "with specificity holding (docs/PHASE-23-MULTITRACK-SUBPHASES.md sections 2, 3.3 and 4)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the downstream-multitrack court reads a committed evidence record and writes no "
            "artifacts/phase23/probes/<probe>.{authority,candidate} pair, so it stages no "
            "transcript to diff and carries no FRF declaration"
        ),
        "counts": counts,
        "epochs": body.get("epochs"),
        "records": [_row(r) for r in body.get("records") or []],
        "not_run": [_row(r) for r in body.get("not_run") or []],
        "content_hash": body.get("content_hash"),
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _delta_engine_court(name: str) -> dict:
    """`RT-DELTA-ENGINE`: 23.6's court, the semantic compatibility delta.

    Stages no probe. It reads the committed edge deltas under `forensics/deltas/` and the committed
    atlases and entity lineage they derive from, re-derives every row through the same engine, and
    establishes that every receipt is a schema-valid `delta_receipt`, every row is directed and
    dimension-specific with evidence, a confidence and an adjudication, every row reproduces from
    the atlases, the dimension set is complete and disjoint, and no row or evidence path is a
    source-line diff standing in for the delta. A composed path equals the composition of its edge
    deltas. Four seeded mutations -- an unclassified change, a composed path that disagrees with
    its edges, a row with no evidence and a dimension the evidence cannot support -- are each
    caught with specificity holding. A passing delta is an **instrument**: it records the changed
    surface between two named nodes, it is not a compatibility claim about either.
    """
    problems: list[str] = []
    if not DELTAS.is_dir():
        problems.append(f"the canonical edge deltas {rel(DELTAS)} are absent")
    bodies: list[tuple[Path, dict]] = []
    if not problems:
        for path in sorted(DELTAS.glob("*.json")):
            bodies.append((path, read_json(path)))
    findings = delta_engine_findings(bodies) if not problems else []
    control = delta_engine_sensitivity_control(bodies) if bodies else {"honest": False}
    verdict = "pass" if (not findings and not problems and control.get("honest")) else "fail"

    summaries = []
    for path, body in bodies:
        if body.get("covered") is False:
            summaries.append({"file": rel(path), "covered": False})
            continue
        summaries.append({
            "file": rel(path),
            "covered": True,
            "from_id": body.get("from_id"),
            "to_id": body.get("to_id"),
            "edge": (body.get("edge") or {}).get("edge_id"),
            "sense": body.get("sense"),
            "counts": body.get("counts"),
            "measured_dimensions": body.get("measured_dimensions"),
            "absent_dimensions": sorted(body.get("absent_dimensions") or {}),
            "content_hash": body.get("content_hash"),
        })
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed edge deltas under forensics/deltas/ and the "
            "committed atlases and entity lineage they derive from, re-derives every row through "
            "the same engine, and establishes that every receipt is a schema-valid delta_receipt, "
            "every row is directed and dimension-specific with evidence, a confidence and an "
            "adjudication, every row reproduces from the atlases, the measured and absent "
            "dimension sets are complete and disjoint, and no row or evidence path is a "
            "source-line diff standing in for the delta. A composed path equals the composition "
            "of its edge deltas. An unclassified change, a composed path that disagrees with its "
            "edges, a row with no evidence and a dimension the evidence cannot support are each "
            "detected with specificity holding (docs/PHASE-23-MULTITRACK-SUBPHASES.md sections "
            "3.1, 3.2 and 4.5)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the delta-engine court reads committed atlas records and writes no "
            "artifacts/phase23/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "edges": summaries,
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
            "(parity-obligations.json) is measured live and undone, never applied. "
            "`RT-LINEAGE-EDGES` is 23.4's court: the typed lineage edges. It stages no probe and "
            "reads forensics/release-catalog.json and forensics/authority-lineage.json, and "
            "establishes that every edge is schema-valid, typed and directed, with its stated "
            "sense following the evidence's chronology and its provenance resolving; that the "
            "graph is a DAG whose parallel supported branches (1.0.2, 1.1.1, 3.x, 4.x) are typed "
            "branch_fork edges rather than a false linear mainline; that a date-order "
            "chronological_successor edge is never presented as an ABI proof; that the "
            "declared_abi_compatibility edges are marked declarations scoped to their declared "
            "family; and that every kind the vocabulary names but the evidence cannot settle is "
            "recorded absent with a reason. A reversed edge direction, a date-order edge "
            "relabelled declared_abi_compatibility, an introduced cycle and an edge stripped of "
            "provenance are each detected with specificity holding. A passing edge set is a set "
            "of relationships, not a compatibility claim. `RT-ENTITY-LINEAGE` is 23.5's court: "
            "the entity lineage. It stages no probe and reads "
            "forensics/multitrack/entity-lineage.json and the committed atlases it derives from, "
            "and establishes that every row is schema-valid, provenanced and names the two "
            "releases, both entities, the strong signals and a confidence; that a settled relation "
            "rests on a strong signal and never on a fuzzy nomination; that same_entity rows are "
            "the same entity and reproduce as such from the atlases; that no relation is settled "
            "on the authority-scoped install prefix moving; that no entity is dropped, silently "
            "merged or both renamed and split; and that the plane names its coverage boundary and "
            "its absent relations. The committed differential atlas corroborates the per-plane "
            "counts independently. A same_entity off name-only similarity, a renamed_to that is "
            "really a split, a settled relation with no strong signal and a silent merge are each "
            "detected with specificity holding. A passing entity plane records what became of "
            "each entity and says nothing about compatibility. `RT-DELTA-ENGINE` is 23.6's court: "
            "the semantic compatibility delta. It stages no probe and reads the committed edge "
            "deltas under forensics/deltas/ and the committed atlases and entity lineage they "
            "derive from, and establishes that every receipt is a schema-valid delta_receipt, "
            "every row is directed and dimension-specific with evidence, a confidence and an "
            "adjudication, every row reproduces from the atlases and the entity lineage, the "
            "measured and absent dimension sets are complete and disjoint, and no row or evidence "
            "path is a source-line diff standing in for the delta. A composed path equals the "
            "composition of its edge deltas, and a pairwise combination the plan forbids is "
            "recorded as a gap rather than committed. An unclassified change, a composed path "
            "that disagrees with its edges, a row with no evidence and a dimension the evidence "
            "cannot support are each detected with specificity holding. A passing delta records "
            "the changed surface between two named nodes; it is not a compatibility claim about "
            "either. `RT-ABI-HISTORY-FACADES` is 23.7's court: the compatibility-policy layer and "
            "the historical ABI/history façades. It stages no probe and reads "
            "forensics/multitrack/abi-facades.json, the generated src/compat/layout_generated.rs "
            "and the compat sources the build gating lives in, and establishes that every record "
            "is a schema-valid abi_facade naming an explicit adapter rather than a blind cast; "
            "that every historical layout is measured from the 0.9.8zh headers and its header "
            "hash resolves in the committed source manifest while the production authority marks "
            "the same struct opaque (the 1.1.0 opacity transition); that a prototype's eras "
            "genuinely differ and its canonical declaration is the production atlas's own; that "
            "the ENGINE -> Provider -> no-ENGINE architecture and the init/thread epochs are the "
            "census's own; and that the generated repr(C) size/alignment/offset assertions are "
            "exactly what the measurement yields. The default 3.6.4 production build is "
            "unaffected: every façade module is cfg-gated behind the non-default compatibility "
            "selection, which build.rs resolves through the committed default-authority alias. A "
            "perturbed struct offset, a provider in a pre-provider epoch and a blind-cast façade "
            "are each detected with specificity holding, and the plane names the boundary of what "
            "is not established (the 1.0.x epoch and the pre-1.1.0 aggregates it does not cover). "
            "A passing façade plane establishes a small historical epoch; it is not a source or "
            "binary compatibility claim about any release. `RT-SEMANTIC-COURTS` is 23.8's court: "
            "the semantic multitrack courts. It stages no probe at court time: the shared probe "
            "courts/phase23/semantic_probe.c is compiled and run against both authorities in the "
            "court venue, and the court re-runs the authority-to-authority comparison from the raw "
            "transcripts the committed plane preserves. It establishes that both sides emit the "
            "same normalized observation vocabulary; that the side-specific adapters for the "
            "declarations that differ across the pair preserve the difference rather than erasing "
            "it; that the committed observations reproduce from the raw bytes through the same "
            "adapter; that every observed difference is a classified release delta resolving in "
            "the committed 23.6 delta engine (or in a dimension it records absent with its reason); "
            "that the candidate-to-authority dimension is discharged by named, passing existing "
            "Phase-2 and Phase-17 courts rather than duplicated; and that a pair the venue cannot "
            "execute is recorded not-run with its reason. An adapter that normalizes away a real "
            "difference, a probe read against the wrong authority and a difference left "
            "unclassified are each detected with specificity holding. A passing semantic court is "
            "an instrument: it records the movement between two named authorities and is not a "
            "compatibility claim about either. `RT-COMPATIBILITY-VIEWS` is 23.9's court: the "
            "directional, dimension-specific compatibility views. It stages no probe and reads "
            "forensics/multitrack/compatibility-views.json, re-deriving the whole plane from the "
            "authorities' own committed evidence through the same generator. It establishes that "
            "every view is a schema-valid, directional, dimension-specific compatibility_view with "
            "an explicit evidence_kind that is never numeric ordering; that no view carries a bare "
            "`compatible` boolean; that every view names an admitted reference authority and a "
            "distribution facet and carries only that authority's reference evidence, so a view "
            "inherits no receipt across a version; that every evidence path is content-addressed; "
            "and that a dimension the evidence cannot support is recorded not-derivable with its "
            "reason. The 3.6.4 production view compares the authority's derived distribution/ABI "
            "shell (library names, SONAMEs, exported symbols/versions, static archives, link names, "
            "pkg-config metadata, installed layout, version identity) against the committed "
            "artifacts/phase2 distribution, and the 0.9.8zh historical views are `not_measured` "
            "because the epoch has no candidate build in this venue. Relaying authority A's "
            "evidence into authority B's view, a view collapsed to a boolean, a view citing "
            "numeric ordering and a view with no reference authority are each detected with "
            "specificity holding. `RT-HISTORICAL-POPULATION` is 23.10's court: the historical "
            "population. It stages no probe and reads "
            "forensics/multitrack/historical-population.json, re-deriving the whole record from "
            "the committed catalogue, authority nodes, acquisition and build receipts, atlases, "
            "compatibility views and semantic pair through the same generator. It establishes "
            "that every catalogue node has exactly one schema-valid support status over the "
            "ladder catalogued, admitted-source, built-authority, atlas-complete, candidate-view, "
            "runtime-evidenced, downstream-evidenced and maintained, with archaeological-only "
            "where a node is studied and not supported; that a built-authority rung is backed by "
            "an actual receipt; that an unavailable release is recorded unavailable and is never "
            "counted runtime-compatible; that runtime_compatible holds only where the runtime "
            "rung does; that each major ABI epoch -- pre-1.0, 1.0.x, 1.1.x, 3.x and 3.6+/4.x -- "
            "has at least one built representative (0.9.8zh, 1.0.2u, 1.1.1w, 3.0.0 and "
            "3.6.3/3.6.4); that no status was typed; and that every evidence path is "
            "content-addressed. A release marked built with no receipt, an unavailable release "
            "marked runtime-compatible, a release with no status and an epoch with no "
            "representative are each detected with specificity holding. `RT-DOWNSTREAM-MULTITRACK` "
            "is 23.11's court: the unmodified downstream consumer per major compatibility epoch. "
            "It stages no probe and reads forensics/multitrack/downstream-multitrack.json, "
            "re-deriving every consumer record from the raw build/run outputs the artefact carries "
            "through the same generator. It establishes that every major ABI epoch -- pre-1.0, "
            "1.0.x, 1.1.x, 3.x and 3.6+/4.x -- is covered by exactly one unmodified real "
            "downstream consumer built against that epoch's built authority and exercised against "
            "the authority's own s_server; that a passing consumer genuinely built and ran (its "
            "raw `ldd` output links the authority's prefix and its own SONAMEs and never the "
            "candidate distribution shell, and its version banner names the authority's OpenSSL); "
            "that a record is never relabelled across authorities; and that a `not_run` pair is "
            "honest unavailability carrying its measured reason and is never counted as passing. "
            "The Phase-17 candidate corpus is checked green and distinct: a candidate result is "
            "never relabelled as authority evidence. A consumer claiming a build with no artifact, "
            "an epoch counted passing while its consumer is `not_run`, and a result relabelled "
            "across authorities are each detected with specificity holding. `RT-COMPATIBILITY-EDGES` "
            "is 23.12's court: the directional compatibility edges. It stages no probe and reads "
            "forensics/multitrack/compatibility-edges.json, re-deriving the whole plane from the "
            "committed edge deltas, the entity lineage, the compatibility views and the Phase-2 "
            "ABI courts through the same generator. It establishes that every edge is a "
            "schema-valid, directional, dimension-specific compatibility_edge whose facet maps "
            "onto its coarse dimension; that each verdict is PASS/FAIL/UNKNOWN with the evidence "
            "that establishes it and never a single boolean; that a facet whose evidence is "
            "absent is UNKNOWN with its reason, never PASS by default; that every evidence entry "
            "is content-addressed and names the side it belongs to, so neither side's evidence is "
            "inherited from the other; and that no evidence kind is numeric ordering. The "
            "3.6.3->3.6.4 edge is read both ways, and its API-source facet passes forward and "
            "fails backward because the two macros 3.6.4 added are absent from 3.6.3; the "
            "candidate's relation to its reference authority 3.6.4-production is read both ways, "
            "with the semantic facet UNKNOWN because no committed candidate-to-authority semantic "
            "measurement exists. A PASS with no evidence, a dimension collapsed to one boolean, "
            "evidence inherited across the two sides, a verdict defaulting to PASS and a "
            "numeric-ordering evidence kind are each detected with specificity holding. "
            "`RT-NEGATIVE-OBLIGATIONS` is 23.13's court: the negative (and positive) obligations. "
            "It stages no probe and reads forensics/multitrack/negative-obligations.json, "
            "re-deriving every obligation from the committed censuses, ABI/history façades, edge "
            "deltas and symbols planes through the same generator. It establishes that every "
            "obligation is a schema-valid negative_obligation whose expected state is the "
            "polarity its kind asserts; that its scope names an admitted authority or a "
            "catalogued release; that everything it names is present and content-addressed and is "
            "the evidence the record's derivation checks actually read, so a negative obligation "
            "is checked against the named authority/view/plane rather than asserted; that its "
            "state is the reading that evidence establishes and never assumed, so an `open` "
            "obligation is a compatibility defect and `unknown` is only where no authority or "
            "view exists; and that both polarities and all six kinds -- must_not_exist, "
            "must_be_opaque and must_not_be_exported beside must_exist, must_be_public and "
            "must_be_exported -- are present. The plane covers the pre-provider authorities' "
            "provider absence (0.9.8zh, 1.0.2u, 1.1.1w) beside 3.0.0 and 3.6.4's presence, the "
            "pre-1.1.0 public layout (EVP_MD_CTX, HMAC_CTX) beside the 3.6.4 opacity transition, "
            "the 3.6.4-added macros' absence from 3.6.3, the exported symbols the 3.6.3 -> 3.6.4 "
            "delta read as present in both, each authority's `.num` NOEXIST rows, and a 4.x "
            "release's ENGINE absence, which is `unknown` because no 4.x authority or view is "
            "admitted. A provider symbol present in a pre-provider authority's view, a "
            "post-1.1.0 layout declared public, an ENGINE symbol retained in a 4.x view, an "
            "obligation with no evidence and a future symbol leaked into an earlier authority's "
            "view are each detected with specificity holding. "
            "`RT-SECURITY-LINEAGE` is 23.14's court: the historical security lineage. It stages no "
            "probe and reads forensics/multitrack/security-lineage.json, re-deriving the whole "
            "plane from the frozen source snapshot, the release catalogue, the default-authority "
            "alias and the divergence register through the same generator. It establishes that "
            "every vulnerability carries an affected range, per-branch fixes and a candidate "
            "disposition; that a branch fix maps to the correct maintained branch; that no "
            "disposition re-adopts a fixed behaviour, so a preserved vulnerable behaviour or a "
            "safe divergence with no recorded divergence is a finding; that an unavailable-source "
            "(extended-support) identifier is an external release reference and is never admitted "
            "as an authority; and that the security_backport edges the observed fixes establish "
            "are present in the authority lineage. A CVE fix mapped to the wrong branch, a "
            "vulnerable behaviour marked preserved, a safe divergence with no recorded "
            "divergence, an extended-support identifier admitted as an authority and a dropped "
            "branch fix are each detected with specificity holding. The property -- the whole "
            "lineage observed and bound -- is NOT_CLAIMED and the unobserved source records are "
            "named as property findings, so a passing RT-SECURITY-LINEAGE is an instrument, never "
            "a statement that the lineage is secure. Phase 23 "
            "lineage is secure. `RT-SUPPORT-STATUS` is 23.15's court: the support-status "
            "ladder. It stages no probe and reads forensics/multitrack/support-status.json, "
            "re-deriving the whole ladder plane from the 23.10 historical population through the "
            "same generator. It establishes that every catalogue node has exactly one schema-valid "
            "row; that every row reconciles node-for-node and rung-for-rung with its population "
            "record, so there is one derivation of a status rather than two; that each rung a node "
            "attained is backed by the evidence that establishes it (a built-authority by a "
            "receipt, a downstream-evidenced by a passing consumer, a candidate-view by a "
            "compatible view, ...); that each rung not attained carries its reason; that "
            "archaeological-only climbs no rung and is never counted a support target; that the "
            "statuses are derived rather than typed and carry no competing PARITY_VERIFIED; that "
            "the core rungs are a prefix while the additive rungs are independent evidence planes; "
            "and that the counts and content hash reproduce and every evidence path is "
            "content-addressed. A node claiming a higher rung with no evidence, a node skipping a "
            "core rung, an archaeological-only node counted a support target and a status typed "
            "rather than derived are each detected with specificity holding. A passing ladder is an "
            "instrument: it records how far each release node reached and is not a compatibility "
            "claim about any release. Phase 23 "
            "owns no exported symbol, so no differential probe "
            "over a symbol set is its evidence, and its remaining two courts -- "
            "RT-COMPATIBILITY-MATRIX and MULTITRACK-SEAL -- are pending with "
            "the subphases that land them (23.16 and 23.17). The one thing the model forbids "
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
        InputRef(name="entity-lineage", path=ENTITY_LINEAGE),
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
        InputRef(name="abi-policy", path=REPO_ROOT / "docs" / "ABI_POLICY.md"),
        InputRef(name="abi-facades", path=ABI_FACADES),
        InputRef(name="abi-facade-rust", path=ABI_FACADE_RUST),
        InputRef(name="compat-mod", path=COMPAT_MOD),
        InputRef(name="compat-policy", path=COMPAT_POLICY),
        InputRef(name="build-script", path=BUILD_SCRIPT),
        InputRef(name="historical-source-manifest", path=HISTORICAL_MANIFEST),
        InputRef(name="semantic-courts", path=SEMANTIC_COURTS),
        InputRef(name="semantic-probe", path=SEMANTIC_PROBE),
        InputRef(name="compatibility-views", path=COMPATIBILITY_VIEWS),
        InputRef(name="compatibility-edges", path=COMPATIBILITY_EDGES),
        InputRef(name="negative-obligations", path=NEGATIVE_OBLIGATIONS),
        InputRef(name="security-lineage", path=SECURITY_LINEAGE),
        InputRef(name="security-source", path=SECURITY_SOURCE),
        InputRef(name="security-divergence-register", path=SECURITY_DIVERGENCE),
        InputRef(name="security-divergence-policy", path=SECURITY_POLICY),
        InputRef(name="historical-population", path=HISTORICAL_POPULATION),
        InputRef(name="support-status", path=SUPPORT_STATUS),
        InputRef(name="downstream-multitrack", path=DOWNSTREAM_MULTITRACK),
        InputRef(name="phase17-downstream-corpus", path=PHASE17_CORPUS),
        InputRef(name="semantic-courts", path=SEMANTIC_COURTS),
    ]
    for path in sorted(DELTAS.glob("*.json")):
        inputs.append(InputRef(name=f"delta/{path.stem}", path=path))
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
        elif r["verdict"] == "pass" and r["court"] == LINEAGE_EDGES_COURT:
            c = r["control"]
            print(f"  {r['court']:<32} pass   (no probe, {r['edges']} edge(s) "
                  f"{r['kinds']}; {r['declared_edges']} declared; dag={r['dag']['is_dag']}; "
                  f"absent={sorted(r['absent_kinds'])}; content_hash={r['content_hash'][:16]}...; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"reversed->{c['injected_reversed_direction_findings']} "
                  f"relabelled->{c['injected_relabelled_date_order_findings']} "
                  f"cycle->{c['injected_cycle_findings']} "
                  f"no-provenance->{c['injected_provenance_drop_findings']} finding(s))")
            for kind in sorted(r["kinds"]):
                print(f"      kind {kind:<28} {r['kinds'][kind]}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == ENTITY_LINEAGE_COURT:
            c = r["control"]
            print(f"  {r['court']:<32} pass   (no probe, {r['rows']} relation(s) "
                  f"{r['relations']}; {r['covered_pairs']} covered pair(s); "
                  f"absent={sorted(r['absent_relations'])}; "
                  f"content_hash={r['content_hash'][:16]}...; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"fuzzy-same-entity->{c['injected_fuzzy_same_entity_findings']} "
                  f"rename-as-split->{c['injected_rename_that_is_a_split_findings']} "
                  f"no-strong-signal->{c['injected_settled_without_strong_signal_findings']} "
                  f"silent-merge->{c['injected_silent_merge_findings']} finding(s))")
            for kind in sorted(r["entity_kinds"]):
                print(f"      kind {kind:<12} {r['entity_kinds'][kind]}")
            print(f"      boundary: {r['boundary']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == DELTA_ENGINE_COURT:
            c = r["control"]
            print(f"  {r['court']:<32} pass   (no probe, {len(r['edges'])} edge delta(s); "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"unclassified->{c['injected_unclassified_change_findings']} "
                  f"disagreeing-composition->{c['injected_disagreeing_composition_findings']} "
                  f"no-evidence->{c['injected_unevidenced_row_findings']} "
                  f"unsupported-dimension->"
                  f"{c['injected_unsupported_dimension_findings']} finding(s))")
            for edge in r["edges"]:
                if not edge.get("covered"):
                    print(f"      {edge['file']}: UNCOVERED")
                    continue
                counts = edge["counts"]
                print(f"      {edge['file']}: {edge['from_id']} -> {edge['to_id']} "
                      f"[{edge['edge']}] sense={edge['sense']} "
                      f"+{counts['added']} -{counts['removed']} ~{counts['changed']}; "
                      f"measured={len(edge['measured_dimensions'])} "
                      f"absent={len(edge['absent_dimensions'])}; "
                      f"content_hash={edge['content_hash'][:16]}...")
                for dim in sorted(counts["by_dimension"]):
                    bucket = counts["by_dimension"][dim]
                    print(f"        {dim:<28} "
                          f"+{bucket['added']} -{bucket['removed']} ~{bucket['changed']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == ABI_HISTORY_FACADES_COURT:
            c = r["control"]
            print(f"  {r['court']:<32} pass   (no probe, {len(r['facades'])} façade record(s); "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"struct-offset->{c['injected_struct_offset_findings']} "
                  f"pre-provider->{c['injected_provider_findings']} "
                  f"blind-cast->{c['injected_blind_cast_findings']} finding(s))")
            for f in r["facades"]:
                detail = f.get("struct_name") or f.get("symbol") or ""
                layout = (f"sizeof={f['sizeof']} align={f['alignof']}"
                          if "sizeof" in f else
                          f"engine={f.get('engine_model')} provider={f.get('provider_model')}"
                          if "engine_model" in f else
                          f"init={f.get('init_model')} thread={f.get('thread_model')}"
                          if "init_model" in f else "")
                print(f"      {f['facade_id']:<28} {f['facade_kind']:<13} "
                      f"{detail:<20} {layout}")
            print(f"      boundary: {r['boundary']}")
            for n in r["not_established"] or []:
                print(f"      not established: {n['claim']} ({n['reason'][:60]}...)")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == SEMANTIC_COURTS_COURT:
            c = r["control"]
            print(f"  {r['court']:<32} pass   (no probe at court time; {r['differs']} classified "
                  f"difference(s), {r['agrees']} agreeing observation(s), "
                  f"{len(r['not_run'] or [])} not-run pair(s); "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"erased->{c['injected_erased_findings']} "
                  f"wrong-authority->{c['injected_wrong_authority_findings']} "
                  f"unclassified->{c['injected_unclassified_findings']} finding(s))")
            for obs in r["observations"]:
                if obs["agreement"]:
                    continue
                ref = obs.get("release_delta") or {}
                tie = (f" [{ref.get('dimension')}:{ref.get('entity_id')}]"
                       if ref else " [error_behavior: absent]")
                print(f"      DELTA {obs['classification']:<20} {obs['vocabulary']:<50} "
                      f"{obs['observed_a']!r} -> {obs['observed_b']!r}{tie}")
            for entry in r["not_run"] or []:
                print(f"      NOT-RUN {entry['pair'][0]} vs {entry['pair'][1]}")
            print(f"      boundary: {r['boundary']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == COMPATIBILITY_VIEWS_COURT:
            c = r["control"]
            counts = r["counts"] or {}
            print(f"  {r['court']:<32} pass   (no probe, {counts.get('views')} view(s) over "
                  f"{counts.get('authorities')} authority/ies; {counts.get('by_status')}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"relayed-authority->{c['injected_relayed_findings']} "
                  f"boolean->{c['injected_boolean_findings']} "
                  f"ordering->{c['injected_ordering_findings']} "
                  f"no-reference->{c['injected_no_reference_findings']} finding(s))")
            for a in r["per_authority"]:
                print(f"      authority {a['authority_id']:<32} "
                      f"support={a['support_status']}")
                for v in a["views"]:
                    print(f"        {v['facet']:<34} {v['dimension']:<14} {v['status']}")
                print(f"        not-derivable: {', '.join(a['not_derivable'])}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == COMPATIBILITY_EDGES_COURT:
            c = r["control"]
            counts = r["counts"] or {}
            print(f"  {r['court']:<32} pass   (no probe, {counts.get('edges')} edge(s) over "
                  f"{counts.get('pairs')} pair(s) / {counts.get('directions')} direction(s); "
                  f"{counts.get('by_verdict')}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"no-evidence->{c['injected_pass_without_evidence_findings']} "
                  f"boolean->{c['injected_collapsed_boolean_findings']} "
                  f"inherited->{c['injected_inherited_evidence_findings']} "
                  f"default-pass->{c['injected_verdict_defaulting_to_pass_findings']} "
                  f"ordering->{c['injected_ordering_evidence_findings']} finding(s))")
            for m in r["matrix"]:
                print(f"      {m['from_id']:<30} -> {m['to_id']:<30} {m['direction']:<22} "
                      f"{m['facet']:<11} {m['verdict']}")
            for u in r["unknown"] or []:
                print(f"      UNKNOWN {u['edge_id']}: {u['reason']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == NEGATIVE_OBLIGATIONS_COURT:
            c = r["control"]
            counts = r["counts"] or {}
            print(f"  {r['court']:<32} pass   (no probe, {counts.get('obligations')} obligation(s) "
                  f"{counts.get('by_kind')}; state={counts.get('by_state')}; "
                  f"positive={counts.get('positive')} negative={counts.get('negative')} "
                  f"over {len(r['authorities'])} authority/ies; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"provider->{c['injected_provider_findings']} "
                  f"opaque-public->{c['injected_opaque_layout_findings']} "
                  f"engine-4x->{c['injected_engine_findings']} "
                  f"no-evidence->{c['injected_no_evidence_findings']} "
                  f"leaked->{c['injected_leaked_symbol_findings']} finding(s))")
            by_kind = r["by_kind"]
            for kind in sorted(by_kind):
                print(f"      {kind:<20} {by_kind[kind]}")
            for o in r["obligations"]:
                where = o["authority_id"] or o["release_id"]
                print(f"      {o['state']:<9} {o['kind']:<20} {o['subject']:<42} {where}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == HISTORICAL_POPULATION_COURT:
            c = r["control"]
            counts = r["counts"] or {}
            print(f"  {r['court']:<32} pass   (no probe, {counts.get('nodes')} node(s); "
                  f"{counts.get('by_status')}; built={counts.get('built')} "
                  f"unavailable={counts.get('unavailable')} "
                  f"runtime_compatible={counts.get('runtime_compatible')}; "
                  f"epochs covered={counts.get('epochs_covered')}/{counts.get('epochs')}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"no-receipt->{c['injected_built_without_receipt_findings']} "
                  f"unavailable-compatible->"
                  f"{c['injected_unavailable_runtime_compatible_findings']} "
                  f"no-status->{c['injected_missing_status_findings']} "
                  f"empty-epoch->"
                  f"{c['injected_epoch_without_representative_findings']} finding(s))")
            for e in r["epochs"] or []:
                reps = ", ".join(e["built_representatives"]) or "-"
                mark = "ok" if e["covered"] else "NO REPRESENTATIVE"
                print(f"      epoch {e['epoch']:<10} members={e['members']:<4} "
                      f"built={reps:<30} {mark}")
            for u in r["unavailable"] or []:
                print(f"      unavailable {u['release_id']:<27} runtime_compatible=false")
            print(f"      runtime-compatible: {', '.join(r['runtime_compatible']) or '-'}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == SUPPORT_STATUS_COURT:
            c = r["control"]
            counts = r["counts"] or {}
            print(f"  {r['court']:<32} pass   (no probe, {counts.get('nodes')} node(s); "
                  f"status={counts.get('by_status')}; role={counts.get('by_support_role')}; "
                  f"runtime_compatible={counts.get('runtime_compatible')}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"higher-rung-no-evidence->"
                  f"{c['injected_higher_rung_without_evidence_findings']} "
                  f"skipped-core-rung->{c['injected_skipped_rung_findings']} "
                  f"archaeology-supported->"
                  f"{c['injected_archaeology_counted_supported_findings']} "
                  f"typed-status->{c['injected_typed_status_findings']} finding(s))")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == DOWNSTREAM_MULTITRACK_COURT:
            c = r["control"]
            counts = r["counts"] or {}
            print(f"  {r['court']:<32} pass   (no probe, {counts.get('passed')} passing "
                  f"consumer(s), {counts.get('not_run')} not_run, {counts.get('failed')} failed; "
                  f"epochs covered={counts.get('epochs_covered')}/{counts.get('epochs')}; "
                  f"content_hash={r['content_hash'][:16]}...; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"no-artifact->{c['injected_pass_without_artifact_findings']} "
                  f"passing-while-not_run->"
                  f"{c['injected_epoch_passing_while_not_run_findings']} "
                  f"relabelled->{c['injected_result_relabelled_across_authorities_findings']} "
                  f"finding(s))")
            for row in r["records"] or []:
                print(f"      epoch {row['epoch']:<10} {row['consumer']} {row['consumer_version']:<8} "
                      f"vs {row['authority_id']:<32} build={row['build_ok']} run={row['run_ok']} "
                      f"http={row['http_code']} tls={row['tls']}")
            for row in r["not_run"] or []:
                print(f"      NOT-RUN {row['epoch']:<10} {row['consumer']} "
                      f"{row['consumer_version']:<8} vs {row['authority_id']:<32} "
                      f"{row['reason']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == SECURITY_LINEAGE_COURT:
            c = r["control"]
            counts = r["counts"] or {}
            print(f"  {r['court']:<32} pass   (no probe, {counts.get('vulnerabilities')} "
                  f"vulnerabilit(y/ies), {counts.get('branch_fixes')} branch fix(es) "
                  f"{counts.get('by_branch')}; dispositions={counts.get('by_disposition')}; "
                  f"external={counts.get('external_release_references')} "
                  f"catalogued={counts.get('catalogued_fixes')}; "
                  f"backport_edges={counts.get('backport_edges')}; "
                  f"observed={r['coverage'].get('observed')}/{r['coverage'].get('source_records')}; "
                  f"{len(r['findings'])} property finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"wrong-branch->{c['injected_wrong_branch_findings']} "
                  f"preserved->{c['injected_preserved_behaviour_findings']} "
                  f"no-divergence->{c['injected_safe_divergence_without_record_findings']} "
                  f"external-authority->{c['injected_external_as_authority_findings']} "
                  f"dropped-fix->{c['injected_dropped_branch_fix_findings']} problem(s))")
            for ident in r["identities"]:
                print(f"      {ident['vulnerability_id']:<16} {ident['severity']:<8} "
                      f"{ident['candidate_disposition']:<16} "
                      f"{ident['subsystem']:<14} fips={ident['fips_impact']:<10} "
                      f"fixes={ident['branch_fixes']:<2} branches={','.join(ident['branches'])}")
            for o in r["observations"]:
                tag = "EXTERNAL" if o["external"] else (o["release_id"] or "")
                print(f"      branch-fix {o['vulnerability_id']:<16} {o['branch']:<7} "
                      f"{o['fixed_in']:<10} {tag}")
            for f in r["findings"][:3]:
                print(f"      property finding: {f}")
            if len(r["findings"]) > 3:
                print(f"      property finding: ... and {len(r['findings']) - 3} more")
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
