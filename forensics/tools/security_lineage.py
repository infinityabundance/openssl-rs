#!/usr/bin/env python3
"""openssl-rs — the security lineage: historical vulnerabilities observed, never reintroduced.

Phase 23 is the multitrack authority stratum (`docs/PHASE-23-MULTITRACK-SUBPHASES.md`). 23.14 is
"the security lineage": a historical security lineage connecting the official OpenSSL
vulnerability records to release ranges, and the rule
`docs/SECURITY_DIVERGENCE_POLICY.md` section 1 fixes -- a historical vulnerability is **observed
but never reintroduced**. This module derives
`forensics/multitrack/security-lineage.json` from the committed source and lineage evidence, and
never types a fact about a vulnerability:

  * **one identity per vulnerability** (`vulnerabilities`), carrying upstream's severity, the
    affected range, the affected subsystem, the FIPS impact upstream states, and the candidate
    disposition; and
  * **separate branch-fix rows** (`observations`), one per (vulnerability, maintained branch),
    each a `security_observation` naming the fixed release, the branch it maps to, and whether the
    identifier's source is publicly available.

Every record is derived from an artefact that already carries the fact:

  * upstream's own vulnerability index and advisories, frozen -- with their URL, fetch date and
    SHA-256 -- into `forensics/multitrack/security-source.json` by
    `forensics/tools/security_acquire.py`;
  * the release catalogue (`forensics/release-catalog.json`), which decides whether a fixed
    identifier is a **catalogued release** or an **external release reference** (an
    extended-support identifier whose source is not publicly available -- never admitted as an
    authority);
  * the divergence register (`forensics/divergence-obligations.json`) and
    `docs/SECURITY_DIVERGENCE_POLICY.md`, which the candidate disposition **references** rather
    than restates (this plane does not duplicate the register).

The no-reintroduction rule, made mechanical
-------------------------------------------
Every observation's `reintroduced` is the literal `false`, and the validator refuses a
`preserve_vulnerable_behaviour` disposition by name. Beside that, each vulnerability carries a
`candidate_disposition` over a closed vocabulary, derived from the committed evidence:

  * `never_contained` -- the candidate's reference authority already carries the fix (the
    reference is not inside any affected range), so the vulnerable behaviour is not the behaviour
    the candidate implements;
  * `safe_divergence` -- the affected subsystem has a **recorded** safety divergence in
    `forensics/divergence-obligations.json`, which this record cites rather than restates;
  * `unresolved` -- the candidate's reference authority lies *inside* an affected range, so the
    fix postdates the reference and the candidate cannot claim it; this is an honest finding and
    never a pass;
  * `preserve_vulnerable_behaviour` -- never produced by the derivation; the value the court's
    control injects to prove a re-adopted fixed behaviour is caught.

The `security_backport` lineage edges
-------------------------------------
For every vulnerability fixed in **two or more catalogued releases**, this module also produces
the typed `security_backport` lineage edges between those fixed releases, which
`forensics/tools/authority_catalog.py` merges into `forensics/authority-lineage.json`. The kind
was recorded absent-with-reason by 23.4 until a vulnerability observation named a fixed release;
it now lands, and its edges are read forward in time.

Outputs
-------
  forensics/multitrack/security-lineage.json

SPDX-License-Identifier: Apache-2.0
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
    sha256_file,
    write_json,
)

import multitrack_schemas as mts  # noqa: E402

OUT = REPO_ROOT / "forensics" / "multitrack" / "security-lineage.json"
GENERATOR = "forensics/tools/security_lineage.py"

SOURCE = REPO_ROOT / "forensics" / "multitrack" / "security-source.json"
CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
LINEAGE = REPO_ROOT / "forensics" / "authority-lineage.json"
DEFAULT_AUTHORITY = REPO_ROOT / "forensics" / "multitrack" / "default-authority.json"
AUTHORITY_NODES = REPO_ROOT / "forensics" / "authority-nodes.json"
AUTHORITIES = REPO_ROOT / "forensics" / "authorities" / "AUTHORITIES.json"
DIVERGENCE = REPO_ROOT / "forensics" / "divergence-obligations.json"
POLICY = REPO_ROOT / "docs" / "SECURITY_DIVERGENCE_POLICY.md"
NEGATIVE_OBLIGATIONS = REPO_ROOT / "forensics" / "multitrack" / "negative-obligations.json"

# The content hash is over these keys, so a typed disposition or a hand-listed fix moves the hash
# as well as the semantic check.
HASH_KEYS: tuple[str, ...] = (
    "reference_authority", "dispositions", "fips_impacts", "subsystem_tokens", "coverage",
    "vulnerabilities", "observations", "backport_edges", "non_claims", "boundary",
)

# The subsystem classifier: the first token whose keyword appears in the advisory **title** (and,
# failing that, the advisory text) names the affected subsystem. The order is specific-before-
# general (GF(2^m) before BN, X.509 before ASN.1) so a narrower match wins. The classifier records
# the keyword it matched and the fragment it matched it in, so the classification is a reading of
# the source rather than a typed label. A record no keyword reaches is `unresolved`.
SUBSYSTEM_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("crypto/bn/gf2m", ("gf(2^m)", "gf2m", "bn_gf2m")),
    ("crypto/bn", ("bn_mod_sqrt", "bn_", "modular square root", "bignum")),
    ("crypto/pkcs12", ("pkcs12", "pkcs#12")),
    ("crypto/cms", ("cms ", "cms(", "cms_", "envelopeddata", "authenveloped")),
    ("crypto/x509", ("generalname", "x.400", "x400", "x.509", "x509", "certificate polic")),
    ("crypto/asn1", ("asn.1", "asn1")),
    ("crypto/ec", ("ecdsa", "elliptic curve", "ec_key", "ec_")),
    ("ssl/dtls", ("dtls",)),
    ("ssl/quic", ("quic",)),
    ("apps/c_rehash", ("c_rehash",)),
)

# The subsystems whose candidate behaviour a recorded safety divergence governs. A record whose
# subsystem appears here is `safe_divergence` and cites the divergence id(s); the register itself
# is not restated. The ids are checked against `forensics/divergence-obligations.json` by the
# court, so a citation that names a row the register does not carry is a finding.
DIVERGENCE_SUBSYSTEMS: dict[str, tuple[str, ...]] = {
    "crypto/bn/gf2m": ("D-GF2M-1", "D-GF2M-2"),
    "crypto/ec": ("D-EC-1", "D-EC-2"),
}

# The disposition vocabulary. `preserve_vulnerable_behaviour` is the forbidden value: it is a
# member so the vocabulary is closed, but the derivation never emits it and the validator refuses
# it by name.
DISPOSITIONS: tuple[str, ...] = mts.SECURITY_DISPOSITIONS
FORBIDDEN_DISPOSITION = "preserve_vulnerable_behaviour"

# The FIPS impacts, and the phrases upstream uses to state them.
FIPS_IMPACTS: tuple[str, ...] = mts.SECURITY_FIPS_IMPACTS

NON_CLAIMS: list[str] = [
    "this plane records historical vulnerabilities as observations; a passing "
    "`RT-SECURITY-LINEAGE` is an instrument and never a statement that the lineage is secure",
    "a historical vulnerability is observed and never reintroduced: `reintroduced` is the literal "
    "false and a `preserve_vulnerable_behaviour` disposition is refused "
    "(docs/SECURITY_DIVERGENCE_POLICY.md sections 1 and 3)",
    "the candidate disposition is derived from the candidate's reference authority and the "
    "recorded safety divergences; the divergence register (forensics/divergence-obligations.json) "
    "is referenced, never restated",
    "an extended-support identifier whose source is not publicly available is an external release "
    "reference and is never admitted as an authority",
    "OpenSSL compatibility is not FIPS validation (docs/FIPS_CLAIMS.md), and a stated FIPS impact "
    "is upstream's own statement, not a validation claim by this crate",
    "the observed selection is a coverage boundary, not the whole source: the vulnerabilities the "
    "source records and this plane does not bind are named as findings",
]

DIVERGENCE_EVIDENCE_KIND = "divergence_register"

_JSON_CACHE: dict[str, dict] = {}
_RANGE = re.compile(r"^from\s+(\S+)\s+before\s+(\S+)$")


def load(path: Path) -> dict:
    """Read a committed artefact, cached and fail-closed when it is absent."""
    key = rel(path)
    if key not in _JSON_CACHE:
        if not path.is_file():
            raise SystemExit(f"security-lineage: {key} is absent; run its generator first")
        _JSON_CACHE[key] = json.loads(path.read_text(encoding="utf-8"))
    return _JSON_CACHE[key]


def load_body(path: Path) -> dict:
    doc = load(path)
    return doc.get("body", doc)


def branch_of(version: str) -> str:
    """The maintained branch a version belongs to.

    Pre-3.0 the series is `MAJOR.MINOR.FIX` (`1.0.2`, `1.1.1`); 3.0-plus it is `MAJOR.MINOR`
    (`3.0`, `3.6`). This is the same series `authority_catalog._series_of` uses for a mainline
    node, so a branch fix and a catalogue node agree rather than being two drifting predicates.
    """
    v = mts.parse_version(version)
    if v.scheme == mts.SCHEME_PRE_3_0:
        return f"{v.major}.{v.minor}.{v.release}"
    return f"{v.major}.{v.minor}"


def parse_range(text: str) -> tuple[str, str] | None:
    """`from <series> before <fixed>` -> `(series, fixed)`, or None when the shape is different."""
    m = _RANGE.match((text or "").strip())
    if m is None:
        return None
    return m.group(1), m.group(2)


def catalog_index(catalog: dict) -> tuple[dict[str, dict], dict[str, dict]]:
    by_version: dict[str, dict] = {}
    by_id: dict[str, dict] = {}
    for node in catalog["nodes"]:
        by_version[node["display_version"]] = node
        by_id[node["release_id"]] = node
    return by_version, by_id


def reference_authority(catalog: dict) -> dict:
    """The candidate's reference release, read from the committed default-authority alias.

    The default is the committed alias, never the catalogue's `latest-stable` and never a version
    sort (`forensics/multitrack/default-authority.json`), so the reference the security lineage
    reasons about is the same reference the archaeology defaults to.
    """
    alias = load(DEFAULT_AUTHORITY)
    release_id = alias["maintained_candidate"]
    by_version, by_id = catalog_index(catalog)
    node = by_id.get(release_id)
    if node is None:
        raise SystemExit(
            f"security-lineage: the default authority names {release_id!r}, which is not a "
            f"catalogue release node"
        )
    return {
        "authority_id": alias["authority_id"],
        "release_id": release_id,
        "display_version": node["display_version"],
        "branch": branch_of(node["display_version"]),
        "source": rel(DEFAULT_AUTHORITY),
    }


def classify_subsystem(title: str, body: str) -> dict:
    """Classify the affected subsystem from the advisory's own words, never a typed label."""
    for haystack, label in (((title or "").lower(), "title"), ((body or "").lower(), "text")):
        for token, keywords in SUBSYSTEM_KEYWORDS:
            for keyword in keywords:
                if keyword in haystack:
                    idx = haystack.index(keyword)
                    return {
                        "token": token,
                        "basis": f"advisory keyword {keyword!r} in the {label}",
                        "source_quote": _quote(haystack, idx, keyword),
                    }
    return {
        "token": "unresolved",
        "basis": "no subsystem keyword matched the advisory title or text",
        "source_quote": (title or "")[:160],
    }


def _quote(haystack: str, idx: int, keyword: str) -> str:
    start = max(0, idx - 40)
    end = min(len(haystack), idx + len(keyword) + 40)
    return ("..." if start > 0 else "") + haystack[start:end].strip() + (
        "..." if end < len(haystack) else "")


def fips_impact(record: dict) -> dict:
    """Upstream's FIPS-impact statement, or `not_stated` where the advisory carries none."""
    raw = record.get("fips_impact")
    if not raw:
        return {"stated": False, "impact": "not_stated", "source_quote": ""}
    low = raw.lower()
    if "fips impact: yes" in low:
        impact = "yes"
    elif ("fips impact: no" in low or "not affected" in low
          or "not part of the fips module" in low):
        impact = "no"
    else:
        impact = "unknown"
    return {"stated": True, "impact": impact, "source_quote": raw}


def is_reference_affected(reference: dict, ranges: list[tuple[str, str]]) -> tuple[bool, str]:
    """Whether the candidate's reference release lies inside one of the affected ranges.

    The range is branch-scoped: `from 3.6.0 before 3.6.5` covers only the 3.6 series, so the
    reference (3.6.4) is inside it, while `from 3.0.0 before 3.0.2` is a different branch and does
    not reach it. Comparing by `parse_version.order_key` keeps the reading a chronology and never
    a compatibility claim.
    """
    for series, fixed in ranges:
        if branch_of(series) != reference["branch"] or branch_of(fixed) != reference["branch"]:
            continue
        lo = mts.parse_version(series).order_key()
        hi = mts.parse_version(fixed).order_key()
        ref = mts.parse_version(reference["display_version"]).order_key()
        if lo <= ref < hi:
            return True, f"from {series} before {fixed}"
    return False, ""


def disposition_of(subsystem: dict, reference: dict,
                   ranges: list[tuple[str, str]], divergence_ids: set[str]) -> dict:
    """The candidate disposition, derived from the reference authority and the divergence register."""
    affected, where = is_reference_affected(reference, ranges)
    if affected:
        return {
            "disposition": "unresolved",
            "basis": "reference_inside_affected_range",
            "reason": (
                f"the candidate's reference authority {reference['authority_id']} "
                f"({reference['display_version']}) lies inside {where}; the fix postdates the "
                f"reference, so the candidate cannot claim the vulnerability is contained and the "
                f"observation stays open"
            ),
            "divergence_references": [],
        }
    cited = DIVERGENCE_SUBSYSTEMS.get(subsystem["token"])
    if cited:
        present = [d for d in cited if d in divergence_ids]
        if present:
            return {
                "disposition": "safe_divergence",
                "basis": "recorded_safety_divergence",
                "reason": (
                    f"the affected subsystem {subsystem['token']!r} has recorded safety "
                    f"divergences {present}; the candidate's divergence is governed by "
                    f"docs/SECURITY_DIVERGENCE_POLICY.md sections 1 and 3 and is not restated here"
                ),
                "divergence_references": present,
            }
    return {
        "disposition": "never_contained",
        "basis": "reference_carries_fix",
        "reason": (
            f"the candidate's reference authority {reference['authority_id']} is outside every "
            f"affected range, so the vulnerable behaviour is not the behaviour the candidate "
            f"implements and the candidate never contained the defect"
        ),
        "divergence_references": [],
    }


def evidence_entry(kind: str, path: Path | None = None, url: str | None = None,
                   sha256: str | None = None, what: str = "") -> dict:
    entry: dict = {"kind": kind, "what": what}
    if path is not None:
        entry["path"] = rel(path)
        entry["sha256"] = sha256 if sha256 is not None else sha256_file(path)
    if url is not None:
        entry["url"] = url
        if sha256 is not None:
            entry["sha256"] = sha256
    return entry


def build_observations(source: dict, catalog: dict, divergence: dict, reference: dict,
                       ) -> tuple[list[dict], list[dict], list[dict]]:
    """The branch-fix observations, the vulnerability identities and the backport edges."""
    by_version, by_id = catalog_index(catalog)
    divergence_ids = {row["id"] for row in divergence.get("rows", [])}
    source_sha = sha256_file(SOURCE)
    catalog_sha = sha256_file(CATALOG)
    divergence_sha = sha256_file(DIVERGENCE)
    negative_sha = sha256_file(NEGATIVE_OBLIGATIONS)
    policy_sha = sha256_file(POLICY)

    observations: list[dict] = []
    vulnerabilities: list[dict] = []
    edges: list[dict] = []
    for record in source["observed"]:
        ref = record["reference"]
        advisory_url = record["advisory_url"]
        advisory_sha = record["advisory_sha256"]
        title = record.get("title") or ""
        ranges = [parse_range(a) for a in record["affected"]]
        ranges = [r for r in ranges if r is not None]
        if not ranges:
            raise SystemExit(
                f"security-lineage: {ref} carries no decodable `from ... before ...` affected "
                f"range; the record cannot be bound and must not be fabricated"
            )
        subsystem = classify_subsystem(title, record.get("advisory_text") or "")
        fips = fips_impact(record)
        disposition = disposition_of(subsystem, reference, ranges, divergence_ids)
        disposition_record = {
            "disposition": disposition["disposition"],
            "basis": disposition["basis"],
            "reason": disposition["reason"],
            "divergence_references": disposition["divergence_references"],
        }

        fix_ids: list[str] = []
        external_versions: list[str] = []
        catalogued_versions: list[str] = []
        for series, fixed in ranges:
            branch = branch_of(fixed)
            if branch_of(series) != branch:
                raise SystemExit(
                    f"security-lineage: {ref} range `from {series} before {fixed}` spans branches "
                    f"{branch_of(series)} and {branch}; the source record is not self-consistent"
                )
            node = by_version.get(fixed)
            external = node is None
            release_id = node["release_id"] if node else f"openssl-{fixed}"
            observation_id = f"SO-{ref}-{release_id}"
            evidence = [
                evidence_entry("upstream_advisory", url=advisory_url, sha256=advisory_sha,
                               what=f"the official OpenSSL advisory for {ref}"),
                evidence_entry("security_source", path=SOURCE, sha256=source_sha,
                               what="the frozen official vulnerability index and advisories"),
                evidence_entry("release_catalog", path=CATALOG, sha256=catalog_sha,
                               what="the release catalogue the fixed identifier resolves in"),
            ]
            if disposition["disposition"] == "safe_divergence":
                evidence.append(evidence_entry(
                    DIVERGENCE_EVIDENCE_KIND, path=DIVERGENCE, sha256=divergence_sha,
                    what="the recorded safety divergence the candidate cites, not restates"))
            elif disposition["disposition"] == "unresolved":
                evidence.append(evidence_entry(
                    "negative_obligation", path=NEGATIVE_OBLIGATIONS, sha256=negative_sha,
                    what="the candidate surface that must not be read as carrying the fix"))
            elif disposition["disposition"] == "never_contained":
                evidence.append(evidence_entry(
                    "policy", path=POLICY, sha256=policy_sha,
                    what="the fixed behaviour wins and the vulnerable behaviour is not reproduced"))
            if node is not None:
                evidence.append(evidence_entry(
                    "release_node", path=CATALOG, sha256=catalog_sha,
                    what=f"catalogue identity of {release_id}"))
            else:
                evidence.append(evidence_entry(
                    "upstream_advisory", url=advisory_url, sha256=advisory_sha,
                    what=f"{fixed} is named upstream but is not a catalogued release; its source "
                         f"is not publicly available"))

            availability_basis = (
                f"{fixed} is a catalogued release "
                f"({node['public_or_extended']}, {node['declared_compatibility_family']})"
                if node is not None else
                f"{fixed} is named by the advisory but is not a catalogue release node, so its "
                f"published source artefact is not available and it is an external release "
                f"reference, never an authority"
            )
            observation = {
                "observation_id": observation_id,
                "vulnerability_id": ref,
                "release_id": release_id,
                "release_node": node["release_id"] if node else None,
                "affected": f"from {series} before {fixed}",
                "fixed_in": fixed,
                "reference": ref,
                "branch": branch,
                "severity": normalize_severity(record.get("severity")),
                "subsystem": subsystem,
                "fips_impact": fips,
                "candidate_disposition": disposition["disposition"],
                "candidate_disposition_basis": disposition_record,
                "external_release_reference": external,
                "source_available": not external,
                "availability_basis": availability_basis,
                "authority_id": None,
                "commit_url": (record.get("commit_urls") or {}).get(fixed),
                "published_at": record.get("published_at"),
                "evidence": evidence,
                "reintroduced": False,
            }
            problems = mts.validate_security_observation(observation)
            if problems:
                raise SystemExit(
                    f"security-lineage: derived an invalid security observation "
                    f"{observation_id}: {problems}")
            observations.append(observation)
            fix_ids.append(observation_id)
            if external:
                external_versions.append(fixed)
            else:
                catalogued_versions.append(fixed)

        vulnerabilities.append({
            "vulnerability_id": ref,
            "severity": normalize_severity(record.get("severity")),
            "published_at": record.get("published_at"),
            "title": title,
            "found_by": record.get("found_by"),
            "cwe": record.get("cwe"),
            "affected_ranges": [f"from {s} before {f}" for s, f in ranges],
            "branches": sorted({branch_of(f) for _s, f in ranges}),
            "subsystem": subsystem,
            "fips_impact": fips,
            "candidate_disposition": disposition["disposition"],
            "candidate_disposition_basis": disposition_record,
            "reference_authority": reference,
            "branch_fixes": fix_ids,
            "catalogued_fixes": catalogued_versions,
            "external_release_references": external_versions,
            "reintroduced": False,
            "evidence": [
                evidence_entry("upstream_advisory", url=advisory_url, sha256=advisory_sha,
                               what=f"the official OpenSSL advisory for {ref}"),
                evidence_entry("security_source", path=SOURCE, sha256=source_sha,
                               what="the frozen official vulnerability index"),
            ],
        })
        edges.extend(security_backport_edges(catalog["nodes"], [record]))

    return observations, vulnerabilities, edges


def normalize_severity(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    return value if value in mts.SECURITY_SEVERITIES else "unknown"


def security_backport_edges(nodes: list[dict], observed: list[dict] | None = None) -> list[dict]:
    """The `security_backport` lineage edges a vulnerability's catalogued fixes establish.

    A single CVE fixed independently across several maintained branches is one vulnerability with
    several fixes; where two or more of those fixes are **catalogue nodes**, the fix carried by the
    earlier release and the fix carried by the later one are joined by a typed `security_backport`
    edge reading forward in time. Fixes whose source is not publicly available are external
    references and are never edge endpoints (an edge endpoints a release node). The edge names the
    `security_reference` it backports, which the lineage schema requires and the court checks.
    """
    source = load(SOURCE)
    records = observed if observed is not None else source["observed"]
    by_version = {node["display_version"]: node for node in nodes}
    out: list[dict] = []
    for record in records:
        ref = record["reference"]
        fixed = []
        for text in record["affected"]:
            parsed = parse_range(text)
            if parsed is None:
                continue
            node = by_version.get(parsed[1])
            if node is not None:
                fixed.append(node)
        if len(fixed) < 2:
            continue
        fixed.sort(key=lambda n: (n["release_date"],
                                  mts.parse_version(n["display_version"]).order_key(),
                                  n["release_id"]))
        for parent, child in zip(fixed, fixed[1:]):
            out.append({
                "edge_id": f"L-security_backport-{parent['release_id']}-{child['release_id']}-{ref}",
                "kind": "security_backport",
                "from_id": parent["release_id"],
                "to_id": child["release_id"],
                "direction": "forward",
                "security_reference": ref,
                "evidence": [
                    f"{ref} is fixed in both {parent['release_id']} and {child['release_id']}; the "
                    f"later release carries the same correction",
                    f"advisory {record['advisory_url']} sha256={record['advisory_sha256']}",
                ],
                "metadata_provenance": [
                    rel(SOURCE),
                    record["advisory_url"],
                ],
            })
    return out


def derive_body() -> dict:
    """The whole plane, derived from the committed evidence; the court compares this with the file."""
    source = load(SOURCE)
    catalog = load_body(CATALOG)
    lineage = load_body(LINEAGE)
    nodes = catalog["nodes"]
    divergence = load_body(DIVERGENCE)
    reference = reference_authority(catalog)
    observations, vulnerabilities, edges = build_observations(
        source, catalog, divergence, reference)

    observed = sorted(v["vulnerability_id"] for v in vulnerabilities)
    all_references = source["source"]["all_references"]
    unobserved = sorted(set(all_references) - set(observed))

    by_severity = Counter(v["severity"] for v in vulnerabilities)
    by_branch = Counter(o["branch"] for o in observations)
    by_disposition = Counter(v["candidate_disposition"] for v in vulnerabilities)
    fips = Counter(v["fips_impact"]["impact"] for v in vulnerabilities)
    tokens = Counter(v["subsystem"]["token"] for v in vulnerabilities)

    # Every observed vulnerability must be fixed in at least one catalogued release or external
    # reference, and every backport edge must resolve to the lineage the plane claims.
    edge_ids = sorted(e["edge_id"] for e in edges)
    lineage_edge_ids = {e["edge_id"] for e in lineage.get("edges", [])}

    coverage = {
        "source": source["source"]["index_url"],
        "source_sha256": source["source"]["index_sha256"],
        "source_records": source["source"]["all_reference_count"],
        "observed": len(observed),
        "unobserved": len(unobserved),
        "unobserved_references": unobserved,
        "note": (
            "the plane binds a documented selection of the source's CVE records; the rest are "
            "named here and surface as the court's property findings, never fabricated"
        ),
    }
    body = {
        "rule": (
            "a historical vulnerability is an observation and is never reintroduced: every "
            "observation's `reintroduced` is false, a `preserve_vulnerable_behaviour` disposition "
            "is refused by name, and the candidate disposition is derived from the reference "
            "authority and the recorded safety divergences rather than typed "
            "(docs/SECURITY_DIVERGENCE_POLICY.md sections 1 and 3)"
        ),
        "reference_authority": reference,
        "dispositions": list(DISPOSITIONS),
        "fips_impacts": list(FIPS_IMPACTS),
        "subsystem_tokens": sorted({t for t, _k in SUBSYSTEM_KEYWORDS} | {"unresolved"}),
        "coverage": coverage,
        "counts": {
            "vulnerabilities": len(vulnerabilities),
            "branch_fixes": len(observations),
            "catalogued_fixes": sum(1 for o in observations
                                    if not o["external_release_reference"]),
            "external_release_references": sum(1 for o in observations
                                               if o["external_release_reference"]),
            "backport_edges": len(edges),
            "by_severity": {k: by_severity[k] for k in sorted(by_severity)},
            "by_branch": {k: by_branch[k] for k in sorted(by_branch)},
            "by_disposition": {k: by_disposition[k] for k in sorted(by_disposition)},
            "by_fips_impact": {k: fips[k] for k in sorted(fips)},
            "by_subsystem": {k: tokens[k] for k in sorted(tokens)},
        },
        "vulnerabilities": vulnerabilities,
        "observations": observations,
        "backport_edges": edge_ids,
        "lineage_edges_present": sorted(edge_ids) == sorted(
            e for e in edge_ids if e in lineage_edge_ids) if lineage_edge_ids else False,
        "boundary": (
            "the plane observes the source's CVE records it binds and records the rest as "
            "unobserved; a fixed identifier that is not a catalogue release is an external "
            "release reference and is never admitted as an authority; the candidate disposition "
            "references docs/SECURITY_DIVERGENCE_POLICY.md and forensics/divergence-obligations.json "
            "rather than duplicating the register"
        ),
        "non_claims": NON_CLAIMS,
    }
    body["content_hash"] = content_hash({k: body.get(k) for k in HASH_KEYS})
    return body


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args(argv)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    body = derive_body()
    inputs = [
        InputRef(name="security-source", path=SOURCE),
        InputRef(name="release-catalog", path=CATALOG),
        InputRef(name="authority-lineage", path=LINEAGE),
        InputRef(name="default-authority", path=DEFAULT_AUTHORITY),
        InputRef(name="authority-nodes", path=AUTHORITY_NODES),
        InputRef(name="authorities", path=AUTHORITIES),
        InputRef(name="divergence-obligations", path=DIVERGENCE),
        InputRef(name="security-divergence-policy", path=POLICY),
        InputRef(name="negative-obligations", path=NEGATIVE_OBLIGATIONS),
    ]
    doc = envelope(kind="security-lineage", authority=auth.id, inputs=inputs, body=body,
                   generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[security-lineage] {c['vulnerabilities']} vulnerability/ies, {c['branch_fixes']} "
          f"branch fix(es) ({c['catalogued_fixes']} catalogued, "
          f"{c['external_release_references']} external), {c['backport_edges']} backport edge(s)")
    print(f"  reference={body['reference_authority']['authority_id']} "
          f"dispositions={c['by_disposition']} branches={c['by_branch']}")
    print(f"  observed {body['coverage']['observed']}/{body['coverage']['source_records']} "
          f"source record(s)")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
