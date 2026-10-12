#!/usr/bin/env python3
"""openssl-rs — the historical CVE census (Phase 25.15).

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). 25.1 enumerates the compiler-derived unsafe
operations, 25.2 records the non-Rust trusted computing base, 25.3 gives every site an obligation,
25.4 models the ownership/allocation/callback machinery, 25.5 maps every site to the Phase-22
reachability roots, 25.6 maps every site to the Phase-24 downstream population, 25.7 classifies
every site's exposure, 25.8 records the reduction worklist and the safe-core reconstruction, and
25.9-25.14 record the dynamic/formal evidence and the two crosswalks. This subphase is 25.15: it
**classifies the historical memory-safety-relevant OpenSSL CVEs from the closed CVE taxonomy**,
each with its affected versions and its fix, so a historical vulnerability is a classified
observation rather than a remembered one.

The rule, and the authority it reads
------------------------------------
    a committed OpenSSL advisory (the frozen official index's observed records) -> its CVE record
       in the committed security lineage (the affected ranges, the fix releases and the subsystem)
       -> the closed CVE taxonomy class the committed advisory section's mechanism names -> the
       candidate's corresponding source region (25.1's census) and whether it exists and is covered
       -> the classified census row

Each step is a fact a committed plane measured, and none of it is typed here:

  * the **advisory** is the frozen official vulnerability index and the advisories it carries
    (`forensics/multitrack/security-source.json`): its `all_references` is the index's own CVE set,
    its `observed` records carry the advisory text, the affected ranges, the fix releases and the
    commit URLs -- so the mechanism a row is classified from is the committed advisory's, not a
    remembered one;
  * the **CVE record** is the committed security lineage's own
    (`forensics/multitrack/security-lineage.json`): its `vulnerabilities` are the records it binds
    (the affected ranges, the branches, the catalogue fixes, the subsystem token and the candidate
    disposition), and its `coverage` names the index references it does *not* bind;
  * the **candidate region** is 25.1's compiler-backed census (`artifacts/phase25/source-census.json`):
    a subsystem token resolves to the candidate's own source paths, and the region's compiler-derived
    unsafe-operation count decides whether it is covered;
  * the **non-Rust TCB** is 25.2's own (`artifacts/phase25/non-rust-tcb.json`): a resolved region that
    lands on a first-party C source, a generated-C scaffold or an assembly site is a non-Rust TCB
    region, so the historical C defects are not read as if the candidate were Rust-only.

No CVE is invented, and an unresolved reference is a residual
------------------------------------------------------------
The census classifies only what the committed evidence supports and records the rest rather than
guessing:

  * a row is derived from a committed lineage vulnerability and carries that advisory's committed
    evidence; a row whose CVE id the committed index does not name, or whose classification the
    lineage does not bind, is a finding, never a fabricated row;
  * the frozen index names 297 references and the committed lineage binds only a documented subset;
    every *unbound* reference gets an explicit `evidence_missing` residual (or `join_evidence_missing`
    where a committed advisory text names it but the classification plane does not bind it), so a
    reference is recorded rather than silently dropped from the census;
  * a subsystem token the candidate carries no source region for is an explicit
    `join_evidence_missing` residual, so the candidate's correspondence is unjoined rather than
    assumed.

A pure derivation, so it executes nothing
-----------------------------------------
It reads committed planes and writes a derived plane; it runs no compiler, no tool and no probe, so
`forensics/memory-safety/container.json` lists it `metadata_only` and the Docker-only guard admits it
on any host (it still calls the guard first, so the rule is never optional).

Outputs
-------
  artifacts/phase25/historical-cves.json

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
)

# The Docker-only execution guard, called first. This tool executes nothing -- it derives a plane
# from committed planes -- so the manifest lists it `metadata_only` and the guard admits it on any
# host exactly as `ms_phase24_safety_coverage.py` is.
import phase25_guard  # noqa: E402

# The historical-CVE and residual schemas and their closed vocabularies. Imported, never restated.
import memory_safety_schemas as schemas  # noqa: E402

# The census (for the candidate region paths and their unsafe-operation counts) and the lossless
# columnar codec (for the 25.2 non-Rust TCB, which references census rows).
import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "historical-cves.json"
GENERATOR = "forensics/tools/ms_historical_cve.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_historical_cve.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# The frozen official vulnerability index and the advisories it carries, and the committed security
# lineage that binds the CVE records. This is the authority the census is classified from.
SECURITY_SOURCE = REPO_ROOT / "forensics" / "multitrack" / "security-source.json"
SECURITY_LINEAGE = REPO_ROOT / "forensics" / "multitrack" / "security-lineage.json"
# 25.1's compiler-backed census (the candidate region paths) and 25.2's non-Rust TCB (the layer a
# resolved region belongs to).
SOURCE_CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
NON_RUST_TCB = REPO_ROOT / "artifacts" / "phase25" / "non-rust-tcb.json"

SECURITY_SOURCE_REL = rel(SECURITY_SOURCE)
SECURITY_LINEAGE_REL = rel(SECURITY_LINEAGE)
SOURCE_CENSUS_REL = rel(SOURCE_CENSUS)
NON_RUST_TCB_REL = rel(NON_RUST_TCB)

# The taxonomy classes that are **not** memory-safety-relevant: a correctness, availability,
# cryptographic-side-channel or out-of-taxonomy issue. The memory-safety set is derived as the
# complement of the closed vocabulary, never restated.
NON_MEMORY_SAFETY_CLASSES = frozenset(
    {"SIDE_CHANNEL", "PROTOCOL_LOGIC", "ALGORITHM_COMPLEXITY", "OTHER"}
)
MEMORY_SAFETY_CLASSES = frozenset(schemas.CVE_TAXONOMY) - NON_MEMORY_SAFETY_CLASSES

# The classifier: an ordered keyword->class list applied to the committed advisory section (the
# CVE's own section of the frozen advisory, normalised to a single line). The first match wins, so
# the order encodes specificity: a specific mechanism (`double free`, `stack buffer overflow`) is
# tried before the generic one (`buffer overflow`). A CWE, where the committed advisory states one,
# is authoritative over the text. The class is a member of the schema's closed taxonomy.
CLASSIFICATION_RULES: tuple[tuple[str, str], ...] = (
    ("double free", "DOUBLE_FREE"),
    ("double-free", "DOUBLE_FREE"),
    ("use-after-free", "USE_AFTER_FREE"),
    ("use after free", "USE_AFTER_FREE"),
    ("type confusion", "TYPE_CONFUSION"),
    ("uninitialised", "UNINITIALIZED_READ"),
    ("uninitialized", "UNINITIALIZED_READ"),
    ("stack-based buffer overflow", "STACK_OOB_WRITE"),
    ("stack buffer overflow", "STACK_OOB_WRITE"),
    ("heap-based buffer overflow", "HEAP_OOB_WRITE"),
    ("heap buffer overflow", "HEAP_OOB_WRITE"),
    ("heap buffer over-read", "HEAP_OOB_READ"),
    ("heap buffer overread", "HEAP_OOB_READ"),
    ("over-read", "HEAP_OOB_READ"),
    ("overread", "HEAP_OOB_READ"),
    ("out-of-bounds read", "HEAP_OOB_READ"),
    ("out of bounds read", "HEAP_OOB_READ"),
    ("out-of-bounds write", "HEAP_OOB_WRITE"),
    ("out of bounds write", "HEAP_OOB_WRITE"),
    ("null pointer dereference", "NULL_DEREFERENCE"),
    ("null dereference", "NULL_DEREFERENCE"),
    ("null-pointer", "NULL_DEREFERENCE"),
    ("integer overflow", "INTEGER_OVERFLOW"),
    ("integer underflow", "INTEGER_UNDERFLOW"),
    ("out-of-bounds memory", "BUFFER_OVERFLOW"),
    ("out of bound", "BUFFER_OVERFLOW"),
    ("out-of-bound", "BUFFER_OVERFLOW"),
    ("buffer overflow", "BUFFER_OVERFLOW"),
    ("side-channel", "SIDE_CHANNEL"),
    ("side channel", "SIDE_CHANNEL"),
    ("infinite loop", "ALGORITHM_COMPLEXITY"),
    ("injection", "OTHER"),
)

# A CVE title line in an advisory: `... (CVE-YYYY-NNNN)`. The section for a CVE runs from its title
# line to the next title line.
_ADVISORY_HEADER = re.compile(r"^(?P<title>.+?)\s*\((?P<cve>CVE-\d{4}-\d{4,})\)\s*$")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
# A fix commit SHA in a committed commit URL: either the gitweb `;h=<sha>` form or the github
# `/commit/<sha>` form.
_COMMIT_SHA = re.compile(r"(?:[;?&]h=|/commit/)([0-9a-f]{6,})")

# The residual classes this plane records. Both are members of the schema's residual vocabulary.
# `evidence_missing` is a reference the frozen index names but no committed classification binds;
# `join_evidence_missing` is a partial join (a reference a committed advisory names but the lineage
# does not bind, or a subsystem token that resolves to no candidate source region).
EVIDENCE_MISSING = "evidence_missing"
JOIN_EVIDENCE_MISSING = "join_evidence_missing"

NON_CLAIMS = (
    "a classification is a reading of the committed advisory, not a re-derivation of the upstream "
    "defect: the taxonomy class is the closed vocabulary's, the affected ranges and the fixes are "
    "the committed lineage's and the advisory's, and the mechanism is the advisory's own issue "
    "summary, so the census names what the committed evidence says rather than what the code does",
    "a candidate region match is a name-and-path join, not a semantic proof: a resolved region says "
    "the candidate carries source under the subsystem token's name, and its compiler-derived unsafe-"
    "operation count says the region is audited -- it is not a claim that the historical defect's "
    "mechanism is present or absent, which is 25.16's replay and 25.17's reconciliation",
    "a memory-safety-relevant class is not a claim about the candidate: the census classifies the "
    "historical upstream defect from the committed advisory, and `memory_safety` records whether the "
    "mechanism is a memory-safety one, never whether the candidate is affected",
    "the census is a documented selection of the frozen index: the committed lineage binds only the "
    "records it can evidence, and every unbound reference is a recorded residual rather than a "
    "silent omission or a fabricated row, so the census is not 'all OpenSSL CVEs'",
    "historical CVE extinction does not predict a future CVE count: classifying the past is not a "
    "forecast of the future, and a class absent from the census is not a class the candidate is "
    "immune to",
)


# --------------------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-historical-cve] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def load_authority() -> dict:
    """The committed planes this plane reads, loaded once so the generator and the court share bytes.

    The security source and the security lineage are the committed classification authority; the
    25.1 census and the 25.2 non-Rust TCB are this stratum's columnar artefacts, so their bodies are
    decoded here (the TCB references census rows by index).
    """
    census_doc = _load(SOURCE_CENSUS)
    census_body = ms_census.decode_body(census_doc.get("body", census_doc))
    refs = ms_codec.refs_from_census(census_body)
    tcb_doc = _load(NON_RUST_TCB)
    tcb_body = ms_codec.decode_body(tcb_doc.get("body", tcb_doc), refs)
    return {
        "security_source": _load(SECURITY_SOURCE),
        "security_lineage": _load(SECURITY_LINEAGE),
        "source_census": {**census_doc, "body": census_body},
        "non_rust_tcb": {**tcb_doc, "body": tcb_body},
    }


def _census_files(census_body: dict) -> dict:
    """`path -> compiler-derived unsafe-operation count` from the committed census."""
    out: dict = {}
    for f in census_body.get("files") or []:
        out[str(f.get("path"))] = int(f.get("unsafe_operations") or 0)
    return out


def _non_rust_paths(tcb_body: dict) -> set:
    """The first-party non-Rust source paths 25.2 inventories (C adapters, generated C, asm)."""
    out: set = set()
    for key in ("c_adapters", "generated_c", "assembly"):
        for row in tcb_body.get(key) or []:
            path = row.get("path")
            if path:
                out.add(str(path))
    return out


def _version_key(release: str) -> tuple:
    """A sortable key for an OpenSSL-style release tag, so the newest fix is deterministic."""
    s = str(release or "")
    m = re.match(r"(\d+)\.(\d+)\.(\d+)(.*)", s)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4) or "")
    m = re.match(r"(\d+)\.(\d+)(.*)", s)
    if m:
        return (int(m.group(1)), int(m.group(2)), 0, m.group(3) or "")
    return (0, 0, 0, s)


def _advisory_section(advisory_text: str, cve_id: str) -> str:
    """The CVE's own section of a committed advisory: its title line to the next title line."""
    lines = str(advisory_text or "").splitlines()
    headers = [i for i, line in enumerate(lines) if _ADVISORY_HEADER.match(line.strip())]
    for j, i in enumerate(headers):
        m = _ADVISORY_HEADER.match(lines[i].strip())
        if m and m.group("cve") == cve_id:
            end = headers[j + 1] if j + 1 < len(headers) else len(lines)
            return "\n".join(lines[i:end])
    return ""


def _classify(section: str, cwe) -> tuple[str, str]:
    """The closed CVE taxonomy class for a committed advisory section, with its basis.

    A committed CWE is authoritative over the text; otherwise the ordered keyword list is applied to
    the normalised section. The basis names what grounded the class, so a class is traceable rather
    than asserted.
    """
    if cwe:
        cwe_s = str(cwe)
        if "787" in cwe_s:
            return "HEAP_OOB_WRITE", f"committed CWE {cwe_s!r} (out-of-bounds write)"
        if "125" in cwe_s:
            return "HEAP_OOB_READ", f"committed CWE {cwe_s!r} (out-of-bounds read)"
    flat = " ".join(str(section or "").lower().split())
    for phrase, cls in CLASSIFICATION_RULES:
        if phrase in flat:
            return cls, f"committed advisory section matched {phrase!r}"
    return "OTHER", "no committed mechanism keyword; the taxonomy's recorded last resort"


def _mechanism(section: str, title: str) -> str:
    """The memory-safety mechanism: the committed advisory section's issue summary, or its title."""
    flat = " ".join(str(section or "").split())
    m = re.search(r"Issue summary:\s*(.+?)(?:\s*Impact summary:|$)", flat)
    if m and m.group(1).strip():
        return m.group(1).strip()
    return str(title or "").strip()


def resolve_region(token: str, census_files: dict) -> tuple:
    """`(region path, files)` for a subsystem token, or `(None, [])` when it resolves to no region.

    A token's trailing one or two path components name the candidate region: `crypto/bn` is the
    `src/bn/` module, `crypto/bn/gf2m` is the `src/bn/gf2m.rs` file. A token the candidate carries no
    such region for does not resolve, and the caller records the unjoined region rather than
    guessing one.
    """
    comps = [c for c in re.split(r"/", str(token or "")) if c]
    for depth in range(min(2, len(comps)), 0, -1):
        tail = comps[-depth:]
        directory = "src/" + "/".join(tail) + "/"
        files = sorted(p for p in census_files if p.startswith(directory))
        if files:
            return directory, files
        single = "src/" + "/".join(tail) + ".rs"
        if single in census_files:
            return single, [single]
    return None, []


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


def derive(authority: dict) -> dict:
    """The whole census, derived: the classified CVE rows, the counts and the residuals."""
    source = authority["security_source"]
    lineage = _body(authority["security_lineage"])
    census_files = _census_files(_body(authority["source_census"]))
    non_rust = _non_rust_paths(_body(authority["non_rust_tcb"]))

    index_refs = [str(r) for r in ((source.get("source") or {}).get("all_references") or [])]
    index_set = set(index_refs)
    observed = {str(o.get("reference")): o for o in (source.get("observed") or [])}
    coverage = lineage.get("coverage") or {}
    unobserved = sorted(str(r) for r in (coverage.get("unobserved_references") or []))
    vulns = sorted(lineage.get("vulnerabilities") or [],
                   key=lambda v: str(v.get("vulnerability_id")))

    # Which unbound references a committed advisory text names (so its residual is a partial join
    # rather than a bare missing evidence), derived by scanning the committed advisory texts.
    advisory_named: dict = {}
    for o in source.get("observed") or []:
        url = str(o.get("advisory_url") or "")
        for cve in sorted(set(_CVE_RE.findall(str(o.get("advisory_text") or "")))):
            if cve not in observed:
                advisory_named.setdefault(cve, url)

    cves: list = []
    residuals: list = []
    for v in vulns:
        cve = str(v.get("vulnerability_id"))
        o = observed.get(cve) or {}
        section = _advisory_section(str(o.get("advisory_text") or ""), cve)
        cwe = v.get("cwe") or o.get("cwe")
        taxonomy, basis = _classify(section, cwe)

        affected = [str(x) for x in (v.get("affected_ranges") or [])]
        fixes: list = []
        for release, url in (o.get("commit_urls") or {}).items():
            m = _COMMIT_SHA.search(str(url))
            fixes.append({"release": str(release), "sha": (m.group(1) if m else None),
                          "url": str(url)})
        fixes.sort(key=lambda r: _version_key(r["release"]))
        fix_commit = ""
        for r in reversed(fixes):
            if r["sha"]:
                fix_commit = r["sha"]
                break

        token = str((v.get("subsystem") or {}).get("token") or "")
        region_path, region_files = resolve_region(token, census_files)
        region_sites = sum(census_files.get(p, 0) for p in region_files)
        if region_files:
            layer = "non_rust_tcb" if any(p in non_rust for p in region_files) else "rust"
        else:
            layer = None
        region = {
            "token": token,
            "resolved": bool(region_files),
            "path": region_path,
            "files": region_files,
            "unsafe_operations": region_sites,
            "layer": layer,
            "covered": bool(region_files) and region_sites > 0,
        }

        advisory_url = str(o.get("advisory_url") or "")
        row = {
            "cve_id": cve,
            "taxonomy": taxonomy,
            "taxonomy_basis": basis,
            "affected_versions": affected,
            "affected_branches": [str(b) for b in (v.get("branches") or [])],
            "fix_commit": fix_commit,
            "fixes": fixes,
            "memory_safety": taxonomy in MEMORY_SAFETY_CLASSES,
            "mechanism": _mechanism(section, str(v.get("title") or "")),
            "mechanism_source": {
                "advisory_url": advisory_url,
                "advisory_sha256": str(o.get("advisory_sha256") or ""),
                "field": "advisory-section",
            },
            "severity": str(v.get("severity") or ""),
            "published_at": str(v.get("published_at") or ""),
            "found_by": str(v.get("found_by") or ""),
            "cwe": (str(cwe) if cwe else None),
            "subsystem": {
                "token": token,
                "source_quote": str((v.get("subsystem") or {}).get("source_quote") or ""),
            },
            "candidate_disposition": str(v.get("candidate_disposition") or ""),
            "candidate_region": region,
            "evidence": [SECURITY_SOURCE_REL, SECURITY_LINEAGE_REL, SOURCE_CENSUS_REL,
                         NON_RUST_TCB_REL] + ([advisory_url] if advisory_url else []),
        }
        cves.append(row)

        if not region["resolved"]:
            residuals.append({
                "residual_id": f"res-region-{cve}",
                "subject": cve,
                "class": JOIN_EVIDENCE_MISSING,
                "disposition": "open",
                "detail": (
                    f"the committed subsystem token {token!r} resolves to no committed candidate "
                    f"source region, so the candidate's correspondence is unjoined rather than "
                    f"assumed"
                ),
                "evidence": [SECURITY_LINEAGE_REL, SOURCE_CENSUS_REL],
            })

    # Every reference the frozen index names but the committed classification plane does not bind is
    # a recorded residual: `join_evidence_missing` where a committed advisory names it, else
    # `evidence_missing`.
    for ref in unobserved:
        named_by = advisory_named.get(ref)
        detail = (
            f"the frozen official index names {ref} but the committed security lineage binds no "
            f"affected range, fix or classification for it"
        )
        evidence = [SECURITY_SOURCE_REL, SECURITY_LINEAGE_REL]
        cls = EVIDENCE_MISSING
        if named_by:
            cls = JOIN_EVIDENCE_MISSING
            detail += f"; the committed advisory {named_by} names it, so the join is partial"
            evidence.append(named_by)
        residuals.append({
            "residual_id": f"res-index-{ref}",
            "subject": ref,
            "class": cls,
            "disposition": "open",
            "detail": detail,
            "evidence": evidence,
        })

    residuals.sort(key=lambda r: r["residual_id"])

    by_taxonomy = Counter(r["taxonomy"] for r in cves)
    by_severity = Counter(r["severity"] for r in cves if r["severity"])
    resolved = [r for r in cves if r["candidate_region"]["resolved"]]
    unjoined = [r for r in cves if not r["candidate_region"]["resolved"]]
    counts = {
        "advisories": len(vulns),
        "cves": len(cves),
        "memory_safety_cves": sum(1 for r in cves if r["memory_safety"]),
        "by_taxonomy": {k: by_taxonomy[k] for k in sorted(by_taxonomy)},
        "by_severity": {k: by_severity[k] for k in sorted(by_severity)},
        "index_references": len(index_refs),
        "index_observed": len(observed),
        "index_unobserved": len(unobserved),
        "unobserved_advisory_named": sum(1 for r in unobserved if r in advisory_named),
        "unobserved_identifier_only": sum(1 for r in unobserved if r not in advisory_named),
        "regions_resolved": len(resolved),
        "regions_unjoined": len(unjoined),
        "regions_covered": sum(1 for r in cves if r["candidate_region"]["covered"]),
        "memory_safety_regions_unjoined": sum(1 for r in unjoined if r["memory_safety"]),
        "non_rust_tcb_regions": sum(1 for r in cves
                                    if r["candidate_region"]["layer"] == "non_rust_tcb"),
        "fixes_with_commit": sum(1 for r in cves if r["fix_commit"]),
        "residuals": len(residuals),
    }
    return {"cves": cves, "counts": counts, "residuals": residuals, "unobserved": unobserved,
            "index_refs": index_refs, "observed": observed, "vulns": vulns}


def _rule(authority: dict) -> dict:
    source = authority["security_source"]
    lineage = _body(authority["security_lineage"])
    coverage = lineage.get("coverage") or {}
    return {
        "authority": {
            "kind": "historical-openssl-cve-evidence",
            "paths": [SECURITY_SOURCE_REL, SECURITY_LINEAGE_REL, SOURCE_CENSUS_REL, NON_RUST_TCB_REL],
            "declaration": (
                "the frozen official vulnerability index and the advisories it carries "
                "(`security-source.json`), the committed security lineage that binds the CVE "
                "records (`security-lineage.json`), 25.1's compiler-backed census and 25.2's "
                "non-Rust TCB are the authority this plane reads: the index names the CVE set and "
                "carries the advisory text, the lineage gives each bound record its affected "
                "ranges, fixes, subsystem and candidate disposition, and the census gives the "
                "candidate's own source regions; no CVE, range, fix or class is typed here"
            ),
            "reference_source": str((source.get("source") or {}).get("index_url") or ""),
            "index_sha256": str((source.get("source") or {}).get("index_sha256") or ""),
        },
        "mapping_rule": (
            "a committed advisory (the index's observed records) -> its CVE record in the committed "
            "security lineage (the affected ranges, the fixes and the subsystem) -> the closed CVE "
            "taxonomy class the committed advisory section names -> the candidate's source region "
            "(25.1's census) and whether it exists and is covered -> the classified census row"
        ),
        "classification_rule": (
            "the taxonomy class is read from the committed evidence: a committed CWE is "
            "authoritative, otherwise the advisory section's own normalised mechanism text is "
            "matched against the ordered keyword list, and a class the committed text does not name "
            "is the taxonomy's recorded `OTHER` last resort -- never a fabricated class"
        ),
        "region_rule": (
            "a subsystem token's trailing path components name the candidate region (`crypto/bn` -> "
            "`src/bn/`, `crypto/bn/gf2m` -> `src/bn/gf2m.rs`); a resolved region is covered when its "
            "compiler-derived unsafe-operation count is positive, and is a non-Rust TCB region when "
            "25.2 inventories a source path in it; a token that resolves to no region is a "
            "`join_evidence_missing` residual rather than a guessed correspondence"
        ),
        "coverage_discipline": {
            "rule": (
                "the frozen index names its references and the committed lineage binds only some of "
                "them; every unbound reference is a recorded residual -- `join_evidence_missing` "
                "where a committed advisory names it, else `evidence_missing` -- so the census is "
                "the bound set plus its named gaps, never a silent subset"
            ),
            "input": SECURITY_LINEAGE_REL,
            "index_references": len((source.get("source") or {}).get("all_references") or []),
            "bound_records": len(lineage.get("vulnerabilities") or []),
            "unobserved_references": len(coverage.get("unobserved_references") or []),
        },
        "memory_safety_classes": sorted(MEMORY_SAFETY_CLASSES),
        "non_memory_safety_classes": sorted(NON_MEMORY_SAFETY_CLASSES),
        "sort_key": "cves by cve_id; fixes by release; region files by path; residuals by residual_id",
    }


def _property_findings(d: dict) -> list:
    c = d["counts"]
    by_class = ", ".join(f"{k}={v}" for k, v in sorted(c["by_taxonomy"].items()))
    return [
        f"{c['cves']} committed OpenSSL advisory record(s) are classified from the closed CVE "
        f"taxonomy, {c['memory_safety_cves']} of them memory-safety-relevant ({by_class}); the "
        f"classification is a reading of the committed advisory, not a re-derivation of the defect",
        f"the frozen official index names {c['index_references']} reference(s); the committed "
        f"security lineage binds {c['index_observed']}, leaving {c['index_unobserved']} unbound -- "
        f"{c['unobserved_advisory_named']} named by a committed advisory "
        f"(`join_evidence_missing`) and {c['unobserved_identifier_only']} identifier-only "
        f"(`evidence_missing`) -- each a recorded residual, never a fabricated row or a silent "
        f"omission",
        f"{c['regions_resolved']} of {c['cves']} classified CVE(s) resolve to a committed candidate "
        f"region and {c['regions_covered']} are covered (their region carries compiler-derived "
        f"unsafe operations); {c['regions_unjoined']} resolve to no region "
        f"({c['memory_safety_regions_unjoined']} of them memory-safety-relevant) and are recorded "
        f"`join_evidence_missing` rather than assumed correspondent",
        f"{c['fixes_with_commit']} of {c['cves']} classified CVE(s) carry a committed fix commit "
        f"from the advisory's commit URLs; the affected ranges and the catalogue fixes are the "
        f"committed lineage's own",
        "the census is a documented selection, not the whole index: it classifies only what the "
        "committed evidence binds and records the rest, so a class present here is a classified "
        "observation and a class absent here is not an immunity claim",
    ]


def build_body(authority: dict) -> dict:
    """The census body: the rule, the classified rows, the counts, the residuals and the findings."""
    d = derive_cached(authority)
    return {
        "rule": _rule(authority),
        "cves": d["cves"],
        "counts": d["counts"],
        "residuals": d["residuals"],
        "findings": _property_findings(d),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def crosswalk_findings(body: dict, authority: dict) -> list:
    """Every way the committed census contradicts the committed security evidence or the candidate.

    Pure over `body` and the authority (the frozen index, the security lineage, the 25.1 census and
    the 25.2 non-Rust TCB): it is what the `MS-HISTORICAL-CVE` court runs. It checks that every
    committed lineage vulnerability has exactly one classified row and no row has a CVE the
    committed evidence does not classify; that every row's CVE id is a reference the frozen index
    names and carries a committed advisory; that every row equals its derivation (its class, its
    memory-safety flag, its affected ranges, its fixes, its mechanism and its candidate region); that
    the mechanism cites a committed advisory source; that every row validates; that the counts equal
    their derivation; that every unbound index reference and every unjoined candidate region has a
    residual; that every residual validates; and that the rule names the committed authorities.
    """
    problems: list = []
    d = derive_cached(authority)
    cves = body.get("cves") or []
    ids = [str(r.get("cve_id")) for r in cves]
    derived_by_id = {r["cve_id"]: r for r in d["cves"]}

    # 1. The CVE ids are unique.
    if len(set(ids)) != len(ids):
        problems.append("the census carries a duplicate cve_id, so a classification is ambiguous")

    # 2. The census is complete over the committed classification: no dropped row, no extra row.
    for cve in sorted(set(derived_by_id) - set(ids)):
        problems.append(f"the census omits the committed CVE {cve} (dropped)")
    for cve in sorted(set(ids) - set(derived_by_id)):
        problems.append(f"the census records {cve}, which the committed security evidence does not "
                        f"classify")

    # 3. Every row's CVE id is a committed index reference with a committed advisory record.
    for cve in sorted(set(ids)):
        if cve not in d["index_refs"]:
            problems.append(f"{cve} is not a reference the committed official index names")
        if cve not in d["observed"]:
            problems.append(f"{cve} carries no committed advisory record")

    # 4. Every row equals its derivation, and its mechanism cites a committed source.
    for cve in sorted(set(ids) & set(derived_by_id)):
        got = next(r for r in cves if str(r.get("cve_id")) == cve)
        want = derived_by_id[cve]
        for field in ("taxonomy", "taxonomy_basis", "memory_safety", "affected_versions",
                      "affected_branches", "fix_commit", "fixes", "mechanism", "candidate_region"):
            if got.get(field) != want[field]:
                problems.append(f"{cve}: the committed `{field}` is not the derived `{field}`")
        ms = got.get("mechanism_source") or {}
        if not ms.get("advisory_url") or not ms.get("advisory_sha256"):
            problems.append(f"{cve}: the mechanism cites no committed advisory source")
        if not got.get("evidence"):
            problems.append(f"{cve}: names no committed evidence")
        problems += [f"{cve}: schema: {p}" for p in schemas.validate("historical_cve", got)]

    # 5. Every plane equals its derivation.
    if body.get("counts") != d["counts"]:
        problems.append("the committed `counts` is not the derived `counts`")
    if (body.get("cves") or []) != d["cves"]:
        problems.append("the committed `cves` is not the derived `cves`")
    if (body.get("residuals") or []) != d["residuals"]:
        problems.append("the committed `residuals` is not the derived `residuals`")

    # 6. Every unbound index reference and every unjoined candidate region is a residual.
    residual_ids = {str(r.get("residual_id")) for r in (body.get("residuals") or [])}
    for ref in d["unobserved"]:
        if f"res-index-{ref}" not in residual_ids:
            problems.append(f"the unbound index reference {ref} has no residual")
    for row in d["cves"]:
        if not row["candidate_region"]["resolved"] \
                and f"res-region-{row['cve_id']}" not in residual_ids:
            problems.append(f"{row['cve_id']}: an unjoined candidate region has no residual")
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}"
                     for p in schemas.validate("residual", r)]

    # 7. The rule names the committed authorities.
    rule = body.get("rule") or {}
    auth_paths = (rule.get("authority") or {}).get("paths") or []
    for want in (SECURITY_SOURCE_REL, SECURITY_LINEAGE_REL, SOURCE_CENSUS_REL, NON_RUST_TCB_REL):
        if want not in auth_paths:
            problems.append(f"the census rule does not name the committed {want} as its authority")
    if not (rule.get("coverage_discipline") or {}).get("rule"):
        problems.append("the rule does not carry the reference-coverage discipline")

    # 8. The rule equals its derivation.
    if rule != _rule(authority):
        problems.append("the committed `rule` is not the derived rule")

    return problems


def crosswalk_sensitivity_control(body: dict, authority: dict) -> dict:
    """Seed six mutations and require each caught, with specificity holding.

    Each is a distinct way the census could lie: a committed CVE silently dropped; a fabricated CVE
    the committed evidence does not classify; a class outside the closed taxonomy; a typed count; a
    mechanism with no traceable committed source; and an unjoined candidate region with its residual
    removed.
    """
    baseline = crosswalk_findings(body, authority)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = crosswalk_findings(mutated, authority)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    # m1: a committed CVE silently dropped from the census.
    def drop_cve() -> dict:
        b = clone()
        b["cves"] = b["cves"][1:]
        return b

    m1 = check("cve_dropped", drop_cve(), "the census omits the committed CVE")

    # m2: a fabricated CVE the committed evidence does not classify.
    def fabricate_cve() -> dict:
        b = clone()
        row = json.loads(json.dumps(b["cves"][0]))
        row["cve_id"] = "CVE-2099-99999"
        b["cves"] = sorted(b["cves"] + [row], key=lambda r: r["cve_id"])
        return b

    m2 = check("fabricated_cve", fabricate_cve(),
               "which the committed security evidence does not classify")

    # m3: a class outside the closed taxonomy (refused by the schema, which the court runs).
    def outside_taxonomy() -> dict:
        b = clone()
        b["cves"][0]["taxonomy"] = "MAGIC"
        return b

    m3 = check("class_outside_taxonomy", outside_taxonomy(), "not one of")

    # m4: a typed count (a count not derived from the classified rows).
    def typed_count() -> dict:
        b = clone()
        b["counts"]["memory_safety_cves"] += 1
        return b

    m4 = check("typed_count", typed_count(), "not the derived `counts`")

    # m5: a mechanism with no traceable committed source.
    def untraceable_mechanism() -> dict:
        b = clone()
        b["cves"][0]["mechanism_source"] = {}
        return b

    m5 = check("untraceable_mechanism", untraceable_mechanism(),
               "cites no committed advisory source")

    # m6: an unjoined candidate region with its residual removed.
    def region_residual_omitted() -> dict:
        b = clone()
        b["residuals"] = [r for r in b["residuals"]
                          if not str(r.get("residual_id")).startswith("res-region-")]
        return b

    m6 = check("region_residual_omitted", region_residual_omitted(),
               "an unjoined candidate region has no residual")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_authority() -> dict:
    """A tiny, self-consistent set of planes: two bound CVEs, one unbound reference."""
    advisories = {
        "CVE-2020-0001": (
            "OpenSSL Security Advisory [1 January 2020]\n"
            "========================================\n\n"
            "Heap buffer overflow in BN (CVE-2020-0001)\n"
            "=========================================\n\n"
            "Severity: High\n\n"
            "Issue summary: A heap buffer overflow occurs when parsing a crafted structure.\n\n"
            "Impact summary: Memory corruption.\n"
        ),
        "CVE-2020-0002": (
            "OpenSSL Security Advisory [1 January 2020]\n"
            "========================================\n\n"
            "Infinite loop in the parser (CVE-2020-0002)\n"
            "==========================================\n\n"
            "Severity: Low\n\n"
            "Issue summary: An infinite loop is reachable with a crafted input.\n\n"
            "Impact summary: Denial of service.\n"
        ),
    }
    source = {
        "source": {"all_references": ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"],
                   "index_url": "https://openssl-library.org/news/vulnerabilities/",
                   "index_sha256": "0" * 64},
        "observed": [
            {"reference": cve, "title": t, "severity": "High", "cwe": None,
             "affected": [], "commit_urls": urls,
             "advisory_url": f"https://example.invalid/{cve}.txt",
             "advisory_sha256": "a" * 64, "advisory_text": advisories[cve]}
            for cve, t, urls in (
                ("CVE-2020-0001", "Heap buffer overflow in BN",
                 {"3.0.2": "https://git.invalid/?a=commitdiff;h=abc123def456",
                  "1.1.1n": "https://git.invalid/?a=commitdiff;h=def789abc012"}),
                ("CVE-2020-0002", "Infinite loop in the parser",
                 {"3.0.4": "https://git.invalid/?a=commitdiff;h=aa11bb22cc33"}),
            )
        ],
    }
    lineage = {"body": {
        "vulnerabilities": [
            {"vulnerability_id": "CVE-2020-0001",
             "affected_ranges": ["from 3.0.0 before 3.0.2", "from 1.1.1 before 1.1.1n"],
             "branches": ["1.1.1", "3.0"],
             "catalogued_fixes": ["3.0.2", "1.1.1n"],
             "cwe": None, "severity": "high", "published_at": "2020-01-01",
             "found_by": "anon",
             "subsystem": {"token": "crypto/bn", "source_quote": "heap buffer overflow in bn"},
             "candidate_disposition": "never_contained",
             "title": "Heap buffer overflow in BN"},
            {"vulnerability_id": "CVE-2020-0002",
             "affected_ranges": ["from 3.0.0 before 3.0.4"],
             "branches": ["3.0"],
             "catalogued_fixes": ["3.0.4"],
             "cwe": None, "severity": "low", "published_at": "2020-01-01",
             "found_by": "anon",
             "subsystem": {"token": "apps/unknown", "source_quote": "infinite loop in the parser"},
             "candidate_disposition": "never_contained",
             "title": "Infinite loop in the parser"},
        ],
        "coverage": {"unobserved_references": ["CVE-2020-0003"], "unobserved": 1},
    }}
    census = {"body": {"files": [
        {"path": "src/bn/bignum.rs", "unsafe_operations": 5},
        {"path": "src/bn/gf2m.rs", "unsafe_operations": 2},
        {"path": "src/apps/x.rs", "unsafe_operations": 1},
    ]}}
    tcb = {"body": {"c_adapters": [], "generated_c": [], "assembly": []}}
    return {"security_source": source, "security_lineage": lineage,
            "source_census": census, "non_rust_tcb": tcb}


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation is clean and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_historical_cve.py", env={},
                                       dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_historical_cve.py is not admitted as a metadata-only generator on a "
                        "host")

    authority = _synth_authority()
    body = build_body(authority)
    baseline = crosswalk_findings(body, authority)
    if baseline:
        failures.append(f"the synthetic census body is not clean: {baseline[:4]}")
    c = body["counts"]
    if (c["cves"], c["memory_safety_cves"]) != (2, 1):
        failures.append(f"the synthetic row counts are wrong: cves={c['cves']} "
                        f"memory_safety={c['memory_safety_cves']}")
    if c["by_taxonomy"] != {"ALGORITHM_COMPLEXITY": 1, "HEAP_OOB_WRITE": 1}:
        failures.append(f"the synthetic taxonomy counts are wrong: {c['by_taxonomy']}")
    if (c["regions_resolved"], c["regions_unjoined"], c["regions_covered"]) != (1, 1, 1):
        failures.append(f"the synthetic region counts are wrong: {c}")
    if c["index_references"] != 3 or c["index_unobserved"] != 1:
        failures.append(f"the synthetic index counts are wrong: references={c['index_references']} "
                        f"unobserved={c['index_unobserved']}")
    # The synthetic must exercise both residual classes.
    classes = {r["class"] for r in body["residuals"]}
    if classes != {EVIDENCE_MISSING, JOIN_EVIDENCE_MISSING}:
        failures.append(f"the synthetic residuals do not carry both classes: {sorted(classes)}")
    row = next(r for r in body["cves"] if r["cve_id"] == "CVE-2020-0001")
    if row["fix_commit"] != "abc123def456" or not row["memory_safety"]:
        failures.append(f"the synthetic row is wrong: fix_commit={row['fix_commit']} "
                        f"taxonomy={row['taxonomy']}")

    control = crosswalk_sensitivity_control(body, authority)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-historical-cve] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-historical-cve] self-test ok: the guard admits it as metadata-only; the synthetic "
          "census is clean (2 classified CVEs, 1 memory-safety-relevant, 1 resolved/covered region, "
          "1 unjoined region, 1 unbound index reference, both residual classes); and all six seeded "
          "mutations (a dropped CVE, a fabricated CVE, a class outside the taxonomy, a typed count, "
          "an untraceable mechanism and an omitted region residual) are caught with specificity "
          "holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_planes(path: Path, doc: dict) -> None:
    """Write the plane compactly, key-sorted and deterministic.

    The plane carries the classified rows, the counts and the residuals; determinism is preserved
    (sorted keys, fixed separators).
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
        InputRef(name="ms-historical-cve-tool", path=TOOL),
        InputRef(name="security-source", path=SECURITY_SOURCE),
        InputRef(name="security-lineage", path=SECURITY_LINEAGE),
        InputRef(name="source-census", path=SOURCE_CENSUS),
        InputRef(name="non-rust-tcb", path=NON_RUST_TCB),
    ]


def _measure() -> int:
    """Derive the census from the committed planes, and write it."""
    authority = load_authority()
    body = build_body(authority)
    problems = crosswalk_findings(body, authority)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-historical-cve-census", authority=auth.id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    _write_planes(OUT, doc)

    c = body["counts"]
    print(f"[ms-historical-cve] {c['cves']} committed advisory record(s) classified, "
          f"{c['memory_safety_cves']} memory-safety-relevant; "
          f"{c['index_unobserved']} of {c['index_references']} index reference(s) unbound "
          f"({c['unobserved_advisory_named']} advisory-named, "
          f"{c['unobserved_identifier_only']} identifier-only)")
    print("  by taxonomy: "
          + ", ".join(f"{k}={v}" for k, v in sorted(c["by_taxonomy"].items())))
    print(f"  candidate regions: {c['regions_resolved']} resolved, "
          f"{c['regions_covered']} covered, {c['regions_unjoined']} unjoined; "
          f"residuals: {c['residuals']}")
    print(f"  -> {rel(OUT)} all_pass={not problems} (findings={len(body['findings'])})")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed census, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-historical-cve] {rel(OUT)} is absent; run --measure")
        return 1
    body = _load(OUT).get("body", {})
    authority = load_authority()
    problems = crosswalk_findings(body, authority)
    if problems:
        print(f"[ms-historical-cve] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = derive_cached(authority)["counts"]
    print(f"[ms-historical-cve] check ok: {c['cves']} classified CVE(s) "
          f"({c['memory_safety_cves']} memory-safety-relevant), {c['residuals']} residual(s); "
          f"every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/historical-cves.json from the committed inputs")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed census")
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
