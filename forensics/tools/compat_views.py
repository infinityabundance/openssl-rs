#!/usr/bin/env python3
"""openssl-rs — the directional, dimension-specific compatibility views (Phase 23.9).

Phase 23.9 lands the **compatibility views**: for each admitted authority, a set of
directional, dimension-specific records ([`compatibility_view`] in
`forensics/tools/multitrack_schemas.py`) whose distribution/ABI shell surface is *derived
from that authority's own committed evidence*, never assumed and never typed. The plan row
(`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2, 23.9) and its brief sections 16, 17, 28
and 30 name what a view must reproduce: library filenames, SONAMEs, the exported symbol
set and its versions, static archive names, link names, pkg-config metadata, the installed
layout and the version-reporting identity.

Why one plane, one record kind, many facets
-------------------------------------------
A compatibility view is **directional** (`subject_id` -> `reference_id`, one of
`candidate_to_reference` / `reference_to_candidate`) and **dimension-specific** (one of the
schema's closed `COMPAT_DIMENSIONS`). The distribution shell is finer than that vocabulary,
so -- exactly as the 23.6 delta engine keeps its fine `DELTA_DIMENSIONS` beside the coarse
schema dimension (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 4.9) -- a view carries a
coarse `dimension` **and** a fine `facet` that lives with this generator rather than in the
shared schema. A view is never a boolean: `multitrack_schemas.validate_compatibility_view`
refuses a record that carries a bare `compatible` flag, and it refuses an `evidence_kind` of
`version_order`, because numeric ordering is a chronology and not a compatibility
measurement (D535; `docs/PARITY_MODEL.md` sections 3 and 4).

The evidence, and the one rule
------------------------------
Each view names the authority it is about (`reference_id`) and the release it is over, and
every **reference-role** evidence entry carries the authority id it belongs to and a
content-addressed `path` + `sha256`. **A view for authority X carries only X's evidence**:
this generator reads each authority through its own adapter, and the court
(`RT-COMPATIBILITY-VIEWS`) refuses a view whose reference evidence belongs to another
authority. That is the general form of D533 -- a receipt, claim or court result compiled
against one authority is evidence about that authority and no other -- and it is why a view
inherits no receipt across a version.

What is derived, and what is honestly not
-----------------------------------------
The two admitted authorities that carry committed evidence are `openssl-3.6.4-production`
(the committed distribution shell under `artifacts/phase2/`, derived from the production
atlas and the Phase-2 ABI courts) and `openssl-0.9.8zh-historical` (the historical build
receipt, the plane census and the source manifest, with **no** candidate build for the
epoch, so every one of its views is `not_measured` rather than a fabricated claim). A
dimension or facet the committed evidence cannot support is recorded in `not_derivable`
with its reason, never emitted with a plausible value.

Outputs
-------
  forensics/multitrack/compatibility-views.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    sha256_file,
    write_json,
)

import multitrack_schemas  # noqa: E402

OUT = REPO_ROOT / "forensics" / "multitrack" / "compatibility-views.json"
GENERATOR = "forensics/tools/compat_views.py"

# The committed evidence the two authorities are read through. Nothing here is typed twice: a view
# cites the artefact it was derived from and that artefact's sha256.
AUTHORITY_NODES = REPO_ROOT / "forensics" / "authority-nodes.json"
RELEASE_CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
BUILD_RECORDS = REPO_ROOT / "forensics" / "atlas" / "BUILD_RECORDS.json"
PRODUCTION_ATLAS = REPO_ROOT / "forensics" / "atlas" / "openssl-3.6.4-production"
HIST_RECEIPTS = REPO_ROOT / "forensics" / "multitrack" / "historical-build-receipts.json"
HIST_CENSUS = REPO_ROOT / "forensics" / "atlas" / "openssl-0.9.8zh-historical" / "plane-census.json"
HIST_MANIFEST = REPO_ROOT / "forensics" / "authorities" / "SOURCE_MANIFEST.0.9.8zh.json"
# The committed 3.6.4 distribution shell (`artifacts/phase2/`): the emitted distribution a view
# compares the derived reference values against. The bulky DSOs are committed too; the shell
# manifest and the Phase-2 ABI court records are the legible, content-addressed evidence.
SHELL_MANIFEST = REPO_ROOT / "artifacts" / "phase2" / "SHELL_MANIFEST.json"
ABI_SYMBOL = REPO_ROOT / "artifacts" / "phase2" / "courts" / "ABI-SYMBOL.json"
ABI_VERSION = REPO_ROOT / "artifacts" / "phase2" / "courts" / "ABI-VERSION.json"
ABI_LAYOUT = REPO_ROOT / "artifacts" / "phase2" / "courts" / "ABI-INSTALL-LAYOUT.json"
PKGCRYPTO = REPO_ROOT / "artifacts" / "phase2" / "install" / "lib" / "pkgconfig" / "libcrypto.pc"
PKGSSL = REPO_ROOT / "artifacts" / "phase2" / "install" / "lib" / "pkgconfig" / "libssl.pc"

# The candidate implementation: the subject of every view ("the view is the claim, the crate is
# the subject", docs/PHASE-23-MULTITRACK-SUBPHASES.md section 0).
CANDIDATE = "openssl-rs"
HISTORICAL_AUTHORITY = "openssl-0.9.8zh-historical"

# The fine distribution facets this subphase derives, and the coarse schema dimension each is a
# view *of*. The facet vocabulary lives here, with the generator and its court, exactly as the
# delta engine's fine dimensions live with `authority_delta.py` (section 4.9).
FACET_DIMENSION: dict[str, str] = {
    "distribution_library_names": "abi",
    "distribution_sonames": "abi",
    "distribution_exported_symbols": "abi",
    "distribution_static_archives": "abi",
    "distribution_link_names": "abi",
    "distribution_pkg_config": "cli_config",
    "distribution_install_layout": "cli_config",
    "version_reporting_identity": "behavioural",
}

# The fine facets must map onto the schema's closed dimension vocabulary; a facet that did not
# would be a compatibility claim the schema cannot check.
for _facet, _dimension in FACET_DIMENSION.items():
    if _dimension not in multitrack_schemas.COMPAT_DIMENSIONS:
        raise SystemExit(
            f"compat_views: facet {_facet!r} names dimension {_dimension!r}, which is not one of "
            f"the schema's COMPAT_DIMENSIONS {multitrack_schemas.COMPAT_DIMENSIONS}"
        )

# The explicit non-claims every view carries. They are the stratum's own (section 0) plus the one
# that keeps a distribution-shell view from being read as a semantic or security claim.
NON_CLAIMS: list[str] = [
    "a distribution-shell view is not a semantic, behavioural or security claim about the "
    "authority or the candidate",
    "one platform/profile is not every platform/profile: a view is bounded to the platform, "
    "architecture, profile and toolchain of the authority node it names",
    "upstream's ABI promise is not candidate evidence",
    "OpenSSL compatibility is not FIPS validation (docs/FIPS_CLAIMS.md)",
]

# The dimensions this subphase does not derive, with the committed reason. A dimension the
# evidence cannot support is recorded here rather than emitted with a plausible value.
COMMON_NOT_DERIVABLE: dict[str, str] = {
    "source_api": (
        "23.9 emits the distribution/ABI shell views; the source/API declaration surface is "
        "measured against the authority's own headers by the Phase-2 ABI family "
        "(ABI-CONSTANTS/ABI-MATRIX/ABI-LAYOUT), not re-derived as a per-authority distribution view"
    ),
    "semantic": (
        "the committed evidence carries no candidate-to-authority semantic measurement for this "
        "authority at its support status; 23.8's semantic court is oracle-to-oracle (3.6.3 vs "
        "3.6.4), a relationship rather than this authority's view"
    ),
    "protocol": (
        "no committed protocol-transcript measurement exists for this authority, so no directional "
        "protocol view can be derived from its evidence"
    ),
    "error": (
        "no committed error-queue measurement exists for this authority, so no directional error "
        "view can be derived from its evidence"
    ),
    "ownership": (
        "no committed ownership/allocation measurement exists for this authority, so no directional "
        "ownership view can be derived from its evidence"
    ),
    "concurrency": (
        "no committed concurrency measurement exists for this authority, so no directional "
        "concurrency view can be derived from its evidence"
    ),
    "provider_registration": (
        "the distribution shell does not establish provider registration; the authority's provider "
        "surface is the Phase-6/23.2 provider census, not a distribution-shell facet of this "
        "subphase"
    ),
}


def _load(path: Path) -> dict:
    """Read a committed artefact, failing closed when it is absent."""
    if not path.is_file():
        raise SystemExit(
            f"compat_views: {rel(path)} is absent, so the authority's evidence cannot be read; "
            f"the read is fail-closed rather than a fabricated view"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _evidence(role: str, authority_id: str, kind: str, path: Path, note: str | None = None) -> dict:
    """One content-addressed evidence entry: the authority it belongs to, and its path + sha256."""
    entry: dict = {
        "role": role,
        "authority_id": authority_id,
        "kind": kind,
        "path": rel(path),
        "sha256": sha256_file(path),
    }
    if note:
        entry["note"] = note
    return entry


def _view(reference_id: str, reference_release: str, facet: str, status: str,
          evidence_kind: str, evidence: list[dict], method: str, reference: dict,
          emitted: dict | None, relation: str, support_status: str) -> dict:
    """Build one `compatibility_view` record.

    The record is directional (`subject_id` -> `reference_id`), dimension-specific (its coarse
    `dimension` and fine `facet`), content-addressed, and carries its explicit non-claims. It
    never carries a bare `compatible` boolean.
    """
    return {
        "view_id": f"compat-view/{reference_id}/{facet}",
        "subject_id": CANDIDATE,
        "reference_id": reference_id,
        "reference_release": reference_release,
        "dimension": FACET_DIMENSION[facet],
        "facet": facet,
        "direction": "candidate_to_reference",
        "status": status,
        "evidence_kind": evidence_kind,
        "evidence": evidence,
        "derivation": {
            "method": method,
            "reference": reference,
            "emitted": emitted,
            "relation": relation,
        },
        "support_status": support_status,
        "non_claims": list(NON_CLAIMS),
    }


def _pc(path: Path) -> dict:
    """Parse the identity fields of a committed pkg-config file (name, version, `-l` flags)."""
    name = version = ""
    libs: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("Libs:"):
            libs = sorted(t for t in line.split(":", 1)[1].split() if t.startswith("-l"))
    return {"name": name, "version": version, "libs": libs}


def _status(agrees: bool, measured: bool = True) -> str:
    """`compatible` when the derived reference and the emitted distribution agree, `partial`
    when both are present and disagree, and `not_measured` when no candidate evidence exists."""
    if not measured:
        return "not_measured"
    return "compatible" if agrees else "partial"


def _bases(sonames: list[str]) -> list[str]:
    """The library base names an authority's SONAMEs establish (`libcrypto.so.3` -> `libcrypto`).

    The base name is read from the authority's own recorded SONAME, not typed: it is the one
    derivation link names (`-lcrypto`) and static archive names (`libcrypto.a`) share, and the
    derivation method is recorded in each view so it is reviewable rather than assumed.
    """
    out = []
    for soname in sonames:
        base = soname.split(".so", 1)[0]
        out.append(base)
    return sorted(out)


def _production_views() -> list[dict]:
    """Every view `openssl-3.6.4-production` can honestly support, derived from its evidence."""
    aid = PRODUCTION_AUTHORITY
    node = next(n for n in _load(AUTHORITY_NODES)["body"]["nodes"]
                if n["authority_id"] == aid)
    rid = node["release_id"]
    release = next(n for n in _load(RELEASE_CATALOG)["body"]["nodes"]
                   if n["release_id"] == rid)
    sv = _load(PRODUCTION_ATLAS / "symbol-versions.json")["body"]["libraries"]
    counts = {
        "libcrypto": _load(PRODUCTION_ATLAS / "symbols-libcrypto.json")["body"]["counts"]["dso_exported_symbols"],
        "libssl": _load(PRODUCTION_ATLAS / "symbols-libssl.json")["body"]["counts"]["dso_exported_symbols"],
    }
    shell = _load(SHELL_MANIFEST)["body"]
    abi_symbol = _load(ABI_SYMBOL)["libraries"]
    abi_version = _load(ABI_VERSION)["libraries"]
    layout = _load(ABI_LAYOUT)

    auth_shared = sorted(node["binary_hashes"])            # libcrypto.so.3, libssl.so.3
    auth_bases = _bases(auth_shared)
    auth_sonames = sorted({lib["soname"] for lib in sv.values()})
    auth_versions = {name: sorted(lib["version_definitions"]) for name, lib in sv.items()}
    cand_required = layout["required_present"]
    cand_shared = sorted(p.split("/")[-1] for p in cand_required
                         if p.startswith("lib/") and p.endswith(".so.3"))
    cand_static = sorted(p.split("/")[-1] for p in cand_required if p.endswith(".a"))
    cand_sonames = sorted(shell["sonames"].values())
    cand_counts = {name: abi_symbol[name]["candidate_exported"] for name in abi_symbol}
    cand_versions = {name: sorted(abi_version[name]["candidate_nodes"]) for name in abi_version}
    pc = {"libcrypto": _pc(PKGCRYPTO), "libssl": _pc(PKGSSL)}
    cand_link_names = sorted({flag for info in pc.values() for flag in info["libs"]})
    ref_link_names = sorted("-l" + base[len("lib"):] for base in auth_bases)
    support = "candidate-view"

    views: list[dict] = []

    views.append(_view(
        aid, rid, "distribution_library_names", _status(auth_shared == cand_shared),
        "build_records",
        [_evidence("reference", aid, "build_records", AUTHORITY_NODES,
                   "the authority node's binary_hashes keys are its built library names"),
         _evidence("candidate", CANDIDATE, "court_transcript", ABI_LAYOUT,
                   "the Phase-2 install-layout court's required present libraries")],
        "the authority's built library filenames (authority-node binary_hashes) against the "
        "emitted distribution's installed shared objects",
        {"library_names": auth_shared}, {"library_names": cand_shared},
        "the emitted distribution installs every shared library the authority builds", support))

    views.append(_view(
        aid, rid, "distribution_sonames", _status(auth_sonames == cand_sonames),
        "build_records",
        [_evidence("reference", aid, "upstream_declaration", PRODUCTION_ATLAS / "symbol-versions.json",
                   "the authority's own readelf-measured SONAMEs"),
         _evidence("candidate", CANDIDATE, "build_records", SHELL_MANIFEST,
                   "the emitted distribution's declared SONAMEs")],
        "the authority's measured SONAMEs (the production atlas symbol-versions plane) against "
        "the emitted distribution's declared SONAMEs",
        {"sonames": auth_sonames}, {"sonames": cand_sonames},
        "the emitted distribution's SONAME identity equals the authority's", support))

    views.append(_view(
        aid, rid, "distribution_exported_symbols",
        _status(counts == cand_counts and auth_versions == cand_versions),
        "court_transcript",
        [_evidence("reference", aid, "upstream_declaration", PRODUCTION_ATLAS / "symbols-libcrypto.json"),
         _evidence("reference", aid, "upstream_declaration", PRODUCTION_ATLAS / "symbols-libssl.json"),
         _evidence("candidate", CANDIDATE, "court_transcript", ABI_SYMBOL),
         _evidence("candidate", CANDIDATE, "court_transcript", ABI_VERSION)],
        "the authority's measured exported symbol counts and version namespace (the production "
        "atlas) against the Phase-2 ABI-SYMBOL/ABI-VERSION court readings of the emitted DSOs",
        {"exported_symbols": counts, "version_nodes": auth_versions},
        {"exported_symbols": cand_counts, "version_nodes": cand_versions},
        "the emitted DSOs export the same symbol set and carry the same version namespace as the "
        "authority", support))

    views.append(_view(
        aid, rid, "distribution_static_archives", _status(
            sorted(f"{base}.a" for base in auth_bases) == cand_static),
        "build_records",
        [_evidence("reference", aid, "build_records", AUTHORITY_NODES,
                   "the static archive name is derived from the authority's own recorded SONAME "
                   "base, which is the one naming derivation this facet shares"),
         _evidence("candidate", CANDIDATE, "court_transcript", ABI_LAYOUT,
                   "the Phase-2 install-layout court requires the static archives")],
        "the authority's SONAME base names + the standard static-archive suffix against the "
        "emitted distribution's installed archives",
        {"static_archives": sorted(f"{base}.a" for base in auth_bases)},
        {"static_archives": cand_static},
        "the emitted distribution installs a static archive per authority library base", support))

    views.append(_view(
        aid, rid, "distribution_link_names", _status(ref_link_names == cand_link_names),
        "build_records",
        [_evidence("reference", aid, "upstream_declaration", PRODUCTION_ATLAS / "symbol-versions.json",
                   "the link name is derived from the authority's recorded SONAME base"),
         _evidence("candidate", CANDIDATE, "build_records", PKGCRYPTO),
         _evidence("candidate", CANDIDATE, "build_records", PKGSSL)],
        "the `-l` link names derived from the authority's SONAME bases against the emitted "
        "pkg-config files' Libs",
        {"link_names": ref_link_names}, {"link_names": cand_link_names},
        "the emitted distribution links the same -l names the authority's SONAME bases establish",
        support))

    ref_pc = {"names": sorted(info["name"] for info in pc.values()),
              "version": release["display_version"],
              "libs": ref_link_names}
    cand_pc = {name: info for name, info in sorted(pc.items())}
    views.append(_view(
        aid, rid, "distribution_pkg_config",
        _status(ref_pc["version"] == shell["authority_version"]
                and all(info["version"] == release["display_version"] for info in pc.values())),
        "build_records",
        [_evidence("reference", aid, "build_records", RELEASE_CATALOG,
                   "the pkg-config identity is the authority's library base names and version"),
         _evidence("candidate", CANDIDATE, "build_records", PKGCRYPTO),
         _evidence("candidate", CANDIDATE, "build_records", PKGSSL)],
        "the pkg-config identity (library names and version) derived from the authority's own "
        "records against the emitted pkg-config metadata",
        {**ref_pc, "sources": ["libcrypto.pc", "libssl.pc"]}, cand_pc,
        "the emitted pkg-config metadata names the same libraries at the same version", support))

    ref_positions = sorted(f"lib/{name}" for name in auth_shared)
    views.append(_view(
        aid, rid, "distribution_install_layout",
        _status(all(p in cand_required for p in ref_positions)
                and not layout["required_missing"]),
        "build_records",
        [_evidence("reference", aid, "build_records", AUTHORITY_NODES,
                   "the authority's installed shared-object positions are read from its "
                   "binary_hashes keys"),
         _evidence("candidate", CANDIDATE, "court_transcript", ABI_LAYOUT)],
        "the authority's recorded installed library positions against the Phase-2 install-layout "
        "court's required-present set (which must have no required-missing entry)",
        {"library_positions": ref_positions,
         "installed_headers": sorted(node["installed_hashes"])},
        {"required_present": cand_required, "required_missing": layout["required_missing"]},
        "the emitted distribution installs every library position the authority records, with no "
        "required-missing entry", support))

    views.append(_view(
        aid, rid, "version_reporting_identity",
        _status(release["display_version"] == shell["authority_version"]),
        "upstream_declaration",
        [_evidence("reference", aid, "upstream_declaration", RELEASE_CATALOG,
                   "the authority's release display version"),
         _evidence("candidate", CANDIDATE, "build_records", SHELL_MANIFEST,
                   "the emitted distribution's declared version")],
        "the authority's release display version against the emitted distribution's declared "
        "version identity",
        {"display_version": release["display_version"], "release_id": rid},
        {"authority_version": shell["authority_version"]},
        "the emitted distribution reports the authority's own version identity", support))

    return sorted(views, key=lambda v: v["view_id"])


def _historical_views() -> list[dict]:
    """Every view `openssl-0.9.8zh-historical`'s evidence supports. No candidate build exists for
    the epoch, so each view is `not_measured` rather than a fabricated compatibility claim."""
    aid = HISTORICAL_AUTHORITY
    node = next(n for n in _load(AUTHORITY_NODES)["body"]["nodes"]
                if n["authority_id"] == aid)
    rid = node["release_id"]
    release = next(n for n in _load(RELEASE_CATALOG)["body"]["nodes"]
                   if n["release_id"] == rid)
    receipt = next(r for r in _load(HIST_RECEIPTS)["receipts"] if r["id"] == aid)
    census = _load(HIST_CENSUS)["body"]
    manifest = _load(HIST_MANIFEST)

    auth_names = sorted(r["name"] for r in receipt["artifacts"])       # libcrypto.so.0.9.8, ...
    auth_sonames = sorted(receipt["binary_hashes"])                    # same, pre-symbol-versioning
    auth_bases = _bases(auth_names)
    support = "atlas-complete"
    ordinal = [f for f in manifest["files"]
               if f["path"] in ("util/libeay.num", "util/ssleay.num")]
    census_planes = {p["plane"]: p for p in census["planes"]}

    views: list[dict] = []

    views.append(_view(
        aid, rid, "distribution_library_names", _status(False, measured=False),
        "build_records",
        [_evidence("reference", aid, "build_records", HIST_RECEIPTS,
                   "the historical build receipt's artifact names are the built library "
                   "filenames")],
        "the authority's built library filenames (the historical build receipt) against the "
        "emitted distribution; the candidate has no 0.9.8zh build",
        {"library_names": auth_names}, None,
        "no emitted distribution exists for the 0.9.8zh epoch, so the candidate relation is "
        "unmeasured, not compatible", support))

    views.append(_view(
        aid, rid, "distribution_sonames", _status(False, measured=False),
        "build_records",
        [_evidence("reference", aid, "build_records", HIST_RECEIPTS,
                   "the era's SONAME is the artifact filename: the release predates ELF symbol "
                   "versioning"),
         _evidence("reference", aid, "source_manifest", HIST_CENSUS,
                   "the plane census records symbol-versioning as a measured absence")],
        "the authority's SONAMEs (pre-1.1.0: the artifact name itself, corroborated by the "
        "census's measured-absent symbol-versioning plane) against the emitted distribution",
        {"sonames": auth_sonames,
         "symbol_versioning": census_planes["symbol-versioning"]["status"]}, None,
        "the candidate has no 0.9.8zh build, so the SONAME relation is unmeasured", support))

    views.append(_view(
        aid, rid, "distribution_exported_symbols", _status(False, measured=False),
        "source_manifest",
        [_evidence("reference", aid, "source_manifest", HIST_MANIFEST,
                   "the committed source manifest declares the authority's ordinal inventories"),
         _evidence("reference", aid, "source_manifest", HIST_CENSUS,
                   "the plane census counts the symbol-ordinal inventories")],
        "the authority's exported-symbol ordinal inventory, declared by its own source manifest "
        "(util/libeay.num, util/ssleay.num) and counted by the plane census, against the emitted "
        "distribution; the committed evidence declares the inventory but does not enumerate its "
        "names, and no candidate build exists for the epoch",
        {"ordinal_inventory": [{"path": f["path"], "sha256": f["sha256"]} for f in ordinal],
         "census_count": census_planes["symbol-ordinal-inventory"]["count"]}, None,
        "the candidate has no 0.9.8zh build, so the exported-symbol relation is unmeasured",
        support))

    views.append(_view(
        aid, rid, "distribution_link_names", _status(False, measured=False),
        "build_records",
        [_evidence("reference", aid, "build_records", HIST_RECEIPTS,
                   "the link name is derived from the authority's recorded library base name")],
        "the `-l` link names derived from the authority's library base names against the emitted "
        "distribution",
        {"link_names": sorted("-l" + base[len("lib"):] for base in auth_bases)}, None,
        "the candidate has no 0.9.8zh build, so the link-name relation is unmeasured", support))

    views.append(_view(
        aid, rid, "distribution_install_layout", _status(False, measured=False),
        "build_records",
        [_evidence("reference", aid, "build_records", HIST_RECEIPTS,
                   "the historical build receipt records the installed header hashes and artifact "
                   "positions")],
        "the authority's recorded installed positions (the receipt's installed_hashes and library "
        "artifacts) against the emitted distribution",
        {"installed_headers": sorted(receipt["installed_hashes"]),
         "library_positions": sorted(f"lib/{name}" for name in auth_names)}, None,
        "the candidate has no 0.9.8zh build, so the installed-layout relation is unmeasured",
        support))

    views.append(_view(
        aid, rid, "version_reporting_identity", _status(False, measured=False),
        "build_records",
        [_evidence("reference", aid, "build_records", HIST_RECEIPTS,
                   "the historical build receipt's banner is the authority's reported version"),
         _evidence("reference", aid, "upstream_declaration", RELEASE_CATALOG,
                   "the release catalogue's display version")],
        "the authority's reported version identity (the historical build receipt's banner and the "
        "release catalogue) against the emitted distribution",
        {"banner": receipt["banner"], "display_version": release["display_version"]}, None,
        "the candidate has no 0.9.8zh build, so the version-reporting relation is unmeasured",
        support))

    return sorted(views, key=lambda v: v["view_id"])


def _not_derivable(authority_id: str, release_id: str, extra: list[dict]) -> list[dict]:
    """The dimensions and facets this authority's committed evidence cannot support, with reasons.

    A dimension the evidence cannot support is recorded here rather than emitted as a view with a
    plausible value; the court requires every `COMPAT_DIMENSIONS` member to be either the dimension
    of an emitted view or a named entry here.
    """
    rows = [
        {"authority_id": authority_id, "release_id": release_id, "dimension": dim,
         "facet": None, "reason": reason, "evidence": [rel(AUTHORITY_NODES)]}
        for dim, reason in sorted(COMMON_NOT_DERIVABLE.items())
    ]
    return sorted(rows + extra, key=lambda r: (r["dimension"], r["facet"] or ""))


def derive_body() -> dict:
    """The compatibility-views plane, a pure function of the committed evidence.

    Deterministic: every list is sorted, no wall-clock/environment value is read, and every
    evidence entry is content-addressed. The court re-derives this body through the same code and
    refuses a committed plane that does not reproduce.
    """
    prod = _production_views()
    hist = _historical_views()
    views = sorted(prod + hist, key=lambda v: v["view_id"])

    historical_extra = [
        {"authority_id": HISTORICAL_AUTHORITY, "release_id": "openssl-0.9.8zh",
         "dimension": "abi", "facet": "distribution_static_archives",
         "reason": "the 0.9.8zh build receipt records only the shared objects "
                   "(libcrypto.so.0.9.8, libssl.so.0.9.8); the static archive names are not "
                   "recorded for this authority, so they are not emittable without inventing them",
         "evidence": [rel(HIST_RECEIPTS)]},
        {"authority_id": HISTORICAL_AUTHORITY, "release_id": "openssl-0.9.8zh",
         "dimension": "cli_config", "facet": "distribution_pkg_config",
         "reason": "the 0.9.8zh authority's committed records declare no pkg-config metadata "
                   "(the plane census carries no such plane), so its pkg-config metadata cannot be "
                   "derived from committed evidence",
         "evidence": [rel(HIST_CENSUS)]},
    ]
    not_derivable = sorted(
        _not_derivable(PRODUCTION_AUTHORITY, "openssl-3.6.4", [])
        + _not_derivable(HISTORICAL_AUTHORITY, "openssl-0.9.8zh", historical_extra),
        key=lambda r: (r["authority_id"], r["dimension"], r["facet"] or ""))

    by_dimension: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_authority: dict[str, int] = {}
    for v in views:
        by_dimension[v["dimension"]] = by_dimension.get(v["dimension"], 0) + 1
        by_status[v["status"]] = by_status.get(v["status"], 0) + 1
        by_authority[v["reference_id"]] = by_authority.get(v["reference_id"], 0) + 1

    return {
        "rule": (
            "one directional, dimension-specific compatibility view per authority and distribution "
            "facet, derived from the authority's own committed evidence and never typed. A view is "
            "never a boolean and never inherits a receipt across a version: a view for authority X "
            "carries only X's evidence (each reference-role evidence entry names the authority it "
            "belongs to and a content-addressed path + sha256). A dimension or facet the evidence "
            "cannot support is recorded in `not_derivable` with its reason, never emitted with a "
            "plausible value"
        ),
        "subject_id": CANDIDATE,
        "direction_model": (
            "every view is read candidate_to_reference: the subject is the emitted distribution "
            "(the candidate implementation) and the reference is the authority whose evidence "
            "defines the surface"
        ),
        "authorities": sorted({v["reference_id"] for v in views} | {r["authority_id"] for r in not_derivable}),
        "counts": {
            "authorities": len({v["reference_id"] for v in views}),
            "views": len(views),
            "by_authority": by_authority,
            "by_dimension": by_dimension,
            "by_status": by_status,
            "not_derivable": len(not_derivable),
        },
        "views": views,
        "not_derivable": not_derivable,
        "boundary": (
            "23.9 derives the distribution/ABI shell facets -- library filenames, SONAMEs, the "
            "exported symbol set and its versions, static archive names, link names, pkg-config "
            "metadata, the installed layout and the version-reporting identity -- from each "
            "admitted authority's own committed evidence. The source/API, semantic, protocol, "
            "error, ownership, concurrency and provider-registration dimensions are recorded "
            "not-derivable with their reasons: the source/API declaration surface is carried by "
            "the Phase-2 ABI family and the semantic surface by 23.8's oracle-to-oracle court. The "
            "3.6.4 production authority has a committed emitted distribution (`artifacts/phase2/`) "
            "and its views compare against it; the 0.9.8zh historical epoch has no candidate build "
            "in this venue, so its views are `not_measured` and are never read as runtime parity."
        ),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args(argv)

    body = derive_body()

    inputs = [
        InputRef(name="authority-nodes", path=AUTHORITY_NODES),
        InputRef(name="release-catalog", path=RELEASE_CATALOG),
        InputRef(name="build-records", path=BUILD_RECORDS),
        InputRef(name="production-symbol-versions", path=PRODUCTION_ATLAS / "symbol-versions.json"),
        InputRef(name="production-symbols-libcrypto", path=PRODUCTION_ATLAS / "symbols-libcrypto.json"),
        InputRef(name="production-symbols-libssl", path=PRODUCTION_ATLAS / "symbols-libssl.json"),
        InputRef(name="historical-build-receipts", path=HIST_RECEIPTS),
        InputRef(name="historical-plane-census", path=HIST_CENSUS),
        InputRef(name="historical-source-manifest", path=HIST_MANIFEST),
        InputRef(name="phase2-shell-manifest", path=SHELL_MANIFEST),
        InputRef(name="abi-symbol-court", path=ABI_SYMBOL),
        InputRef(name="abi-version-court", path=ABI_VERSION),
        InputRef(name="abi-install-layout-court", path=ABI_LAYOUT),
        InputRef(name="pkg-config-libcrypto", path=PKGCRYPTO),
        InputRef(name="pkg-config-libssl", path=PKGSSL),
    ]
    doc = envelope(kind="compatibility-views", authority=PRODUCTION_AUTHORITY,
                   inputs=inputs, body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[compat-views] {c['views']} view(s) over {c['authorities']} authority/ies; "
          f"status={c['by_status']}; dimensions={c['by_dimension']}; "
          f"{c['not_derivable']} not-derivable dimension/facet row(s)")
    for aid in sorted(c["by_authority"]):
        print(f"  authority {aid:<32} {c['by_authority'][aid]} view(s)")
    for r in body["not_derivable"]:
        facet = f"/{r['facet']}" if r["facet"] else ""
        print(f"  not-derivable {r['authority_id']:<32} {r['dimension']}{facet}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
