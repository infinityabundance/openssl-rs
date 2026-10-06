#!/usr/bin/env python3
"""openssl-rs — the negative (and positive) obligations, so an absence is a claim (Phase 23.13).

Phase 23 is the multitrack authority stratum (`docs/PHASE-23-MULTITRACK-SUBPHASES.md`). A
historical compatibility view is **not** a monotonic superset: a release that must not carry a
surface is a contract about its *absence*, and an omission is not a claim. 23.13 makes absence
first-class. It derives `forensics/multitrack/negative-obligations.json` -- a set of
[`negative_obligation`](multitrack_schemas.py) records -- from the committed authorities, views and
planes, and never types one:

  * `must_not_exist` / `must_be_opaque` / `must_not_be_exported` **beside** the positive
    `must_exist` / `must_be_public` / `must_be_exported`, so the set is a contract rather than a
    list of prohibitions (D536);
  * each record names the authority or release it is about, the surface, the obligation kind, the
    expected state and the **evidence** that establishes it, and carries a `state` that is *derived
    from that evidence* rather than assumed: `satisfied` where the committed evidence affirms it,
    `open` where the evidence contradicts it (a compatibility defect), and `unknown` only where the
    evidence cannot adjudicate it (no authority or view exists to check).

Where the facts come from
-------------------------
Every obligation is derived from an artefact that already carries the fact:

  * **provider planes** (`forensics/atlas/<authority>/plane-census.json` and the production census
    in `forensics/atlas/parameterization-receipt.json`, 23.3): a `measured_absence` provider or
    provider-registration plane is a `must_not_exist`, a `produced` one a `must_exist`. The
    pre-provider authorities (0.9.8zh, 1.0.2u, 1.1.1w) carry the absence; 3.0.0 and 3.6.4 carry the
    presence.
  * **the ABI/history façades** (`forensics/multitrack/abi-facades.json`, 23.7): a pre-1.1.0
    `public_layout` façade is `must_be_public` in its own authority and `must_be_opaque` in the
    canonical authority; the `architecture` façade's engine/provider model is a `must_exist` or
    `must_not_exist`. The model's terminal `no_engine` epoch names the 4.x release, which carries no
    admitted authority, so its ENGINE obligation reads `unknown` rather than satisfied.
  * **the delta engine** (`forensics/deltas/`, 23.6): an entity the later release *added* must not
    exist in the earlier authority's view and must exist in the later one; an exported symbol the
    delta read as present in both must be exported by both.
  * **the symbols planes** (`forensics/atlas/<authority>/symbols-*.json`, 23.1): a `.num` row whose
    status is `NOEXIST` is a `must_not_be_exported`.

The court (`RT-NEGATIVE-OBLIGATIONS`) re-derives the whole plane through `derive_body` and, for
every record, re-reads the evidence the record names through `adjudicate`; a state that was typed,
a leaked future symbol, a retained removed surface or an obligation with no evidence is a finding
rather than a plausible value.

Outputs
-------
  forensics/multitrack/negative-obligations.json

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
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

import multitrack_schemas as mts  # noqa: E402

OUT = REPO_ROOT / "forensics" / "multitrack" / "negative-obligations.json"
GENERATOR = "forensics/tools/negative_obligations.py"

CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
AUTHORITY_NODES = REPO_ROOT / "forensics" / "authority-nodes.json"
CENSUS_RECEIPT = REPO_ROOT / "forensics" / "atlas" / "parameterization-receipt.json"
ATLAS_ROOT = REPO_ROOT / "forensics" / "atlas"
ABI_FACADES = REPO_ROOT / "forensics" / "multitrack" / "abi-facades.json"
COMPAT_VIEWS = REPO_ROOT / "forensics" / "multitrack" / "compatibility-views.json"
DELTA = REPO_ROOT / "forensics" / "deltas" / "openssl-3.6.3--openssl-3.6.4.json"

# The obligations this generator derives, and the state each kind asserts about its subject. The
# `expected_state` is the polarity a reader sees; `state` in each record is whether the evidence
# establishes it, derived by `adjudicate` rather than typed.
EXPECTED_STATE: dict[str, str] = {
    "must_exist": "present",
    "must_not_exist": "absent",
    "must_be_opaque": "opaque",
    "must_be_public": "public",
    "must_be_exported": "exported",
    "must_not_be_exported": "not_exported",
}

# The three negative kinds the plan row names, kept so the court can require them present.
NEGATIVE_KINDS: tuple[str, ...] = ("must_not_exist", "must_be_opaque", "must_not_be_exported")
POSITIVE_KINDS: tuple[str, ...] = ("must_exist", "must_be_public", "must_be_exported")

# The architecture planes a census reads, and the surface each is about. The subject is the *surface*
# the plane measures, not a path: a `measured_absence` is the whole provider store being absent.
CENSUS_PLANES: dict[str, str] = {
    "providers": "provider-store",
    "provider-registrations": "provider-registration",
}

# The ENGINE epoch models that mean the surface exists, and the terminal model that means it does not.
ENGINE_PRESENT_MODELS: tuple[str, ...] = ("engine", "deprecated_engine")

# The public-layout epochs. `transparent_pre_1_1_0` is the pre-1.1.0 public `#[repr(C)]` layout, and
# `opaque_post_1_1_0` is the 1.1.0 opacity transition the canonical authority marks.
LAYOUT_PUBLIC = "transparent_pre_1_1_0"
LAYOUT_OPAQUE = "opaque_post_1_1_0"

# The explicit non-claims every obligation carries. They are the stratum's own (section 0) plus the
# one that keeps an obligation from being read as a compatibility pass.
NON_CLAIMS: list[str] = [
    "an obligation records a surface that must exist, must be absent, must be opaque, must be public "
    "or must (not) be exported in one named authority or release; it is not a one-boolean "
    "compatibility claim",
    "an obligation is bounded to the authority or release it names and the evidence it carries; a "
    "receipt from one authority is never inherited as evidence for another",
    "an obligation that cannot be adjudicated reads `unknown`, never `satisfied`",
    "OpenSSL compatibility is not FIPS validation (docs/FIPS_CLAIMS.md)",
]

# The evidence-kind each obligation's decisive evidence entry records, by the artefact it reads.
EVIDENCE_KIND_OF_PATH: tuple[tuple[str, str], ...] = (
    ("plane-census.json", "build_records"),
    ("parameterization-receipt.json", "build_records"),
    ("source_manifest", "source_manifest"),
    ("deliberately-absent", "manual_adjudication"),
    ("abi-facades.json", "build_records"),
    ("structs.json", "source_manifest"),
    ("symbols-", "build_records"),
    ("deltas/", "atlas_differential"),
    ("compatibility-views.json", "court_transcript"),
)

_JSON_CACHE: dict[str, dict] = {}


def load(path: Path) -> dict:
    """Read a committed artefact, cached and fail-closed when it is absent."""
    key = rel(path)
    if key not in _JSON_CACHE:
        if not path.is_file():
            raise SystemExit(
                f"negative-obligations: {key} is absent, so the obligation cannot be derived; the "
                f"read is fail-closed rather than a fabricated record"
            )
        doc = json.loads(path.read_text(encoding="utf-8"))
        _JSON_CACHE[key] = doc.get("body", doc)
    return _JSON_CACHE[key]


def _evidence_kind(path_str: str) -> str:
    """The evidence kind a committed artefact's path records."""
    for marker, kind in EVIDENCE_KIND_OF_PATH:
        if marker in path_str:
            return kind
    return "manual_adjudication"


def _strip_fragment(path_str: str) -> str:
    """The artefact path behind an evidence citation, with any `#fragment` removed."""
    return path_str.split("#", 1)[0]


class Evidence:
    """A content-addressed evidence cache: one artefact, hashed once, cited many times."""

    def __init__(self) -> None:
        self._digests: dict[str, str] = {}

    def entry(self, path: Path, role: str, what: str) -> dict:
        key = rel(path)
        if key not in self._digests:
            self._digests[key] = sha256_file(path)
        return {
            "role": role,
            "path": key,
            "sha256": self._digests[key],
            "kind": _evidence_kind(key),
            "what": what,
        }

    def reference(self, path_str: str, role: str, what: str) -> dict:
        """An evidence entry from a committed citation, which may carry a `#fragment`."""
        return self.entry(REPO_ROOT / _strip_fragment(path_str), role, what)


def _authority_release() -> dict[str, str]:
    """`authority_id -> release_id` for every admitted authority node."""
    return {n["authority_id"]: n["release_id"] for n in load(AUTHORITY_NODES).get("nodes") or []}


def _census_index() -> dict[str, dict]:
    """`authority_id -> {census, path}` for every authority the parameterized census covers.

    The historical authorities carry a standalone `plane-census.json`; the production authority's
    census lives only in the parameterization receipt, so the receipt is its census evidence.
    """
    receipt = load(CENSUS_RECEIPT)
    index: dict[str, dict] = {}
    for aid, census in (receipt.get("censuses") or {}).items():
        standalone = ATLAS_ROOT / aid / "plane-census.json"
        index[aid] = {"census": census, "path": standalone if standalone.is_file() else CENSUS_RECEIPT}
    return index


def _census_plane(aid: str, plane_name: str) -> dict | None:
    """The named plane of an authority's census, or `None` when the authority carries no census."""
    entry = _census_index().get(aid)
    if entry is None:
        return None
    for plane in entry["census"].get("planes") or []:
        if plane.get("plane") == plane_name:
            return plane
    return None


def _facades() -> list[dict]:
    return list(load(ABI_FACADES).get("facades") or [])


def _facade(facade_id: str) -> dict | None:
    return next((f for f in _facades() if f.get("facade_id") == facade_id), None)


def _view_of(reference_id: str, dimension: str) -> str | None:
    """The id of the compatibility view for an authority and dimension, when one exists."""
    views = [v for v in load(COMPAT_VIEWS).get("views") or []
             if v.get("reference_id") == reference_id and v.get("dimension") == dimension]
    return sorted(v["view_id"] for v in views)[0] if views else None


def _latest_final_of_major(major: int) -> str | None:
    """The latest public mainline final release whose parsed major is `major`, from the catalogue."""
    candidates: list[tuple[tuple, str]] = []
    for node in load(CATALOG).get("nodes") or []:
        if node.get("release_channel") != "final" \
                or node.get("mainline_or_auxiliary") != "mainline":
            continue
        try:
            v = mts.parse_version(str(node["display_version"]))
        except mts.VersionError:
            continue
        if v.major == major:
            candidates.append((v.order_key(), str(node["release_id"])))
    if not candidates:
        return None
    return sorted(candidates)[-1][1]


def _symbol_record(symbols_path: Path, symbol: str) -> dict | None:
    """The record for a symbol in a committed symbols plane, or `None` when it is absent."""
    for rec in load(symbols_path).get("records") or []:
        if rec.get("symbol") == symbol:
            return rec
    return None


def _delta_rows() -> list[dict]:
    """Every classified row of the canonical 3.6.3 -> 3.6.4 edge delta."""
    body = load(DELTA)
    rows: list[dict] = []
    for receipt in body.get("receipts") or []:
        for classification in ("added", "changed", "removed"):
            for row in receipt.get(classification) or []:
                rows.append(row)
    return rows


def _symbols_path(authority_id: str, library: str) -> Path:
    return ATLAS_ROOT / authority_id / f"symbols-{library}.json"


def derive_body() -> dict:
    """The negative-obligation plane, a pure function of the committed evidence.

    Deterministic: every list is sorted, no wall-clock/environment value is read, and every
    obligation's state is the one `adjudicate` reads back from the evidence it names. The court
    re-derives this body through the same code and refuses a committed plane that does not
    reproduce.
    """
    ev = Evidence()
    auth_release = _authority_release()
    censuses = _census_index()

    drafts: dict[str, dict] = {}

    def add(obligation_id: str, kind: str, subject: str, subject_kind: str, dimension: str,
            scope: dict, rationale: str, role: str, evidence_entry: dict,
            check: dict, view_id: str | None = None) -> None:
        """Add or merge one obligation draft, keyed by its id.

        Merging is deliberate: the same surface may be established by two independent planes (a
        provider store by both its census and its architecture façade), and the merged record must
        carry both checks and both evidence entries rather than one silently winning.
        """
        rec = drafts.get(obligation_id)
        if rec is None:
            rec = {
                "obligation_id": obligation_id,
                "kind": kind,
                "subject": subject,
                "subject_kind": subject_kind,
                "dimension": dimension,
                "scope": scope,
                "expected_state": EXPECTED_STATE[kind],
                "rationale": rationale,
                "view_id": view_id,
                "checks": [],
                "evidence": {},
                "basis": [],
            }
            drafts[obligation_id] = rec
        rec["checks"].append(check)
        rec["evidence"][evidence_entry["path"]] = evidence_entry
        rec["basis"].append(check["rule"])

    # -- R1/R3: the provider planes, from each authority's census and its architecture façade. ----
    facade_by_authority = {f["authority_id"]: f for f in _facades()
                           if f.get("facade_kind") == "architecture"}
    node_role = "authority"
    for aid in sorted(censuses):
        entry = censuses[aid]
        rel_census = rel(entry["path"])
        census_ev = ev.entry(entry["path"], node_role,
                             "the authority's plane census, which measures its provider planes")
        for plane_name, subject in CENSUS_PLANES.items():
            plane = _census_plane(aid, plane_name)
            if plane is None:
                continue
            present = plane.get("status") == "produced" and int(plane.get("count") or 0) > 0
            kind = "must_exist" if present else "must_not_exist"
            absent = "present" if present else "absent"
            add(
                f"NO-{aid}-{kind}-{subject}",
                kind, subject, "surface", "provider_registration",
                {"authority_id": aid, "release_id": auth_release.get(aid)},
                f"the authority's `{plane_name}` plane is a measured {plane.get('status')} "
                f"(count {plane.get('count')}), so the {subject} surface must be {absent} in its view",
                node_role, census_ev,
                {"rule": "census-plane", "authority_id": aid, "plane": plane_name,
                 "evidence": [rel_census]},
                view_id=_view_of(aid, "provider_registration"),
            )

    # The architecture façade's provider model is an independent check on the same surface, and its
    # engine model is the one surface the census does not name.
    for aid in sorted(facade_by_authority):
        facade = facade_by_authority[aid]
        facade_ev = ev.entry(ABI_FACADES, node_role,
                             "the authority's architecture façade: its engine/provider model")
        pmodel = facade.get("provider_model")
        if pmodel == "provider_store":
            add(f"NO-{aid}-must_exist-provider-store", "must_exist", "provider-store", "surface",
                "provider_registration", {"authority_id": aid, "release_id": auth_release.get(aid)},
                "the authority's architecture façade records `provider_store`, so the provider "
                "store must exist in its view",
                node_role, facade_ev,
                {"rule": "architecture-provider", "facade_id": facade["facade_id"],
                 "authority_id": aid, "evidence": [rel(ABI_FACADES)]},
                view_id=_view_of(aid, "provider_registration"))
        elif pmodel == "no_provider":
            add(f"NO-{aid}-must_not_exist-provider-store", "must_not_exist", "provider-store",
                "surface", "provider_registration",
                {"authority_id": aid, "release_id": auth_release.get(aid)},
                "the authority's architecture façade records `no_provider`, so no provider store "
                "may exist in its view",
                node_role, facade_ev,
                {"rule": "architecture-provider", "facade_id": facade["facade_id"],
                 "authority_id": aid, "evidence": [rel(ABI_FACADES)]},
                view_id=_view_of(aid, "provider_registration"))
        emodel = facade.get("engine_model")
        if emodel in ENGINE_PRESENT_MODELS:
            add(f"NO-{aid}-must_exist-ENGINE", "must_exist", "ENGINE", "surface",
                "provider_registration", {"authority_id": aid, "release_id": auth_release.get(aid)},
                f"the authority's architecture façade records `{emodel}`, so the ENGINE surface "
                f"must exist in its view",
                node_role, facade_ev,
                {"rule": "architecture-engine", "facade_id": facade["facade_id"],
                 "authority_id": aid, "evidence": [rel(ABI_FACADES)]},
                view_id=_view_of(aid, "provider_registration"))
        elif emodel == "no_engine":
            add(f"NO-{aid}-must_not_exist-ENGINE", "must_not_exist", "ENGINE", "surface",
                "provider_registration", {"authority_id": aid, "release_id": auth_release.get(aid)},
                "the authority's architecture façade records `no_engine`, so the ENGINE surface "
                "must not exist in its view",
                node_role, facade_ev,
                {"rule": "architecture-engine", "facade_id": facade["facade_id"],
                 "authority_id": aid, "evidence": [rel(ABI_FACADES)]},
                view_id=_view_of(aid, "provider_registration"))

    # The ENGINE -> Provider -> no-ENGINE model's terminal epoch: a 4.x release is beyond every
    # admitted authority (the highest is the 3.6.4 `deprecated_engine` façade), so its view must not
    # retain ENGINE -- and no 4.x authority or view exists to check, so the obligation reads
    # `unknown` rather than satisfied.
    architecture_ev = ev.entry(ABI_FACADES, "model",
                               "the architecture model's highest measured epoch: the 3.6.4 "
                               "`deprecated_engine` façade")
    latest_4x = _latest_final_of_major(4)
    if latest_4x is not None:
        display = next(n["display_version"] for n in load(CATALOG)["nodes"]
                       if n["release_id"] == latest_4x)
        catalog_ev = ev.entry(CATALOG, "release",
                              "the release node beyond the highest measured authority epoch")
        add(
            f"NO-{latest_4x}-must_not_exist-ENGINE",
            "must_not_exist", "ENGINE", "surface", "provider_registration",
            {"release_id": latest_4x},
            f"the architecture model moves ENGINE -> Provider -> no-ENGINE; {display} is beyond the "
            f"highest measured authority epoch (3.6.4 `deprecated_engine`), so a 4.x view must not "
            f"retain the ENGINE surface. No 4.x authority or view is admitted, so the obligation "
            f"cannot be adjudicated and reads `unknown`",
            "model", architecture_ev,
            {"rule": "architecture-future", "release_id": latest_4x,
             "evidence": [rel(ABI_FACADES), rel(CATALOG)]},
        )
        drafts[f"NO-{latest_4x}-must_not_exist-ENGINE"]["evidence"].setdefault(
            catalog_ev["path"], catalog_ev)

    # -- R2: the public-layout epoch, from the layout façades. ------------------------------------
    for facade in _facades():
        if facade.get("facade_kind") != "public_layout":
            continue
        struct = facade["struct_name"]
        tag = facade.get("c_tag")
        facade_ev = ev.entry(ABI_FACADES, "authority",
                             f"the {struct} public-layout façade: its measured layout epoch")
        if facade.get("public_layout_epoch") == LAYOUT_PUBLIC:
            aid = facade["authority_id"]
            add(
                f"NO-{aid}-must_be_public-{struct}", "must_be_public", struct, "struct", "abi",
                {"authority_id": aid, "release_id": facade.get("release_id")},
                f"{struct} is measured `{LAYOUT_PUBLIC}` in {aid}: the pre-1.1.0 public `#[repr(C)]` "
                f"layout is transparent, so the struct must be public and must not be opaque in "
                f"its view",
                "authority", facade_ev,
                {"rule": "layout-epoch", "facade_id": facade["facade_id"],
                 "field": "public_layout_epoch", "authority_id": aid, "struct_tag": tag,
                 "evidence": [rel(ABI_FACADES)]},
                view_id=_view_of(aid, "abi"),
            )
        canonical_aid = facade.get("canonical_authority_id")
        canonical_tag = facade.get("canonical_c_tag")
        if facade.get("canonical_public_layout_epoch") == LAYOUT_OPAQUE and canonical_aid:
            structs_path = ATLAS_ROOT / canonical_aid / "structs.json"
            structs_ev = ev.entry(structs_path, "authority",
                                  f"the canonical authority's struct plane, which marks {struct} "
                                  f"incomplete (opaque)") if structs_path.is_file() else facade_ev
            oid = f"NO-{canonical_aid}-must_be_opaque-{struct}"
            add(
                oid, "must_be_opaque", struct, "struct",
                "abi", {"authority_id": canonical_aid,
                        "release_id": auth_release.get(canonical_aid)},
                f"{struct} is `{LAYOUT_OPAQUE}` in the canonical authority {canonical_aid} (the "
                f"1.1.0 opacity transition): the post-1.1.0 layout is opaque, so the struct must be "
                f"opaque and must not be public in its view",
                "authority", facade_ev,
                {"rule": "layout-epoch", "facade_id": facade["facade_id"],
                 "field": "canonical_public_layout_epoch", "authority_id": canonical_aid,
                 "struct_tag": canonical_tag,
                 "structs": rel(structs_path) if structs_path.is_file() else None,
                 "evidence": ([rel(ABI_FACADES), rel(structs_path)] if structs_path.is_file()
                              else [rel(ABI_FACADES)])},
                view_id=_view_of(canonical_aid, "abi"),
            )
            if structs_path.is_file():
                drafts[oid]["evidence"].setdefault(rel(structs_path), structs_ev)

    # -- R5/R7: the delta. An added entity is absent from the earlier authority and present in the
    # later one; a symbol the delta read as present in both must be exported by both. --------------
    delta_rel = rel(DELTA)
    delta_ev = ev.entry(DELTA, "pair", "the canonical 3.6.3 -> 3.6.4 edge delta")
    from_release = load(DELTA).get("from_release")
    to_release = load(DELTA).get("to_release")
    for row in _delta_rows():
        classification = row.get("classification")
        entity_id = str(row.get("entity_id") or "")
        name = entity_id.split(":", 1)[-1]
        kind_of_entity = "macro" if row.get("entity_kind") == "macro" else "symbol"
        if classification == "added" and row.get("dimension") == "api_presence":
            for side, obligation_kind in (("from", "must_not_exist"), ("to", "must_exist")):
                aid = row[f"{side}_id"]
                add(
                    f"NO-{aid}-{obligation_kind}-{name}", obligation_kind, name, kind_of_entity,
                    "source_api", {"authority_id": aid,
                                   "release_id": from_release if side == "from" else to_release},
                    f"`{name}` is added in {to_release} and absent from {from_release}: it must "
                    f"{'not ' if obligation_kind == 'must_not_exist' else ''}exist in {aid}'s view",
                    "pair", delta_ev,
                    {"rule": "delta-row", "delta": delta_rel, "row_id": row["row_id"],
                     "classification": classification, "side": side, "entity_id": entity_id,
                     "evidence": [delta_rel]},
                    view_id=_view_of(aid, "source_api"),
                )
        elif classification == "changed" and row.get("dimension") == "abi_symbol_presence" \
                and row.get("facet") == "st_size":
            libraries = sorted({Path(_strip_fragment(p)).stem.split("-")[-1]
                                for p in row.get("evidence") or [] if "symbols-" in p})
            for side in ("from", "to"):
                aid = row[f"{side}_id"]
                for library in libraries:
                    symbols_path = _symbols_path(aid, library)
                    if not symbols_path.is_file():
                        continue
                    add(
                        f"NO-{aid}-must_be_exported-{library}-{name}", "must_be_exported", name,
                        "symbol", "abi",
                        {"authority_id": aid,
                         "release_id": from_release if side == "from" else to_release},
                        f"the delta read `{name}` as an exported {library} symbol present in both "
                        f"{from_release} and {to_release}, so {aid} must export it",
                        "pair", delta_ev,
                        {"rule": "delta-row", "delta": delta_rel, "row_id": row["row_id"],
                         "classification": classification, "side": side, "entity_id": entity_id,
                         "evidence": [delta_rel]},
                        view_id=_view_of(aid, "abi"),
                    )
                    drafts[f"NO-{aid}-must_be_exported-{library}-{name}"]["evidence"].setdefault(
                        rel(symbols_path), ev.entry(symbols_path, "authority",
                                                    "the authority's exported-symbol plane"))

    # -- R6: deliberately unexported symbols, from the `.num` plane. ------------------------------
    for aid in sorted(auth_release):
        for library in ("libcrypto", "libssl"):
            symbols_path = _symbols_path(aid, library)
            if not symbols_path.is_file():
                continue
            plane = load(symbols_path)
            declared = (plane.get("explained_absences") or {}).get("declared_nonexistent") or []
            if not declared:
                continue
            symbols_ev = ev.entry(symbols_path, "authority",
                                  "the authority's symbols plane: the `.num` NOEXIST rows")
            for symbol in declared:
                add(
                    f"NO-{aid}-must_not_be_exported-{symbol}", "must_not_be_exported", symbol,
                    "symbol", "abi",
                    {"authority_id": aid, "release_id": auth_release.get(aid)},
                    f"the authority's `.num` declares `{symbol}` NOEXIST, so it must not be "
                    f"exported by {aid}'s view",
                    "authority", symbols_ev,
                    {"rule": "symbol-export", "authority_id": aid, "library": library,
                     "symbol": symbol, "evidence": [rel(symbols_path)]},
                    view_id=_view_of(aid, "abi"),
                )

    # -- finalize: derive each state from its own evidence, and sort. -----------------------------
    obligations: list[dict] = []
    for oid in sorted(drafts):
        rec = drafts[oid]
        checks = []
        seen_checks: set[tuple] = set()
        for check in rec["checks"]:
            key = (check["rule"], tuple(sorted((k, str(v)) for k, v in check.items()
                                               if k != "evidence")))
            if key in seen_checks:
                continue
            seen_checks.add(key)
            checks.append(check)
        record = {
            "obligation_id": rec["obligation_id"],
            "kind": rec["kind"],
            "subject": rec["subject"],
            "subject_kind": rec["subject_kind"],
            "dimension": rec["dimension"],
            "scope": rec["scope"],
            "expected_state": rec["expected_state"],
            "view_id": rec["view_id"],
            "rationale": rec["rationale"],
            "evidence": [rec["evidence"][p] for p in sorted(rec["evidence"])],
            "derivation": {"checks": checks, "rules": sorted(set(rec["basis"]))},
        }
        state, _detail = adjudicate(record)
        record["state"] = state
        obligations.append(record)

    by_kind: dict[str, int] = {}
    by_state: dict[str, int] = {}
    by_authority: dict[str, int] = {}
    for o in obligations:
        by_kind[o["kind"]] = by_kind.get(o["kind"], 0) + 1
        by_state[o["state"]] = by_state.get(o["state"], 0) + 1
        scope = o["scope"]
        aid = scope.get("authority_id") if isinstance(scope, dict) else None
        key = aid or (scope.get("release_id") if isinstance(scope, dict) else str(scope))
        if key:
            by_authority[key] = by_authority.get(key, 0) + 1

    authorities = sorted({o["scope"]["authority_id"] for o in obligations
                          if isinstance(o["scope"], dict) and o["scope"].get("authority_id")})
    releases = sorted({o["scope"]["release_id"] for o in obligations
                       if isinstance(o["scope"], dict) and o["scope"].get("release_id")})

    return {
        "rule": (
            "one negative or positive obligation per surface a named authority or release must "
            "(not) carry, derived from the committed censuses, façades, deltas and symbols planes "
            "and never typed. Each record names its scope, subject, kind and expected state, and "
            "carries the evidence that establishes it; `state` is the reading `adjudicate` takes "
            "from that evidence -- `satisfied` where it affirms the obligation, `open` where it "
            "contradicts it, and `unknown` only where no authority or view exists to adjudicate it"
        ),
        "kinds": list(mts.NEGATIVE_OBLIGATION_KINDS),
        "states": list(mts.NEGATIVE_OBLIGATION_STATES),
        "expected_state_of_kind": dict(EXPECTED_STATE),
        "authorities": authorities,
        "releases": releases,
        "counts": {
            "obligations": len(obligations),
            "by_kind": {k: by_kind[k] for k in sorted(by_kind)},
            "by_state": {k: by_state[k] for k in sorted(by_state)},
            "by_authority": {k: by_authority[k] for k in sorted(by_authority)},
            "negative": sum(1 for o in obligations if o["kind"] in NEGATIVE_KINDS),
            "positive": sum(1 for o in obligations if o["kind"] in POSITIVE_KINDS),
            "open": by_state.get("open", 0),
            "unknown": by_state.get("unknown", 0),
        },
        "obligations": obligations,
        "content_hash": content_hash(obligations),
        "non_claims": list(NON_CLAIMS),
        "boundary": (
            "23.13 derives the obligations the committed evidence supports: the provider planes of "
            "every censused authority, the public-layout and architecture façades, the 3.6.3 -> "
            "3.6.4 delta's added entities and measured exports, and each authority's `.num` NOEXIST "
            "rows. A 4.x release carries no admitted authority or view, so its ENGINE obligation "
            "reads `unknown` rather than satisfied. An obligation is bounded to the authority or "
            "release it names; no obligation inherits another authority's evidence."
        ),
    }


def _run_check(check: dict, kind: str) -> tuple[str, str]:
    """The state one derivation check reads from the committed evidence it names."""
    rule = check.get("rule")
    if rule == "census-plane":
        plane = _census_plane(check["authority_id"], check["plane"])
        if plane is None:
            return "unknown", f"census plane {check['plane']!r} is absent"
        present = plane.get("status") == "produced" and int(plane.get("count") or 0) > 0
        required = kind == "must_exist"
        ok = present == required
        return ("satisfied" if ok else "open"), (
            f"census plane {check['plane']!r} is {plane.get('status')} (count {plane.get('count')})"
        )
    if rule == "layout-epoch":
        facade = _facade(check["facade_id"])
        if facade is None:
            return "unknown", f"façade {check['facade_id']!r} is absent"
        value = facade.get(check["field"])
        if kind == "must_be_public":
            ok = value == LAYOUT_PUBLIC
            return ("satisfied" if ok else "open"), f"{check['field']}={value!r}"
        if kind == "must_be_opaque":
            ok = value == LAYOUT_OPAQUE
            structs = check.get("structs")
            if ok and structs:
                rec = next((s for s in load(REPO_ROOT / structs).get("records") or []
                            if s.get("name") == check.get("struct_tag")), None)
                if rec is not None and rec.get("complete"):
                    ok = False
                    value = f"{value}, but {check['struct_tag']} is complete"
            return ("satisfied" if ok else "open"), f"{check['field']}={value!r}"
        return "unknown", "layout check has no kind"
    if rule == "architecture-engine":
        facade = _facade(check["facade_id"])
        if facade is None:
            return "unknown", f"façade {check['facade_id']!r} is absent"
        value = facade.get("engine_model")
        present = value in ENGINE_PRESENT_MODELS
        required = kind == "must_exist"
        return ("satisfied" if present == required else "open"), f"engine_model={value!r}"
    if rule == "architecture-provider":
        facade = _facade(check["facade_id"])
        if facade is None:
            return "unknown", f"façade {check['facade_id']!r} is absent"
        value = facade.get("provider_model")
        present = value == "provider_store"
        required = kind == "must_exist"
        return ("satisfied" if present == required else "open"), f"provider_model={value!r}"
    if rule == "architecture-future":
        return "unknown", (
            f"no admitted authority or view exists for {check['release_id']}, so the obligation "
            f"cannot be adjudicated"
        )
    if rule == "delta-row":
        row = next((r for r in _delta_rows() if r.get("row_id") == check["row_id"]), None)
        if row is None:
            return "unknown", f"delta row {check['row_id']!r} is absent"
        classification = row.get("classification")
        present_in = {"added": {"to"}, "changed": {"from", "to"},
                      "removed": {"from"}}.get(classification, set())
        present = check["side"] in present_in
        required = kind in ("must_exist", "must_be_exported")
        return ("satisfied" if present == required else "open"), (
            f"delta row {classification} in {check['side']} side"
        )
    if rule == "symbol-export":
        rec = _symbol_record(_symbols_path(check["authority_id"], check["library"]),
                             check["symbol"])
        if rec is None:
            return "unknown", f"symbol {check['symbol']!r} is absent from the plane"
        present = bool((rec.get("dso") or {}).get("present"))
        status = (rec.get("num") or {}).get("status")
        if kind == "must_not_be_exported":
            ok = (not present) and status == "NOEXIST"
            return ("satisfied" if ok else "open"), (
                f"dso.present={present}, num.status={status!r}"
            )
        ok = present
        return ("satisfied" if ok else "open"), f"dso.present={present}"
    return "unknown", f"unknown rule {rule!r}"


def adjudicate(record: dict) -> tuple[str, str]:
    """The state the record's own evidence establishes, recomputed from the committed artefacts.

    The court calls this for every committed record, so a state that was typed rather than read
    fails. `open` dominates (a violated obligation is a compatibility defect), then `satisfied` when
    every check holds; otherwise the record is `unknown`.
    """
    checks = (record.get("derivation") or {}).get("checks") or []
    if not checks:
        return "unknown", "the record carries no derivation check"
    states: list[str] = []
    details: list[str] = []
    for check in checks:
        state, detail = _run_check(check, record.get("kind"))
        states.append(state)
        details.append(f"{check.get('rule')}: {detail}")
    if any(s == "open" for s in states):
        return "open", "; ".join(details)
    if all(s == "satisfied" for s in states):
        return "satisfied", "; ".join(details)
    return "unknown", "; ".join(details)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    body = derive_body()

    for record in body["obligations"]:
        problems = mts.validate_negative_obligation(record)
        if problems:
            raise SystemExit(
                f"negative-obligations: derived obligation {record['obligation_id']} is not "
                f"schema-valid: {problems}"
            )

    inputs = [
        InputRef(name="release-catalog", path=CATALOG),
        InputRef(name="authority-nodes", path=AUTHORITY_NODES),
        InputRef(name="parameterization-receipt", path=CENSUS_RECEIPT),
        InputRef(name="abi-facades", path=ABI_FACADES),
        InputRef(name="compatibility-views", path=COMPAT_VIEWS),
        InputRef(name="delta-3.6.3-3.6.4", path=DELTA),
    ]
    doc = envelope(kind="negative-obligations", authority=auth.id, inputs=inputs, body=body,
                   generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[negative-obligations] {c['obligations']} obligation(s): {c['by_kind']}; "
          f"state={c['by_state']}; positive={c['positive']} negative={c['negative']}")
    print(f"  authorities: {', '.join(body['authorities'])}")
    for o in body["obligations"]:
        scope = o["scope"]
        where = scope.get("authority_id") or scope.get("release_id") if isinstance(scope, dict) \
            else scope
        print(f"  {o['state']:<9} {o['kind']:<20} {o['subject']:<44} {where}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
