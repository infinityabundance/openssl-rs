#!/usr/bin/env python3
"""openssl-rs — shared atlas infrastructure.

Common utilities for the Phase 1 archaeology generators. Every atlas generator
in forensics/tools/ imports this module so that provenance, determinism and
authority binding are enforced in one place rather than re-implemented (and
diverging) per generator.

Determinism contract
--------------------
Atlas files are *derived evidence* and must be reproducible byte-for-byte from
(a) the admitted authorities and (b) the generator sources. Therefore:

  * no wall-clock time, PID, hostname, absolute path or environment value is
    ever written into an atlas file;
  * JSON is emitted with sort_keys=True and a trailing newline;
  * all inputs are content-addressed and their hashes recorded in the file;
  * any set-like structure is emitted as a sorted list.

Wall-clock and environment belong in *captures* and *receipts* (the record of
an execution event), never in the derived atlas.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
FORENSICS = REPO_ROOT / "forensics"
AUTH_ROOT = FORENSICS / "authorities"
ATLAS = FORENSICS / "atlas"
CUSTOMER_ROOT = FORENSICS
REGISTRY = AUTH_ROOT / "AUTHORITIES.json"
BUILD_RECORDS = ATLAS / "BUILD_RECORDS.json"

# The Phase-23 multitrack plane: the committed default-authority alias and the historical
# acquisition / build registries live here.
MULTITRACK = FORENSICS / "multitrack"

# A ledger whose obligations are not exports declares its `body.unit` here, and the tools that
# partition the *export* universe (`court_coverage.py`, `ownership_audit.py`) skip it. Phase 22
# owns no `libcrypto` symbol -- its unit is a *compatibility plane* and its `implemented` list
# names subphases -- so a ledger that counted symbols would count zero. **Phase 16 owns no export
# either**: the ownership atlas assigns `owner_phase == 16` no row, and its unit is the CLI /
# config / filesystem contract over 39 provider registration rows, six prerequisite deferrals and
# three contract units, which a symbol-counting ledger would count zero. **Phase 17 owns no export
# either**: the ownership atlas assigns `owner_phase == 17` no row, and its unit is the downstream
# replacement contract over the 52 `apps/<name>.c` command unit deferrals and four contract units,
# which a symbol-counting ledger would count zero. **Phase 18 owns no export either**: the
# ownership atlas assigns `owner_phase == 18` no row, and its unit is the hostile hardening
# contract over five contract units and no deferral, which a symbol-counting ledger would count
# zero. **Phase 19 owns no export either**: the ownership atlas assigns `owner_phase == 19` no
# row, and its unit is the performance dispatch contract over five contract units and no
# deferral, which a symbol-counting ledger would count zero. **Phase 20 owns no export either**:
# zero. **Phase 20 owns no export either**:
# the ownership atlas assigns `owner_phase == 20` no row, and its unit is the custodian seal
# contract over five contract units and no deferral, which a symbol-counting ledger would count
# zero. **Phase 21 owns no export either**: the ownership atlas assigns `owner_phase == 21` no
# row, and its unit is the maintenance delta contract over five contract units and no deferral,
# which a symbol-counting ledger would count zero. **Phase 23 owns no export either**: the
# ownership atlas assigns `owner_phase == 23` no row, and its unit is the multitrack authority
# contract over twelve contract units and no deferral, which a symbol-counting ledger would
# count zero. **Phase 24 owns no export either**: the ownership atlas assigns `owner_phase == 24`
# no row, and its unit is the downstream 1000 contract over sixteen contract units and no
# deferral, which a symbol-counting ledger would count zero. The marker is a property
# of the document rather than a phase number those tools know (`docs/PHASE-22-SUBPHASES.md`, D485;
# `docs/PHASE-16-SUBPHASES.md`, section 1; `docs/PHASE-17-SUBPHASES.md`, section 1;
# `docs/PHASE-18-SUBPHASES.md`, section 1; `docs/PHASE-19-SUBPHASES.md`, section 1;
# `docs/PHASE-20-SUBPHASES.md`, section 1; `docs/PHASE-21-SUBPHASES.md`, section 1;
# `docs/PHASE-23-MULTITRACK-SUBPHASES.md`, section 1;
# `docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md`, section 1).
NON_EXPORT_UNITS = {
    "compatibility plane",
    "cli-config contract",
    "downstream replacement contract",
    "hostile hardening contract",
    "performance dispatch contract",
    "custodian seal contract",
    "maintenance delta contract",
    "multitrack authority contract",
    "downstream 1000 contract",
}
HISTORICAL_AUTHORITY = "openssl-3.6.3-historical"

# Which seal document belongs to which stratum, where one exists. **One table, because two tools
# read it and had drifted apart.** `render_seal_census.py` carried a copy that knew phases 3-7 and
# `phase_state.py` carried a copy that knew only phases 1-2, so the two tools -- which mean the
# same thing by a seal's identity -- disagreed about which strata are sealed. The consequence was
# measured: `docs/PHASE-3-CORE-RUNTIME-SEAL.md` through `docs/PHASE-7-EVP-SEAL.md` were all on
# disk, the census named every one of them, and `forensics/phase-state.json` recorded
# `seal_sha256: null` for phases 3 through 7 because `phase_state.py` never learned they existed.
# A derived record silently contradicting a generated census is exactly the class of gap where
# nothing objected because nothing looked, so the table lives here and both tools read it.
#
# A stratum with no entry -- or whose document has not landed yet -- is not an error: the census
# prints `none written yet` and `phase_state.py` records `null`, because a missing seal is a fact
# about the tree rather than a failure to read it. The table covers every stratum whose document
# exists or is being written; later strata are deliberately absent until theirs land. See
# docs/DECISIONS.md D97 for why the seal census is one generated document the seals cite.
SEAL_DOCS: dict[int, str] = {
    1: "docs/PHASE-1-ARCHAEOLOGY-SEAL.md",
    2: "docs/PHASE-2-DISTRIBUTION-SEAL.md",
    3: "docs/PHASE-3-CORE-RUNTIME-SEAL.md",
    4: "docs/PHASE-4-BIO-CONF-SEAL.md",
    5: "docs/PHASE-5-BN-ASN1-PEM-SEAL.md",
    6: "docs/PHASE-6-PROVIDER-SEAL.md",
    7: "docs/PHASE-7-EVP-SEAL.md",
    8: "docs/PHASE-8-CRYPTO-SEAL.md",
    9: "docs/PHASE-9-RAND-DRBG-SEAL.md",
    10: "docs/PHASE-10-KEYFORMATS-SEAL.md",
    11: "docs/PHASE-11-X509-SEAL.md",
    12: "docs/PHASE-12-PROTOCOL-FAMILIES-SEAL.md",
    13: "docs/PHASE-13-LEGACY-SEAL.md",
    14: "docs/PHASE-14-TLS-SEAL.md",
    15: "docs/PHASE-15-QUIC-SEAL.md",
    16: "docs/PHASE-16-CLI-SEAL.md",
    17: "docs/PHASE-17-DOWNSTREAM-SEAL.md",
    18: "docs/PHASE-18-HARDENING-SEAL.md",
    19: "docs/PHASE-19-PERFORMANCE-SEAL.md",
    20: "docs/PHASE-20-CUSTODIAN-SEAL.md",
    21: "docs/PHASE-21-MAINTENANCE-SEAL.md",
    # Phase 22 is an atlas stratum rather than an export stratum, but its seal is the same kind of
    # document and `phase_state.py` records its sha256 the same way. Its `evidence_for` branch is
    # its own because its ledger's unit is a compatibility plane, not a symbol (D485).
    22: "docs/PHASE-22-ATLAS-SEAL.md",
    # Phase 23 is another non-export stratum (its unit is the multitrack authority contract), so it
    # too is read by the generic `STRATUM_EVIDENCE` rule. Its seal is named from the day 23.0 lands
    # the plan, so its absence is the record that the stratum is still open rather than a missing
    # table row.
    23: "docs/PHASE-23-MULTITRACK-SEAL.md",
    # Phase 24 is another non-export stratum (its unit is the downstream 1000 contract), so it too
    # is read by the generic `STRATUM_EVIDENCE` rule. Its seal is named from the day 24.0 lands the
    # plan, so its absence is the record that the stratum is still open rather than a missing table
    # row.
    24: "docs/PHASE-24-DOWNSTREAM-1000-SEAL.md",
}


class AtlasError(RuntimeError):
    """Fatal condition: the generator cannot produce trustworthy evidence."""


class EvidenceError(AtlasError):
    """A committed evidence record contradicts itself or the tool that reads it.

    Separate from `AtlasError` so a caller can tell "the atlas is missing" from "the
    evidence says two different things", which are different failures with different
    repairs.
    """


# ---------------------------------------------------------------------------
# the default-authority alias (Phase 23.3)
# ---------------------------------------------------------------------------
#
# The Phase 1 / Phase 22 archaeology generators are parameterized by authority identity -- there
# is one generator per plane, not a `phase1_old.py` per version -- and a generator invoked with no
# `--authority` selects the **maintained** authority through this committed alias. The default is
# therefore a file a reader can review, and it is deliberately **not** the catalogue's
# `latest-stable` alias (`openssl-4.0.3`, a newer compatibility profile the candidate does not
# target) and not "the newest admitted build". See forensics/multitrack/default-authority.json.
#
# `PRODUCTION_AUTHORITY` is derived from the alias rather than typed a second time, so the
# thirty-nine or so call sites that default to it cannot drift from the one committed choice.
DEFAULT_AUTHORITY_FILE = MULTITRACK / "default-authority.json"


def load_default_authority() -> dict:
    """The committed default-authority alias, or a fail-closed error.

    An absent or malformed alias is fatal rather than defaulted to a literal: a missing file
    would otherwise silently re-introduce the very second source of truth this file removes.
    """
    if not DEFAULT_AUTHORITY_FILE.is_file():
        raise AtlasError(
            f"the default-authority alias {rel(DEFAULT_AUTHORITY_FILE)} is absent; the "
            f"parameterized generators have no explicit default"
        )
    doc = json.loads(DEFAULT_AUTHORITY_FILE.read_text(encoding="utf-8"))
    body = doc.get("body", doc)
    authority_id = body.get("authority_id")
    if not isinstance(authority_id, str) or not authority_id:
        raise AtlasError(
            f"the default-authority alias {rel(DEFAULT_AUTHORITY_FILE)} names no authority_id"
        )
    return body


def default_authority_id() -> str:
    """The authority id the parameterized generators default to, read from the committed alias."""
    return str(load_default_authority()["authority_id"])


# The maintained authority. Derived from the committed alias, never typed twice (D538).
PRODUCTION_AUTHORITY = default_authority_id()


# ---------------------------------------------------------------------------
# the one reading of a court's observation count
# ---------------------------------------------------------------------------

def has_transcript(row: dict) -> bool:
    """Whether a court record compares two *transcripts*, or something else entirely.

    Both kinds are courts and both are evidence. The Phase 2 ABI courts compare ELF
    structures -- symbol tables, dynamic tags, layouts -- and produce no transcript at
    all, so they carry no observation counts; every court from Phase 3 on compiles a C
    probe twice and diffs `key=value` lines, so it carries two counts that must agree.
    Telling the two apart is what stops "this court has no transcript" from being read
    as "this court observed nothing".
    """
    return "authority_observations" in row or "candidate_observations" in row


def court_observations(row: dict) -> int:
    """The number of observations a court record establishes, and the invariant behind it.

    **One accessor, because two tools read a field that does not exist.** The seal census
    read `row.get("observations", 0)` and the court runner read the same, so every runtime
    court was rendered with **0** observations in `docs/SEAL-CENSUS.md` while its manifest
    said 124 or 1,162 -- a generated document that understated the evidence by three orders
    of magnitude and looked entirely plausible doing it. The field is
    `authority_observations`; the candidate's own count is the second half of the same
    fact, and a transcript court whose two sides disagree is a record that cannot be true,
    because the comparison is line-wise over both.

    A court with no transcript answers **0** and is not an error -- but it answers 0 for
    that reason and not by defaulting, which is why `has_transcript` exists beside this.
    """
    a = row.get("authority_observations")
    c = row.get("candidate_observations")
    if a is None and c is None:
        return 0
    if a is None or c is None:
        raise EvidenceError(
            f"court {row.get('court')!r} carries only one of "
            f"authority_observations/candidate_observations: a transcript court needs both "
            f"(authority={a!r}, candidate={c!r})"
        )
    a, c = int(a), int(c)
    if a != c:
        raise EvidenceError(
            f"court {row.get('court')!r} has {a} authority observations and {c} candidate "
            f"observations: the comparison is line-wise over both transcripts, so a "
            f"difference here is a record that cannot be true"
        )
    return a


def contract_unit_lines(ledger_body: dict) -> list[str]:
    """Markdown lines for a ledger's contract-unit block, or `[]` when it has none.

    A contract unit has **two** axes, and a renderer that showed only one would let a passing
    court read as a claim about the security property the unit names. `measurement_state` is the
    instrument's state; `property_status` and `findings` are the property's. For the
    `constant-time` unit the property is `NOT_CLAIMED` while its court records the two BN paths
    as `separated` findings, so every surface that summarises units says so explicitly. Shared by
    `render_seal_census.py` and `render_status.py` so the two cannot drift.
    """
    units = ledger_body.get("contract_units") or []
    if not units:
        return []
    lines = ["Contract units (measurement vs property):", "",
             "| unit | measurement_state | property_status | findings |",
             "|---|---|---|---|"]
    for u in units:
        findings = u.get("findings") or []
        rendered = ", ".join(f"`{f}`" for f in findings) or "—"
        lines.append(f"| {u.get('unit')} | `{u.get('measurement_state')}` | "
                     f"`{u.get('property_status')}` | {rendered} |")
    lines += [
        "",
        "A `complete` measurement means the unit's court ran and its control was honest. It is "
        "**not** a claim that the security property the unit names is achieved: where a property "
        "is measured and the court recorded findings, the property reads `NOT_CLAIMED` with "
        "`findings_present` and the findings are named above.",
    ]
    return lines


# ---------------------------------------------------------------------------
# hashing / canonicalisation
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


IMPLEMENTED_SURFACE = FORENSICS / "atlas" / "implemented-surface.json"


def implemented_surface_input() -> InputRef:
    """The implemented surface as an *evidence* input, for the obligation ledgers.

    Bound by `body_hash`, not by the file digest. The artefact also records
    build-product observations (the archive digest, the compiler-emitted symbol
    count), so its file digest is not reproducible across machines; binding it
    would push a build product into every ledger that consumes the surface.
    `body_hash` is computed over the evidence subset of the body, so it is a
    function of committed inputs only. See docs/DECISIONS.md D30.
    """
    doc = json.loads(IMPLEMENTED_SURFACE.read_text(encoding="utf-8"))
    return InputRef(
        name="implemented-surface",
        sha256=doc["body_hash"],
        note=(
            "evidence digest (body_hash) of forensics/atlas/implemented-surface.json; "
            "the artefact's file digest is deliberately not used because the file "
            "also records build-product observations"
        ),
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Canonical JSON used for content-addressing derived objects."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(obj: Any) -> str:
    return sha256_bytes(canonical_json(obj).encode("utf-8"))


def write_json(path: Path, obj: Any) -> str:
    """Write an atlas file deterministically. Returns its sha256."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")
    return sha256_bytes(text.encode("utf-8"))


def write_text(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not text.endswith("\n"):
        text += "\n"
    path.write_text(text, encoding="utf-8")
    return sha256_bytes(text.encode("utf-8"))


def rel(path: Path) -> str:
    """Repository-relative POSIX path, or the absolute path if outside."""
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def authority_atlas_dir(authority_id: str) -> Path:
    """Atlas output directory for one authority.

    The atlas is scoped per authority rather than flat, because a claim is
    always made *of a specific authority*. A flat layout would silently let the
    last-generated authority overwrite the evidence of an earlier one.
    """
    return ATLAS / authority_id


# ---------------------------------------------------------------------------
# subprocess
# ---------------------------------------------------------------------------

@dataclass
class CmdResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(
    argv: list[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
) -> CmdResult:
    proc = subprocess.run(
        argv, cwd=str(cwd) if cwd else None, env=env,
        capture_output=True, text=True, check=False,
    )
    return CmdResult(argv=argv, returncode=proc.returncode,
                     stdout=proc.stdout, stderr=proc.stderr)


def must_run(
    argv: list[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
) -> CmdResult:
    res = run(argv, cwd=cwd, env=env)
    if not res.ok:
        raise AtlasError(
            f"command failed ({res.returncode}): {' '.join(argv)}\n{res.stderr.strip()}"
        )
    return res


# ---------------------------------------------------------------------------
# authority + build records
# ---------------------------------------------------------------------------

def load_registry() -> dict:
    if not REGISTRY.exists():
        raise AtlasError(f"authority registry missing: {REGISTRY}")
    return json.loads(REGISTRY.read_text())


def load_build_records() -> dict[str, dict]:
    if not BUILD_RECORDS.exists():
        raise AtlasError(
            f"build records missing: {BUILD_RECORDS}; run authority_build.py first"
        )
    data = json.loads(BUILD_RECORDS.read_text())
    return {b["id"]: b for b in data.get("builds", [])}


def authority_source(authority_id: str) -> Path:
    reg = load_registry()
    for a in reg["authorities"]:
        if a["id"] == authority_id:
            return REPO_ROOT / a["source_tree"]["path"]
    hist = historical_authority(authority_id)
    if hist is not None:
        return hist.source
    raise AtlasError(f"authority not admitted: {authority_id}")


def authority_prefix(authority_id: str) -> Path:
    builds = load_build_records()
    if authority_id in builds:
        return REPO_ROOT / builds[authority_id]["prefix"]
    hist = historical_authority(authority_id)
    if hist is not None:
        return hist.prefix
    raise AtlasError(f"authority not built: {authority_id}")


def authority_build_dir(authority_id: str) -> Path:
    builds = load_build_records()
    if authority_id in builds:
        return REPO_ROOT / builds[authority_id]["build_dir"]
    # A historical authority is built by `historical_build.py`, which installs under
    # authorities/build/<id> and records only the prefix; the build directory follows the
    # venue's own convention, and is present whenever the historical build is present.
    hist = historical_authority(authority_id)
    if hist is not None:
        return AUTH_ROOT / "build" / hist.id
    raise AtlasError(f"authority not built: {authority_id}")


# ---------------------------------------------------------------------------
# historical authorities (the separately pinned venue)
# ---------------------------------------------------------------------------
#
# Phase 23.2 admits historical releases as archaeology in a separate venue; their acquisition and
# build records are committed (`historical-acquisition.json`, `historical-build-receipts.json`)
# while the source tree and prefix they describe are local build products, exactly as for the
# court authorities. `resolve_authority` therefore reads both registries, so the same parameterized
# generator serves an admitted court authority and a built historical authority without a bespoke
# script. `all_authority_ids` keeps its old court-only default so the atlas `--all` walk is
# unchanged; `all_known_authority_ids` is the merged set.
HISTORICAL_ACQUISITION = MULTITRACK / "historical-acquisition.json"
HISTORICAL_BUILD_RECEIPTS = MULTITRACK / "historical-build-receipts.json"


def _load_json_or_empty(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def historical_authority(authority_id: str) -> "Optional[HistoricalAuthority]":
    """The historical authority for an id, or `None` when the registries do not name it.

    A release is an authority only once it is both acquired and built: an acquisition with no
    build receipt has no prefix for a court to be run against, so it is not resolved.
    """
    acq_doc = _load_json_or_empty(HISTORICAL_ACQUISITION)
    receipts_doc = _load_json_or_empty(HISTORICAL_BUILD_RECEIPTS)
    rec = next((a for a in acq_doc.get("acquisitions", []) if a.get("id") == authority_id),
               None)
    if rec is None:
        return None
    receipt = next((r for r in receipts_doc.get("receipts", []) if r.get("id") == authority_id),
                   None)
    if receipt is None or receipt.get("outcome") != "built":
        return None
    return HistoricalAuthority(
        id=rec["id"],
        release_id=rec["release_id"],
        version=rec["version"],
        source=REPO_ROOT / rec["source_tree"]["path"],
        prefix=REPO_ROOT / "forensics" / "authorities" / "prefix" / rec["id"],
    )


@dataclass
class HistoricalAuthority:
    """A historical authority resolved from its committed acquisition + build receipts."""

    id: str
    release_id: str
    version: str
    source: Path
    prefix: Path


def historical_authority_ids() -> list[str]:
    """The historical authorities that are both acquired and built."""
    acq_doc = _load_json_or_empty(HISTORICAL_ACQUISITION)
    return sorted(a["id"] for a in acq_doc.get("acquisitions", []) if a.get("id"))


@dataclass
class Authority:
    """An admitted + built authority, resolved to concrete paths."""

    id: str
    version: str
    role: str
    source: Path
    prefix: Path

    @property
    def libdir(self) -> Path:
        for cand in ("lib", "lib64"):
            if (self.prefix / cand).is_dir():
                return self.prefix / cand
        return self.prefix / "lib"

    def dso(self, name: str) -> Path:
        # Prefer the versioned runtime object (libcrypto.so.3), falling back to
        # the linker name (libcrypto.so). A historical authority's soname carries its own era
        # (`libcrypto.so.0.9.8`), so the glob is the last resort rather than a typed list.
        for cand in (f"{name}.so.3", f"{name}.so"):
            p = self.libdir / cand
            if p.exists() or p.is_symlink():
                return p
        for p in sorted(self.libdir.glob(f"{name}.so.*")):
            if not p.is_symlink():
                return p
        raise AtlasError(f"{self.id}: {name} not found under {self.libdir}")


def resolve_authority(authority_id: str) -> Authority:
    reg = load_registry()
    rec = next((a for a in reg["authorities"] if a["id"] == authority_id), None)
    if rec is not None:
        return Authority(
            id=rec["id"],
            version=rec["version"],
            role=rec["role"],
            source=REPO_ROOT / rec["source_tree"]["path"],
            prefix=authority_prefix(authority_id),
        )
    hist = historical_authority(authority_id)
    if hist is not None:
        return Authority(
            id=hist.id,
            version=hist.version,
            role="historical",
            source=hist.source,
            prefix=hist.prefix,
        )
    raise AtlasError(f"authority not admitted: {authority_id}")


def all_authority_ids(include_historical: bool = False) -> list[str]:
    """The authority ids a generator's `--all` walk covers.

    The default is the admitted court authorities, so `--all` in the Phase 1 / Phase 22 pipeline
    keeps its contract and does not silently acquire a historical release. `include_historical`
    merges the built historical authorities in, which is what the Phase-23 parameterization proof
    reads.
    """
    reg = load_registry()
    ids = {a["id"] for a in reg["authorities"]}
    if include_historical:
        ids |= set(historical_authority_ids())
    return sorted(ids)


def all_known_authority_ids() -> list[str]:
    """Every authority a court can be run against: the court-admitted set plus the historical."""
    return all_authority_ids(include_historical=True)


# ---------------------------------------------------------------------------
# one place for a generator's authority selection
# ---------------------------------------------------------------------------

def add_authority_selector(parser: "Any", *, multi: bool = False) -> None:
    """Add the standard authority selection to an `argparse` parser.

    A single-authority generator adds `--authority` (defaulting through the committed alias); a
    multi-authority generator additionally adds `--all`. Centralised here so the default is the
    alias everywhere, and a generator cannot quietly choose "the newest".
    """
    if multi:
        parser.add_argument("--authority", action="append", default=[],
                            help="authority id to process (repeatable)")
        parser.add_argument("--all", action="store_true",
                            help="process every admitted court authority")
    else:
        parser.add_argument("--authority", default=None,
                            help="authority id (default: the committed default-authority alias)")


def selected_authority(args: "Any") -> str:
    """The one authority a single-authority generator was asked for."""
    aid = getattr(args, "authority", None)
    return str(aid) if aid else default_authority_id()


def selected_authorities(args: "Any") -> list[str]:
    """The authorities a multi-authority generator was asked for."""
    ids = list(getattr(args, "authority", []) or [])
    if getattr(args, "all", False):
        ids = all_authority_ids()
    if not ids:
        return [default_authority_id()]
    return sorted(set(ids))


# ---------------------------------------------------------------------------
# atlas document envelope
# ---------------------------------------------------------------------------

@dataclass
class InputRef:
    """A content-addressed input to an atlas document."""

    name: str
    path: Optional[Path] = None
    sha256: Optional[str] = None
    note: Optional[str] = None

    def resolved(self) -> dict:
        out: dict[str, Any] = {"name": self.name}
        if self.path is not None:
            out["path"] = self.path.relative_to(REPO_ROOT).as_posix()
            if self.sha256 is None:
                out["sha256"] = sha256_file(self.path)
            else:
                out["sha256"] = self.sha256
        if self.sha256 is not None and self.path is None:
            out["sha256"] = self.sha256
        if self.note:
            out["note"] = self.note
        return out


def envelope(kind: str, generator: str, inputs: Iterable[InputRef],
             body: dict, *, authority: Optional[str] = None) -> dict:
    """Wrap a generator body in the standard atlas document envelope.

    Keeping the envelope uniform is what lets atlas_reconcile.py compare
    inventories across evidence planes without special-casing each file.
    """
    doc: dict[str, Any] = {
        "schema": f"openssl-rs/atlas/{kind}/v1",
        "kind": kind,
        "generator": generator,
        "inputs": [i.resolved() for i in inputs],
        "body": body,
    }
    if authority:
        doc["authority"] = authority
    return doc


# ---------------------------------------------------------------------------
# .num file parsing (util/libcrypto.num, util/libssl.num)
# ---------------------------------------------------------------------------

_NUM_LINE = re.compile(
    r"^(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s+(?P<ordinal>[0-9]+)"
    r"\s+(?P<version>[0-9A-Za-z_]+)"
    r"(?:\s+(?P<condition>\S+.*?))?"
    r"\s*$"
)


@dataclass
class NumEntry:
    """One line of an OpenSSL linker `.num` inventory.

    The condition field grammar (as produced by util/mkdef.pl) is four
    colon-separated fields, any of which after the first may be empty:

        STATUS : PLATFORM : KIND : CONDS

    Examples observed in util/libcrypto.num:

        EXIST::FUNCTION:DEPRECATEDIN_3_0,EC      status=EXIST platform=None
                                                 kind=FUNCTION
                                                 conds=[DEPRECATEDIN_3_0, EC]
        EXIST:VMS:FUNCTION:OCSP                  platform=VMS -> not built on ELF
        NOEXIST::FUNCTION:                       declared, deliberately NOT
                                                 exported (e.g. ERR_put_error)

    Modelling `status` and `platform` explicitly is what stops the reconciler
    from reporting a correct absence as a defect.
    """

    symbol: str
    ordinal: int
    version: str          # e.g. "3_0_0" -> normalised to "OPENSSL_3.0.0"
    status: str           # "EXIST", "NOEXIST", ...
    platform: Optional[str]  # e.g. "VMS"; None means platform-independent
    kind: str             # "FUNCTION", "VARIABLE", ""
    conditions: list[str]  # e.g. ["DEPRECATEDIN_3_0", "EC"]
    raw: str

    @property
    def version_node(self) -> str:
        return "OPENSSL_" + self.version.replace("_", ".")

    @property
    def deprecated(self) -> bool:
        return any(c.startswith("DEPRECATEDIN_") for c in self.conditions)

    @property
    def declared_nonexistent(self) -> bool:
        return self.status.upper() != "EXIST"

    @property
    def platform_scoped_away(self) -> bool:
        """True if the entry is scoped to a non-ELF platform.

        The admitted authority profile is linux-x86_64 (ELF), so an entry
        scoped to VMS or a legacy platform is *expected* to be absent and its
        absence is not a residual.
        """
        return self.platform is not None and self.platform.upper() != "LINUX"


def parse_num_file(path: Path) -> tuple[list[NumEntry], list[dict]]:
    """Parse a linker `.num` inventory.

    Returns (entries, unparsed). Unparsed lines are *residuals*, not noise:
    the caller must surface them so a silent parse failure cannot quietly
    shrink the inventory.
    """
    entries: list[NumEntry] = []
    unparsed: list[dict] = []
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _NUM_LINE.match(line)
        if not m:
            unparsed.append({"line": lineno, "text": raw})
            continue
        condition = m.group("condition") or ""
        status = kind = ""
        platform: Optional[str] = None
        conditions: list[str] = []
        if condition:
            fields = condition.split(":", 3)
            status = fields[0]
            if len(fields) > 1:
                platform = fields[1] or None
            if len(fields) > 2:
                kind = fields[2]
            if len(fields) > 3:
                conditions = [c for c in fields[3].split(",") if c]
            if not status:
                unparsed.append({"line": lineno, "text": raw})
                continue
        entries.append(NumEntry(
            symbol=m.group("symbol"),
            ordinal=int(m.group("ordinal")),
            version=m.group("version"),
            status=status,
            platform=platform,
            kind=kind,
            conditions=conditions,
            raw=line,
        ))
    return entries, unparsed


# ---------------------------------------------------------------------------
# Generated linker version script (libcrypto.ld / libssl.ld)
# ---------------------------------------------------------------------------

# A version script is the *build-profile-specific* export promise. It is
# generated from the .num inventory at configure time, so the difference
# between the two is exactly the set of exclusions the build configuration made.
#
#   OPENSSL_3.0.0 {
#       global:
#           ACCESS_DESCRIPTION_free;
#           ...
#       local:
#           *;
#   };

_LD_NODE = re.compile(r"^(?P<node>[A-Za-z_][A-Za-z0-9_.]*)\s*\{\s*$")
_LD_SYMBOL = re.compile(r"^\s*(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$")


def parse_version_script(path: Path) -> dict[str, list[str]]:
    """Parse a GNU ld version script into {version_node: [symbols]}.

    Only `global:` symbols are collected; the `local:` block (typically `*;`)
    is not a symbol list.
    """
    nodes: dict[str, list[str]] = {}
    current: Optional[str] = None
    in_global = False
    for line in path.read_text().splitlines():
        if line.lstrip().startswith("#") or not line.strip():
            continue
        m = _LD_NODE.match(line)
        if m:
            current = m.group("node")
            nodes.setdefault(current, [])
            in_global = False
            continue
        stripped = line.strip()
        if stripped == "global:":
            in_global = True
            continue
        if stripped == "local:":
            in_global = False
            continue
        if stripped == "};" or stripped == "}":
            current = None
            in_global = False
            continue
        if current is not None and in_global:
            ms = _LD_SYMBOL.match(line)
            if ms:
                nodes[current].append(ms.group("symbol"))
    return {k: sorted(set(v)) for k, v in nodes.items()}


# ---------------------------------------------------------------------------
# ELF dynamic symbol table parsing (readelf --dyn-syms --wide)
# ---------------------------------------------------------------------------

@dataclass
class DynSym:
    name: str
    value: int
    size: int
    stype: str      # FUNC, OBJECT, NOTYPE, ...
    bind: str       # GLOBAL, WEAK, LOCAL
    vis: str        # DEFAULT, PROTECTED, HIDDEN
    ndx: str
    version: Optional[str]  # from name suffix symbol@@VERSION

    @property
    def defined(self) -> bool:
        return self.ndx != "UND"


_DYNSYM_ROW = re.compile(
    r"^\s*(?P<num>\d+):\s+"
    r"(?P<value>[0-9a-fA-F]+)\s+"
    r"(?P<size>\d+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<bind>\S+)\s+"
    r"(?P<vis>\S+)\s+"
    r"(?P<ndx>\S+)\s+"
    r"(?P<name>\S+)\s*$"
)


def read_dynsyms(path: Path) -> list[DynSym]:
    res = run(["readelf", "--dyn-syms", "--wide", str(path)])
    syms: list[DynSym] = []
    for line in res.stdout.splitlines():
        m = _DYNSYM_ROW.match(line)
        if not m:
            continue
        raw_name = m.group("name")
        version = None
        name = raw_name
        if "@" in raw_name:
            name, _, version = raw_name.partition("@")
            version = version.lstrip("@")
        syms.append(DynSym(
            name=name,
            value=int(m.group("value"), 16),
            size=int(m.group("size")),
            stype=m.group("type"),
            bind=m.group("bind"),
            vis=m.group("vis"),
            ndx=m.group("ndx"),
            version=version,
        ))
    return syms


# readelf version-info parsing (version definition / needs sections)


def read_version_definition_names(path: Path) -> list[str]:
    """Return the version *definition* node names in a DSO (e.g. OPENSSL_3.0.0).

    readelf --version-info prints three sections. In the definition section each
    entry is a row like:

        000000: Rev: 1  Flags: BASE  Index: 1  Cnt: 1  Name: libcrypto.so.3
        0x001c: Rev: 1  Flags: none  Index: 2  Cnt: 2  Name: OPENSSL_3.0.0

    We extract the `Name:` token from every row inside the definition section
    only, so the version-needs (dependency) names are never mixed in.
    """
    res = run(["readelf", "--version-info", "--wide", str(path)])
    if not res.ok:
        raise AtlasError(f"readelf --version-info failed for {path}: {res.stderr.strip()}")
    names: list[str] = []
    in_def = False
    for line in res.stdout.splitlines():
        if "Version definition section" in line:
            in_def = True
            continue
        if "Version symbols section" in line or "Version needs section" in line:
            in_def = False
            continue
        if in_def and "Name:" in line:
            token = line.rsplit("Name:", 1)[1].strip()
            if token:
                names.append(token)
    # The BASE node is the library's own SONAME, not an ABI version namespace.
    return [n for n in names if n.startswith("OPENSSL_")]


def read_version_needed_names(path: Path) -> list[str]:
    """Return the version *needs* (i.e. dependency) names of an ELF object."""
    res = run(["readelf", "--version-info", "--wide", str(path)])
    names: list[str] = []
    in_needs = False
    for line in res.stdout.splitlines():
        if "Version needs section" in line:
            in_needs = True
            continue
        if "Version definition section" in line or "Version symbols section" in line:
            in_needs = False
            continue
        if in_needs and "Name:" in line:
            token = line.rsplit("Name:", 1)[1].strip()
            if token:
                names.append(token)
    return names


def main(argv: list[str]) -> int:  # pragma: no cover - module is a library
    print("atlas_common is a library; use a generator such as atlas_symbols.py")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
