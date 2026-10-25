#!/usr/bin/env python3
"""openssl-rs — S63 phase A: read-only admission inventory and source resolver.

This module is the **inventory** half of the frozen P1000 admission factory.  It
reads the frozen population, the shared recipe catalogue and the two committed
downstream atlases, resolves what source identity can be established from
*trusted metadata*, and writes a complete per-family inventory.  It never
builds, never downloads a source archive into the repository, and never edits a
recipe.

Why the source resolver is separate from the recipe catalogue
-------------------------------------------------------------
A recipe is evidence that a family *was* built; it is not evidence that every
other family has a known source.  For a Debian-derived family the trustworthy
source identity is the Debian **Sources** index, which publishes the source
package, the version, the archive directory and the archive's SHA-256.  This
tool reads that index (the pinned
``snapshot.debian.org/archive/debian/20241001T000000Z/dists/bookworm/main/source/Sources.xz``
snapshot, with the live ``deb.debian.org`` bookworm/main index only as a stated
fallback) and resolves binary package -> source package from its ``Binary``
field.

The four identity fields are deliberately distinct
--------------------------------------------------
``binary_identity`` is the frozen family and its Debian binary package names.
``source_identity`` is the source package/archive that the recipe (or the
Debian index) names.  ``upstream_project`` is the project metadata frozen in
``families.json``.  ``executable_name`` is the program the recipe builds, when
the metadata establishes one.  ``libpq`` is the motivating example: the family
binary is ``libpq5``, the Debian source package is ``postgresql-15``, the
upstream project is PostgreSQL, and the family is a library with no executable
of its own.  Those are four different things and this inventory never collapses
them.

Status vocabulary
-----------------
The committed atlases use one umbrella label, ``SOURCE-UNREACHABLE``, for a
family with no admitted recipe.  That label hides four different situations.
This inventory keeps a finer, mutually exclusive status:

``NO_SOURCE_MAPPING``
    We have not identified a trustworthy source identity.  No exact Debian
    binary/source identity is present in the frozen registry or the bookworm/main
    Sources index, there is no admitted recipe, and no URL is inferred.
``NO_ADMITTED_RECIPE``
    A source identity is resolved from trusted metadata, but no admitted recipe
    exists yet.
``ACQUISITION_FAILED``
    A URL was actually tried and failed, and the failure is not evidence that the
    source is gone.
``SOURCE_UNREACHABLE_CONFIRMED``
    Recorded evidence shows the source is demonstrably gone (a 404 or an absent
    Debian pool directory) and the Sources index agrees.
``ADMITTED_RECIPE``
    An admitted recipe exists.  This is the complement of the four fine-grained
    statuses; it is not part of the legacy ``SOURCE-UNREACHABLE`` bucket.

All 1,000 frozen families are emitted exactly once.  The tool asserts that the
status counts sum to 1,000 and that no family id is duplicated.  It fails loudly
if either assertion is violated.

Outputs
-------
  forensics/memory-safety/campaign/safe-c33/atlas-refresh/s63-admission-inventory.json
  forensics/memory-safety/campaign/safe-c33/atlas-refresh/s63-admission-inventory.md

The tool is read-only apart from those two outputs and a metadata cache under
``$TMPDIR`` / ``/work/court/tmp``.  It does not build.  It does not fetch a
source archive.  It does not modify the atlases or the recipe catalogue.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import collections
import datetime as _dt
import hashlib
import json
import lzma
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import warnings
from pathlib import Path

# Do not leave __pycache__ inside the repository: this tool's only repository
# writes are the two committed inventory outputs.
sys.dont_write_bytecode = True

# ---------------------------------------------------------------------------
# Repository paths and fixed identities.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"

FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
RUNTIME_ATLAS = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
ATLAS_REFRESH = REPO_ROOT / "forensics" / "memory-safety" / "campaign" / "safe-c33" / "atlas-refresh"
OUT_JSON = ATLAS_REFRESH / "s63-admission-inventory.json"
OUT_MD = ATLAS_REFRESH / "s63-admission-inventory.md"

GENERATOR = "forensics/tools/downstream_admission_discover.py"
SCHEMA = "safe-c33/downstream-admission-inventory/v1"
RECEIPT = "S63-ADMISSION-INVENTORY-A"
SUBPHASE = "S63"
USER_AGENT = "openssl-rs-s63/1"

# The four fine-grained statuses replace the legacy umbrella for the unadmitted
# cohort.  ADMITTED_RECIPE is the complement, not a legacy SOURCE-UNREACHABLE row.
STATUS_ADMITTED = "ADMITTED_RECIPE"
STATUS_NO_SOURCE_MAPPING = "NO_SOURCE_MAPPING"
STATUS_NO_ADMITTED_RECIPE = "NO_ADMITTED_RECIPE"
STATUS_ACQUISITION_FAILED = "ACQUISITION_FAILED"
STATUS_SOURCE_UNREACHABLE_CONFIRMED = "SOURCE_UNREACHABLE_CONFIRMED"

FINE_GRAINED_STATUSES = (
    STATUS_NO_SOURCE_MAPPING,
    STATUS_NO_ADMITTED_RECIPE,
    STATUS_ACQUISITION_FAILED,
    STATUS_SOURCE_UNREACHABLE_CONFIRMED,
)
ALL_STATUSES = (STATUS_ADMITTED,) + FINE_GRAINED_STATUSES

# The Debian metadata origin.  The snapshot is a timestamped bookworm/main
# Sources index, so its bytes are immutable; the live index is only a fallback
# and the output records which origin was actually used.
DEBIAN_SNAPSHOT = "20241001T000000Z"
DEBIAN_SNAPSHOT_POOL_BASE = (
    f"https://snapshot.debian.org/archive/debian/{DEBIAN_SNAPSHOT}"
)
DEBIAN_LIVE_POOL_BASE = "https://deb.debian.org/debian"
DEBIAN_INDEXES = (
    {
        "origin": "snapshot",
        "suite": "bookworm/main",
        "url": (
            f"{DEBIAN_SNAPSHOT_POOL_BASE}/dists/bookworm/main/source/Sources.xz"
        ),
        "pool_base": DEBIAN_SNAPSHOT_POOL_BASE,
        "snapshot": DEBIAN_SNAPSHOT,
    },
    {
        "origin": "live",
        "suite": "bookworm/main",
        "url": "https://deb.debian.org/debian/dists/bookworm/main/source/Sources.xz",
        "pool_base": DEBIAN_LIVE_POOL_BASE,
        "snapshot": None,
    },
)

# Recorded acquisition history.  These are *attempts that actually happened* in
# earlier subphases, preserved so the current admitted status does not erase the
# failed URL.  They are deliberately not ACQUISITION_FAILED rows: both were
# retried successfully and now have admitted recipes.
ACQUISITION_HISTORY: dict[str, list[dict]] = {
    "family:libssh": [
        {
            "attempt": "s42/s44",
            "url": "https://www.libssh.org/files/0.10/libssh-0.10.6.tar.xz",
            "outcome": "failed",
            "reason": "www.libssh.org was unreachable from the court (curl 7) during and after S42",
            "evidence": "atlas-refresh/s44-corpus-batch.json#part1_infrastructure_losses",
        },
        {
            "attempt": "s44 retry",
            "url": (
                "https://deb.debian.org/debian/pool/main/libs/libssh/"
                "libssh_0.10.6.orig.tar.xz"
            ),
            "outcome": "succeeded",
            "sha256": "1861d498f5b6f1741b6abc73e608478491edcf9c9d4b6630eef6e74596de9dc1",
            "evidence": "atlas-refresh/s44-corpus-batch.json#part1_infrastructure_losses",
        },
    ],
    "family:sslscan": [
        {
            "attempt": "s42",
            "url": "https://github.com/rbsec/sslscan/archive/refs/tags/2.1.5.tar.gz",
            "outcome": "failed",
            "reason": "GitHub was subject to a transient DNS failure in the runtime run",
            "evidence": "atlas-refresh/s44-corpus-batch.json#part1_infrastructure_losses",
        },
        {
            "attempt": "s44 retry",
            "url": (
                "https://deb.debian.org/debian/pool/main/s/sslscan/"
                "sslscan_2.1.5.orig.tar.gz"
            ),
            "outcome": "succeeded",
            "sha256": "b36616b1d59f3276af6ff9495ab8178ec6812393582fb3c094c56cc873efe956",
            "evidence": "atlas-refresh/s44-corpus-batch.json#part1_infrastructure_losses",
        },
    ],
}

# Recorded evidence that a source is demonstrably gone.  Only a 404 / absent
# Debian pool directory qualifies; "not found by a search" and "deferred" do
# not.  Each entry names the receipt that recorded the observation.
RECORDED_SOURCE_GONE: dict[str, dict] = {
    "family:unrealircd": {
        "reason": (
            "the recorded Debian-pool attempt returned 404 and no Debian orig "
            "archive exists; upstream was not pinned"
        ),
        "evidence": [
            "atlas-refresh/s44-corpus-batch.json#skipped_families",
            "atlas-refresh/s46-corpus-batch.json#skipped_families.unreachable_or_absent_source",
        ],
    },
    "family:podofo": {
        "reason": "the recorded Debian pool directory is absent (no pool directory)",
        "evidence": [
            "atlas-refresh/s46-corpus-batch.json#skipped_families.unreachable_or_absent_source",
        ],
    },
}

# Recorded acquisition attempts that were recorded as unreachable but are not
# evidence that the source is gone.  These remain NO_SOURCE_MAPPING when no
# exact metadata identity exists.
RECORDED_NO_MAPPING: dict[str, dict] = {
    "family:hinsightd": {
        "reason": "no upstream repository was found from the court",
        "evidence": [
            "atlas-refresh/s46-corpus-batch.json#skipped_families.unreachable_or_absent_source",
        ],
    },
    "family:libdkimpp": {
        "reason": "no Debian source package was found",
        "evidence": [
            "atlas-refresh/s46-corpus-batch.json#skipped_families.unreachable_or_absent_source",
        ],
    },
}

# Prior classifications this inventory is allowed to contradict.  The metadata
# wins, but the prior claim is kept in the row and in the contradiction list.
PRIOR_CLASSIFICATIONS: dict[str, dict] = {
    "family:weex": {
        "status": "SOURCE-UNREACHABLE",
        "reason": (
            "the Debian pool directory carries no orig archive (listing empty); "
            "SOURCE-UNREACHABLE without a verified URL"
        ),
        "evidence": [
            "atlas-refresh/s44-corpus-batch.json#skipped_families",
            "atlas-refresh/s46-corpus-batch.json#skipped_families.unreachable_or_absent_source",
        ],
    },
}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DEBIAN_POOL = re.compile(r"/pool/([^/]+)/([^/]+)/([^/]+)/([^/]+)$")


# ---------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------


def _fatal(message: str) -> None:
    raise SystemExit(f"FATAL: {message}")


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        _fatal(f"required input {_rel(path)} is absent")
    except json.JSONDecodeError as exc:
        _fatal(f"required input {_rel(path)} is not valid JSON: {exc}")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _first(stanza: dict[str, list[str]], key: str) -> str | None:
    values = stanza.get(key) or []
    return values[0] if values else None


def _now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


# ---------------------------------------------------------------------------
# Debian Sources index: fetch, parse, and resolve binary -> source.
# ---------------------------------------------------------------------------


def parse_deb822(text: str) -> list[dict[str, list[str]]]:
    """Parse Debian control-file (deb822) stanzas.

    A line starting with a space or tab is a continuation of the previous field;
    a truly empty line ends the stanza.  This distinction matters: the
    ``Checksums-Sha256`` field contains whitespace-only continuation lines.
    """
    stanzas: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    key: str | None = None
    for raw_line in text.splitlines():
        if raw_line[:1] in (" ", "\t"):
            if key is not None:
                current[key].append(raw_line.strip())
            continue
        if not raw_line.strip():
            if current:
                stanzas.append(current)
                current = {}
                key = None
            continue
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        key = key.strip()
        current.setdefault(key, []).append(value.strip())
    if current:
        stanzas.append(current)
    return stanzas


def _binary_names(stanza: dict[str, list[str]]) -> list[str]:
    """The source package's binary-package list, whitespace-wrapped."""
    joined = " ".join(stanza.get("Binary") or [])
    names = []
    for part in joined.split(","):
        name = part.strip().split("(")[0].strip()
        if name:
            names.append(name)
    return names


def _checksums(stanza: dict[str, list[str]]) -> list[dict]:
    entries = []
    for line in stanza.get("Checksums-Sha256") or []:
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        digest, size, name = parts
        if not _HEX64.match(digest):
            continue
        if not size.isdigit():
            continue
        entries.append({"sha256": digest, "size": int(size), "name": name})
    return entries


def _select_source_archive(stanza: dict[str, list[str]]) -> dict | None:
    """The upstream archive whose digest is the source identity.

    Prefer a plain ``.orig.tar.*`` file; then a native ``.tar.*`` file; then an
    ``.orig-<variant>.tar.*`` bootstrap archive (for example rustc's
    ``orig-stage0``).  A ``.dsc``, ``.debian.tar.*`` or ``.diff.gz`` is packaging
    metadata, not the upstream source archive, and is never used as the source
    identity.
    """
    entries = _checksums(stanza)
    usable: list[tuple[int, dict]] = []
    for entry in entries:
        name = entry["name"]
        if name.endswith(".dsc") or name.endswith(".diff.gz"):
            continue
        if ".debian.tar" in name:
            continue
        if ".orig.tar" in name:
            priority = 0
        elif re.search(r"\.orig-[^/]*\.tar\.", name):
            priority = 2
        elif re.search(r"\.tar\.(gz|xz|bz2|lzma|zst)$", name):
            priority = 1
        else:
            continue
        usable.append((priority, entry))
    if not usable:
        return None
    usable.sort(key=lambda item: (item[0], item[1]["name"]))
    return usable[0][1]


def _dsc_entry(stanza: dict[str, list[str]]) -> dict | None:
    for entry in _checksums(stanza):
        if entry["name"].endswith(".dsc"):
            return entry
    return None


class DebianIndex:
    """The parsed bookworm/main Sources index."""

    def __init__(self, stanzas: list[dict[str, list[str]]], identity: dict):
        self.stanzas = stanzas
        self.identity = identity
        self.by_source: dict[str, list[dict]] = collections.defaultdict(list)
        self.binary_to_sources: dict[str, set[str]] = collections.defaultdict(set)
        for stanza in stanzas:
            package = _first(stanza, "Package")
            version = _first(stanza, "Version")
            if not package or not version:
                continue
            self.by_source[package].append(stanza)
            for binary in _binary_names(stanza):
                self.binary_to_sources[binary].add(package)
        self.duplicate_sources = {
            package: [_first(s, "Version") for s in entries]
            for package, entries in self.by_source.items()
            if len(entries) > 1
        }

    def source_names(self) -> set[str]:
        return set(self.by_source)

    def stanzas_for(self, source_package: str) -> list[dict]:
        return self.by_source.get(source_package) or []

    def select_stanza(
        self, source_package: str, matched_binaries: set[str]
    ) -> tuple[dict | None, str, dict]:
        """Select the published stanza for a source package.

        A suite can briefly publish more than one version of a source package.
        When the family's binary package appears in exactly one of those stanzas,
        that stanza is selected -- a metadata fact, not a version guess.  If the
        binary appears in several (or the match came from a source name rather
        than a binary), the highest published version is selected and the
        ambiguity is recorded.
        """
        entries = self.stanzas_for(source_package)
        if not entries:
            return None, "UNRESOLVED", {}
        if matched_binaries:
            hits = [
                entry
                for entry in entries
                if matched_binaries & set(_binary_names(entry))
            ]
            if len(hits) == 1:
                return hits[0], "matched-binary", {
                    "matched_binaries": sorted(matched_binaries),
                }
            if len(hits) > 1:
                chosen = max(
                    hits,
                    key=lambda entry: _version_key(_first(entry, "Version") or ""),
                )
                return chosen, "ambiguous-highest-version", {
                    "matched_binaries": sorted(matched_binaries),
                    "candidates": [_first(entry, "Version") for entry in hits],
                }
        if len(entries) == 1:
            return entries[0], "single-published-version", {}
        chosen = max(
            entries, key=lambda entry: _version_key(_first(entry, "Version") or "")
        )
        return chosen, "ambiguous-highest-version", {
            "candidates": [_first(entry, "Version") for entry in entries],
        }


def _cache_name(index: dict) -> str:
    return f"s63-{index['origin']}-{index['suite'].replace('/', '-')}-Sources.xz"


def _read_cached(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _write_cached(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def fetch_debian_index(
    cache_dir: Path,
    *,
    offline: bool,
    timeout: int,
    candidates: tuple[dict, ...] = DEBIAN_INDEXES,
) -> tuple[DebianIndex, dict]:
    """Fetch (or reuse) the Sources index and return the parsed index.

    The first candidate that yields a parseable Sources index is used.  Every
    attempt is recorded so the output names the exact metadata origin, final
    URL and observed SHA-256.  If none succeeds and no cached index exists, the
    command fails loudly rather than fabricating a source identity.
    """
    attempts: list[dict] = []
    chosen: tuple[dict, bytes, str] | None = None  # (candidate, payload, sha)
    for candidate in candidates:
        cache_path = cache_dir / _cache_name(candidate)
        if offline:
            cached = _read_cached(cache_path)
            if cached is None:
                attempts.append(
                    {
                        **candidate,
                        "result": "cache-miss",
                        "error": "offline mode and no cached Sources index",
                    }
                )
                continue
            attempts.append(
                {
                    **candidate,
                    "result": "cache-hit",
                    "cache_path": str(cache_path),
                    "bytes": len(cached),
                    "sha256": _sha256_bytes(cached),
                }
            )
            chosen = (candidate, cached, _sha256_bytes(cached))
            break

        request = urllib.request.Request(candidate["url"], headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
                status = getattr(response, "status", None)
                final_url = response.geturl()
            digest = _sha256_bytes(payload)
            _write_cached(cache_path, payload)
            attempts.append(
                {
                    **candidate,
                    "result": "fetched",
                    "http_status": status,
                    "final_url": final_url,
                    "bytes": len(payload),
                    "sha256": digest,
                    "cache_path": str(cache_path),
                }
            )
            chosen = (candidate, payload, digest)
            break
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
            attempts.append(
                {
                    **candidate,
                    "result": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    if chosen is None:
        _fatal(
            "could not obtain a Debian bookworm/main Sources index from any "
            f"candidate ({', '.join(c['url'] for c in candidates)}) and no cached "
            f"index exists under {cache_dir}; refusing to infer source identities"
        )

    candidate, payload, digest = chosen
    try:
        text = lzma.decompress(payload).decode("utf-8", "replace")
    except (lzma.LZMAError, OSError) as exc:
        _fatal(f"the Debian Sources index from {candidate['url']} is not valid xz: {exc}")

    stanzas = parse_deb822(text)
    if len(stanzas) < 1000:
        _fatal(
            f"the Debian Sources index from {candidate['url']} yielded only "
            f"{len(stanzas)} stanzas; refusing to treat it as bookworm/main"
        )

    identity = {
        "origin": candidate["origin"],
        "suite": candidate["suite"],
        "snapshot": candidate["snapshot"],
        "url": candidate["url"],
        "pool_base": candidate["pool_base"],
        "sha256": digest,
        "bytes": len(payload),
        "uncompressed_bytes": len(text.encode("utf-8")),
        "stanza_count": len(stanzas),
        "attempts": attempts,
        "source": (
            "snapshot.debian.org timestamped bookworm/main Sources index"
            if candidate["origin"] == "snapshot"
            else "deb.debian.org live bookworm/main Sources index"
        ),
    }
    index = DebianIndex(stanzas, identity)
    # A suite can briefly publish more than one version of a source package
    # during a transition.  Name those packages in the metadata identity so a
    # reader can see every version-selection decision rather than only its
    # result.
    identity["duplicate_source_packages"] = sorted(index.duplicate_sources)
    identity["duplicate_source_package_count"] = len(index.duplicate_sources)
    return index, identity


# ---------------------------------------------------------------------------
# Inputs: frozen registry, families, recipe catalogue, atlases.
# ---------------------------------------------------------------------------


def load_frozen_population() -> list[dict]:
    body = _load_json(FAMILY_FREEZE).get("body") or {}
    p1000 = body.get("p1000")
    if not isinstance(p1000, list):
        _fatal(f"{_rel(FAMILY_FREEZE)} has no body.p1000 list")
    if len(p1000) != 1000:
        _fatal(f"the frozen P1000 is {len(p1000)} rows, not 1000")
    ids = [row.get("family_id") for row in p1000]
    if any(not fid for fid in ids):
        _fatal("the frozen P1000 contains a row without family_id")
    if len(set(ids)) != 1000:
        duplicates = [fid for fid, n in collections.Counter(ids).items() if n > 1]
        _fatal(f"the frozen P1000 double-counts family ids: {duplicates[:10]}")
    ranks = sorted(int(row.get("p1000_rank") or -1) for row in p1000)
    if ranks != list(range(1, 1001)):
        _fatal("the frozen P1000 ranks are not exactly 1..1000")
    return p1000


def load_families() -> dict[str, dict]:
    body = _load_json(FAMILIES).get("body") or {}
    families = body.get("families")
    if not isinstance(families, list):
        _fatal(f"{_rel(FAMILIES)} has no body.families list")
    by_id = {}
    for row in families:
        fid = row.get("family_id")
        if fid:
            by_id[fid] = row
    return by_id


def load_recipe_catalogue() -> tuple[dict[str, dict], str]:
    """Import the shared catalogue from its single source of truth.

    The import is read-only: ``downstream_build_link`` computes its catalogue
    as a pure derivation and executes no build at import time.  The catalogue
    is the same object the build/link atlas uses, so the two cannot disagree
    about which families have an admitted recipe.
    """
    sys.path.insert(0, str(TOOLS))
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            import downstream_build_link as bl  # noqa: PLC0415
        catalogue = bl._build_catalogue()
    except Exception as exc:  # noqa: BLE001 - a failure here must be loud
        _fatal(
            "could not import the shared recipe catalogue from "
            f"{_rel(TOOLS / 'downstream_build_link.py')}: {type(exc).__name__}: {exc}"
        )

    by_family: dict[str, dict] = {}
    for recipe in catalogue:
        family = recipe.get("family")
        if not family:
            _fatal("the shared recipe catalogue contains a recipe without family")
        if family in by_family:
            _fatal(f"the shared recipe catalogue contains two recipes for {family!r}")
        by_family[family] = recipe
    return by_family, "forensics/tools/downstream_build_link.py#_build_catalogue()"


def load_atlas(path: Path) -> dict:
    body = _load_json(path).get("body") or {}
    runs = body.get("runs")
    if not isinstance(runs, list):
        _fatal(f"{_rel(path)} has no body.runs list")
    by_family: dict[str, dict[str, dict]] = collections.defaultdict(dict)
    for run in runs:
        fid = run.get("family_id")
        subject = run.get("subject")
        if not fid or not subject:
            continue
        if subject in by_family[fid]:
            _fatal(f"{_rel(path)} has two {subject} runs for {fid}")
        by_family[fid][subject] = run
    return {
        "body": body,
        "runs": by_family,
        "recipe_programs": {
            row["family"]: row
            for row in body.get("recipe_catalogue") or []
            if isinstance(row, dict) and row.get("family")
        },
        "specimens": {
            row["family_id"]: row
            for row in body.get("specimens") or []
            if isinstance(row, dict) and row.get("family_id")
        },
    }


# ---------------------------------------------------------------------------
# Debian resolution.
# ---------------------------------------------------------------------------


def _debian_pool_coords(url: str | None) -> dict | None:
    """``/pool/<component>/<letter>/<source>/<file>`` coordinates, if present."""
    if not url:
        return None
    match = _DEBIAN_POOL.search(url)
    if not match:
        return None
    component, _letter, source, filename = match.groups()
    return {
        "component": component,
        "source_package": source,
        "filename": filename,
    }


def _upstream_version(debian_version: str) -> str:
    """Strip the Debian epoch and revision for a conservative version compare."""
    version = debian_version.split(":", 1)[-1]
    if "-" in version:
        version = version.rsplit("-", 1)[0]
    return version


def _version_key(version: str) -> tuple:
    """A conservative, documented sort key for a Debian version string.

    This is used only to choose between two versions a suite publishes at once;
    a binary-package match, when available, is preferred and is not a version
    guess.  The key separates epoch, upstream version and Debian revision and
    compares digit runs numerically.
    """
    epoch = 0
    rest = version
    if ":" in version:
        epoch_text, rest = version.split(":", 1)
        epoch = int(epoch_text) if epoch_text.isdigit() else 0
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, ""

    def part_key(text: str) -> tuple:
        parts = re.findall(r"\d+|[A-Za-z]+|~|\+|[^A-Za-z0-9~+]", text)
        return tuple(
            (0, int(piece)) if piece.isdigit() else (1, piece) for piece in parts
        )

    return (epoch, part_key(upstream), part_key(revision))


def resolve_debian_identity(
    family: dict,
    family_record: dict,
    index: DebianIndex,
    recipe: dict | None,
) -> dict:
    """Resolve the family's binary/name identities against bookworm/main.

    The returned object always has a ``status`` of ``RESOLVED``, ``AMBIGUOUS``
    or ``UNRESOLVED``.  An ambiguous match is not silently collapsed: the
    candidate sources are kept and the family is treated as unmapped unless an
    admitted recipe's Debian-pool URL disambiguates it.
    """
    canonical = family.get("canonical_name") or family.get("family_id", "").split(":", 1)[-1]
    distro_packages = family_record.get("distro_packages") or []
    debian_binaries = sorted(
        {
            pkg.get("package")
            for pkg in distro_packages
            if pkg.get("ecosystem") == "debian" and pkg.get("package")
        }
    )
    other_binaries = sorted(
        {
            (pkg.get("ecosystem"), pkg.get("package"))
            for pkg in distro_packages
            if pkg.get("ecosystem") != "debian" and pkg.get("package")
        }
    )
    aliases = sorted({str(a) for a in (family_record.get("aliases") or []) if a})
    names = sorted({canonical, *aliases})

    pairs: list[dict] = []
    source_from_debian: set[str] = set()
    matched_binaries_for_source: dict[str, set[str]] = collections.defaultdict(set)
    for binary in debian_binaries:
        sources = sorted(index.binary_to_sources.get(binary, set()))
        for source in sources:
            pairs.append(
                {
                    "binary": binary,
                    "source": source,
                    "basis": "debian-sources-index:Binary",
                }
            )
            source_from_debian.add(source)
            matched_binaries_for_source[source].add(binary)

    selection: str | None = None
    selection_reason = ""
    confidence = "UNRESOLVED"

    if source_from_debian:
        if len(source_from_debian) == 1:
            selection = next(iter(source_from_debian))
            selection_reason = (
                "all Debian binary-package identities in the frozen registry map "
                "to one source package in bookworm/main"
            )
            confidence = "HIGH"
        elif canonical in source_from_debian:
            selection = canonical
            selection_reason = (
                "the Debian binary identities map to several source packages, and "
                "the family canonical name is one of them"
            )
            confidence = "HIGH"
        else:
            selection_reason = (
                "the Debian binary identities map to multiple source packages: "
                + ", ".join(sorted(source_from_debian))
            )
            confidence = "AMBIGUOUS"
    else:
        # No Debian identity in the frozen registry.  If the admitted recipe's
        # URL is a Debian-pool URL, that URL is recorded evidence of the intended
        # source and wins over a same-name metapackage or an ambiguous bi
        # name match (ruby -> ruby3.1, php -> php8.2).  Otherwise only exact name
        # matches in the authoritative index are used; nothing is guessed from a
        # similar name (bind is not silently treated as bind9, exim as exim4).
        recipe_coords = _debian_pool_coords((recipe or {}).get("url"))
        if recipe_coords and recipe_coords["source_package"] in index.source_names():
            selection = recipe_coords["source_package"]
            selection_reason = (
                "the admitted recipe's Debian-pool URL names this source package"
            )
            confidence = "HIGH"
            pairs.append(
                {
                    "binary": "UNRESOLVED",
                    "source": selection,
                    "basis": "recipe-catalogue:Debian-pool",
                }
            )

        if selection is None:
            source_name_hits = {name for name in names if name in index.source_names()}
            binary_name_hits: set[str] = set()
            for name in names:
                for source in index.binary_to_sources.get(name, set()):
                    binary_name_hits.add(source)
                    pairs.append(
                        {
                            "binary": name,
                            "source": source,
                            "basis": "debian-sources-index:Binary(name-match)",
                        }
                    )
            all_sources = source_name_hits | binary_name_hits
            if len(all_sources) == 1:
                selection = next(iter(all_sources))
                if source_name_hits and not binary_name_hits:
                    selection_reason = (
                        "an exact family name is a source package in bookworm/main"
                    )
                    confidence = "HIGH"
                    pairs.append(
                        {
                            "binary": "UNRESOLVED",
                            "source": selection,
                            "basis": "debian-sources-index:Package(name-match)",
                        }
                    )
                else:
                    selection_reason = (
                        "an exact family name is a binary package in bookworm/main "
                        "and its Binary field maps to one source package"
                    )
                    confidence = "MEDIUM"
            elif len(all_sources) > 1:
                selection_reason = (
                    "exact family names match multiple Debian source packages: "
                    + ", ".join(sorted(all_sources))
                )
                confidence = "AMBIGUOUS"
            else:
                selection_reason = (
                    "no exact Debian binary-package or source-package identity is "
                    "present in the frozen registry or bookworm/main"
                )
                confidence = "UNRESOLVED"

    # A Debian-pool recipe URL may also disambiguate a family that does have a
    # Debian identity but whose binary identities map to several source packages.
    recipe_coords = _debian_pool_coords((recipe or {}).get("url"))
    if selection is None and recipe_coords and recipe_coords["source_package"] in (
        source_from_debian
    ):
        selection = recipe_coords["source_package"]
        selection_reason = (
            "the admitted recipe's Debian-pool URL names this source package"
        )
        confidence = "HIGH"

    if selection is None:
        return {
            "status": "UNRESOLVED" if confidence == "UNRESOLVED" else "AMBIGUOUS",
            "source_package": None,
            "version": "UNRESOLVED",
            "directory": "UNRESOLVED",
            "archive_origin": "UNRESOLVED",
            "archive_url": "UNRESOLVED",
            "sha256": "UNRESOLVED",
            "sha256_file": "UNRESOLVED",
            "dsc_sha256": "UNRESOLVED",
            "confidence": confidence,
            "selection_reason": selection_reason,
            "debian_binaries": debian_binaries,
            "other_distro_binaries": [
                {"ecosystem": eco, "package": pkg} for eco, pkg in other_binaries
            ],
            "binary_to_source": pairs,
            "candidate_sources": sorted(source_from_debian)
            if source_from_debian
            else sorted(
                {
                    *{name for name in names if name in index.source_names()},
                    *{
                        source
                        for name in names
                        for source in index.binary_to_sources.get(name, set())
                    },
                }
            ),
        }

    stanza, version_rule, version_meta = index.select_stanza(
        selection, matched_binaries_for_source.get(selection, set())
    )
    if stanza is None:
        _fatal(f"internal: selected source {selection!r} is absent from the index")
    version = _first(stanza, "Version") or "UNRESOLVED"
    directory = _first(stanza, "Directory") or "UNRESOLVED"
    archive = _select_source_archive(stanza)
    dsc = _dsc_entry(stanza)
    sha256 = archive["sha256"] if archive else "UNRESOLVED"
    sha256_file = archive["name"] if archive else "UNRESOLVED"

    archive_url = "UNRESOLVED"
    if archive and directory != "UNRESOLVED":
        archive_url = f"{index.identity['pool_base'].rstrip('/')}/{directory}/{archive['name']}"

    versions = [
        _first(entry, "Version") for entry in index.by_source.get(selection, [])
    ]
    if version_rule == "ambiguous-highest-version":
        confidence = "AMBIGUOUS_VERSION"

    return {
        "status": "RESOLVED",
        "source_package": selection,
        "version": version,
        "version_selection": {
            "rule": version_rule,
            "selected_version": version,
            "published_versions": versions,
            **version_meta,
        },
        "directory": directory,
        "archive_origin": {
            "kind": "debian-sources-index",
            "origin": index.identity["origin"],
            "suite": index.identity["suite"],
            "snapshot": index.identity["snapshot"],
            "index_url": index.identity["url"],
            "pool_base": index.identity["pool_base"],
        },
        "archive_url": archive_url,
        "sha256": sha256,
        "sha256_file": sha256_file,
        "dsc_sha256": dsc["sha256"] if dsc else "UNRESOLVED",
        "confidence": confidence,
        "selection_reason": selection_reason,
        "debian_binaries": debian_binaries,
        "other_distro_binaries": [
            {"ecosystem": eco, "package": pkg} for eco, pkg in other_binaries
        ],
        "binary_to_source": pairs,
        "candidate_sources": sorted(source_from_debian)
        if source_from_debian
        else [selection],
        "published_versions": versions,
    }


def _infer_executable(recipe: dict | None, runtime_program: str | None) -> str:
    """The family's own executable, or UNRESOLVED when the metadata is a library.

    A runtime harness is not the family's executable.  The harness is recorded
    separately as ``admitted_program``.
    """
    artifact = (recipe or {}).get("artifact") or ""
    base = artifact.rstrip("/*")
    if "/" in base:
        base = base.rsplit("/", 1)[-1]
    if base and not any(
        marker in base for marker in (".so", ".a", ".o", ".la", ".pc")
    ) and not base.startswith("lib"):
        return base
    if runtime_program and "harness" not in runtime_program.lower():
        name = Path(runtime_program).name
        if name and not name.endswith((".so", ".a")):
            return name
    return "UNRESOLVED"


def _runtime_summary(runtime: dict, family_id: str) -> dict:
    runs = runtime["runs"].get(family_id) or {}
    specimen = runtime["specimens"].get(family_id) or {}
    return {
        "authority_level": (runs.get("authority") or {}).get("level") or "UNRESOLVED",
        "authority_outcome": (runs.get("authority") or {}).get("outcome") or "UNRESOLVED",
        "authority_reason": (runs.get("authority") or {}).get("reason") or "UNRESOLVED",
        "candidate_level": (runs.get("candidate") or {}).get("level") or "UNRESOLVED",
        "candidate_outcome": (runs.get("candidate") or {}).get("outcome") or "UNRESOLVED",
        "candidate_reason": (runs.get("candidate") or {}).get("reason") or "UNRESOLVED",
        "specimen_id": specimen.get("specimen_id") or "UNRESOLVED",
        "pristine_source_sha256": specimen.get("pristine_source_sha256") or "UNRESOLVED",
        "pristine_source_url": specimen.get("upstream_ref") or "UNRESOLVED",
    }


def _build_link_summary(build_link: dict, family_id: str) -> dict:
    runs = build_link["runs"].get(family_id) or {}
    return {
        "authority_level": (runs.get("authority") or {}).get("level") or "UNRESOLVED",
        "authority_outcome": (runs.get("authority") or {}).get("outcome") or "UNRESOLVED",
        "candidate_level": (runs.get("candidate") or {}).get("level") or "UNRESOLVED",
        "candidate_outcome": (runs.get("candidate") or {}).get("outcome") or "UNRESOLVED",
    }


def cross_check_recipe(
    family_id: str,
    recipe: dict | None,
    debian: dict,
    runtime: dict,
) -> tuple[list[dict], list[dict]]:
    """Return (contradictions, informational_notes).

    A contradiction is a disagreement about the same source identity (source
    package, archive file or SHA-256).  A version difference between a recipe
    and the bookworm/main candidate is a note, not a contradiction: they are
    allowed to be different releases of the same source package.
    """
    contradictions: list[dict] = []
    notes: list[dict] = []
    if not recipe:
        return contradictions, notes

    recipe_url = recipe.get("url") or ""
    recipe_sha = recipe.get("sha256")
    coords = _debian_pool_coords(recipe_url)
    if debian.get("status") == "RESOLVED":
        if coords:
            if coords["source_package"] != debian.get("source_package"):
                contradictions.append(
                    {
                        "kind": "recipe_debian_source_package_mismatch",
                        "family_id": family_id,
                        "recipe_source_package": coords["source_package"],
                        "debian_source_package": debian.get("source_package"),
                        "recipe_url": recipe_url,
                    }
                )
            if (
                coords["filename"] == debian.get("sha256_file")
                and recipe_sha
                and debian.get("sha256") not in (None, "UNRESOLVED")
                and recipe_sha != debian.get("sha256")
            ):
                contradictions.append(
                    {
                        "kind": "recipe_sha256_vs_debian_metadata_mismatch",
                        "family_id": family_id,
                        "file": coords["filename"],
                        "recipe_sha256": recipe_sha,
                        "debian_published_sha256": debian.get("sha256"),
                    }
                )
        if recipe.get("version") and debian.get("version"):
            recipe_version = str(recipe["version"])
            debian_upstream = _upstream_version(str(debian["version"]))
            if recipe_version != str(debian["version"]) and recipe_version != debian_upstream:
                notes.append(
                    {
                        "kind": "recipe_version_differs_from_bookworm_main",
                        "family_id": family_id,
                        "recipe_version": recipe_version,
                        "debian_version": debian["version"],
                        "note": (
                            "the recipe and the bookworm/main candidate are different "
                            "releases; this is not a contradiction"
                        ),
                    }
                )

    specimen = runtime["specimens"].get(family_id) or {}
    specimen_sha = specimen.get("pristine_source_sha256")
    if recipe_sha and specimen_sha and recipe_sha != specimen_sha:
        contradictions.append(
            {
                "kind": "recipe_sha256_vs_runtime_atlas_specimen_mismatch",
                "family_id": family_id,
                "recipe_sha256": recipe_sha,
                "runtime_atlas_pristine_source_sha256": specimen_sha,
            }
        )
    if not recipe_sha and specimen_sha:
        notes.append(
            {
                "kind": "recipe_pin_missing",
                "family_id": family_id,
                "runtime_atlas_pristine_source_sha256": specimen_sha,
                "note": "the recipe catalogue carries no sha256 for this recipe",
            }
        )
    return contradictions, notes


# ---------------------------------------------------------------------------
# Inventory construction.
# ---------------------------------------------------------------------------


def _source_identity(
    family_id: str,
    recipe: dict | None,
    debian: dict,
    catalogue_source: str,
) -> dict:
    if recipe:
        url = recipe.get("url") or "UNRESOLVED"
        sha = recipe.get("sha256") or "UNRESOLVED"
        coords = _debian_pool_coords(url)
        source_package = "UNRESOLVED"
        if coords and debian.get("status") == "RESOLVED" and (
            coords["source_package"] == debian.get("source_package")
        ):
            source_package = coords["source_package"]
        return {
            "status": "RESOLVED" if sha != "UNRESOLVED" else "RESOLVED_HASH_UNRESOLVED",
            "basis": "recipe-catalogue",
            "source_package": source_package,
            "version": recipe.get("version") or "UNRESOLVED",
            "archive_origin": {
                "kind": "recipe-catalogue",
                "url": url,
                "recipe_id": recipe.get("recipe_id") or "UNRESOLVED",
                "debian_pool_coords": coords,
            },
            "archive_url": url,
            "sha256": sha,
            "sha256_file": (coords or {}).get("filename") or "UNRESOLVED",
            "provenance": catalogue_source,
            "debian_published_sha256": debian.get("sha256", "UNRESOLVED")
            if debian.get("status") == "RESOLVED"
            else "UNRESOLVED",
        }

    if debian.get("status") == "RESOLVED":
        return {
            "status": "RESOLVED"
            if debian.get("sha256") not in (None, "UNRESOLVED")
            else "RESOLVED_HASH_UNRESOLVED",
            "basis": "debian-sources-index",
            "source_package": debian.get("source_package"),
            "version": debian.get("version"),
            "archive_origin": debian.get("archive_origin"),
            "archive_url": debian.get("archive_url"),
            "sha256": debian.get("sha256"),
            "sha256_file": debian.get("sha256_file"),
            "provenance": "forensics/tools/downstream_admission_discover.py#DebianIndex",
            "debian_published_sha256": debian.get("sha256"),
        }

    return {
        "status": "UNRESOLVED",
        "basis": "UNRESOLVED",
        "source_package": "UNRESOLVED",
        "version": "UNRESOLVED",
        "archive_origin": "UNRESOLVED",
        "archive_url": "UNRESOLVED",
        "sha256": "UNRESOLVED",
        "sha256_file": "UNRESOLVED",
        "provenance": "UNRESOLVED",
        "debian_published_sha256": "UNRESOLVED",
    }


def build_inventory(
    population: list[dict],
    families_by_id: dict[str, dict],
    recipes: dict[str, dict],
    catalogue_source: str,
    runtime: dict,
    build_link: dict,
    index: DebianIndex,
) -> dict:
    rows: list[dict] = []
    contradictions: list[dict] = []
    notes: list[dict] = []

    frozen_ids = {row["family_id"] for row in population}
    for atlas_name, atlas in (("runtime", runtime), ("build-link", build_link)):
        atlas_ids = set(atlas["runs"])
        if atlas_ids != frozen_ids:
            missing = sorted(frozen_ids - atlas_ids)
            extra = sorted(atlas_ids - frozen_ids)
            _fatal(
                f"the {atlas_name} atlas family set differs from the frozen P1000: "
                f"missing={missing[:10]} extra={extra[:10]}"
            )
        incomplete = sorted(
            fid
            for fid in frozen_ids
            if set(atlas["runs"][fid]) != {"authority", "candidate"}
        )
        if incomplete:
            _fatal(
                f"the {atlas_name} atlas lacks both subjects for: {incomplete[:10]}"
            )

    for family in population:
        family_id = family["family_id"]
        canonical = family.get("canonical_name") or family_id.split(":", 1)[-1]
        family_record = families_by_id.get(family_id)
        if family_record is None:
            _fatal(
                f"{family_id} is in the frozen P1000 but absent from "
                f"{_rel(FAMILIES)}; refusing to invent its binary identity"
            )
        recipe = recipes.get(canonical)
        debian = resolve_debian_identity(family, family_record, index, recipe)

        recipe_contradictions, recipe_notes = cross_check_recipe(
            family_id, recipe, debian, runtime
        )
        contradictions.extend(recipe_contradictions)
        notes.extend(recipe_notes)

        # A recorded "source is gone" observation is only accepted when the
        # authoritative index also has no exact identity for the family.  If the
        # index does resolve one, the prior claim is contradicted (weex).
        recorded_gone = RECORDED_SOURCE_GONE.get(family_id)
        prior = PRIOR_CLASSIFICATIONS.get(family_id)
        row_contradictions = list(recipe_contradictions)
        if prior and debian.get("status") == "RESOLVED":
            prior_contradiction = {
                "kind": "prior_source_unreachable_contradicted_by_metadata",
                "family_id": family_id,
                "prior_status": prior["status"],
                "prior_reason": prior["reason"],
                "prior_evidence": prior["evidence"],
                "resolved_source_package": debian.get("source_package"),
                "resolved_version": debian.get("version"),
                "resolved_sha256": debian.get("sha256"),
                "note": (
                    "the bookworm/main Sources index carries this source and a "
                    "published archive digest; the prior unreachable claim is "
                    "recorded, not erased"
                ),
            }
            row_contradictions.append(prior_contradiction)
            contradictions.append(prior_contradiction)

        if recipe:
            status = STATUS_ADMITTED
            status_reason = (
                f"an admitted recipe is recorded in the shared catalogue "
                f"({recipe.get('recipe_id') or canonical})"
            )
        elif recorded_gone and debian.get("status") != "RESOLVED":
            status = STATUS_SOURCE_UNREACHABLE_CONFIRMED
            status_reason = recorded_gone["reason"]
        elif debian.get("status") == "RESOLVED":
            status = STATUS_NO_ADMITTED_RECIPE
            status_reason = (
                "source identity resolved from the Debian Sources index "
                f"({debian.get('source_package')} {debian.get('version')}); "
                "no admitted recipe is recorded"
            )
        elif debian.get("status") == "AMBIGUOUS":
            status = STATUS_NO_SOURCE_MAPPING
            status_reason = (
                "the exact-name match is ambiguous and no admitted recipe "
                "disambiguates it: " + debian.get("selection_reason", "")
            )
        else:
            status = STATUS_NO_SOURCE_MAPPING
            status_reason = debian.get("selection_reason") or (
                "no trustworthy source identity is available"
            )

        recorded_no_mapping = RECORDED_NO_MAPPING.get(family_id)
        if status == STATUS_NO_SOURCE_MAPPING and recorded_no_mapping:
            status_reason = (
                f"{status_reason}; recorded evidence: {recorded_no_mapping['reason']}"
            )

        source_identity = _source_identity(
            family_id, recipe, debian, catalogue_source
        )
        runtime_summary = _runtime_summary(runtime, family_id)
        executable = _infer_executable(
            recipe, (runtime["recipe_programs"].get(canonical) or {}).get("program")
        )

        rows.append(
            {
                "family_id": family_id,
                "canonical_name": canonical,
                "p1000_rank": family.get("p1000_rank"),
                "status": status,
                "status_reason": status_reason,
                "legacy_status": (
                    "SOURCE-UNREACHABLE"
                    if status in FINE_GRAINED_STATUSES
                    else None
                ),
                "binary_identity": {
                    "family_id": family_id,
                    "canonical_name": canonical,
                    "debian_binaries": debian.get("debian_binaries") or [],
                    "other_distro_binaries": debian.get("other_distro_binaries") or [],
                    "recipe_artifact": (recipe or {}).get("artifact") or None,
                },
                "source_identity": source_identity,
                "debian_metadata_identity": debian,
                "upstream_project": {
                    "name": canonical,
                    "homepage": family_record.get("homepage") or "UNRESOLVED",
                    "repository": family_record.get("upstream_repository") or "UNRESOLVED",
                    "packaging_page": family_record.get("project_url") or "UNRESOLVED",
                    "source_ecosystem": family_record.get("source_ecosystem") or "UNRESOLVED",
                },
                "executable_name": executable,
                "admitted_program": (
                    (runtime["recipe_programs"].get(canonical) or {}).get("program")
                    or "UNRESOLVED"
                ),
                "recipe": (
                    {
                        "recipe_id": recipe.get("recipe_id"),
                        "version": recipe.get("version"),
                        "url": recipe.get("url"),
                        "sha256": recipe.get("sha256"),
                        "artifact": recipe.get("artifact"),
                        "build_system": recipe.get("build_system"),
                    }
                    if recipe
                    else None
                ),
                "atlas": {
                    "runtime": runtime_summary,
                    "build_link": _build_link_summary(build_link, family_id),
                },
                "acquisition_history": ACQUISITION_HISTORY.get(family_id) or [],
                "prior_recorded_classification": prior,
                "contradictions": row_contradictions,
                "notes": recipe_notes,
            }
        )

    # ------------------------------------------------------------------
    # Population accounting: exact, total and mutually exclusive.
    # ------------------------------------------------------------------
    ids = [row["family_id"] for row in rows]
    if len(ids) != 1000:
        _fatal(f"inventory emitted {len(ids)} rows, not 1000")
    if len(set(ids)) != len(ids):
        duplicates = [fid for fid, n in collections.Counter(ids).items() if n > 1]
        _fatal(f"inventory double-counts family ids: {duplicates[:10]}")
    expected_ids = {row["family_id"] for row in population}
    if set(ids) != expected_ids:
        missing = sorted(expected_ids - set(ids))
        extra = sorted(set(ids) - expected_ids)
        _fatal(f"inventory family set differs from the freeze: missing={missing[:10]} extra={extra[:10]}")

    status_counts = collections.Counter(row["status"] for row in rows)
    unknown = sorted(set(status_counts) - set(ALL_STATUSES))
    if unknown:
        _fatal(f"inventory emitted unknown statuses: {unknown}")
    if sum(status_counts.values()) != 1000:
        _fatal(
            f"status counts sum to {sum(status_counts.values())}, not 1000: "
            f"{dict(status_counts)}"
        )
    admitted = status_counts.get(STATUS_ADMITTED, 0)
    fine_grained_sum = sum(status_counts.get(s, 0) for s in FINE_GRAINED_STATUSES)
    if admitted + fine_grained_sum != 1000:
        _fatal(
            "the four fine-grained statuses plus ADMITTED_RECIPE do not sum to "
            f"1000: {admitted} + {fine_grained_sum}"
        )

    recipe_families = {family for family in recipes if family in {
        row.get("canonical_name") for row in population
    }}
    if admitted != len(recipe_families):
        _fatal(
            f"ADMITTED_RECIPE count {admitted} does not match the "
            f"{len(recipe_families)} catalogue families in the P1000"
        )
    catalogue_outside_population = sorted(set(recipes) - {
        row.get("canonical_name") for row in population
    })
    if catalogue_outside_population:
        _fatal(
            "the shared recipe catalogue contains families outside the frozen "
            f"P1000: {catalogue_outside_population[:10]}"
        )

    # ------------------------------------------------------------------
    # Source-identity accounting.
    # ------------------------------------------------------------------
    debian_resolved = sum(
        1
        for row in rows
        if row["debian_metadata_identity"].get("status") == "RESOLVED"
        and row["debian_metadata_identity"].get("sha256") not in (None, "UNRESOLVED")
    )
    debian_resolved_hash_unresolved = sum(
        1
        for row in rows
        if row["debian_metadata_identity"].get("status") == "RESOLVED"
        and row["debian_metadata_identity"].get("sha256") in (None, "UNRESOLVED")
    )
    debian_unresolved = 1000 - debian_resolved - debian_resolved_hash_unresolved
    source_identity_hash_resolved = sum(
        1 for row in rows if row["source_identity"].get("sha256") not in (None, "UNRESOLVED")
    )
    source_identity_hash_unresolved = 1000 - source_identity_hash_resolved
    resolved_source_identity_hash_unresolved = sum(
        1
        for row in rows
        if row["source_identity"].get("status") != "UNRESOLVED"
        and row["source_identity"].get("sha256") in (None, "UNRESOLVED")
    )
    source_identity_basis = collections.Counter(
        row["source_identity"].get("basis") for row in rows
    )

    # A SHA-256 may legitimately be shared by two frozen families when the
    # metadata or both recipes independently name the same source archive (curl
    # and curl-minimal; afflib, afftools and libafflib0v5).  It must never be
    # shared across two *different* Debian source packages, which would be the
    # signature of a copied hash rather than a shared source identity.
    debian_hash_sources: dict[str, set[str]] = collections.defaultdict(set)
    recipe_hash_groups: dict[str, dict[str, set[str]]] = collections.defaultdict(
        lambda: {"families": set(), "urls": set()}
    )
    for row in rows:
        debian = row["debian_metadata_identity"]
        if debian.get("status") == "RESOLVED" and debian.get("sha256") not in (
            None,
            "UNRESOLVED",
        ):
            debian_hash_sources[debian["sha256"]].add(debian.get("source_package"))
        source = row["source_identity"]
        if source.get("basis") == "recipe-catalogue" and source.get("sha256") not in (
            None,
            "UNRESOLVED",
        ):
            group = recipe_hash_groups[source["sha256"]]
            group["families"].add(row["family_id"])
            group["urls"].add(source.get("archive_url"))

    cross_source_hashes = {
        digest: sorted(sources)
        for digest, sources in debian_hash_sources.items()
        if len(sources) > 1
    }
    if cross_source_hashes:
        _fatal(
            "a Debian-published SHA-256 is shared by different source packages; "
            f"refusing to treat a copied hash as a source identity: {cross_source_hashes}"
        )
    shared_recipe_hashes = [
        {
            "sha256": digest,
            "families": sorted(group["families"]),
            "archive_urls": sorted(group["urls"]),
            "classification": (
                "same source archive named by more than one family; the hash is "
                "shared because the source is shared, not copied"
            ),
        }
        for digest, group in recipe_hash_groups.items()
        if len(group["families"]) > 1
    ]
    shared_recipe_hashes.sort(key=lambda item: item["sha256"])

    return {
        "schema": SCHEMA,
        "receipt": RECEIPT,
        "subphase": SUBPHASE,
        "date": _dt.datetime.now(_dt.timezone.utc).date().isoformat(),
        "generated_at": _now_utc(),
        "generator": GENERATOR,
        "kind": "read-only-admission-inventory",
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD") or "UNRESOLVED",
        "source_head": _git("rev-parse", "HEAD") or "UNRESOLVED",
        "method": {
            "builds_performed": False,
            "archives_downloaded": False,
            "recipes_modified": False,
            "atlases_modified": False,
            "network_used": "Debian bookworm/main Sources index only",
            "metadata_cache": (
                "a Sources-index cache under $TMPDIR or --cache-dir (court scratch); "
                "never a source archive in the repository"
            ),
            "population_registry": _rel(FAMILY_FREEZE),
            "recipe_catalogue": catalogue_source,
            "runtime_atlas": _rel(RUNTIME_ATLAS),
            "build_link_atlas": _rel(BUILD_LINK_ATLAS),
        },
        "population": {
            "registry": _rel(FAMILY_FREEZE),
            "family_role": "p1000",
            "count": len(rows),
            "unique_family_ids": len(set(ids)),
            "ranks": {"min": 1, "max": 1000, "contiguous": True},
            "status_counts": {status: status_counts.get(status, 0) for status in ALL_STATUSES},
            "status_sum": sum(status_counts.values()),
            "unadmitted_status_counts": {
                status: status_counts.get(status, 0) for status in FINE_GRAINED_STATUSES
            },
            "unadmitted_status_sum": fine_grained_sum,
            "admitted_recipe_count": admitted,
            "accounting_assertion": "PASS",
        },
        "vocabulary": {
            "legacy_umbrella": "SOURCE-UNREACHABLE",
            "fine_grained": {
                STATUS_NO_SOURCE_MAPPING: {
                    "meaning": (
                        "we have not identified a trustworthy source identity; no "
                        "exact Debian binary/source identity and no admitted recipe"
                    ),
                    "legacy_label": "SOURCE-UNREACHABLE",
                },
                STATUS_NO_ADMITTED_RECIPE: {
                    "meaning": (
                        "a source identity is resolved from trusted metadata, but no "
                        "admitted recipe exists yet"
                    ),
                    "legacy_label": "SOURCE-UNREACHABLE",
                },
                STATUS_ACQUISITION_FAILED: {
                    "meaning": (
                        "a URL was actually tried and failed, and the failure is not "
                        "evidence that the source is gone"
                    ),
                    "legacy_label": "SOURCE-UNREACHABLE",
                },
                STATUS_SOURCE_UNREACHABLE_CONFIRMED: {
                    "meaning": (
                        "recorded evidence shows the source is demonstrably gone and "
                        "the Sources index agrees"
                    ),
                    "legacy_label": "SOURCE-UNREACHABLE",
                },
            },
            "complement": {
                STATUS_ADMITTED: {
                    "meaning": "an admitted recipe exists",
                    "legacy_label": None,
                    "note": (
                        "not part of the legacy SOURCE-UNREACHABLE bucket; these "
                        "families already have a recipe"
                    ),
                }
            },
            "compatibility": (
                "This inventory is additive.  It does not rewrite the runtime or "
                "build/link atlas vocabularies; their SOURCE-UNREACHABLE label is "
                "unchanged.  The four fine-grained statuses above replace that "
                "umbrella only for the unadmitted cohort, and ADMITTED_RECIPE is "
                "the complement."
            ),
        },
        "fields_distinct": {
            "binary_identity": (
                "the frozen family and its Debian binary package names; a binary "
                "package is not a source package"
            ),
            "source_identity": (
                "the source package/archive named by the recipe or the Debian "
                "Sources index, with its selected version, origin and published "
                "SHA-256"
            ),
            "upstream_project": (
                "the project metadata frozen in families.json (homepage, "
                "repository, packaging page); a family is not a source package"
            ),
            "executable_name": (
                "the family's own program when the metadata establishes one; a "
                "runtime harness is recorded separately as admitted_program"
            ),
        },
        "debian_metadata": {
            "index": index.identity,
            "suite": index.identity["suite"],
            "snapshot": index.identity["snapshot"],
            "note": (
                "the SHA-256 values in each family's debian_metadata_identity are "
                "the values published by this Sources index; no hash was computed "
                "from a downloaded archive and no hash was copied from another family"
            ),
        },
        "source_identity_accounting": {
            "total": 1000,
            "debian_metadata_resolved_with_published_sha256": debian_resolved,
            "debian_metadata_resolved_hash_unresolved": debian_resolved_hash_unresolved,
            "debian_metadata_unresolved": debian_unresolved,
            "source_identity_sha256_resolved": source_identity_hash_resolved,
            "source_identity_sha256_unresolved": source_identity_hash_unresolved,
            "source_identity_basis": {
                basis: source_identity_basis.get(basis, 0)
                for basis in ("debian-sources-index", "recipe-catalogue", "UNRESOLVED")
            },
            "shared_sha256_groups": len(shared_recipe_hashes),
            "shared_sha256_note": (
                "A shared SHA-256 is recorded only when the metadata or two recipes "
                "independently name the same source archive.  No Debian-published "
                "hash is shared across two different source packages (asserted)."
            ),
            "sum": 1000,
        },
        "shared_hash_audit": {
            "debian_hashes_shared_across_different_source_packages": [],
            "recipe_hashes_shared_across_families": shared_recipe_hashes,
            "note": (
                "The one group with different archive URLs is hcxkeys/hcxtools: "
                "both recipes name the same upstream 6.2.7 release and independently "
                "pin the same digest; the URLs differ (GitHub tag archive vs Debian "
                "orig).  It is reported here, not silently collapsed."
            ),
        },
        "contradictions": contradictions,
        "notes": notes,
        "acquisition_failures_recorded": [],
        "acquisition_failure_note": (
            "No per-family acquisition attempt in the committed evidence failed "
            "and remained unresolved in this phase.  S44 records two transient "
            "failures (libssh, sslscan) that were retried successfully and are now "
            "admitted recipes; those failed URLs are preserved in each family's "
            "acquisition_history, not relabelled ACQUISITION_FAILED."
        ),
        "unresolved": {
            "families_without_any_source_identity": sum(
                1 for row in rows if row["source_identity"].get("status") == "UNRESOLVED"
            ),
            "families_with_resolved_source_identity_but_hash_unresolved": (
                resolved_source_identity_hash_unresolved
            ),
            "families_with_source_identity_hash_unresolved": source_identity_hash_unresolved,
            "families_without_debian_metadata_identity": debian_unresolved,
            "executable_name_unresolved": sum(
                1 for row in rows if row["executable_name"] == "UNRESOLVED"
            ),
            "upstream_project_homepage_unresolved": sum(
                1
                for row in rows
                if row["upstream_project"].get("homepage") == "UNRESOLVED"
            ),
            "upstream_project_repository_unresolved": sum(
                1
                for row in rows
                if row["upstream_project"].get("repository") == "UNRESOLVED"
            ),
            "ambiguous_exact_name_matches": sorted(
                row["family_id"]
                for row in rows
                if row["debian_metadata_identity"].get("status") == "AMBIGUOUS"
            ),
            "note": (
                "UNRESOLVED is a result, not a placeholder.  No source URL or hash "
                "was inferred for an unresolved family.  The frozen families.json "
                "carries no upstream homepage or repository values, so those fields "
                "are UNRESOLVED for every family rather than guessed from a source "
                "package name."
            ),
        },
        "non_claims": [
            "An inventory is not an admission and not a build: a resolved source identity says nothing about whether the family builds or behaves.",
            "The Debian Sources index is bookworm/main metadata at a pinned snapshot.  A family absent from that suite is not thereby proven absent from every Debian suite or every upstream host.",
            "A recipe catalogue pin is repository-authored evidence, not Debian-published metadata; the two provenance kinds are recorded separately.",
            "The four fine-grained statuses describe the unadmitted cohort.  ADMITTED_RECIPE is the complement and is not a claim that the recipe is safe, correct or complete.",
        ],
        "families": rows,
    }


# ---------------------------------------------------------------------------
# Markdown summary.
# ---------------------------------------------------------------------------


def _sample(rows: list[dict], status: str, limit: int = 5) -> list[dict]:
    selected = [row for row in rows if row["status"] == status]
    selected.sort(key=lambda row: int(row.get("p1000_rank") or 0))
    return selected[:limit]


def _truncate(text: str, limit: int = 220) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_markdown(inventory: dict) -> str:
    population = inventory["population"]
    counts = population["status_counts"]
    accounting = inventory["source_identity_accounting"]
    metadata = inventory["debian_metadata"]["index"]
    rows = inventory["families"]

    lines: list[str] = []
    lines.append("# S63 phase A — read-only admission inventory")
    lines.append("")
    lines.append(
        f"Source HEAD `{inventory['source_head']}`; frozen P1000 "
        f"`{population['count']}` families; generator `{inventory['generator']}`."
    )
    lines.append("")
    lines.append(
        "This inventory is read-only: it built nothing, downloaded no source "
        "archive into the repository, and modified no recipe or atlas."
    )
    lines.append("")
    lines.append("## Population accounting")
    lines.append("")
    lines.append("| status | count | meaning |")
    lines.append("|---|---:|---|")
    meanings = {
        STATUS_ADMITTED: "an admitted recipe exists (complement; not legacy SOURCE-UNREACHABLE)",
        STATUS_NO_ADMITTED_RECIPE: "source identified from trusted metadata; no recipe yet",
        STATUS_NO_SOURCE_MAPPING: "no trustworthy source identity; no URL or hash inferred",
        STATUS_ACQUISITION_FAILED: "a URL was tried and failed, not evidence the source is gone",
        STATUS_SOURCE_UNREACHABLE_CONFIRMED: "recorded evidence shows the source is gone",
    }
    for status in ALL_STATUSES:
        lines.append(f"| `{status}` | {counts.get(status, 0)} | {meanings[status]} |")
    lines.append(f"| **total** | **{population['status_sum']}** | |")
    lines.append("")
    lines.append(
        f"The four fine-grained statuses partition the "
        f"{population['unadmitted_status_sum']} unadmitted families: "
        + ", ".join(
            f"`{status}`={population['unadmitted_status_counts'][status]}"
            for status in FINE_GRAINED_STATUSES
        )
        + f".  `{STATUS_ADMITTED}`={population['admitted_recipe_count']} is the "
        "already-admitted complement.  Together they sum to "
        f"{population['status_sum']}."
    )
    lines.append("")
    lines.append("## Source identities")
    lines.append("")
    lines.append(
        f"Debian metadata: `{metadata['url']}` "
        f"(origin `{metadata['origin']}`, suite `{metadata['suite']}`, "
        f"snapshot `{metadata['snapshot'] or 'live'}`, "
        f"SHA-256 `{metadata['sha256']}`, {metadata['stanza_count']} source stanzas)."
    )
    lines.append("")
    lines.append(
        f"- Debian-metadata identity resolved with a **published** SHA-256: "
        f"**{accounting['debian_metadata_resolved_with_published_sha256']}**"
    )
    lines.append(
        f"- Debian-metadata identity resolved but the index published no archive "
        f"hash: **{accounting['debian_metadata_resolved_hash_unresolved']}**"
    )
    lines.append(
        f"- No Debian-metadata identity: **{accounting['debian_metadata_unresolved']}**"
    )
    lines.append(
        f"- Primary source-identity hash resolved (Debian or recipe pin): "
        f"**{accounting['source_identity_sha256_resolved']}**; "
        f"UNRESOLVED: **{accounting['source_identity_sha256_unresolved']}**"
    )
    non_debian_recipes = sum(
        1
        for row in rows
        if row["recipe"]
        and row["debian_metadata_identity"].get("status") != "RESOLVED"
    )
    lines.append(
        "  Of the "
        f"{accounting['debian_metadata_unresolved']} without a Debian-metadata "
        f"identity, **{non_debian_recipes}** are recipe-backed families whose "
        "source is not a Debian source package."
    )
    lines.append(
        "- Primary source-identity basis: "
        + ", ".join(
            f"`{basis}`={count}"
            for basis, count in accounting["source_identity_basis"].items()
        )
    )
    lines.append("")
    lines.append("The four fields kept distinct per family are:")
    lines.append("")
    lines.append("- `binary_identity` — frozen family and Debian binary package names")
    lines.append("- `source_identity` — source package/archive, version, origin and hash")
    lines.append("- `upstream_project` — project homepage/repository/packaging page")
    lines.append("- `executable_name` — the family's own program, or `UNRESOLVED` for a library")
    lines.append("")
    lines.append("## Samples by status")
    lines.append("")
    for status in ALL_STATUSES:
        sample = _sample(rows, status)
        lines.append(f"### `{status}` ({counts.get(status, 0)})")
        lines.append("")
        if not sample:
            lines.append("_No family has this status._")
            if status == STATUS_ACQUISITION_FAILED:
                lines.append("")
                lines.append(inventory["acquisition_failure_note"])
            lines.append("")
            continue
        for row in sample:
            lines.append(
                f"- `{row['family_id']}` — {_truncate(row['status_reason'])}"
            )
        lines.append("")
    lines.append("## Contradictions (reported, not fixed)")
    lines.append("")
    if inventory["contradictions"]:
        for item in inventory["contradictions"]:
            if item["kind"] == "prior_source_unreachable_contradicted_by_metadata":
                lines.append(
                    f"- `{item['kind']}` — `{item['family_id']}`: prior "
                    f"`{item['prior_status']}` (\"{_truncate(item['prior_reason'])}\") "
                    f"is contradicted by bookworm/main: source "
                    f"`{item['resolved_source_package']}` version "
                    f"`{item['resolved_version']}` with published SHA-256 "
                    f"`{item['resolved_sha256']}`."
                )
            else:
                lines.append(
                    f"- `{item['kind']}` — `{item['family_id']}`: "
                    f"{_truncate(json.dumps(item, sort_keys=True))}"
                )
    else:
        lines.append("_No contradiction was found._")
    lines.append("")
    if inventory["notes"]:
        notes_by_kind = collections.Counter(
            note["kind"] for note in inventory["notes"]
        )
        lines.append(
            "Informational notes (not contradictions): "
            + ", ".join(
                f"`{kind}`={count}" for kind, count in sorted(notes_by_kind.items())
            )
            + ".  A recipe and the bookworm/main candidate are allowed to be "
            "different releases of the same source package."
        )
        lines.append("")
    lines.append("## Shared source hashes")
    lines.append("")
    shared = inventory["shared_hash_audit"]
    lines.append(
        f"- Debian-published hashes shared across different source packages: "
        f"**{len(shared['debian_hashes_shared_across_different_source_packages'])}** "
        "(asserted; a non-zero count would be a copied-hash defect)"
    )
    groups = shared["recipe_hashes_shared_across_families"]
    lines.append(
        f"- Recipe-pinned hashes shared by more than one family: **{len(groups)}** groups. "
        "These are families that name the same source archive (for example "
        "`curl`/`curl-minimal` or `nmap`/`nmap-ncat`), not copied hashes."
    )
    different_urls = [group for group in groups if len(group["archive_urls"]) > 1]
    for group in different_urls:
        lines.append(
            f"  - `{group['sha256'][:16]}…` is independently pinned by "
            + ", ".join(f"`{family}`" for family in group["families"])
            + " from different URLs: "
            + ", ".join(group["archive_urls"])
            + "."
        )
    lines.append("")
    lines.append("## Unresolved, stated plainly")
    lines.append("")
    unresolved = inventory["unresolved"]
    lines.append(
        f"- Families with no source identity at all: "
        f"**{unresolved['families_without_any_source_identity']}**"
    )
    lines.append(
        f"- Families with a resolved source identity but no hash: "
        f"**{unresolved['families_with_resolved_source_identity_but_hash_unresolved']}**"
    )
    lines.append(
        f"- Families with no executable name in the metadata (library-only or "
        f"artifact is a shared object): **{unresolved['executable_name_unresolved']}**"
    )
    lines.append(
        f"- Families with no upstream homepage / repository in the frozen registry: "
        f"**{unresolved['upstream_project_homepage_unresolved']}** / "
        f"**{unresolved['upstream_project_repository_unresolved']}**.  These fields "
        "are `UNRESOLVED`, not guessed from a source package or project name."
    )
    lines.append(
        f"- Families with no Debian-metadata identity: "
        f"**{unresolved['families_without_debian_metadata_identity']}**"
    )
    if unresolved["ambiguous_exact_name_matches"]:
        lines.append(
            "- Ambiguous exact-name matches (kept unresolved, not guessed): "
            + ", ".join(f"`{fid}`" for fid in unresolved["ambiguous_exact_name_matches"])
        )
    lines.append("")
    lines.append(
        "A family absent from bookworm/main is recorded `NO_SOURCE_MAPPING`; the "
        "resolver does not turn `bind` into `bind9`, `exim` into `exim4`, or an "
        "upstream project name into a guessed GitHub URL."
    )
    lines.append("")
    lines.append("## Non-claims")
    lines.append("")
    for claim in inventory["non_claims"]:
        lines.append(f"- {claim}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the read-only S63 admission inventory for the frozen P1000.  "
            "This tool never builds and never fetches a source archive."
        )
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(os.environ.get("TMPDIR", tempfile.gettempdir()))
        / "s63-admission-metadata",
        help="where to cache the Debian Sources index (default: $TMPDIR/s63-admission-metadata)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use only a cached Debian Sources index; never open the network",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="per-index fetch timeout in seconds (default: 180)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=OUT_JSON,
        help=f"inventory JSON output (default: {_rel(OUT_JSON)})",
    )
    parser.add_argument(
        "--md-out",
        type=Path,
        default=OUT_MD,
        help=f"inventory markdown output (default: {_rel(OUT_MD)})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="assert the accounting of an existing inventory and exit without writing",
    )
    args = parser.parse_args(argv)

    if args.check:
        if not args.json_out.is_file():
            _fatal(f"{args.json_out} is absent; there is nothing to check")
        inventory = _load_json(args.json_out)
        population = inventory.get("population") or {}
        rows = inventory.get("families") or []
        counts = population.get("status_counts") or {}
        if len(rows) != 1000:
            _fatal(f"{args.json_out} has {len(rows)} family rows, not 1000")
        frozen_ids = {row["family_id"] for row in load_frozen_population()}
        row_ids = {row.get("family_id") for row in rows}
        if len(row_ids) != 1000:
            _fatal(f"{args.json_out} double-counts a family id")
        if row_ids != frozen_ids:
            missing = sorted(frozen_ids - row_ids)
            extra = sorted(row_ids - frozen_ids)
            _fatal(
                f"{args.json_out} family set differs from the freeze: "
                f"missing={missing[:10]} extra={extra[:10]}"
            )
        if sum(counts.values()) != 1000:
            _fatal(f"{args.json_out} status counts sum to {sum(counts.values())}, not 1000")
        fine_grained = sum(counts.get(s, 0) for s in FINE_GRAINED_STATUSES)
        if counts.get(STATUS_ADMITTED, 0) + fine_grained != 1000:
            _fatal(
                f"{args.json_out} ADMITTED_RECIPE + the four fine-grained "
                "statuses do not sum to 1000"
            )
        print(
            f"OK: 1000 families, status counts sum to 1000, "
            f"admitted={counts.get(STATUS_ADMITTED, 0)}, "
            f"unadmitted={fine_grained}"
        )
        return 0

    population = load_frozen_population()
    families_by_id = load_families()
    recipes, catalogue_source = load_recipe_catalogue()
    runtime = load_atlas(RUNTIME_ATLAS)
    build_link = load_atlas(BUILD_LINK_ATLAS)

    index, _identity = fetch_debian_index(
        args.cache_dir, offline=args.offline, timeout=args.timeout
    )
    inventory = build_inventory(
        population,
        families_by_id,
        recipes,
        catalogue_source,
        runtime,
        build_link,
        index,
    )

    body_for_hash = {
        "population": inventory["population"],
        "source_identity_accounting": inventory["source_identity_accounting"],
        "debian_metadata": inventory["debian_metadata"],
        "contradictions": inventory["contradictions"],
        "shared_hash_audit": inventory["shared_hash_audit"],
        "families": inventory["families"],
    }
    inventory["inventory_body_sha256"] = _sha256_bytes(
        json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.md_out.write_text(render_markdown(inventory), encoding="utf-8")

    counts = inventory["population"]["status_counts"]
    print(
        "S63 admission inventory: "
        + ", ".join(f"{status}={counts.get(status, 0)}" for status in ALL_STATUSES)
        + f"; total={inventory['population']['status_sum']}"
    )
    print(
        "source identities: Debian-published SHA-256="
        f"{inventory['source_identity_accounting']['debian_metadata_resolved_with_published_sha256']}, "
        "recipe-pin basis="
        f"{inventory['source_identity_accounting']['source_identity_basis']['recipe-catalogue']}, "
        "UNRESOLVED basis="
        f"{inventory['source_identity_accounting']['source_identity_basis']['UNRESOLVED']}"
    )
    print(f"wrote {_rel(args.json_out)} and {_rel(args.md_out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
