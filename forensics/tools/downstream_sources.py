#!/usr/bin/env python3
"""openssl-rs — Phase-24.1 ranking-source acquisition: the frozen precommitment evidence.

Phase 24's population of 1,000 downstream project families is *selected*, not sampled, and
`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` sections 1 and 3.4 make the selection rule
load-bearing: the families are ranked from **multi-source ranking evidence acquired and
content-addressed before any candidate result exists**, so the population cannot be chosen by
what the candidate happens to pass. This module is 24.1's instrument: it acquires, inside the
admitted court container only, every reproducibly-obtainable ranking / reverse-dependency input
the P1000 selection will rank from, and freezes each source's identity so the selection is
reproducible.

What is acquired
----------------
The sources are the ones 24.1 names: the Debian reverse-dependency graph and the Debian Popcon
install/vote counts (Debian snapshot where possible), the Fedora reverse package dependencies,
the Alpine reverse package dependencies, Homebrew `openssl@3`'s dependency relationships and its
formula analytics, the OpenSSF Criticality Score, and the supported-ecosystem dependent-count data
that bears on OpenSSL wrappers and bindings. Each source that cannot be obtained reproducibly is
recorded `unavailable` with the precise reason -- never invented -- and is excluded from the frozen
root. **Raw GitHub stars are never the usage definition.**

What each source row records (brief section 7)
----------------------------------------------
For every source the manifest row carries its `source_id`, its citation URL/API, the retrieval
timestamp (`retrieved_at`) and `fetch_date`, the **raw payload SHA-256** (and, where a source has
more than one payload, a `raw_payloads` list with each payload's hash, size and content type), the
payload size and content type, the snapshot/repository timestamp, the parser version, the
normalized row count and the **normalization hash** (the SHA-256 of the committed normalized
bytes). A `sha256` of `unknown` marks a source that was not obtainable; it is stated, not guessed.

Large payloads are never committed (brief section 49)
-----------------------------------------------------
The raw payloads are large (tens of megabytes) and are not committed into the tree. What is
committed is the **manifest** plus the **normalized inputs** (`forensics/downstream/ranking/`),
and, for a payload small enough to keep, its bytes under a content-addressed name
(`raw/<source_id>-<sha256>.<ext>`); for a payload too large to keep, its hash plus a deterministic
retrieval `recipe` (the exact `curl` invocation) so it can be regenerated. The court
`RT-RANKING-SOURCES` validates the committed manifest against the committed normalized inputs and
re-derives the frozen root; it never fetches.

The frozen selection root
-------------------------
`selection_input_root_hash` binds the identity of every **present** source -- `source_id`, `kind`,
`url`, raw `sha256`, `row_count` and `normalization_sha256` -- through `atlas_common.content_hash`,
so the precommitted selection input is a single digest a later subphase selects the population from.
An `unavailable` source carries a reason and is not counted present, so it cannot enter the root.

The Docker-only guard is called first
-------------------------------------
This module fetches from the network and computes hashes over real payloads, so it is an
**execution** entry point: `phase24_guard.require_admitted()` is the first statement of `main` and a
host invocation is refused rather than producing unreproducible evidence
(`docs/REPRODUCIBILITY.md` section 1).

Outputs
-------
  forensics/downstream/ranking-sources.json           the source manifest (schema kind `ranking_source`)
  forensics/downstream/ranking/normalized/<id>.json   the committed normalized inputs
  forensics/downstream/ranking/raw/<id>-<sha>.<ext>   small committed raw payloads (<= 256 KiB)

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import datetime
import gzip
import json
import lzma
import re
import struct
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
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
    sha256_bytes,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool fetches
# from the network, so it is an execution entry point and the manifest does not list it
# `metadata_only`, which means a host invocation is refused.
import phase24_guard  # noqa: E402

# The record schema each manifest row is validated against (kind `ranking_source`), so a malformed
# row is a finding rather than a plausible-looking one.
import downstream_schemas  # noqa: E402

MANIFEST = REPO_ROOT / "forensics" / "downstream" / "ranking-sources.json"
NORMALIZED_DIR = REPO_ROOT / "forensics" / "downstream" / "ranking" / "normalized"
RAW_DIR = REPO_ROOT / "forensics" / "downstream" / "ranking" / "raw"
# Scratch is kept under /work (the task's instruction) and under the gitignored `/court/` path, so
# a large payload never pollutes the tree and is deleted after it has been hashed.
SCRATCH = REPO_ROOT / "court" / "phase24-sources"

GENERATOR = "forensics/tools/downstream_sources.py"
PARSER_VERSION = "downstream-sources/1"
USER_AGENT = "openssl-rs-forensics/1"
# A raw payload at or below this size is committed content-addressed; a larger one is hashed,
# deleted, and recorded with its deterministic retrieval recipe (brief section 49).
RAW_COMMIT_LIMIT = 256 * 1024

_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# The Debian binary packages whose reverse dependencies are the OpenSSL graph, and the Fedora /
# Alpine capability and package names the same graph is read from. These are the *providers* the
# reverse-dependency scan looks for; a dependent is a package that names one of them.
DEBIAN_PROVIDERS = ("libssl3", "libcrypto3", "openssl")
FEDORA_PROVIDERS = ("openssl-libs", "libssl.so.3", "libcrypto.so.3")
ALPINE_PROVIDERS = ("so:libssl.so.3", "so:libcrypto.so.3", "openssl")
# The Homebrew formula whose dependents and analytics rank the ecosystem, and the formulae whose
# analytics rows the popularity source normalizes.
HOMEBREW_FORMULA = "openssl@3"
HOMEBREW_ANALYTICS_FORMULAE = ("openssl@3", "openssl", "openssl@1.1")
# The Rust wrapper/binding whose reverse dependencies are the supported-ecosystem dependent count.
CRATES_CRATE = "openssl"

# The acquisition plan. `payloads` names every raw payload a source is retrieved from; `parser` is
# the pure function that turns the downloaded bytes into normalized rows. `repository_timestamp`
# is the snapshot/repository identity when the URL itself does not carry it (Fedora's and Popcon's
# are read from the payloads at acquisition time; `None` means "read it from the payload").
SOURCE_SPECS: tuple[dict, ...] = (
    {
        "source_id": "debian-rdepends",
        "kind": "distro-package",
        "url": ("https://snapshot.debian.org/archive/debian/20241001T000000Z/dists/"
                "bookworm/main/binary-amd64/Packages.xz"),
        "repository_timestamp": "2024-10-01T00:00:00Z",
        "parser": "debian_rdepends_rows",
        "payloads": ({"role": "packages",
                      "url": ("https://snapshot.debian.org/archive/debian/20241001T000000Z/"
                              "dists/bookworm/main/binary-amd64/Packages.xz")},),
        "notes": ("Debian bookworm main binary-amd64 Packages, pinned to the snapshot.debian.org "
                  "timestamp 20241001T000000Z; reverse dependencies of libssl3/libcrypto3/openssl "
                  "computed from the Depends/Pre-Depends/Recommends fields"),
    },
    {
        "source_id": "debian-popcon",
        "kind": "popularity",
        "url": "https://popcon.debian.org/all-popcon-results.txt.gz",
        "repository_timestamp": None,  # read from the gzip header mtime
        "parser": "popcon_rows",
        "payloads": ({"role": "popcon",
                      "url": "https://popcon.debian.org/all-popcon-results.txt.gz"},),
        "notes": ("Debian Popcon install/vote counts; Popcon is a moving snapshot, so the payload "
                  "hash plus the retrieval timestamp and the gzip header mtime pin the exact bytes "
                  "rather than a date"),
    },
    {
        "source_id": "fedora-rdepends",
        "kind": "distro-package",
        "url": ("https://dl.fedoraproject.org/pub/archive/fedora/linux/releases/39/Everything/"
                "x86_64/os/repodata/"
                "e681f4dcf1aa9814a1393a685d70b94210232b8997d2bc8a02c080e0ba8e51e3-primary.xml.gz"),
        "repository_timestamp": None,  # read from repomd <revision>
        "parser": "fedora_rdepends_rows",
        "payloads": (
            {"role": "primary",
             "url": ("https://dl.fedoraproject.org/pub/archive/fedora/linux/releases/39/"
                     "Everything/x86_64/os/repodata/"
                     "e681f4dcf1aa9814a1393a685d70b94210232b8997d2bc8a02c080e0ba8e51e3-"
                     "primary.xml.gz")},
            {"role": "repomd",
             "url": ("https://dl.fedoraproject.org/pub/archive/fedora/linux/releases/39/"
                     "Everything/x86_64/os/repodata/repomd.xml")},
        ),
        "notes": ("Fedora 39 Everything x86_64 primary metadata (the newest archived Fedora "
                  "release whose repodata is gzip rather than zstd, so it regenerates without a "
                  "zstd dependency); reverse dependencies of openssl-libs / libssl.so.3 / "
                  "libcrypto.so.3"),
    },
    {
        "source_id": "alpine-main-rdepends",
        "kind": "distro-package",
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/APKINDEX.tar.gz",
        "repository_timestamp": "alpine-v3.20",
        "parser": "alpine_rdepends_rows",
        "payloads": ({"role": "apkindex",
                      "url": ("https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/"
                              "APKINDEX.tar.gz")},),
        "notes": "Alpine v3.20 main APKINDEX: reverse dependencies of so:libssl.so.3",
    },
    {
        "source_id": "alpine-community-rdepends",
        "kind": "distro-package",
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.20/community/x86_64/APKINDEX.tar.gz",
        "repository_timestamp": "alpine-v3.20",
        "parser": "alpine_rdepends_rows",
        "payloads": ({"role": "apkindex",
                      "url": ("https://dl-cdn.alpinelinux.org/alpine/v3.20/community/x86_64/"
                              "APKINDEX.tar.gz")},),
        "notes": "Alpine v3.20 community APKINDEX: reverse dependencies of so:libssl.so.3",
    },
    {
        "source_id": "homebrew-dependencies",
        "kind": "language-registry",
        "url": "https://formulae.brew.sh/api/formula.json",
        "repository_timestamp": None,  # read from each formula's generated_date
        "parser": "homebrew_dependency_rows",
        "payloads": ({"role": "formulae",
                      "url": "https://formulae.brew.sh/api/formula.json"},),
        "notes": ("Homebrew formulae metadata: the reverse dependency relationships of "
                  "openssl@3 (the formulae that depend on it) and openssl@3's own forward "
                  "dependencies and version"),
    },
    {
        "source_id": "homebrew-analytics",
        "kind": "popularity",
        "url": "https://formulae.brew.sh/api/analytics/install-on-request/365d.json",
        "repository_timestamp": None,  # read from the report's start_date..end_date
        "parser": "homebrew_analytics_rows",
        "payloads": ({"role": "analytics",
                      "url": ("https://formulae.brew.sh/api/analytics/install-on-request/"
                              "365d.json")},),
        "notes": ("Homebrew 365-day install-on-request analytics: the install counts for the "
                  "openssl formulae, the usage signal the selection ranks on (never GitHub stars)"),
    },
    {
        "source_id": "crates-rdepends",
        "kind": "language-registry",
        "url": "https://crates.io/api/v1/crates/openssl/reverse_dependencies?per_page=100",
        "repository_timestamp": None,  # read from the reverse-dependency response timestamps
        "parser": "crates_rdepends_rows",
        "payloads": ({"role": "reverse-dependencies",
                      "url": ("https://crates.io/api/v1/crates/openssl/reverse_dependencies"
                              "?per_page=100")},),
        "notes": ("crates.io reverse dependencies of the openssl crate (the Rust OpenSSL "
                  "binding): the dependent-crate count and the first page of dependent crate "
                  "names, the supported-ecosystem dependent-count data for a wrapper/binding"),
    },
    {
        "source_id": "openssf-scorecard",
        "kind": "security-advisory",
        "url": "https://api.securityscorecards.dev/projects/github.com/openssl/openssl",
        "repository_timestamp": None,  # read from the scorecard's own `date`
        "parser": "scorecard_rows",
        "payloads": ({"role": "scorecard",
                      "url": "https://api.securityscorecards.dev/projects/github.com/openssl/openssl"},),
        "notes": ("OpenSSF Scorecard for openssl/openssl: the obtainable OpenSSF security signal, "
                  "recorded as Scorecard (not the Criticality Score, which has no reproducible "
                  "public endpoint and is recorded unavailable below)"),
    },
    {
        "source_id": "openssf-criticality",
        "kind": "security-advisory",
        "url": "https://github.com/ossf/criticality_score",
        "repository_timestamp": None,
        "parser": None,
        "payloads": (),
        "unavailable_reason": ("no reproducibly-obtainable public endpoint: ossf/criticality_score "
                               "is a local CLI over a BigQuery snapshot, and deps.dev (which wraps "
                               "OpenSSF Scorecard) exposes no criticality field, so a criticality "
                               "payload cannot be regenerated from a committed recipe"),
    },
)


# --------------------------------------------------------------------------------------------
# small shared helpers
# --------------------------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _gzip_mtime(path: Path) -> str | None:
    """The ISO timestamp of a gzip header's mtime field, or `None` when it is absent."""
    with path.open("rb") as fh:
        head = fh.read(8)
    if len(head) < 8 or head[:2] != b"\x1f\x8b":
        return None
    mtime = struct.unpack("<I", head[4:8])[0]
    if not mtime:
        return None
    return datetime.datetime.fromtimestamp(
        mtime, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _recipe(url: str) -> str:
    return f"curl -sSL --fail -A {USER_AGENT} -o <out> {url!r}"


def _ext_for(url: str, content_type: str) -> str:
    if ".tar.gz" in url:
        return "tar.gz"
    suffix = Path(url.split("?")[0]).suffix.lstrip(".")
    if suffix:
        return suffix
    if "json" in content_type:
        return "json"
    return "raw"


def _split_relations(value: str) -> list[str]:
    """The package names in a Debian relation field, alternatives and versions stripped."""
    names: list[str] = []
    for group in value.split(","):
        first = group.split("|")[0].strip()
        if not first:
            continue
        name = first.split("(")[0].split("[")[0].split("<")[0].strip()
        name = name.split(":")[0].strip()
        if name:
            names.append(name)
    return names


# --------------------------------------------------------------------------------------------
# the parsers: each is a pure function of the downloaded bytes -> normalized rows
# --------------------------------------------------------------------------------------------

def _debian_stanzas(text: str):
    fields: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if fields:
                yield fields
            fields = {}
            current = None
            continue
        if line[0] in " \t" and current is not None:
            fields[current] += " " + line.strip()
        elif ":" in line:
            key, value = line.split(":", 1)
            current = key.strip()
            fields[current] = value.strip()
    if fields:
        yield fields


def debian_rdepends_rows(paths: list[Path]) -> list[dict]:
    """The Debian reverse-dependency graph: packages depending on an OpenSSL provider."""
    with lzma.open(paths[0], "rt", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    dependents: dict[str, set[str]] = {p: set() for p in DEBIAN_PROVIDERS}
    seen: set[str] = set()
    for stanza in _debian_stanzas(text):
        pkg = stanza.get("Package")
        if not pkg or pkg in seen:
            continue
        seen.add(pkg)
        named: set[str] = set()
        for field in ("Pre-Depends", "Depends", "Recommends"):
            names = _split_relations(stanza.get(field, ""))
            named.update(n for n in names if n in DEBIAN_PROVIDERS)
        for provider in named:
            dependents[provider].add(pkg)
    rows = []
    for provider in DEBIAN_PROVIDERS:
        for pkg in sorted(dependents[provider]):
            rows.append({"dependent": pkg, "provides": provider})
    rows.sort(key=lambda r: (r["dependent"], r["provides"]))
    return rows


def _fedora_requirement_names(elem: ET.Element) -> list[str]:
    names: list[str] = []
    for req in elem.iter("{http://linux.duke.edu/metadata/rpm}requires"):
        for entry in req.iter("{http://linux.duke.edu/metadata/rpm}entry"):
            name = entry.get("name")
            if name:
                names.append(name)
    return names


def fedora_rdepends_rows(paths: list[Path]) -> list[dict]:
    """The Fedora reverse-dependency graph, streamed so a 170 MB primary.xml.gz stays bounded."""
    primary = next(p for p in paths if ".primary." in p.name)
    ns = "{http://linux.duke.edu/metadata/common}"
    rows: list[dict] = []
    with gzip.open(primary, "rb") as fh:
        for _event, elem in ET.iterparse(fh, events=("end",)):
            if elem.tag != f"{ns}package":
                continue
            name = elem.findtext(f"{ns}name")
            requires = _fedora_requirement_names(elem)
            matched = sorted({r for r in requires
                              if r in FEDORA_PROVIDERS
                              or r.startswith("libssl.so.3")
                              or r.startswith("libcrypto.so.3")})
            if name and matched:
                rows.append({"dependent": name, "requires": matched})
            elem.clear()
    rows.sort(key=lambda r: r["dependent"])
    return rows


def _apkindex_stanzas(path: Path):
    with tarfile.open(path, "r:gz") as tar:
        member = next(m for m in tar.getmembers() if m.name.endswith("APKINDEX"))
        data = tar.extractfile(member).read().decode("utf-8", "replace")
    fields: dict[str, str] = {}
    for line in data.splitlines():
        if not line.strip():
            if fields:
                yield fields
            fields = {}
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value
    if fields:
        yield fields


def alpine_rdepends_rows(paths: list[Path]) -> list[dict]:
    """The Alpine reverse-dependency graph: packages whose Depends name the OpenSSL sonames."""
    rows: list[dict] = []
    for stanza in _apkindex_stanzas(paths[0]):
        pkg = stanza.get("P")
        if not pkg:
            continue
        depends = [d.split("=")[0] for d in stanza.get("D", "").split()]
        matched = sorted({d for d in depends if d in ALPINE_PROVIDERS})
        if matched:
            rows.append({"dependent": pkg, "requires": matched})
    rows.sort(key=lambda r: r["dependent"])
    return rows


def popcon_rows(paths: list[Path]) -> list[dict]:
    """The Debian Popcon rows for the OpenSSL packages (install/vote counts)."""
    rows: list[dict] = []
    with gzip.open(paths[0], "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("Package:"):
                continue
            parts = line.split()
            # `Package: <name> <vote> <recent> <...>` -- the name and the two leading counts.
            if len(parts) < 4:
                continue
            name = parts[1]
            if not (name == "openssl" or name.startswith("libssl")
                    or name.startswith("libcrypto")):
                continue
            rows.append({"package": name, "vote": parts[2], "recent": parts[3]})
    rows.sort(key=lambda r: r["package"])
    return rows


def _dep_names(value) -> list[str]:
    """The formula names in a Homebrew dependency list, where an entry may be a bare name or a
    mapping (a versioned/optional dependency carries its name in a sub-field)."""
    names: list[str] = []
    for item in value or []:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name = item.get("name") or item.get("formula")
            if name:
                names.append(str(name))
    return names


def homebrew_dependency_rows(paths: list[Path]) -> list[dict]:
    """The Homebrew dependency relationships of `openssl@3` (reverse, then forward)."""
    formulae = json.loads(paths[0].read_text(encoding="utf-8"))
    rows: list[dict] = []
    for formula in formulae:
        name = formula.get("name")
        if not name or name == HOMEBREW_FORMULA:
            continue
        declared = set(_dep_names(formula.get("dependencies")))
        declared.update(_dep_names(formula.get("uses_from_macos")))
        if HOMEBREW_FORMULA in declared:
            rows.append({"dependent": name, "relation": "depends_on", "dependency": HOMEBREW_FORMULA})
    own = next((f for f in formulae if f.get("name") == HOMEBREW_FORMULA), None)
    if own:
        for dep in sorted(set(_dep_names(own.get("dependencies")))):
            rows.append({"dependent": HOMEBREW_FORMULA, "relation": "depends_on", "dependency": dep})
        for dep in sorted(set(_dep_names(own.get("uses_from_macos")))):
            rows.append({"dependent": HOMEBREW_FORMULA, "relation": "uses_from_macos",
                         "dependency": dep})
    rows.sort(key=lambda r: (r["dependent"], r["relation"], r["dependency"]))
    return rows


def homebrew_analytics_rows(paths: list[Path]) -> list[dict]:
    """The Homebrew 365-day install-on-request rows for the OpenSSL formulae."""
    report = json.loads(paths[0].read_text(encoding="utf-8"))
    rows = []
    for item in report.get("items", []):
        formula = item.get("formula")
        if formula in HOMEBREW_ANALYTICS_FORMULAE:
            rows.append({"formula": formula, "count": item.get("count"),
                         "percent": item.get("percent")})
    rows.sort(key=lambda r: r["formula"])
    return rows


def crates_rdepends_rows(paths: list[Path]) -> list[dict]:
    """The crates.io reverse dependencies of the `openssl` binding crate."""
    body = json.loads(paths[0].read_text(encoding="utf-8"))
    rows = []
    for version in body.get("versions", []):
        crate = version.get("crate")
        if crate:
            rows.append({"dependent": crate, "downloads": version.get("downloads"),
                         "version": version.get("num")})
    rows.sort(key=lambda r: r["dependent"])
    return rows


def scorecard_rows(paths: list[Path]) -> list[dict]:
    """The OpenSSF Scorecard checks for openssl/openssl."""
    body = json.loads(paths[0].read_text(encoding="utf-8"))
    rows = []
    for check in body.get("checks", []):
        rows.append({"check": check.get("name"), "score": check.get("score"),
                     "reason": check.get("reason")})
    rows.sort(key=lambda r: r["check"] or "")
    return rows


PARSERS = {
    "debian_rdepends_rows": debian_rdepends_rows,
    "fedora_rdepends_rows": fedora_rdepends_rows,
    "alpine_rdepends_rows": alpine_rdepends_rows,
    "popcon_rows": popcon_rows,
    "homebrew_dependency_rows": homebrew_dependency_rows,
    "homebrew_analytics_rows": homebrew_analytics_rows,
    "crates_rdepends_rows": crates_rdepends_rows,
    "scorecard_rows": scorecard_rows,
}


# --------------------------------------------------------------------------------------------
# the frozen selection root
# --------------------------------------------------------------------------------------------

def selection_input_root_hash(rows: list[dict]) -> str:
    """The frozen digest over every **present** ranking source's identity.

    Only `availability == "available"` sources enter the root: an unavailable source carries a
    reason and is never counted present, so it cannot influence the precommitted selection input.
    """
    present = sorted((r for r in rows if r.get("availability") == "available"),
                     key=lambda r: str(r.get("source_id")))
    payload = [{
        "source_id": r.get("source_id"),
        "kind": r.get("kind"),
        "url": r.get("url"),
        "sha256": r.get("sha256"),
        "row_count": r.get("row_count"),
        "normalization_sha256": r.get("normalization_sha256"),
    } for r in present]
    return content_hash({"sources": payload})


# --------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed manifest (never fetching)
# --------------------------------------------------------------------------------------------

def _row_problems(row: dict, index: int, normalized: dict[str, bytes]) -> list[str]:
    sid = str(row.get("source_id") or f"#{index}")
    problems = [f"source {sid}: {p}"
                for p in downstream_schemas.validate_ranking_source(row)]
    availability = row.get("availability")
    if availability not in ("available", "unavailable"):
        problems.append(f"source {sid}: availability {availability!r} is neither "
                        f"`available` nor `unavailable`")

    retrieved = row.get("retrieved_at")
    if not isinstance(retrieved, str) or not _ISO.match(retrieved):
        problems.append(f"source {sid}: retrieved_at {retrieved!r} is not an ISO-8601 UTC "
                        f"retrieval timestamp")
    for field in ("parser_version", "repository_timestamp"):
        if not row.get(field):
            problems.append(f"source {sid}: {field} is empty")

    payloads = row.get("raw_payloads")
    if not isinstance(payloads, list):
        payloads = []
    if availability == "available" and not payloads:
        problems.append(f"source {sid}: an available source carries no raw_payloads entry")
    for j, payload in enumerate(payloads):
        digest = payload.get("sha256")
        if not isinstance(digest, str) or not _HEX64.match(digest):
            problems.append(f"source {sid}: raw_payloads[{j}].sha256 {digest!r} is not a "
                            f"64-hex digest")
        if not payload.get("url"):
            problems.append(f"source {sid}: raw_payloads[{j}] carries no url")
        if not isinstance(payload.get("size_bytes"), int) or payload["size_bytes"] < 0:
            problems.append(f"source {sid}: raw_payloads[{j}].size_bytes {payload.get('size_bytes')!r} "
                            f"is not a non-negative integer")
        if not payload.get("content_type"):
            problems.append(f"source {sid}: raw_payloads[{j}] carries no content_type")
        if not payload.get("recipe"):
            problems.append(f"source {sid}: raw_payloads[{j}] carries no deterministic recipe")
        committed = payload.get("committed_path")
        if committed:
            path = REPO_ROOT / committed
            if not path.is_file():
                problems.append(f"source {sid}: committed raw payload {committed} is absent")
            elif sha256_file(path) != digest:
                problems.append(f"source {sid}: committed raw payload {committed} does not hash "
                                f"to its recorded sha256")

    if availability == "available":
        if not isinstance(row.get("sha256"), str) or not _HEX64.match(row["sha256"]):
            problems.append(f"source {sid}: an available source must record a 64-hex raw sha256, "
                            f"not {row.get('sha256')!r}")
        if not isinstance(row.get("normalization_sha256"), str) \
                or not _HEX64.match(row["normalization_sha256"]):
            problems.append(f"source {sid}: an available source must record a 64-hex "
                            f"normalization_sha256")
        blob = normalized.get(sid)
        if blob is None:
            problems.append(f"source {sid}: the committed normalized input is absent")
        else:
            if sha256_bytes(blob) != row.get("normalization_sha256"):
                problems.append(f"source {sid}: the committed normalized input does not hash to "
                                f"its recorded normalization_sha256 (the payload moved)")
            try:
                doc = json.loads(blob.decode("utf-8"))
                count = int(doc.get("row_count", -1))
            except (json.JSONDecodeError, ValueError, AttributeError):
                problems.append(f"source {sid}: the committed normalized input is not readable JSON")
                count = -1
            if count != row.get("row_count"):
                problems.append(f"source {sid}: normalized row_count {count} disagrees with the "
                                f"manifest's row_count {row.get('row_count')!r}")
    else:
        if not row.get("unavailable_reason"):
            problems.append(f"source {sid}: an unavailable source must carry a reason")
        if row.get("sha256") != "unknown":
            problems.append(f"source {sid}: an unavailable source must not assert a payload hash "
                            f"(sha256={row.get('sha256')!r})")
        if sid in normalized:
            problems.append(f"source {sid}: an unavailable source is counted present (it has a "
                            f"committed normalized input)")
    return problems


def ranking_source_findings(manifest: dict, normalized: dict[str, bytes]) -> list[str]:
    """Every way the committed ranking-source manifest fails its own subject.

    A pure function of the committed manifest body and the committed normalized-input bytes, so
    the court re-runs it without fetching and the sensitivity control can mutate it.
    """
    findings: list[str] = []
    rows = manifest.get("sources")
    if not isinstance(rows, list) or not rows:
        return ["the manifest records no ranking sources"]

    seen: set[str] = set()
    for i, row in enumerate(rows):
        findings += _row_problems(row, i, normalized)
        sid = str(row.get("source_id"))
        if sid in seen:
            findings.append(f"source {sid}: duplicated source_id")
        seen.add(sid)

    present = [r for r in rows if r.get("availability") == "available"]
    if not present:
        findings.append("the manifest records no available source, so nothing was acquired")

    recomputed = selection_input_root_hash(rows)
    if recomputed != manifest.get("selection_input_root_hash"):
        findings.append("the selection_input_root_hash does not reproduce from the manifest's "
                        "present sources")
    counts = manifest.get("counts") or {}
    if counts.get("available") != len(present):
        findings.append(f"the manifest's available count {counts.get('available')!r} disagrees "
                        f"with the {len(present)} available source(s)")
    unavailable = [r for r in rows if r.get("availability") == "unavailable"]
    if counts.get("unavailable") != len(unavailable):
        findings.append(f"the manifest's unavailable count {counts.get('unavailable')!r} "
                        f"disagrees with the {len(unavailable)} unavailable source(s)")
    return findings


def load_committed(manifest: dict) -> dict[str, bytes]:
    """The committed normalized-input bytes, keyed by source_id, for the manifest's present rows."""
    out: dict[str, bytes] = {}
    for row in manifest.get("sources", []):
        if row.get("availability") != "available":
            continue
        path = row.get("normalized_path")
        if path and (REPO_ROOT / path).is_file():
            out[str(row["source_id"])] = (REPO_ROOT / path).read_bytes()
    return out


def ranking_sensitivity_control(manifest: dict, normalized: dict[str, bytes]) -> dict:
    """Prove the court can fail: seed four mutations and require each to be caught.

    The honest manifest must yield **zero** findings (specificity), and each seeded mutation --
    a source stripped of its hash, a normalized payload mutated so its hash no longer matches, an
    unavailable source counted present, and a missing retrieval timestamp -- must be caught.
    """
    base = ranking_source_findings(manifest, normalized)
    specificity = not base

    present_id = next((str(r["source_id"]) for r in manifest.get("sources", [])
                       if r.get("availability") == "available"), None)
    unavailable_id = next((str(r["source_id"]) for r in manifest.get("sources", [])
                           if r.get("availability") == "unavailable"), None)

    # (a) a source stripped of its raw hash.
    no_hash = copy.deepcopy(manifest)
    for row in no_hash.get("sources", []):
        if str(row.get("source_id")) == present_id:
            row["sha256"] = None
    no_hash_findings = ranking_source_findings(no_hash, normalized)
    caught_no_hash = any("64-hex raw sha256" in f for f in no_hash_findings)

    # (b) a normalized payload mutated so its hash no longer matches the manifest.
    if present_id is not None and present_id in normalized:
        mutated = dict(normalized)
        blob = bytearray(mutated[present_id])
        blob[-2] = blob[-2] ^ 0x20 if len(blob) > 1 else blob
        mutated[present_id] = bytes(blob)
    else:
        mutated = normalized
    mutated_findings = ranking_source_findings(manifest, mutated)
    caught_mutated = any("does not hash to its recorded normalization_sha256" in f
                         for f in mutated_findings)

    # (c) an unavailable source counted present.
    counted_present = copy.deepcopy(manifest)
    for row in counted_present.get("sources", []):
        if str(row.get("source_id")) == unavailable_id:
            row["availability"] = "available"
    counted_findings = ranking_source_findings(counted_present, normalized)
    caught_counted = any("must record a 64-hex raw sha256" in f for f in counted_findings)

    # (d) a present source with no retrieval timestamp.
    no_retrieval = copy.deepcopy(manifest)
    for row in no_retrieval.get("sources", []):
        if str(row.get("source_id")) == present_id:
            row["retrieved_at"] = None
    no_retrieval_findings = ranking_source_findings(no_retrieval, normalized)
    caught_retrieval = any("not an ISO-8601 UTC retrieval timestamp" in f
                           for f in no_retrieval_findings)

    return {
        "baseline_findings": len(base),
        "specificity_holds": specificity,
        "injected_no_hash": present_id,
        "caught_no_hash": caught_no_hash,
        "injected_mutated_payload": present_id,
        "caught_mutated_payload": caught_mutated,
        "injected_unavailable_counted_present": unavailable_id,
        "caught_unavailable_counted_present": caught_counted,
        "injected_missing_retrieval_timestamp": present_id,
        "caught_missing_retrieval_timestamp": caught_retrieval,
        "honest": bool(specificity and caught_no_hash and caught_mutated and caught_counted
                       and caught_retrieval),
    }


# --------------------------------------------------------------------------------------------
# the acquisition itself (network; runs only in the admitted container)
# --------------------------------------------------------------------------------------------

def _fetch(url: str, out: Path) -> tuple[str, str]:
    """Download `url` to `out`; return `(content_type, recipe)` or raise on failure."""
    out.parent.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        ["curl", "-sSL", "--fail", "--retry", "3", "--retry-delay", "2",
         "--max-time", "300", "-A", USER_AGENT, "-w", "%{content_type}", "-o", str(out), url],
        capture_output=True, text=True, check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(f"curl exited {res.returncode}: {res.stderr.strip()[:200]}")
    return res.stdout.strip() or "application/octet-stream", _recipe(url)


def _acquire_available(spec: dict, retrieved_at: str) -> dict:
    payloads: list[dict] = []
    paths: list[Path] = []
    for payload in spec["payloads"]:
        ext = _ext_for(payload["url"], "")
        raw = SCRATCH / f"{spec['source_id']}.{payload['role']}.{ext}"
        content_type, recipe = _fetch(payload["url"], raw)
        digest = sha256_file(raw)
        size = raw.stat().st_size
        committed_path = None
        if size <= RAW_COMMIT_LIMIT:
            committed = RAW_DIR / f"{spec['source_id']}-{digest}.{_ext_for(payload['url'], content_type)}"
            committed.parent.mkdir(parents=True, exist_ok=True)
            committed.write_bytes(raw.read_bytes())
            committed_path = rel(committed)
        payloads.append({
            "role": payload["role"],
            "url": payload["url"],
            "sha256": digest,
            "size_bytes": size,
            "content_type": content_type,
            "committed_path": committed_path,
            "recipe": recipe,
        })
        paths.append(raw)

    parser = PARSERS[spec["parser"]]
    rows = parser(paths)

    normalized_doc = {"source_id": spec["source_id"], "rows": rows, "row_count": len(rows)}
    normalized_path = NORMALIZED_DIR / f"{spec['source_id']}.json"
    normalization_sha256 = write_json(normalized_path, normalized_doc)

    # The repository timestamp: read it from the payload when the URL does not carry it.
    repository_timestamp = spec.get("repository_timestamp")
    if repository_timestamp is None:
        repository_timestamp = _repository_timestamp(spec, paths, rows)

    primary = payloads[0]
    return {
        "source_id": spec["source_id"],
        "kind": spec["kind"],
        "url": spec["url"],
        "fetch_date": retrieved_at[:10],
        "retrieved_at": retrieved_at,
        "sha256": primary["sha256"],
        "frozen": True,
        "row_count": len(rows),
        "normalized_row_count": len(rows),
        "normalization_sha256": normalization_sha256,
        "normalized_path": rel(normalized_path),
        "parser_version": PARSER_VERSION,
        "repository_timestamp": repository_timestamp,
        "content_type": primary["content_type"],
        "size_bytes": primary["size_bytes"],
        "availability": "available",
        "raw_payloads": payloads,
        "recipe": primary["recipe"],
        "notes": spec.get("notes", ""),
        "evidence": [
            f"normalized:{rel(normalized_path)}",
            *[f"raw:{payload['sha256']}" for payload in payloads],
        ],
    }


def _repository_timestamp(spec: dict, paths: list[Path], rows: list[dict]) -> str:
    """The snapshot/repository identifier a source carries, read from its own payloads."""
    sid = spec["source_id"]
    if sid == "debian-popcon":
        return _gzip_mtime(paths[0]) or "popcon-rolls-continuously"
    if sid == "fedora-rdepends":
        repomd = next((p for p in paths if ".repomd." in p.name), None)
        if repomd is not None:
            match = re.search(r"<revision>(\d+)</revision>", repomd.read_text(encoding="utf-8"))
            if match:
                return datetime.datetime.fromtimestamp(
                    int(match.group(1)), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return "fedora-39-archived"
    if sid == "homebrew-dependencies":
        return "formulae.brew.sh formula.json (live)"
    if sid == "homebrew-analytics":
        report = json.loads(paths[0].read_text(encoding="utf-8"))
        start, end = report.get("start_date"), report.get("end_date")
        return f"{start}..{end}" if start and end else "brew-analytics-365d"
    if sid == "crates-rdepends":
        return f"{CRATES_CRATE} on crates.io (live)"
    if sid == "openssf-scorecard":
        scorecard = json.loads(paths[0].read_text(encoding="utf-8"))
        return str(scorecard.get("date") or "scorecards.dev")
    return "unknown"


def _acquire_unavailable(spec: dict, retrieved_at: str) -> dict:
    return {
        "source_id": spec["source_id"],
        "kind": spec["kind"],
        "url": spec["url"],
        "fetch_date": retrieved_at[:10],
        "retrieved_at": retrieved_at,
        "sha256": "unknown",
        "frozen": True,
        "row_count": 0,
        "normalized_row_count": 0,
        "normalization_sha256": "unknown",
        "normalized_path": None,
        "parser_version": PARSER_VERSION,
        "repository_timestamp": spec.get("repository_timestamp") or "unavailable",
        "content_type": "none",
        "size_bytes": 0,
        "availability": "unavailable",
        "unavailable_reason": spec["unavailable_reason"],
        "raw_payloads": [],
        "recipe": "",
        "notes": spec.get("notes", ""),
        "evidence": [f"unavailable:{spec['unavailable_reason']}"],
    }


def acquire(retrieved_at: str) -> dict:
    """Acquire every source and return the manifest body."""
    rows: list[dict] = []
    for spec in SOURCE_SPECS:
        if spec.get("unavailable_reason"):
            print(f"  {spec['source_id']:<28} unavailable -- {spec['unavailable_reason'][:70]}")
            rows.append(_acquire_unavailable(spec, retrieved_at))
            continue
        try:
            row = _acquire_available(spec, retrieved_at)
        except Exception as exc:  # noqa: BLE001 - a failed fetch is recorded, never invented
            print(f"  {spec['source_id']:<28} FETCH FAILED -- {exc}")
            failed = {**spec, "unavailable_reason": f"acquisition failed: {exc}"}
            row = _acquire_unavailable(failed, retrieved_at)
        rows.append(row)
        print(f"  {row['source_id']:<28} available   sha256={row['sha256'][:16]}... "
              f"{row['size_bytes']:>9} B  rows={row['row_count']}")

    rows.sort(key=lambda r: str(r["source_id"]))
    present = [r for r in rows if r["availability"] == "available"]
    unavailable = [r for r in rows if r["availability"] == "unavailable"]
    return {
        "rule": (
            "the P1000 population is selected from these frozen, multi-source ranking inputs and "
            "never from a candidate result: each available source is content-addressed by its raw "
            "payload SHA-256 and its committed normalized-input SHA-256, and the "
            "selection_input_root_hash binds every available source's identity. An unavailable "
            "source carries a reason and is excluded from the root, so it cannot influence the "
            "selection. Raw GitHub stars are never the usage definition."
        ),
        "selection_input_root_hash": selection_input_root_hash(rows),
        "counts": {
            "sources": len(rows),
            "available": len(present),
            "unavailable": len(unavailable),
            "normalized_rows": sum(int(r["row_count"]) for r in present),
        },
        "sources": rows,
    }


def _inputs(body: dict) -> list[InputRef]:
    out = [InputRef(name="downstream-schemas",
                    path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py")]
    for row in body["sources"]:
        path = row.get("normalized_path")
        if path:
            out.append(InputRef(name=f"normalized/{row['source_id']}", path=REPO_ROOT / path))
        for payload in row.get("raw_payloads", []):
            if payload.get("committed_path"):
                out.append(InputRef(name=f"raw/{row['source_id']}/{payload['role']}",
                                    path=REPO_ROOT / payload["committed_path"]))
    return out


def cmd_acquire() -> int:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    retrieved_at = _utc_now()
    print(f"[downstream-sources] acquiring at {retrieved_at}")
    body = acquire(retrieved_at)

    findings = ranking_source_findings(body, load_committed(body))
    if findings:
        print("[downstream-sources] the acquired manifest fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        return 1

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="downstream-ranking-sources", authority=auth.id,
                   inputs=_inputs(body), body=body, generator=GENERATOR)
    write_json(MANIFEST, doc)

    # Clean up the large scratch payloads: only the committed (small) ones persist in the tree.
    for path in sorted(SCRATCH.glob("*")):
        path.unlink()
    try:
        SCRATCH.rmdir()
    except OSError:
        pass

    c = body["counts"]
    print(f"[downstream-sources] sources={c['sources']} available={c['available']} "
          f"unavailable={c['unavailable']} normalized_rows={c['normalized_rows']}")
    print(f"  selection_input_root_hash={body['selection_input_root_hash']}")
    print(f"  -> {rel(MANIFEST)}")
    return 0


def cmd_check() -> int:
    if not MANIFEST.is_file():
        print(f"[downstream-sources] {rel(MANIFEST)} is absent")
        return 1
    body = json.loads(MANIFEST.read_text(encoding="utf-8"))["body"]
    findings = ranking_source_findings(body, load_committed(body))
    control = ranking_sensitivity_control(body, load_committed(body))
    if findings:
        print(f"[downstream-sources] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    print(f"[downstream-sources] root={body['selection_input_root_hash']} "
          f"findings={len(findings)} control honest={control['honest']} "
          f"specificity={control['specificity_holds']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the pure functions of this module behave, without fetching."""
    failures: list[str] = []
    if not MANIFEST.is_file():
        failures.append(f"{rel(MANIFEST)} is absent")
    else:
        body = json.loads(MANIFEST.read_text(encoding="utf-8"))["body"]
        normalized = load_committed(body)
        findings = ranking_source_findings(body, normalized)
        if findings:
            failures.append(f"the committed manifest has findings: {findings[:3]}")
        control = ranking_sensitivity_control(body, normalized)
        if not control["honest"]:
            failures.append(f"the sensitivity control is not honest: {control}")
    if failures:
        print("[downstream-sources] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-sources] self-test ok: the committed manifest yields zero findings and "
          "every seeded mutation (no hash, mutated payload, unavailable-counted-present, missing "
          "retrieval timestamp) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="validate the committed manifest without fetching (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the committed manifest and its control")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool fetches from the network, so it is
    # an execution entry point and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    return cmd_acquire()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
