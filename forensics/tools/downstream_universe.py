#!/usr/bin/env python3
"""openssl-rs — Phase-24.2 candidate universe: from frozen evidence to project families.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over a
frozen population of 1,000 *families*. Before a population can be selected (24.4) or an authority
baseline taken per specimen (24.3), the *universe* it is selected from has to exist, and that
universe is what this module builds: the several thousand downstream **candidate package
identities** the frozen 24.1 evidence discovers, normalised and deduplicated into **project
families**, each classified by how it consumes OpenSSL.

Derived, never hand-listed
--------------------------
Every identity is read from a committed 24.1 source row -- the Debian / Fedora / Alpine
reverse-dependency graph, Homebrew's `openssl@3` dependency relationships, the crates.io reverse
dependencies of the `openssl` binding, and the Debian Popcon / Homebrew analytics provider-package
rows. This module fetches nothing and types no package name: it parses the committed normalized
inputs under `forensics/downstream/ranking/normalized/` and records, per identity, the source row
it came from. A package identity the sources do not carry cannot appear.

The counted unit is the family, not the package alias
-----------------------------------------------------
`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` section 3.1 makes the family the counted unit and a
package alias never one. So identities are collapsed by a **canonical project name**: `curl`,
`curl-dev`, `curl-doc`, Debian `libcurl4` and Fedora/Alpine `libcurl` are one family `curl`, and
the four do not count as four consumers. `libssl3`, `libcrypto3`, `openssl` and Homebrew's
`openssl@3`/`openssl@1.1` are one family `openssl` -- the OpenSSL *provider* itself, which is not a
downstream consumer and is classified `NOT_ACTUALLY_OPENSSL` rather than counted. A name collision
is handled the same way: `libcrypto++` is Crypto++, a different library, and is never merged with
OpenSSL's `libcrypto`.

A fork is not independent without evidence
------------------------------------------
A *fork* is collapsed into the family whose upstream it forks unless it carries explicit evidence
of materially different OpenSSL integration (`fork_evidence`). The rule is enforced structurally:
two families whose canonical names share a `fork_base` (a canonical name stripped of the fork
markers `-ng`/`-fips`/`-compat`/...) are one upstream under two names, so the second may stand
alone only with non-empty evidence -- and the instrument-sensitivity control seeds exactly the
family that stands alone without it.

Directness, kept apart
----------------------
Per brief section 8 an identity is one of `DIRECT_OPENSSL_CONSUMER` (a distro package or Homebrew
formula that names an OpenSSL provider/soname directly), `TRANSITIVE_OPENSSL_CONSUMER` (a crate
that depends on the `openssl` binding rather than on `libcrypto`/`libssl`), `NOT_ACTUALLY_OPENSSL`
(the providers themselves and name collisions) or `UNKNOWN`. The brief's remaining classes
(`OPTIONAL_`, `BUILD_ONLY_`, `VENDORED_`) are not established by this frozen evidence and are
therefore recorded as *empty* rather than invented -- `optional`/`build-depends` fields were
flattened by the 24.1 parsers, so a class the evidence cannot distinguish is not claimed.
Software that merely depends on libcurl is **not** inflated into the direct count: the reverse
scan admits a package only when it names an OpenSSL provider directly, so `git` (whose OpenSSL
link is transitive through `libcurl4`) is absent from the universe.

The Docker-only guard is called first
-------------------------------------
This module reads committed evidence and writes two artefacts; it executes nothing. Its `main`
still calls `phase24_guard.require_admitted()` first, so a host invocation is refused exactly as
every Phase-24 entry point is (`docs/REPRODUCIBILITY.md` section 1).

Outputs
-------
  forensics/downstream/candidates.json   the candidate identity universe (package identities)
  forensics/downstream/families.json     the deduplicated project families (schema kind `family`)

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import re
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
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`, exactly as it is for
# every Phase-24 entry point.
import phase24_guard  # noqa: E402

# The schemas the families are validated against (kind `family`), imported rather than restated so
# the vocabulary this module emits cannot drift from the module the court checks it with.
import downstream_schemas  # noqa: E402

# The 24.1 acquisition tool, for the provider package names its reverse-dependency scan looked for
# -- the identities that *are* OpenSSL rather than consume it -- and for the committed-input loader
# the court re-uses.
import downstream_sources  # noqa: E402

RANKING_SOURCES = REPO_ROOT / "forensics" / "downstream" / "ranking-sources.json"
RANKING_SOURCES_REL = "forensics/downstream/ranking-sources.json"
CANDIDATES = REPO_ROOT / "forensics" / "downstream" / "candidates.json"
FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
GENERATOR = "forensics/tools/downstream_universe.py"

# The directness vocabulary is owned by the schema module; re-exported here so callers name it once.
DIRECTNESS_CLASSES = downstream_schemas.DIRECTNESS_CLASSES
DIRECT = "DIRECT_OPENSSL_CONSUMER"
TRANSITIVE = "TRANSITIVE_OPENSSL_CONSUMER"
NOT_ACTUALLY = "NOT_ACTUALLY_OPENSSL"
UNKNOWN = "UNKNOWN"

# The ecosystems the frozen sources carry, mapped to the schema's `source_ecosystem` vocabulary.
ECOSYSTEMS = ("debian", "fedora", "alpine", "homebrew", "crates")
DISTRO_ECOSYSTEMS = ("debian", "fedora", "alpine")
SOURCE_ECOSYSTEM_OF = {
    "debian": "distro", "fedora": "distro", "alpine": "distro",
    "homebrew": "distro", "crates": "crates",
}

# The OpenSSL *provider* package names -- the identities that are OpenSSL rather than consume it.
# Read from the 24.1 source spec (never typed), so the scan's own providers and this classifier
# cannot drift apart.
PROVIDER_PACKAGES = {
    "openssl", "openssl-libs",
    *[p.lower() for p in downstream_sources.DEBIAN_PROVIDERS],
    *[p.lower() for p in downstream_sources.FEDORA_PROVIDERS],
    *[p.lower() for p in downstream_sources.ALPINE_PROVIDERS],
}
# The crates.io binding whose reverse dependencies are the transitive-consumer evidence.
CRATES_BINDING = downstream_sources.CRATES_CRATE
# The Homebrew formulae whose rows are the provider's own, not a consumer's.
HOMEBREW_PROVIDER_FORMULAE = {downstream_sources.HOMEBREW_FORMULA, "openssl", "openssl@1.1"}

# The smallest universe the plan calls "substantially larger than 1,000": the P1000 is selected
# *from* this, so a universe at or below 2,000 would leave no reserve to select against.
UNIVERSE_FLOOR = 2000

# The alias set the brief names as one family, not four: the court re-checks that these four
# package names canonicalise to a single upstream project.
ALIAS_SET_PROBE = ("libcurl4", "curl", "curl-dev", "curl-doc")

# --------------------------------------------------------------------------------------------
# canonicalisation: many package aliases -> one upstream project name
# --------------------------------------------------------------------------------------------

_HOMEBREW_VERSION = re.compile(r"@[0-9][0-9.a-z_-]*$")
_VERSION_TAIL = re.compile(r"[0-9][0-9a-z.]*$")
_ROLE_SUFFIX = re.compile(
    r"[-_.](dev|doc|docs|dbg|dbgsym|debug|common|data|utils|util|bin|tools|tool|core|example|"
    r"examples|module|modules|libs|lib|headers|static|compat|devel|plugin|plugins|perl|python|"
    r"python3|runtime|scripts?|man|locale|lang|pkg|tests?)$"
)
_MOD_SUFFIX = re.compile(r"[-_.]mod(ule)?[-_.][a-z0-9]+$")
_VARIANT_SUFFIX = re.compile(r"[-_.](openssl|gnutls|nss|libressl|gcrypt|wolfssl)$")
# The fork markers whose presence makes a second family a *fork candidate* rather than a project.
_FORK_MARKERS = re.compile(r"[-_.](ng|fips|compat|legacy|fork|next)$")


def _strip_candidates(name: str) -> list[str]:
    """The names one canonicalisation step may produce from `name`.

    A trailing version is offered **unconditionally** when the name is a library (`lib...`) or ends
    in `++`, so a soname version is always removed; otherwise it is offered only for the caller to
    accept when the stem is itself a package name. Every role / subpackage / backend-variant suffix
    is offered the same way, so a suffix is stripped only when the result is a package the universe
    carries (which is what makes `curl-dev` -> `curl` but leaves `apr-util` alone).
    """
    out: list[str] = []
    for candidate in (_ROLE_SUFFIX.sub("", name), _MOD_SUFFIX.sub("", name),
                      _VARIANT_SUFFIX.sub("", name)):
        candidate = candidate.replace("_", "-").strip("-._")
        if candidate and candidate != name:
            out.append(candidate)
    tail = _VERSION_TAIL.search(name)
    if tail is not None:
        base = name[: tail.start()].replace("_", "-").strip("-._")
        if base and (base.endswith("++") or name.startswith("lib")):
            out.append(base)
    return out


def canonical_package_name(name: str, universe_names: frozenset[str]) -> str:
    """The canonical upstream-project name a package alias collapses to.

    Pure and deterministic. It strips a Homebrew version alias (`openssl@3` -> `openssl`), then
    repeatedly applies the packaging/version suffix strips -- each accepted only when the result is
    a package name the universe carries, so `libcurl4` -> `libcurl` -> `curl` but `apr-util` is left
    alone -- then collapses a leading `lib` when the stem is itself a package name, and finally maps
    the OpenSSL provider aliases (`libssl3`, `libcrypto3`, `openssl-libs`) onto `openssl`. A
    name collision is never merged: `libcrypto++` stays itself and is never read as `libcrypto`.
    """
    n = name.strip().lower()
    n = _HOMEBREW_VERSION.sub("", n)
    for _ in range(6):
        nxt = n
        for candidate in _strip_candidates(n):
            if candidate in universe_names or candidate.endswith("++"):
                nxt = candidate
                break
        if nxt == n:
            break
        n = nxt
    if n.startswith("lib") and len(n) > 4:
        stem = n[3:]
        if stem in universe_names or stem.split("-")[0] in universe_names:
            n = stem
    return _provider_canonical(n) or name.strip().lower()


def _provider_canonical(n: str) -> str:
    """Collapse the OpenSSL provider aliases onto `openssl`, never a name collision."""
    if n.startswith("libcrypto++") or n.startswith("crypto++"):
        return n
    if n.startswith("libssl") or n.startswith("libcrypto") or n in ("ssl", "crypto"):
        return "openssl"
    if n.startswith("openssl"):
        return "openssl"
    return n


def fork_base(canonical: str) -> str:
    """The name a family's fork marker is stripped from: `minizip-ng` -> `minizip`."""
    return _FORK_MARKERS.sub("", canonical)


# --------------------------------------------------------------------------------------------
# discovery: the committed source rows -> candidate package identities
# --------------------------------------------------------------------------------------------

def _identity(source_id: str, ecosystem: str, package: str, relation: dict,
              repo: str | None = None) -> dict:
    return {
        "source_id": source_id,
        "ecosystem": ecosystem,
        "package": package,
        "repo": repo,
        "relation": relation,
    }


def _source_identities(source_id: str, rows: list[dict]) -> list[dict]:
    """The candidate identities one normalized source's rows carry.

    A row's `dependent`/`package` is the identity; the provider or crate it names is the relation
    the identity consumes OpenSSL through. Rows that describe the OpenSSL provider itself (a
    Homebrew formula's own dependencies, Popcon's provider packages, the analytics formulae) are
    identities too -- so they are classified `NOT_ACTUALLY_OPENSSL` rather than silently dropped.
    """
    out: list[dict] = []
    if source_id == "debian-rdepends":
        for r in rows:
            out.append(_identity(source_id, "debian", str(r["dependent"]),
                                 {"kind": "depends-on", "ons": [str(r["provides"])]}))
    elif source_id == "fedora-rdepends":
        for r in rows:
            out.append(_identity(source_id, "fedora", str(r["dependent"]),
                                 {"kind": "requires", "ons": sorted(map(str, r["requires"]))}))
    elif source_id.startswith("alpine-") and source_id.endswith("-rdepends"):
        repo = "main" if "main" in source_id else "community"
        for r in rows:
            out.append(_identity(source_id, "alpine", str(r["dependent"]),
                                 {"kind": "requires", "ons": sorted(map(str, r["requires"]))},
                                 repo=repo))
    elif source_id == "homebrew-dependencies":
        for r in rows:
            dependent = str(r["dependent"])
            if dependent in HOMEBREW_PROVIDER_FORMULAE:
                # openssl@3's own forward dependencies: the provider, not a consumer.
                out.append(_identity(source_id, "homebrew", dependent,
                                     {"kind": "is-openssl-provider",
                                      "ons": [str(r["dependency"])]}))
            else:
                out.append(_identity(source_id, "homebrew", dependent,
                                     {"kind": "depends-on", "ons": [str(r["dependency"])]}))
    elif source_id == "crates-rdepends":
        for r in rows:
            out.append(_identity(source_id, "crates", str(r["dependent"]),
                                 {"kind": "depends-on-crate", "ons": [CRATES_BINDING],
                                  "downloads": r.get("downloads")}))
    elif source_id == "debian-popcon":
        for r in rows:
            out.append(_identity(source_id, "debian", str(r["package"]),
                                 {"kind": "popcon", "vote": r.get("vote"),
                                  "recent": r.get("recent")}))
    elif source_id == "homebrew-analytics":
        for r in rows:
            out.append(_identity(source_id, "homebrew", str(r["formula"]),
                                 {"kind": "provider-analytics", "count": r.get("count")}))
    # openssf-scorecard's rows are checks of openssl/openssl, not packages: no identity.
    return out


def classify_identity(ecosystem: str, package: str) -> str:
    """The directness class of a discovered package identity (brief section 8).

    A name collision is resolved before anything else: Crypto++'s `libcrypto++*` starts with
    `libcrypto` but is a different library, so it is `NOT_ACTUALLY_OPENSSL` and never merged with
    OpenSSL's `libcrypto`. The provider package names are OpenSSL itself (`NOT_ACTUALLY_OPENSSL`),
    a crate that depends on the `openssl` binding is a `TRANSITIVE_OPENSSL_CONSUMER` (it does not
    name `libcrypto`/`libssl`), and a distro package or Homebrew formula that names an OpenSSL
    provider/soname directly is a `DIRECT_OPENSSL_CONSUMER`.
    """
    low = package.strip().lower()
    if low.startswith("libcrypto++") or low.startswith("crypto++"):
        return NOT_ACTUALLY
    if low in PROVIDER_PACKAGES or low.startswith("openssl@") or low.startswith("libssl") \
            or low.startswith("libcrypto") or low.startswith("openssl-") or low == "openssl":
        return NOT_ACTUALLY
    if ecosystem == "crates":
        return TRANSITIVE
    if ecosystem in ("debian", "fedora", "alpine", "homebrew"):
        return DIRECT
    return UNKNOWN


def build_identities(manifest: dict, normalized: dict[str, bytes]) -> tuple[list[dict], int]:
    """Every candidate identity, deduplicated by `(ecosystem, package)`, with its provenance.

    Returns `(identities, rows_scanned)`. Each identity aggregates the relations every contributing
    row names, the source ids it was built from and the popularity signal where the source carries
    one (crates.io downloads, Popcon votes), so a family built from it is provenance-backed.
    """
    merged: dict[tuple[str, str], dict] = {}
    rows_scanned = 0
    sources = sorted((r for r in manifest.get("sources", [])
                      if r.get("availability") == "available" and r.get("normalized_path")),
                     key=lambda r: str(r.get("source_id")))
    all_rows = 0
    for row in sources:
        sid = str(row["source_id"])
        blob = normalized.get(sid)
        if blob is None:
            continue
        doc = json.loads(blob.decode("utf-8"))
        rows = doc.get("rows") or []
        all_rows += len(rows)
        for ident in _source_identities(sid, rows):
            key = (ident["ecosystem"], ident["package"])
            entry = merged.get(key)
            if entry is None:
                entry = {
                    "ecosystem": ident["ecosystem"],
                    "package": ident["package"],
                    "relations": [],
                    "repos": set(),
                    "source_ids": set(),
                    "popularity": [],
                }
                merged[key] = entry
            if ident["relation"] not in entry["relations"]:
                entry["relations"].append(ident["relation"])
            if ident["repo"]:
                entry["repos"].add(ident["repo"])
            entry["source_ids"].add(sid)
            downloads = ident["relation"].get("downloads")
            if downloads is not None and not any(p.get("source_id") == sid
                                                 for p in entry["popularity"]):
                entry["popularity"].append({"source_id": sid, "signal": "downloads",
                                            "value": downloads})
            if ident["relation"].get("recent") is not None and not any(
                    p.get("source_id") == sid for p in entry["popularity"]):
                entry["popularity"].append({"source_id": sid, "signal": "popcon-recent",
                                            "value": ident["relation"]["recent"]})
    rows_scanned = all_rows

    identities: list[dict] = []
    for (ecosystem, package), entry in sorted(merged.items()):
        identities.append({
            "ecosystem": ecosystem,
            "package": package,
            "repos": sorted(entry["repos"]),
            "source_ids": sorted(entry["source_ids"]),
            "relations": sorted(entry["relations"],
                                key=lambda r: (str(r.get("kind")), str(r.get("ons")))),
            "popularity": sorted(entry["popularity"], key=lambda p: str(p.get("source_id"))),
        })
    return identities, rows_scanned


# --------------------------------------------------------------------------------------------
# normalisation: identities -> families
# --------------------------------------------------------------------------------------------

def _canonical_map(identities: list[dict]) -> dict[str, str]:
    universe_names = frozenset(i["package"].lower() for i in identities)
    return {(i["ecosystem"], i["package"]):
            canonical_package_name(i["package"], universe_names) for i in identities}


def build_families(identities: list[dict]) -> tuple[list[dict], list[dict]]:
    """Collapse identities into families, and return `(families, excluded_identities)`.

    An identity is grouped by its canonical project name. A group that carries no consuming
    identity (the provider packages themselves, a name collision) is **excluded** from the family
    universe with the reason recorded -- a provider is not a downstream consumer -- and its
    identities are returned separately so the candidates artefact still accounts for them.
    """
    canon = _canonical_map(identities)
    classes = {(i["ecosystem"], i["package"]): classify_identity(i["ecosystem"], i["package"])
               for i in identities}

    groups: dict[str, list[dict]] = {}
    for i in identities:
        groups.setdefault(canon[(i["ecosystem"], i["package"])], []).append(i)

    # The fork rule, applied as a *merge*: a canonical name that differs from another only by a
    # fork marker (`bind9-next` vs `bind9`) is the same upstream under two names and is collapsed
    # into the base unless the fork carries explicit evidence of materially different OpenSSL
    # integration -- which this frozen evidence does not establish for any pair.
    fork_merges: dict[str, list[str]] = {}
    for name in sorted(groups):
        base = fork_base(name)
        if base == name or base not in groups:
            continue
        members = groups.pop(name)
        groups[base].extend(members)
        fork_merges.setdefault(base, []).extend(sorted({m["package"] for m in members}))

    families: list[dict] = []
    excluded: list[dict] = []
    for name in sorted(groups):
        members = groups[name]
        member_classes = {classes[(m["ecosystem"], m["package"])] for m in members}
        consumer_classes = member_classes & {DIRECT, TRANSITIVE}
        if not consumer_classes:
            for m in members:
                excluded.append({
                    "ecosystem": m["ecosystem"], "package": m["package"],
                    "canonical_name": name,
                    "directness_class": classes[(m["ecosystem"], m["package"])],
                    "reason": "not-an-openssl-consumer",
                    "source_ids": m["source_ids"],
                })
            continue

        directness = DIRECT if DIRECT in consumer_classes else TRANSITIVE
        linkage = downstream_schemas.DIRECTNESS_LINKAGE[directness]

        aliases = sorted({m["package"] for m in members})
        distro_packages = sorted(
            ({"ecosystem": m["ecosystem"], "package": m["package"]} for m in members
             if m["ecosystem"] in DISTRO_ECOSYSTEMS),
            key=lambda p: (p["ecosystem"], p["package"]))
        ecosystem_packages = sorted(
            ({"ecosystem": m["ecosystem"], "package": m["package"]} for m in members),
            key=lambda p: (p["ecosystem"], p["package"]))
        source_ids = sorted({sid for m in members for sid in m["source_ids"]})
        provenance = sorted(
            ({"source_id": sid, "ecosystem": m["ecosystem"], "package": m["package"]}
             for m in members for sid in m["source_ids"]),
            key=lambda p: (p["source_id"], p["ecosystem"], p["package"]))
        popularity = sorted(
            ({**p, "ecosystem": m["ecosystem"], "package": m["package"]}
             for m in members for p in m["popularity"]),
            key=lambda p: (p["source_id"], p["ecosystem"], p["package"]))
        evidence = sorted({f"{RANKING_SOURCES_REL}#{sid}" for sid in source_ids} |
                          {"forensics/downstream/ranking/normalized/"
                           f"{sid}.json" for sid in source_ids})

        fam = {
            "family_id": f"family:{name}",
            "name": name,
            "canonical_name": name,
            "source_ecosystem": _family_source_ecosystem(members),
            "project_url": _family_project_url(members),
            "upstream_repository": None,
            "homepage": None,
            "aliases": aliases,
            "distro_packages": distro_packages,
            "ecosystem_packages": ecosystem_packages,
            "licence": None,
            "openssl_linkage": linkage,
            "directness_class": directness,
            "primary_language": "unknown",
            "category": "unknown",
            "ranking_source_id": source_ids[0],
            "popularity_signals": popularity,
            "criticality_signals": [],
            "selection_provenance": provenance,
            "fork_of": None,
            "fork_evidence": [],
            "fork_merged": sorted(fork_merges.get(name, [])),
            "evidence": evidence,
        }
        families.append(fam)

    families.sort(key=lambda f: f["family_id"])
    excluded.sort(key=lambda e: (e["ecosystem"], e["package"]))
    return families, excluded


def _family_source_ecosystem(members: list[dict]) -> str:
    ecos = {m["ecosystem"] for m in members}
    for candidate in ("crates", "pypi", "cran", "github", "gitlab", "distro", "vendor", "other"):
        if any(SOURCE_ECOSYSTEM_OF.get(e) == candidate for e in ecos):
            return candidate
    return "other"


def _family_project_url(members: list[dict]) -> str:
    """The package-registry page of the family's primary identity.

    The frozen evidence names no upstream repository or homepage (the 24.1 parsers keep the
    package identity, not the formula's `homepage`), so `upstream_repository`/`homepage` are
    `null` and 24.3's specimen acquisition is what resolves them. This is the *registry* page the
    package itself lives at, recorded so `project_url` is not fabricated.
    """
    ecosystem, package = sorted((m["ecosystem"], m["package"]) for m in members)[0]
    if ecosystem == "crates":
        return f"https://crates.io/crates/{package}"
    if ecosystem == "homebrew":
        return f"https://formulae.brew.sh/formula/{package}"
    if ecosystem == "debian":
        return f"https://packages.debian.org/{package}"
    if ecosystem == "fedora":
        return f"https://src.fedoraproject.org/rpms/{package}"
    if ecosystem == "alpine":
        return f"https://pkgs.alpinelinux.org/packages?name={package}"
    return ""


# --------------------------------------------------------------------------------------------
# the derived artefacts
# --------------------------------------------------------------------------------------------

def derive_universe(manifest: dict, normalized: dict[str, bytes]) -> tuple[dict, dict]:
    """The `(candidates_body, families_body)` the two committed artefacts carry."""
    identities, rows_scanned = build_identities(manifest, normalized)
    families, excluded = build_families(identities)

    by_class: dict[str, int] = {}
    by_ecosystem: dict[str, int] = {}
    for i in identities:
        cls = classify_identity(i["ecosystem"], i["package"])
        by_class[cls] = by_class.get(cls, 0) + 1
        by_ecosystem[i["ecosystem"]] = by_ecosystem.get(i["ecosystem"], 0) + 1

    fam_class: dict[str, int] = {}
    fam_eco: dict[str, int] = {}
    for f in families:
        fam_class[f["directness_class"]] = fam_class.get(f["directness_class"], 0) + 1
        fam_eco[f["source_ecosystem"]] = fam_eco.get(f["source_ecosystem"], 0) + 1

    candidates_body = {
        "rule": (
            "the candidate universe is every package identity the frozen 24.1 ranking evidence "
            "discovers, deduplicated by (ecosystem, package): the reverse dependencies of the "
            "OpenSSL providers in Debian, Fedora and Alpine, the Homebrew formulae that "
            "`depends_on` openssl@3, the crates.io reverse dependencies of the `openssl` binding, "
            "and the Popcon / Homebrew-analytics provider-package rows. Each identity records the "
            "committed source row it came from. Nothing is fetched and no package name is typed."
        ),
        "classification_rule": (
            "a name collision is resolved first (Crypto++'s `libcrypto++*` is a different library, "
            "not OpenSSL); the provider packages are `NOT_ACTUALLY_OPENSSL`; a crate depending on "
            "the `openssl` binding is `TRANSITIVE_OPENSSL_CONSUMER`; a distro package or Homebrew "
            "formula that names an OpenSSL provider/soname directly is `DIRECT_OPENSSL_CONSUMER`. "
            "The brief's `OPTIONAL_`/`BUILD_ONLY_`/`VENDORED_` classes are not established by this "
            "frozen evidence and are recorded empty rather than invented."
        ),
        "directness_classes": list(DIRECTNESS_CLASSES),
        "counts": {
            "rows_scanned": rows_scanned,
            "identities": len(identities),
            "before_dedup": len(identities),
            "by_ecosystem": dict(sorted(by_ecosystem.items())),
            "by_directness": dict(sorted(by_class.items())),
        },
        "identities": [
            {
                "ecosystem": i["ecosystem"],
                "package": i["package"],
                "repos": i["repos"],
                "source_ids": i["source_ids"],
                "relations": i["relations"],
                "popularity": i["popularity"],
                "directness_class": classify_identity(i["ecosystem"], i["package"]),
            }
            for i in identities
        ],
    }

    families_body = {
        "rule": (
            "a family is the counted unit and a package alias is never one: identities are "
            "collapsed by canonical project name, so `curl`, `curl-dev`, `curl-doc`, Debian "
            "`libcurl4` and Fedora/Alpine `libcurl` are one family, and the OpenSSL providers "
            "(`openssl`, `libssl3`, `libcrypto3`, `openssl@3`) are one non-consumer group that is "
            "excluded rather than counted. A fork is not independent without explicit evidence of "
            "materially different OpenSSL integration."
        ),
        "counts": {
            "families": len(families),
            "identities_in_families": len(identities) - len(excluded),
            "aliases_collapsed": (len(identities) - len(excluded)) - len(families),
            "forks_merged": sum(len(f["fork_merged"]) for f in families),
            "excluded_identities": len(excluded),
            "by_directness": dict(sorted(fam_class.items())),
            "by_source_ecosystem": dict(sorted(fam_eco.items())),
        },
        "by_directness": dict(sorted(fam_class.items())),
        "families": families,
        "excluded": excluded,
    }
    return candidates_body, families_body


def _inputs(manifest: dict) -> list[InputRef]:
    out = [
        InputRef(name="ranking-sources", path=RANKING_SOURCES),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
    ]
    for row in manifest.get("sources", []):
        path = row.get("normalized_path")
        if path:
            out.append(InputRef(name=f"normalized/{row['source_id']}", path=REPO_ROOT / path))
    return out


# --------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefacts (never re-deriving from the network)
# --------------------------------------------------------------------------------------------

def _family_problems(fam: dict, source_ids: set[str], seen_aliases: dict[str, str],
                     seen_canon: dict[str, str], canon_of: dict[tuple[str, str], str]) -> list[str]:
    fid = str(fam.get("family_id") or "<no family_id>")
    problems = [f"{fid}: {p}" for p in downstream_schemas.validate_family(fam)]
    name = fam.get("canonical_name")
    if name in seen_canon and seen_canon[name] != fid:
        problems.append(f"{fid}: canonical_name {name!r} is already family "
                        f"{seen_canon[name]!r}: two families for one upstream")
    seen_canon.setdefault(name, fid)
    for alias in fam.get("aliases") or []:
        key = str(alias).lower()
        if key in seen_aliases and seen_aliases[key] != fid:
            problems.append(f"{fid}: alias {alias!r} is already family {seen_aliases[key]!r}: "
                            f"a package alias counted twice")
        seen_aliases.setdefault(key, fid)
    for entry in fam.get("selection_provenance") or []:
        sid = entry.get("source_id")
        if sid not in source_ids:
            problems.append(f"{fid}: provenance names unknown source {sid!r}")
        if not entry.get("package") or not entry.get("ecosystem"):
            problems.append(f"{fid}: provenance entry {entry!r} names no package")
    for pkg in fam.get("ecosystem_packages") or []:
        key = (str(pkg.get("ecosystem")), str(pkg.get("package")))
        expected = canon_of.get(key)
        # A package whose canonical name is a *fork* of the family's (`bind9-next` in `bind9`) is
        # folded in on purpose, so it agrees with the family through its fork base.
        if expected is not None and expected != name and fork_base(expected) != name:
            problems.append(f"{fid}: package {key[1]!r} of {key[0]} canonicalises to "
                            f"{expected!r}, not {name!r}")
    return problems


def universe_findings(manifest: dict, candidates_body: dict, families_body: dict) -> list[str]:
    """Every way the committed candidate/family universe fails its own subject.

    Pure over the two committed bodies and the committed ranking manifest, so the court re-runs it
    without re-deriving from the network and the sensitivity control can mutate it.
    """
    findings: list[str] = []
    source_ids = {str(r.get("source_id")) for r in manifest.get("sources", [])}
    families = families_body.get("families")
    identities = candidates_body.get("identities")
    if not isinstance(families, list) or not families:
        return ["the family universe records no families"]
    if not isinstance(identities, list) or not identities:
        return ["the candidate universe records no identities"]

    # The universe must be substantially larger than 1,000 before deduplication, because the P1000
    # is selected *from* it and needs a reserve.
    count = int((candidates_body.get("counts") or {}).get("identities", len(identities)))
    if count <= UNIVERSE_FLOOR:
        findings.append(f"the candidate universe carries {count} identity(ies), not the "
                        f"substantially-more-than-1,000 the P1000 selection needs "
                        f"(floor {UNIVERSE_FLOOR})")

    canon_of: dict[tuple[str, str], str] = {}
    universe_names = frozenset(str(i.get("package", "")).lower() for i in identities)
    for i in identities:
        canon_of[(str(i.get("ecosystem")), str(i.get("package")))] = \
            canonical_package_name(str(i.get("package")), universe_names)

    # The documented alias set the brief names collapses to one family, not four: `libcurl4`,
    # `curl`, `curl-dev` and `curl-doc` are the one project `curl`.
    collapsed = {canonical_package_name(alias, universe_names) for alias in ALIAS_SET_PROBE}
    if len(collapsed) != 1:
        findings.append(f"the alias set {list(ALIAS_SET_PROBE)} canonicalises to "
                        f"{sorted(collapsed)}, not one family")

    # Each family's directness must be re-derivable from the identities it claims: a family whose
    # identities are all crates-binding dependents is transitive and may not be called direct.
    expected: dict[str, str] = {}
    for i in identities:
        cls = classify_identity(str(i.get("ecosystem")), str(i.get("package")))
        if cls not in (DIRECT, TRANSITIVE):
            continue
        canonical = canon_of[(str(i.get("ecosystem")), str(i.get("package")))]
        cur = expected.get(f"family:{canonical}")
        if cur == DIRECT:
            continue
        expected[f"family:{canonical}"] = DIRECT if cls == DIRECT else (cur or TRANSITIVE)

    seen_aliases: dict[str, str] = {}
    seen_canon: dict[str, str] = {}
    for fam in families:
        findings += _family_problems(fam, source_ids, seen_aliases, seen_canon, canon_of)
        fid = fam.get("family_id")
        want = expected.get(fid)
        if want is not None and fam.get("directness_class") != want:
            findings.append(f"{fid}: directness_class {fam.get('directness_class')!r} disagrees "
                            f"with the class its identities imply ({want!r}): a transitive "
                            f"consumer is not counted as direct")

    # The fork rule: a family that shares a fork_base with another may stand alone only with
    # explicit evidence of materially different OpenSSL integration.
    by_base: dict[str, list[str]] = {}
    for fam in families:
        by_base.setdefault(fork_base(str(fam.get("canonical_name"))), []).append(
            str(fam.get("family_id")))
    for base, members in sorted(by_base.items()):
        if len(members) <= 1:
            continue
        for fam in families:
            if str(fam.get("family_id")) in members and not fam.get("fork_evidence"):
                findings.append(f"{fam.get('family_id')}: is a fork of {base!r} counted as "
                                f"independent with no evidence of materially different OpenSSL "
                                f"integration")

    # Counts are read, not typed: a body whose counts disagree with its rows is a record that has
    # drifted from what it claims.
    fcounts = families_body.get("counts") or {}
    if fcounts.get("families") not in (None, len(families)):
        findings.append(f"families.json counts.families {fcounts.get('families')!r} disagrees "
                        f"with the {len(families)} family record(s)")
    ccounts = candidates_body.get("counts") or {}
    if ccounts.get("identities") not in (None, len(identities)):
        findings.append(f"candidates.json counts.identities {ccounts.get('identities')!r} "
                        f"disagrees with the {len(identities)} identity record(s)")
    return findings


def _mutation_bodies(candidates_body: dict, families_body: dict) -> list[tuple[str, str, dict, dict]]:
    """`(name, needle, mutated_candidates, mutated_families)` for each seeded mutation."""
    out: list[tuple[str, str, dict, dict]] = []

    # (a) a distro alias double-counted as its own family.
    c1 = copy.deepcopy(candidates_body)
    f1 = copy.deepcopy(families_body)
    victim = next((f for f in f1["families"] if len(f.get("aliases") or []) >= 2), None)
    if victim is not None:
        clone = copy.deepcopy(victim)
        clone["family_id"] = victim["family_id"] + "-alias-twin"
        clone["name"] = victim["name"] + "-alias-twin"
        clone["canonical_name"] = victim["name"] + "-alias-twin"
        f1["families"].append(clone)
    out.append(("alias_double_counted",
                "already family", c1, f1))

    # (b) a transitive consumer promoted to direct.
    c2 = copy.deepcopy(candidates_body)
    f2 = copy.deepcopy(families_body)
    trans = next((f for f in f2["families"]
                  if f.get("directness_class") == TRANSITIVE
                  and all(p.get("ecosystem") == "crates" for p in f.get("ecosystem_packages") or [])),
                 None)
    if trans is not None:
        trans["directness_class"] = DIRECT
        trans["openssl_linkage"] = "direct"
    out.append(("transitive_promoted_to_direct",
                "transitive consumer is not counted as direct", c2, f2))

    # (c) a fork counted as an independent family with no evidence.
    c3 = copy.deepcopy(candidates_body)
    f3 = copy.deepcopy(families_body)
    base_fam = f3["families"][0] if f3["families"] else None
    if base_fam is not None:
        fork = copy.deepcopy(base_fam)
        fork["family_id"] = f"family:{base_fam['canonical_name']}-ng"
        fork["canonical_name"] = f"{base_fam['canonical_name']}-ng"
        fork["name"] = fork["canonical_name"]
        fork["fork_of"] = base_fam["family_id"]
        fork["fork_evidence"] = []
        f3["families"].append(fork)
    out.append(("fork_independent_without_evidence",
                "counted as independent with no evidence", c3, f3))

    # (d) a family with no provenance.
    c4 = copy.deepcopy(candidates_body)
    f4 = copy.deepcopy(families_body)
    if f4["families"]:
        f4["families"][0]["selection_provenance"] = []
    out.append(("family_without_provenance",
                "selection_provenance must be non-empty", c4, f4))
    return out


def universe_sensitivity_control(manifest: dict, candidates_body: dict,
                                 families_body: dict) -> dict:
    """Prove the court can fail: seed four mutations and require each to be caught.

    The honest universe must yield **zero** findings (specificity), and each seeded mutation -- a
    distro alias double-counted, a transitive consumer promoted to direct, a fork counted as
    independent with no evidence, and a family with no provenance -- must be caught with a finding
    that names what it is.
    """
    base = universe_findings(manifest, candidates_body, families_body)
    specificity = not base
    control: dict = {"baseline_findings": len(base), "specificity_holds": specificity}
    honest = specificity
    for name, needle, mc, mf in _mutation_bodies(candidates_body, families_body):
        findings = universe_findings(manifest, mc, mf)
        caught = any(needle in f for f in findings)
        control[f"caught_{name}"] = caught
        control[f"injected_{name}"] = name
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# --------------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------------

def load_committed(manifest: dict) -> dict[str, bytes]:
    """The committed normalized-input bytes, keyed by source_id, via the 24.1 loader."""
    return downstream_sources.load_committed(manifest)


def cmd_generate(manifest: dict) -> int:
    normalized = load_committed(manifest)
    candidates_body, families_body = derive_universe(manifest, normalized)

    findings = universe_findings(manifest, candidates_body, families_body)
    if findings:
        print("[downstream-universe] the derived universe fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        return 1

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    inputs = _inputs(manifest)
    doc_c = envelope(kind="downstream-candidate-universe", authority=auth.id, inputs=inputs,
                     body=candidates_body, generator=GENERATOR)
    doc_f = envelope(kind="downstream-families", authority=auth.id, inputs=inputs,
                     body=families_body, generator=GENERATOR)
    write_json(CANDIDATES, doc_c)
    write_json(FAMILIES, doc_f)

    c = candidates_body["counts"]
    fc = families_body["counts"]
    print(f"[downstream-universe] {c['rows_scanned']} row(s) -> {c['identities']} identity(ies) "
          f"-> {fc['families']} family(ies); {fc['excluded_identities']} excluded non-consumer "
          f"identity(ies)")
    print(f"  identities by directness: {c['by_directness']}")
    print(f"  families by directness: {fc['by_directness']}")
    print(f"  -> {rel(CANDIDATES)}")
    print(f"  -> {rel(FAMILIES)}")
    return 0


def self_test() -> int:
    """Prove the pure functions of this module behave, over the committed evidence."""
    failures: list[str] = []
    if not RANKING_SOURCES.is_file():
        failures.append(f"{rel(RANKING_SOURCES)} is absent")
    else:
        manifest = json.loads(RANKING_SOURCES.read_text(encoding="utf-8"))["body"]
        names = frozenset({"curl", "libcurl", "openssl", "apr-util"})
        cases = {
            "libcurl4": "curl", "libcurl": "curl", "curl": "curl",
            "curl-dev": "curl", "curl-doc": "curl",
            "openssl@3": "openssl", "openssl@1.1": "openssl", "openssl": "openssl",
            "libssl3": "openssl", "libcrypto3": "openssl",
            "libcrypto++8": "libcrypto++", "libcrypto++5.2c2a": "libcrypto++",
            "apr-util-openssl": "apr-util", "apr-util": "apr-util",
        }
        for raw, want in cases.items():
            got = canonical_package_name(raw, names)
            if got != want:
                failures.append(f"canonical_package_name({raw!r}) = {got!r}, expected {want!r}")
        for collision in ("libcrypto++8", "libcrypto++5.2c2a"):
            if classify_identity("debian", collision) != NOT_ACTUALLY:
                failures.append(f"{collision} is not classified NOT_ACTUALLY_OPENSSL")
        if classify_identity("crates", "actix-http") != TRANSITIVE:
            failures.append("a crates dependent is not classified transitive")
        if classify_identity("debian", "libcurl4") != DIRECT:
            failures.append("a distro dependent is not classified direct")
        if not CANDIDATES.is_file() or not FAMILIES.is_file():
            failures.append("the committed candidate universe is absent; run the generator")
        else:
            cb = json.loads(CANDIDATES.read_text(encoding="utf-8"))["body"]
            fb = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
            findings = universe_findings(manifest, cb, fb)
            if findings:
                failures.append(f"the committed universe has findings: {findings[:3]}")
            control = universe_sensitivity_control(manifest, cb, fb)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")
    if failures:
        print("[downstream-universe] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-universe] self-test ok: the canonicalisation collapses the curl and "
          "openssl alias sets, Crypto++ is never OpenSSL, and every seeded mutation is caught")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first, exactly as every Phase-24 entry point does.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()

    if not RANKING_SOURCES.is_file():
        print(f"[downstream-universe] {rel(RANKING_SOURCES)} is absent; run 24.1 first")
        return 1
    manifest = json.loads(RANKING_SOURCES.read_text(encoding="utf-8"))["body"]
    return cmd_generate(manifest)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
