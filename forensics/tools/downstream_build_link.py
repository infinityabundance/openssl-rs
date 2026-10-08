#!/usr/bin/env python3
"""openssl-rs — Phase-24.6 build/link atlas: the identical-build-intent linkage measurement.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over the
frozen P1000 (`forensics/downstream/family-freeze.json`). 24.4 froze the population and 24.5 fixed
the holdout, and both did so **before any candidate result existed**. This module is the first
subphase that **runs the candidate**: for every family for which an admitted pristine-source recipe
exists it acquires the family's released source, configures, builds and links it **twice** -- once
against the admitted authority and once against the candidate drop-in install -- and records how far
each subject reached on the ladder `L0-catalogued` through `L4-linked`, with the candidate's linkage
proven from the real ELF.

The identical-build-intent rule
-------------------------------
The comparison is only meaningful if the two runs differ in **exactly one thing**: the OpenSSL
install prefix. So there is **one** recipe per family, and the same acquire -> configure -> make
argv is run for both subjects with the single substitution `{prefix}` = the subject's OpenSSL
prefix. No candidate-specific downstream patch is applied, ever: a generated build file (a
`Makefile`, a `config.status`) is not a source patch, and the working source tree is the released
tarball unmodified -- `candidate_specific_patch_count` is asserted `0`. A family whose recipe cannot
build against both subjects is recorded honestly at the level it reached, never fabricated into a
pass.

Pristine source, content-addressed
----------------------------------
Each recipe pins the released tarball's URL and SHA-256; the fetch is verified against the pin, and
the pristine source root is the extracted tarball with no edit, recorded by its archive digest. A
fetch whose digest disagrees with the pin is a failure of the recipe, not built.

What the linkage proof is
-------------------------
Reaching `L4-linked` is not inferred from the recipe: it is read back from the built ELF. A
candidate row reaching `L4-linked` must (a) declare a `libssl`/`libcrypto` `DT_NEEDED`, (b) import at
least one OpenSSL symbol, (c) resolve **every** OpenSSL `DT_NEEDED` soname under the candidate
install prefix, and (d) resolve none of them under the admitted authority prefix nor any system
path -- the resolution is taken with `LD_LIBRARY_PATH=<prefix>/lib`, and the default resolution (no
`LD_LIBRARY_PATH`) is recorded so the proof is visibly load-bearing rather than vacuous. An
authority row reaching `L4-linked` must resolve every OpenSSL soname under the authority prefix.
The ELF version-needs tags (`OPENSSL_3.x.y`) are recorded too, so "the right soname" is not the only
evidence. Where a build linked OpenSSL **statically** (no OpenSSL `DT_NEEDED`), the static linkage
proof is recorded honestly as unavailable rather than asserted.

Every P1000 family is accounted for
-----------------------------------
The atlas accounts for **all 1000** frozen families under both subjects: a family with no admitted
recipe gets an honest `not_attempted`/`unavailable` row (with a reason naming that no recipe is
admitted) rather than being omitted or fabricated into a pass. A sparse-but-complete atlas is the
correct outcome; a fabricated pass never is.

The candidate identity is a measurement, not a pure function of committed inputs
--------------------------------------------------------------------------------
This tool performs real builds; the artefact it writes is **measurement**. It is therefore **not**
listed in `forensics/tools/evidence_determinism.py`'s `GENERATORS` or `COMPARED` -- exactly as the
Phase-17 measured corpus under `courts/phase17/downstream/*/result.json` is not -- because the level
each build reaches and the ELF it produces are a function of the court's toolchain and of the
network, not of committed inputs, and because a host invocation is refused by the Docker-only guard
before it builds anything. The court `RT-BUILD-LINK-ATLAS` re-runs only this module's **pure**
functions over the committed artefact and never rebuilds. The tool does still record the candidate
install's `libssl.so.3`/`libcrypto.so.3` digests in `candidate_identity`, so the atlas names the
exact candidate build it measured.

The Docker-only guard is called first
-------------------------------------
This module fetches from the network and compiles real projects, so it is an **execution** entry
point: `phase24_guard.require_admitted()` is the first statement of `main`, and a host invocation is
refused rather than producing unreproducible evidence (`docs/REPRODUCIBILITY.md` section 1).

Outputs
-------
  forensics/downstream/build-link-atlas.json   the build/link runs, specimens and variants

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    read_version_needed_names,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool fetches and
# compiles, so it is an execution entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The record schemas the rows are validated against, imported rather than restated so the vocabulary
# cannot drift from the module the court checks it with.
import downstream_schemas  # noqa: E402

# The 24.3 census tool: its pristine-source recipes, its ELF/linkage primitives, its resource-limit
# reader and its subprocess helpers are **reused by importing it**, so the build/link atlas and the
# authority census share one code path rather than two that can drift (the brief's "no divergent
# predicate").
import downstream_census as census  # noqa: E402

# The 24.18 admission campaign, imported so the shared recipe catalogue includes exactly the recipes
# the campaign admitted (empirically built against both subjects) and the two can never disagree
# about which families are recipe-backed. The campaign module is a pure derivation (it executes
# nothing), so importing it here adds no execution.
import downstream_recipe_campaign as campaign  # noqa: E402

# The 24.19 close-candidate reclamation batch, imported for the same reason: its admitted recipes are
# extensions to the shared catalogue, and the record and the catalogue are the same single source of
# truth. It is a pure derivation (it executes nothing; its recipes were built by this tool), so
# importing it here adds no execution.
import downstream_close_batch as close_batch  # noqa: E402

# The stratum's four non-claims, imported from 24.4 so the atlas and the freeze cannot drift about
# what the model never claims.
from downstream_freeze import NON_CLAIMS as STRATUM_NON_CLAIMS  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
OUT = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"

# The candidate drop-in install prefix. Its `lib/libssl.so.3` and `lib/libcrypto.so.3` are the
# subject of every candidate row; if it is absent the measurement cannot be taken.
CANDIDATE_PREFIX = REPO_ROOT / "artifacts" / "phase2" / "install"

# Scratch is kept under `/work/court` (never `/tmp` or the container's `/`), and deleted after the
# measurement; only the small committed artefact persists in the tree.
SCRATCH = REPO_ROOT / "court" / "phase24-build-link"

GENERATOR = "forensics/tools/downstream_build_link.py"
PARSER_VERSION = "downstream-build-link/1"

# The rungs this atlas climbs. It stops at `L4-linked`: loading and running are 24.7's measurement,
# and a build is not a functional proof.
L0 = "L0-catalogued"
L1 = "L1-admitted-source"
L2 = "L2-configured"
L3 = "L3-built"
L4 = "L4-linked"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK

# Per-step wall-clock bound and fetch bound, reused from the census so a runaway build cannot hold
# the venue.
STEP_TIMEOUT = census.STEP_TIMEOUT
FETCH_TIMEOUT = census.FETCH_TIMEOUT
MAKE_JOBS = census.MAKE_JOBS

# The frozen build/link-intent rule, recorded verbatim in the artefact and re-derived by the court.
RULE: dict = {
    "id": "downstream-build-link-atlas/1",
    "name": "the identical-build-intent build/link atlas",
    "identical_intent": (
        "one pristine-source recipe per family; the same acquire -> configure -> make argv is run "
        "for both subjects with the single substitution {prefix} = the subject's OpenSSL install "
        "prefix and no other difference; a generated build file is not a source patch, and "
        "candidate_specific_patch_count is 0"
    ),
    "levels": [L2, L3, L4],
    "subjects": ["authority", "candidate"],
    "linkage_proof": (
        "read from the built ELF: a libssl/libcrypto DT_NEEDED, at least one imported OpenSSL "
        "symbol, every OpenSSL soname resolving under the subject prefix (LD_LIBRARY_PATH=<prefix>"
        "/lib), the default resolution recorded, and the ELF version-needs tags recorded; a "
        "candidate L4 row must resolve under the candidate install and under neither the authority "
        "prefix nor a system library"
    ),
    "static_linkage_proof": (
        "where a build declares no OpenSSL DT_NEEDED the static linkage proof is recorded honestly "
        "as unavailable rather than asserted"
    ),
    "accounting": (
        "all 1000 frozen families are emitted under both subjects; a family with no admitted recipe "
        "is `not_attempted`/`unavailable` with a reason naming that no recipe is admitted, never "
        "omitted and never fabricated into a pass"
    ),
    "confinement": (
        "each fetch and build runs inside the admitted court container under its cgroup caps and "
        "this tool's own wall-clock bounds; scratch is under /work/court and removed afterwards"
    ),
    "constants": {"make_jobs": MAKE_JOBS, "step_timeout_seconds": STEP_TIMEOUT},
}

# The stratum's four non-claims (imported from 24.4 so the two cannot drift) plus the one this
# subphase's measurement adds: a build/link is not a runtime or functional proof.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "a build is not a functional proof, and a linkage proof is not a behaviour proof: reaching "
    "L4-linked says the candidate's libssl/libcrypto resolved, not that any consumer works against "
    "it -- the runtime and functional levels are 24.7's measurement",
]


# --------------------------------------------------------------------------------------------
# the admitted specimen/recipe catalogue
# --------------------------------------------------------------------------------------------
#
# Reuse the 24.3 census recipes, pin each released tarball by its observed digest, and extend the
# catalogue with the sibling Phase-17 downstream intent (nginx). Every recipe is a **pristine**
# source: the released tarball, unmodified. `{prefix}` is the admitted subject's OpenSSL prefix.

# The released-tarball digests, observed by the 24.3 authority census and pinned here so a fetch
# whose bytes disagree is refused rather than built. (The census recorded the fetched digest; the
# pin turns it into an authored assertion the atlas re-checks on every run.)
_CENSUS_PINS: dict[str, str] = {
    "libssh": "1861d498f5b6f1741b6abc73e608478491edcf9c9d4b6630eef6e74596de9dc1",
    "curl": "d15ebab765d793e2e96db090f0e172d127859d78ca6f6391d7eafecfd894bbc0",
    "haproxy": "cf1bf58b5bc79c48db7b01667596ffd98343adb29a41096f075f00a8f90a7335",
    "monit": "669d8b95ddec124d1444ba5264f67fdeae8e90e53b2929719f4750fc5ff3ba60",
    "openssh": "b343fbcdbff87f15b1986e6e15d6d4fc9a7d36066be6b7fb507087ba8f966c02",
    # 24.17 pinned openvpn to the 2.5 line (2.6.12 requires libnl-genl-3.0 for DCO and then
    # libcap-ng on Linux, neither admitted in this venue), so the pin moves with the version.
    "openvpn": "d1d38a3fc7e200f9221f988ef1cc9c7a7d62b69bb5fa52742da1229e5f24d36f",
    "pure-ftpd": "1126f3a95856d08889ff89703cb1aa9ec9924d939d154e96904c920f05dc3c74",
    "redis": "bc34b878eb89421bbfca6fa78752343bf37af312a09eb0fae47c9575977dfaa2",
    "isync": "a0c81e109387bf279da161453103399e77946afecf5c51f9413c5e773557f78d",
    "kmod": "dc768b3155172091f56dc69430b5481f2d76ecd9ccb54ead8c2540dbcf5ea9bc",
    "lighttpd": "ba14a030889518194fd88b33e419d51cc38c8fe917126d5a7a965be79b53e995",
}

# The 24.17 remediation overrides, applied in `_build_catalogue` rather than in the 24.3 census so
# the census's own provisional measurement (`authority-baselines.jsonl`, `usage-fingerprints.json`)
# is untouched: the build/link, runtime and P1000-run tools all import this catalogue, the census
# does not. `ldflags_extra` is appended to the configure/link environment with `{prefix}` substituted.
_RECIPE_OVERRIDES: dict[str, dict] = {
    "kmod": {
        "configure": ["--with-openssl", "--disable-manpages", "--silent"],
        "artifact": "tools/kmod",
        "note": ("kmod 33 with --disable-manpages (24.17): the scdoc man-page build is disabled, so "
                 "the configure no longer stops on the absent scdoc tool; the built kmod links "
                 "libcrypto"),
    },
    "openvpn": {
        "version": "2.5.10",
        "url": "https://swupdate.openvpn.net/community/releases/openvpn-2.5.10.tar.gz",
        "archive": "tar.gz",
        "configure": ["--with-crypto-library=openssl", "--disable-lzo", "--disable-lz4",
                      "--disable-plugin-auth-pam", "--silent"],
        "artifact": "src/openvpn/openvpn",
        "note": ("openvpn 2.5.10 (24.17): pinned to the 2.5 line, whose build system the venue "
                 "supports, because 2.6.12 requires libnl-genl-3.0 for DCO and then libcap-ng on "
                 "Linux, neither admitted here"),
    },
    "isync": {
        "ldflags_extra": "-Wl,-rpath-link,{prefix}/lib",
        "note": ("isync 1.5.0 with -Wl,-rpath-link (24.17): the linker is given the prefix lib "
                 "directory so libssl's transitive libcrypto dependency resolves, which the "
                 "authority prefix needs and the candidate prefix did not (both subjects are "
                 "measured with the identical recipe)"),
    },
    "libssh": {
        "note": ("libssh 0.10.6 ships only CMakeLists.txt: still blocked in this venue, which "
                 "admits no cmake; 24.17 recorded it still-blocked rather than faking a build"),
    },
    "lighttpd": {
        "note": ("lighttpd 1.4.76 ships no generated ./configure (a source tree with "
                 "configure.ac, CMakeLists.txt, meson.build and SConstruct only): still blocked in "
                 "this venue, which admits no autoconf/automake, cmake or meson; 24.17 recorded it "
                 "still-blocked"),
    },
}

# The 24.17 admission batch: recipe-less counted families whose pinned release tarball ships a
# build entry point the venue can execute (a generated `configure`, or a plain `Makefile`) and needs
# no tool the venue lacks, empirically verified before authoring. Each carries its own pinned
# digest; the batch is bounded and deterministic, not an attempt at all 988.
_EXTRA_SPECS: tuple[dict, ...] = (
    {
        "family": "socat", "version": "1.8.0.0",
        "url": "http://www.dest-unreach.org/socat/download/socat-1.8.0.0.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "6010f4f311e5ebe0e63c77f78613d264253680006ac8979f52b0711a9a231e82",
        "configure": ["--disable-readline"], "make": [MAKE_JOBS], "artifact": "socat",
        "launch": ["-V"],
        "note": "socat 1.8.0.0's own configure links the subject OpenSSL (24.17 admission)",
    },
    {
        "family": "ldns", "version": "1.8.3",
        "url": "https://www.nlnetlabs.nl/downloads/ldns/ldns-1.8.3.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "c3f72dd1036b2907e3a56e6acf9dfb2e551256b3c1bbd9787942deeeb70e7860",
        "configure": ["--with-ssl={prefix}", "--disable-dane-verify"], "make": [MAKE_JOBS],
        "artifact": ".libs/libldns.so*", "launch": None,
        "note": "ldns 1.8.3's libldns links the subject libcrypto (24.17 admission)",
    },
    {
        "family": "stunnel", "version": "5.73",
        "url": "https://www.stunnel.org/downloads/archive/5.x/stunnel-5.73.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "bc917c3bcd943a4d632360c067977a31e85e385f5f4845f69749bce88183cb38",
        "configure": ["--with-ssl={prefix}", "--disable-systemd", "--disable-libwrap",
                      "--disable-fips"], "make": [MAKE_JOBS], "artifact": "src/stunnel",
        "launch": ["-version"],
        "note": "stunnel 5.73 links the subject libssl/libcrypto (24.17 admission)",
    },
    {
        "family": "links", "version": "2.30",
        "url": "http://links.twibright.com/download/links-2.30.tar.bz2",
        "archive": "tar.bz2", "build_system": "autotools",
        "sha256": "c4631c6b5a11527cdc3cb7872fc23b7f2b25c2b021d596be410dadb40315f166",
        "configure": ["--with-ssl={prefix}", "--without-gpm", "--without-x",
                      "--without-libtiff", "--without-lzma", "--without-zstd",
                      "--without-libevent"], "make": [MAKE_JOBS], "artifact": "links",
        "launch": ["-version"],
        "note": "links 2.30 links the subject libssl (24.17 admission)",
    },
    {
        "family": "libevent", "version": "2.1.12-stable",
        "url": ("https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/"
                "libevent-2.1.12-stable.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb",
        "configure": ["--disable-samples", "--disable-libevent-regress"], "make": [MAKE_JOBS],
        "artifact": ".libs/libevent_openssl*.so*", "launch": None,
        "note": "libevent 2.1.12's libevent_openssl links the subject libcrypto (24.17 admission)",
    },
    {
        "family": "dovecot", "version": "2.3.21",
        "url": "https://dovecot.org/releases/2.3/dovecot-2.3.21.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "05b11093a71c237c2ef309ad587510721cc93bbee6828251549fc1586c36502d",
        "configure": ["--with-ssl=openssl", "--without-ldap", "--without-sql", "--without-pam",
                      "--without-gssapi", "--without-lua", "--without-lz4", "--without-zstd",
                      "--without-lzma", "--without-bzlib", "--disable-static"],
        "make": [MAKE_JOBS], "artifact": "src/lib-dcrypt/.libs/libdcrypt_openssl.so*",
        "launch": None,
        "note": ("dovecot 2.3.21's libdcrypt_openssl links the subject libcrypto (24.17 "
                 "admission)"),
    },
    {
        "family": "cyrus-sasl", "version": "2.1.28",
        "url": ("https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-2.1.28/"
                "cyrus-sasl-2.1.28.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "7ccfc6abd01ed67c1a0924b353e526f1b766b21f42d4562ee635a8ebfc5bb38c",
        "configure": ["--with-openssl={prefix}", "--disable-static", "--enable-shared",
                      "--disable-otp", "--disable-ldapdb", "--without-pam", "--disable-sql"],
        "make": [MAKE_JOBS], "artifact": "plugins/.libs/libdigestmd5.so*", "launch": None,
        "note": ("cyrus-sasl 2.1.28's digestmd5 plugin links the subject libcrypto (24.17 "
                 "admission)"),
    },
    {
        "family": "fossil", "version": "2.24",
        "url": "https://fossil-scm.org/home/tarball/version-2.24/fossil-src-2.24.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "01aafcff3309ba9eb0ca6bcf4267108961676af336727b8adbc05475d96edd36",
        "configure": ["--with-openssl={prefix}", "--disable-fusefs"], "make": [MAKE_JOBS],
        "artifact": "fossil", "launch": ["version"],
        "note": "fossil 2.24 links the subject libssl/libcrypto (24.17 admission)",
    },
)

# The Phase-17 downstream harnesses' pinned releases, added to widen the direct-consumer set. nginx
# 1.26.3 is the TLS-server slice (its own `configure`, so it is treated like autotools).
_PHASE17_PINS: dict[str, str] = {
    "nginx": "69ee2b237744036e61d24b836668aad3040dda461fe6f570f1787eab570c75aa",
}

# 24.17's own admission batch, exposed so 24.17's remediation record scopes its `new_recipes` to the
# families **24.17** admitted rather than to every later subphase's admissions (24.18's campaign adds
# its own; without this scoping the remediation record's admission-batch consistency check would
# mistake a 24.18 admission for a 24.17 rejected probe).
ADMISSION_BATCH_24_17: frozenset[str] = frozenset(s["family"] for s in _EXTRA_SPECS)


def _build_catalogue() -> tuple[dict, ...]:
    """The admitted recipe catalogue: the 24.3 census recipes (with the 24.17 overrides applied),
    the 24.17 admission batch, and the Phase-17 nginx slice.

    Each recipe carries a `recipe_id`, the pinned archive digest, and the exact argv templates with
    the single `{prefix}` substitution. Nothing here is candidate-specific: the same recipe is run
    against both subjects. The 24.17 overrides fix the four recipe-backed blockers (kmod, openvpn,
    isync; libssh/lighttpd stay blocked) and the extra specs admit the bounded 24.17 batch.
    """
    recipes: list[dict] = []
    for spec in census.SPECS:
        rec = dict(spec)
        rec.update(_RECIPE_OVERRIDES.get(rec["family"], {}))
        rec["sha256"] = _CENSUS_PINS.get(rec["family"])
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    for spec in _EXTRA_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    recipes.append({
        "family": "nginx", "version": "1.26.3",
        "url": "https://nginx.org/download/nginx-1.26.3.tar.gz", "archive": "tar.gz",
        "sha256": _PHASE17_PINS["nginx"], "build_system": "configure",
        "configure": [
            "--with-http_ssl_module", "--without-http_rewrite_module",
            "--without-http_gzip_module",
            "--with-cc-opt=-I{prefix}/include",
            "--with-ld-opt=-L{prefix}/lib -Wl,-rpath,{prefix}/lib",
        ],
        "make": [MAKE_JOBS], "artifact": "objs/nginx", "launch": ["-v"],
        "note": ("nginx 1.26.3 from the Phase-17 downstream harness: its own `configure` builds the "
                 "http_ssl module against the subject prefix through --with-cc-opt/--with-ld-opt"),
        "recipe_id": "recipe:nginx:1.26.3",
    })
    # The 24.18 admission campaign's recipes: each was empirically built against both subjects before
    # it was admitted, and `campaign.admitted_recipe_specs()` is the single source of truth, so the
    # catalogue and the campaign record cannot disagree about which families were admitted.
    for spec in campaign.admitted_recipe_specs():
        recipes.append(dict(spec))
    # The 24.19 close-candidate reclamation's recipes, admitted the same way and from the same
    # single source of truth in `close_batch.admitted_recipe_specs()`.
    for spec in close_batch.admitted_recipe_specs():
        recipes.append(dict(spec))
    return tuple(recipes)


RECIPES: tuple[dict, ...] = _build_catalogue()
_RECIPE_BY_FAMILY: dict[str, dict] = {r["family"]: r for r in RECIPES}


# --------------------------------------------------------------------------------------------
# ELF / linkage inspection (thin wrappers over the census primitives, so they cannot drift)
# --------------------------------------------------------------------------------------------

def resolve_linkage(artifact: Path, prefix: Path, authority_prefix: Path) -> dict:
    """The linkage proof for one artifact, resolving under `prefix`, checking for authority bleed.

    Every OpenSSL `DT_NEEDED` soname is resolved with `LD_LIBRARY_PATH=<prefix>/lib`; the proof
    records where each resolved, whether it is under `prefix`, whether it is under the authority
    prefix, and the default resolution (no `LD_LIBRARY_PATH`) so the proof is visibly load-bearing.
    """
    needed = [s for s in census.dt_needed(artifact) if census._is_openssl_soname(s)]
    env_sub = dict(os.environ, LD_LIBRARY_PATH=str(prefix / "lib"))
    proof: dict = {
        "prefix": rel(prefix),
        "sonames": {},
        "all_under_prefix": bool(needed),
        "resolved_under_authority": False,
        "default_resolution": {},
    }
    for soname in needed:
        sub = census._resolved_path(artifact, soname, env_sub)
        dflt = census._resolved_path(artifact, soname, dict(os.environ))
        under = bool(sub) and census._under(sub, prefix)
        under_auth = bool(sub) and census._under(sub, authority_prefix)
        proof["sonames"][soname] = {
            "resolved": f"prefix:{soname}" if under else (sub or "unresolved"),
            "under_prefix": under,
            "under_authority": under_auth,
        }
        proof["default_resolution"][soname] = dflt or "unresolved"
        proof["all_under_prefix"] = proof["all_under_prefix"] and under
        proof["resolved_under_authority"] = proof["resolved_under_authority"] or under_auth
    return proof


def _norm(text: str, prefix: Path, *extra: Path) -> str:
    """Portable text: the ephemeral absolute paths become tokens."""
    if text is None:
        return ""
    for p in (prefix, *extra):
        text = text.replace(str(p), "{prefix}")
    text = text.replace(str(SCRATCH), "{scratch}")
    return text


# --------------------------------------------------------------------------------------------
# measurement: one family, one pristine source, both subjects
# --------------------------------------------------------------------------------------------

def _confinement(limits: dict) -> dict:
    """The compact confinement record carried on every attempted row."""
    return {k: limits.get(k) for k in ("memory_max", "memory_swap_max", "pids_max", "cpu_max",
                                       "image", "platform")}


def _source_root_hash(root: Path) -> str:
    """A content hash of the extracted pristine source tree: sorted (relpath, size, sha256).

    The archive digest identifies the released tarball; this identifies the **tree** it extracted
    to, so the authority and the candidate rows can prove they built the same pristine source.
    """
    entries = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            entries.append([os.path.relpath(p, root), p.stat().st_size, sha256_file(p)])
    return content_hash(entries)


def _subject_row(fam: dict, recipe: dict | None, subject: str, *, level: str, outcome: str,
                 residual: str, failure_class: str | None, reason: str | None,
                 specimen_id: str | None, variant_id: str | None, source_sha256: str | None,
                 evidence: list[str], steps: list[dict] | None, canvas: dict | None,
                 limits: dict, prefix: Path, source_root_hash: str | None = None) -> dict:
    """One build/link run row: a schema-valid `run` record plus the build/link extension."""
    c = canvas or {}
    return {
        # the `run` schema fields (kind `run`)
        "run_id": f"run:build-link:{subject}:{fam.get('canonical_name')}",
        "specimen_id": specimen_id,
        "variant_id": variant_id,
        "subject": subject,
        "level": level,
        "outcome": outcome,
        "residual_class": residual,
        "evidence": evidence,
        # the build/link extension
        "family_id": fam.get("family_id"),
        "canonical_name": str(fam.get("canonical_name")),
        "p1000_rank": fam.get("_rank"),
        "openssl_linkage": fam.get("openssl_linkage"),
        "directness_class": fam.get("directness_class"),
        "recipe_id": recipe["recipe_id"] if recipe else None,
        "has_recipe": recipe is not None,
        "failure_class": failure_class,
        "reason": reason,
        "source_sha256": source_sha256,
        "source_root_hash": source_root_hash,
        "source_url": recipe["url"] if recipe else None,
        "linkage_proven": bool(c.get("linkage_proven")),
        "resolved_under_authority": bool(c.get("resolved_under_authority")),
        "candidate_specific_patch_count": 0,
        "dt_needed": c.get("dt_needed", []),
        "imported_openssl_symbols_count": c.get("imported_openssl_symbols_count", 0),
        "linkage": c.get("linkage"),
        "static_linkage": c.get("static_linkage", {"applicable": False, "proven": False,
                                                   "reason": "no build was attempted"}),
        "container_image": limits.get("image"),
        "resource_limits": _confinement(limits),
        "steps": [
            {"name": s["name"], "ok": s["ok"], "exit_code": s["exit_code"],
             "elapsed_seconds": s["elapsed_seconds"], "argv": [_norm(a, prefix) for a in s["argv"]]}
            for s in (steps or [])
        ],
    }


def _no_recipe_row(fam: dict, subject: str, limits: dict) -> dict:
    return _subject_row(
        fam, None, subject, level=L0, outcome="not_attempted", residual="unavailable",
        failure_class="acquire-failure",
        reason=("no admitted pristine-source build recipe is recorded for this family; the atlas "
                "does not manufacture a source URL"),
        specimen_id=None, variant_id=None, source_sha256=None,
        evidence=[f"family:{fam.get('family_id')}"], steps=None, canvas=None,
        limits=limits, prefix=Path("/"))


def _measure_subject(fam: dict, recipe: dict, archive_sha: str, archive: Path, subject: str,
                     prefix: Path, defined: set[str], authority_prefix: Path, limits: dict) -> dict:
    """Build one family's pristine source against one subject and return its run row."""
    name = str(fam.get("canonical_name"))
    specimen_id = f"specimen:{name}:{recipe['version']}"
    variant_id = f"variant:{name}:{recipe['version']}:pristine"
    work = SCRATCH / name / subject
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    steps: list[dict] = []

    def stage(label: str, res: dict) -> dict:
        res = dict(res, name=label)
        steps.append(res)
        return res

    extract = stage("extract", census._extract(archive, work / "src"))
    root = census._single_source_root(work / "src")
    if not extract["ok"] or root is None:
        return _subject_row(
            fam, recipe, subject, level=L1, outcome="failed", residual="unbuildable",
            failure_class="acquire-failure",
            reason=f"extracting the pristine source failed: {census._error_line(extract)}",
            specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
            evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                      f"source:{recipe['url']}#{archive_sha}"],
            steps=steps, canvas=None, limits=limits, prefix=prefix)

    # The pristine source root hash: a content hash of the extracted tree, so the authority and the
    # candidate rows can prove they built the same source.
    root_hash = _source_root_hash(root)

    env = dict(os.environ,
               PKG_CONFIG_PATH=f"{prefix}/lib/pkgconfig",
               CPPFLAGS=f"-I{prefix}/include",
               LDFLAGS=f"-L{prefix}/lib")
    # A recipe may extend the link environment (24.17's isync override adds -Wl,-rpath-link so the
    # subject lib dir resolves libssl's transitive libcrypto dependency). Substituted identically for
    # both subjects, so the identical-build-intent rule holds.
    if recipe.get("ldflags_extra"):
        env["LDFLAGS"] = env["LDFLAGS"] + " " + str(recipe["ldflags_extra"]).format(prefix=prefix)
    # A recipe may extend the environment with prefix-derived variables (24.18's admitted recipes
    # carry the consumer's own `OPENSSL_CFLAGS`/`OPENSSL_LIBS` override, because the candidate install
    # ships no `openssl.pc` while the authority does). Substituted identically for both subjects, so
    # the identical-build-intent rule holds.
    for key, val in (recipe.get("env_extra") or {}).items():
        env[str(key)] = str(val).format(prefix=prefix)

    level = L1
    if recipe["build_system"] in ("autotools", "configure"):
        argv = ["./configure"] + [a.format(prefix=prefix) for a in recipe["configure"]]
        conf = stage("configure", census._run(argv, cwd=root, env=env))
        if not conf["ok"]:
            return _subject_row(
                fam, recipe, subject, level=L1, outcome="failed", residual="unbuildable",
                failure_class="configure-failure",
                reason=f"configure failed: {census._error_line(conf)}",
                specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
                evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                          f"source:{recipe['url']}#{archive_sha}"],
                steps=steps, canvas=None, limits=limits, prefix=prefix,
                source_root_hash=root_hash)
        level = L2

    make_argv = ["make"] + [a.format(prefix=prefix) for a in recipe["make"]]
    build = stage("make", census._run(make_argv, cwd=root, env=env))
    if not build["ok"]:
        return _subject_row(
            fam, recipe, subject, level=level, outcome="failed", residual="unbuildable",
            failure_class="authority-build-failure" if subject == "authority"
            else "candidate-build-failure",
            reason=f"the build failed: {census._error_line(build)}",
            specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
            evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                      f"source:{recipe['url']}#{archive_sha}"],
            steps=steps, canvas=None, limits=limits, prefix=prefix,
            source_root_hash=root_hash)
    level = L3

    artifact = census._pick_artifact(root, recipe["artifact"])
    if artifact is None:
        return _subject_row(
            fam, recipe, subject, level=L3, outcome="failed", residual="unbuildable",
            failure_class="authority-build-failure" if subject == "authority"
            else "candidate-build-failure",
            reason=f"the build produced no artifact matching {recipe['artifact']!r}",
            specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
            evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                      f"source:{recipe['url']}#{archive_sha}"],
            steps=steps, canvas=None, limits=limits, prefix=prefix,
            source_root_hash=root_hash)

    artifact_rel = os.path.relpath(artifact, root)
    dt = census.dt_needed(artifact)
    imported = sorted(census.undefined_symbols(artifact) & defined)
    proof = resolve_linkage(artifact, prefix, authority_prefix)
    version_needs = sorted({n.split()[0] for n in read_version_needed_names(artifact)
                            if n.startswith("OPENSSL_")})
    openssl_needed = [s for s in dt if census._is_openssl_soname(s)]
    linkage_proven = (
        bool(openssl_needed) and bool(imported) and proof["all_under_prefix"]
        and (subject == "authority" or not proof["resolved_under_authority"])
    )
    canvas = {
        "dt_needed": dt,
        "imported_openssl_symbols_count": len(imported),
        "linkage": {
            "all_under_prefix": proof["all_under_prefix"],
            "resolved_under_authority": proof["resolved_under_authority"],
            "sonames": proof["sonames"],
            "default_resolution": proof["default_resolution"],
            "version_needs": version_needs,
            "artifact_rel": artifact_rel,
            "artifact_sha256": sha256_file(artifact),
        },
        "resolved_under_authority": proof["resolved_under_authority"],
        "linkage_proven": linkage_proven,
        "static_linkage": (
            {"applicable": False, "proven": False,
             "reason": "the artifact declares a shared libssl/libcrypto DT_NEEDED"}
            if openssl_needed else
            {"applicable": True, "proven": False,
             "reason": ("the artifact declares no libssl/libcrypto DT_NEEDED and imports "
                        f"{len(imported)} OpenSSL symbol(s); the static archive/linker-map "
                        "provenance was not captured in this run")}
        ),
    }
    evidence = [f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                f"source:{recipe['url']}#{archive_sha}", f"artifact:{artifact_rel}"]

    # L4 -- link: a DT_NEEDED names an OpenSSL soname, it imports an OpenSSL symbol, and it resolves
    # under this subject's prefix (and not the authority's, for the candidate).
    if not openssl_needed:
        return _subject_row(
            fam, recipe, subject, level=L3, outcome="failed", residual="unlinked",
            failure_class="link-failure",
            reason=("the built artifact declares no libssl/libcrypto dependency, so the subject "
                    "was not consumed"),
            specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
            evidence=evidence, steps=steps, canvas=canvas, limits=limits, prefix=prefix,
            source_root_hash=root_hash)
    if not linkage_proven:
        reason = ("the built artifact declares " + ", ".join(openssl_needed) +
                  " but it did not resolve to the subject prefix")
        if not imported:
            reason = ("the built artifact links " + ", ".join(openssl_needed) +
                      " but imports no OpenSSL symbol")
        return _subject_row(
            fam, recipe, subject, level=L3, outcome="failed", residual="unlinked",
            failure_class="link-failure", reason=reason,
            specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
            evidence=evidence, steps=steps, canvas=canvas, limits=limits, prefix=prefix,
            source_root_hash=root_hash)

    return _subject_row(
        fam, recipe, subject, level=L4, outcome="reached", residual="none",
        failure_class=None, reason=None, specimen_id=specimen_id, variant_id=variant_id,
        source_sha256=archive_sha, evidence=evidence, steps=steps, canvas=canvas,
        limits=limits, prefix=prefix, source_root_hash=root_hash)


def measure_family(fam: dict, recipe: dict, auth_prefix: Path, cand_prefix: Path,
                   auth_defined: set[str], cand_defined: set[str],
                   limits: dict) -> tuple[list[dict], dict | None, dict | None]:
    """Acquire one pristine source once and build it against both subjects; return rows + records."""
    name = str(fam.get("canonical_name"))
    work = SCRATCH / name
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)

    archive = work / f"source.{recipe['archive']}"
    fetch = census._fetch(recipe["url"], archive)
    if not fetch["ok"] or not archive.is_file():
        # No source: both subjects are honestly `not_attempted`/acquire-failure. The specimen is
        # still recorded with the recipe's pinned digest -- the intended released tarball.
        rows = [
            _subject_row(
                fam, recipe, subject, level=L0, outcome="not_attempted", residual="unavailable",
                failure_class="acquire-failure",
                reason=f"fetching the pristine source failed: {census._error_line(fetch)}",
                specimen_id=f"specimen:{name}:{recipe['version']}",
                variant_id=f"variant:{name}:{recipe['version']}:pristine",
                source_sha256=None,
                evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                          f"source:{recipe['url']}"],
                steps=[dict(fetch, name="fetch")], canvas=None, limits=limits, prefix=auth_prefix)
            for subject in ("authority", "candidate")
        ]
        return rows, _specimen(fam, recipe), _variant(fam, recipe)

    observed = sha256_file(archive)

    # The pin is an authored assertion the atlas re-checks: a released tarball whose bytes disagree
    # is refused rather than built.
    if recipe.get("sha256") and observed != recipe["sha256"]:
        rows = [
            _subject_row(
                fam, recipe, subject, level=L1, outcome="failed", residual="unavailable",
                failure_class="acquire-failure",
                reason=(f"the fetched {name} {recipe['version']} archive digest {observed} does "
                        f"not match the pinned {recipe['sha256']}"),
                specimen_id=f"specimen:{name}:{recipe['version']}",
                variant_id=f"variant:{name}:{recipe['version']}:pristine",
                source_sha256=observed,
                evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                          f"source:{recipe['url']}#{observed}"],
                steps=[dict(fetch, name="fetch")], canvas=None, limits=limits, prefix=auth_prefix)
            for subject in ("authority", "candidate")
        ]
        return rows, _specimen(fam, recipe, observed), _variant(fam, recipe)

    rows = []
    for subject, prefix, defined in (("authority", auth_prefix, auth_defined),
                                     ("candidate", cand_prefix, cand_defined)):
        rows.append(_measure_subject(fam, recipe, observed, archive, subject, prefix, defined,
                                     auth_prefix, limits))
    root_hash = next((r.get("source_root_hash") for r in rows if r.get("source_root_hash")),
                     None)
    return rows, _specimen(fam, recipe, observed, root_hash), _variant(fam, recipe)


def _specimen(fam: dict, recipe: dict, observed: str | None = None,
              root_hash: str | None = None) -> dict:
    name = str(fam.get("canonical_name"))
    digest = observed or recipe.get("sha256") or "unknown"
    return {
        "specimen_id": f"specimen:{name}:{recipe['version']}",
        "family_id": fam.get("family_id"),
        "version": recipe["version"],
        "upstream_ref": recipe["url"],
        "pristine_source_sha256": digest,
        "pristine_source_root_hash": root_hash or "unknown",
        "licence": "unknown",
        "evidence": [f"source:{recipe['url']}#{recipe.get('sha256') or 'unpinned'}",
                     f"recipe:{recipe['recipe_id']}", f"pinned_sha256:{recipe.get('sha256')}"],
    }


def _variant(fam: dict, recipe: dict) -> dict:
    name = str(fam.get("canonical_name"))
    return {
        "variant_id": f"variant:{name}:{recipe['version']}:pristine",
        "specimen_id": f"specimen:{name}:{recipe['version']}",
        "build_profile": f"{recipe['build_system']}-pristine-shared",
        "platform": "linux",
        "arch": "x86_64",
        "patch_set": "pristine",
        "evidence": [f"recipe:{recipe['recipe_id']}", f"build_system:{recipe['build_system']}"],
    }


# --------------------------------------------------------------------------------------------
# the atlas: every P1000 family, under both subjects, then the artefact
# --------------------------------------------------------------------------------------------

def candidate_identity() -> dict:
    """The candidate install prefix and the digests of the libs the candidate rows link."""
    ident = {"install_prefix": rel(CANDIDATE_PREFIX)}
    for soname in ("libssl.so.3", "libcrypto.so.3"):
        p = CANDIDATE_PREFIX / "lib" / soname
        ident[f"{soname.replace('.', '_')}_sha256"] = sha256_file(p) if p.is_file() else "unknown"
    return ident


def derive_atlas(families_body: dict, freeze_body: dict, authority_id: str) -> dict:
    """Measure the whole P1000 under both subjects and return the atlas `body`."""
    auth_prefix = resolve_authority(authority_id).prefix
    if not (CANDIDATE_PREFIX / "lib" / "libssl.so.3").is_file():
        raise SystemExit(f"[downstream-build-link] the candidate install prefix "
                         f"{rel(CANDIDATE_PREFIX)} holds no lib/libssl.so.3")
    limits = census.resource_limits()
    auth_defined = census.authority_defined_symbols(auth_prefix)
    cand_defined = census.authority_defined_symbols(CANDIDATE_PREFIX)

    p1000 = freeze_body.get("p1000") or []
    rows: list[dict] = []
    specimens: list[dict] = []
    variants: list[dict] = []
    for entry in p1000:
        name = str(entry.get("canonical_name"))
        fam = {
            "family_id": entry.get("family_id"),
            "canonical_name": name,
            "openssl_linkage": entry.get("openssl_linkage"),
            "directness_class": entry.get("directness_class"),
            "_rank": entry.get("p1000_rank"),
        }
        recipe = _RECIPE_BY_FAMILY.get(name)
        if recipe is None:
            rows.append(_no_recipe_row(fam, "authority", limits))
            rows.append(_no_recipe_row(fam, "candidate", limits))
            continue
        fam_rows, specimen, variant = measure_family(
            fam, recipe, auth_prefix, CANDIDATE_PREFIX, auth_defined, cand_defined, limits)
        rows.extend(fam_rows)
        if specimen:
            specimens.append(specimen)
        if variant:
            variants.append(variant)
        auth = next(r for r in fam_rows if r["subject"] == "authority")
        cand = next(r for r in fam_rows if r["subject"] == "candidate")
        print(f"  [p1000 {entry.get('p1000_rank'):>4}] {name:<12} "
              f"auth={auth['level']:<16} cand={cand['level']:<16} "
              f"{(cand['reason'] or '')[:70]}"[:150], flush=True)

    rows.sort(key=lambda r: (str(r.get("family_id")), str(r.get("subject"))))
    specimens.sort(key=lambda s: str(s["specimen_id"]))
    variants.sort(key=lambda v: str(v["variant_id"]))

    counts = _counts(p1000, rows)
    body = {
        "rule": RULE,
        "authority": authority_id,
        "authority_prefix": rel(auth_prefix),
        "candidate_identity": candidate_identity(),
        "recipe_catalogue": [
            {"family": r["family"], "version": r["version"], "url": r["url"],
             "archive": r["archive"], "sha256": r.get("sha256"),
             "build_system": r["build_system"], "artifact": r["artifact"],
             "env_extra": r.get("env_extra"),
             "recipe_id": r["recipe_id"], "note": r.get("note")}
            for r in RECIPES
        ],
        "specimens": specimens,
        "variants": variants,
        "runs": rows,
        "counts": counts,
        "resource_limits": limits,
        "non_claims": NON_CLAIMS,
    }
    return body


def _counts(p1000: list[dict], rows: list[dict]) -> dict:
    """The counts, derived from the rows and the frozen P1000, never typed."""
    recipe_families = {r["family"] for r in RECIPES}
    recipe_backed = [e for e in p1000 if str(e.get("canonical_name")) in recipe_families]

    def levels(subject: str, rung: str) -> int:
        return sum(1 for r in rows
                   if r.get("subject") == subject
                   and RANK.get(str(r.get("level")), -1) >= RANK[rung])

    def failed(subject: str) -> int:
        return sum(1 for r in rows
                   if r.get("subject") == subject and r.get("outcome") in ("failed",))

    candidate_linkage_proven = sum(
        1 for r in rows
        if r.get("subject") == "candidate" and r.get("level") == L4
        and r.get("linkage_proven") and not r.get("resolved_under_authority"))
    failure_histogram: dict[str, int] = {}
    for r in rows:
        if r.get("subject") == "candidate" and r.get("failure_class"):
            failure_histogram[r["failure_class"]] = failure_histogram.get(r["failure_class"], 0) + 1
    return {
        "p1000": len(p1000),
        "rows": len(rows),
        "with_recipe": len(recipe_backed),
        "no_recipe": len(p1000) - len(recipe_backed),
        "measured_families": len(recipe_backed),
        "by_subject": {
            subject: {
                "configured": levels(subject, L2),
                "built": levels(subject, L3),
                "linked": levels(subject, L4),
                "failed": failed(subject),
                "not_attempted": sum(1 for r in rows if r.get("subject") == subject
                                     and r.get("outcome") == "not_attempted"),
            }
            for subject in ("authority", "candidate")
        },
        "candidate_linkage_proven": candidate_linkage_proven,
        "authority_linkage_proven": sum(
            1 for r in rows
            if r.get("subject") == "authority" and r.get("level") == L4
            and r.get("linkage_proven")),
        "candidate_failures": failure_histogram,
        "candidate_specific_patch_count": sum(
            int(r.get("candidate_specific_patch_count") or 0) for r in rows),
    }


def write_outputs(body: dict, authority_id: str) -> None:
    inputs = [
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="families", path=FAMILIES),
        InputRef(name="downstream-census",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_census.py"),
        InputRef(name="downstream-freeze",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_freeze.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]
    doc = envelope(kind="downstream-build-link-atlas", authority=authority_id,
                   inputs=inputs, body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


# --------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; never rebuilding)
# --------------------------------------------------------------------------------------------

def _load_atlas() -> dict:
    if not OUT.is_file():
        return {}
    return json.loads(OUT.read_text(encoding="utf-8")).get("body", {})


def build_link_findings(families_body: dict, freeze_body: dict, atlas_body: dict) -> list[str]:
    """Every way the recorded build/link atlas fails its own subject.

    Pure over the committed frozen P1000 and the committed atlas body, so the court re-runs it
    without rebuilding and the sensitivity control can mutate an in-memory copy. Every check is a
    re-derivation from the recorded rows: the population is accounted for under both subjects, the
    identical-build-intent pairing holds, a linked row is backed by a real linkage proof, the
    candidate's linkage resolves the candidate and never the authority or a system library, the
    candidate-specific patch count is zero, a non-measured row carries a reason and a schema-valid
    residual/failure class, and the counts are read rather than typed.
    """
    findings: list[str] = []
    p1000 = freeze_body.get("p1000") or []
    p1000_ids = [str(e.get("family_id")) for e in p1000]
    p1000_set = set(p1000_ids)
    recipe_families = {r["family"] for r in RECIPES}

    # Every recipe must name a P1000 family: a recipe that selects outside the frozen population
    # would let the population be re-picked by the recipe set.
    canonical_by_name = {str(e.get("canonical_name")): str(e.get("family_id")) for e in p1000}
    for r in RECIPES:
        if r["family"] not in canonical_by_name:
            findings.append(f"the recipe for {r['family']!r} names a family outside the frozen "
                            f"P1000: the atlas would select its measured set by recipe")
        if not r.get("sha256"):
            findings.append(f"the recipe for {r['family']!r} pins no archive SHA-256")

    runs = atlas_body.get("runs") or []
    if not runs:
        return findings + ["the atlas records no build/link run"]

    by_family_subject: dict[tuple[str, str], dict] = {}
    seen_run_ids: set[str] = set()
    for row in runs:
        fid = str(row.get("family_id"))
        subject = str(row.get("subject"))
        # A build/link row is a `run` record.
        findings += [f"{fid}/{subject}: {p}" for p in downstream_schemas.validate_run(row)]
        rid = str(row.get("run_id"))
        if rid in seen_run_ids:
            findings.append(f"two build/link rows share run_id {rid!r}")
        seen_run_ids.add(rid)
        if fid not in p1000_set:
            findings.append(f"{fid} is not a frozen P1000 family: the atlas must account for the "
                            f"frozen population")
        if subject not in ("authority", "candidate"):
            findings.append(f"{fid}: a build/link row names subject {subject!r}, not "
                            f"`authority`/`candidate`")
        by_family_subject[(fid, subject)] = row

        if int(row.get("candidate_specific_patch_count") or 0) != 0:
            findings.append(f"{fid}/{subject}: candidate_specific_patch_count is "
                            f"{row.get('candidate_specific_patch_count')!r}, not 0: the atlas "
                            f"applies no candidate-specific downstream patch")

        outcome = row.get("outcome")
        if outcome in ("failed", "not_attempted"):
            if not row.get("reason"):
                findings.append(f"{fid}/{subject}: a {outcome} row carries no reason")
            if not row.get("failure_class"):
                findings.append(f"{fid}/{subject}: a {outcome} row carries no failure class")
            elif row["failure_class"] not in downstream_schemas.FAILURE_CLASSES:
                findings.append(f"{fid}/{subject}: failure class {row['failure_class']!r} is outside "
                                f"the taxonomy")
            if row.get("residual_class") in (None, "none"):
                findings.append(f"{fid}/{subject}: a {outcome} row carries no residual class")

        if RANK.get(row.get("level"), -1) >= RANK[L4]:
            # A linked row must be backed by a real linkage proof.
            if not row.get("linkage_proven"):
                findings.append(f"{fid}/{subject}: claims {row.get('level')} but its linkage is not "
                                f"proven")
            link = row.get("linkage") or {}
            if subject == "candidate":
                if row.get("resolved_under_authority") or link.get("resolved_under_authority"):
                    findings.append(f"{fid}/{subject}: a candidate {row.get('level')} row resolves "
                                    f"the authority prefix, so the linkage proves the authority, "
                                    f"not the candidate")
                if link.get("all_under_prefix") is not True:
                    findings.append(f"{fid}/{subject}: a candidate {row.get('level')} row does not "
                                    f"resolve every libssl/libcrypto under the candidate prefix "
                                    f"(or resolves a system library)")
                for soname, res in sorted((link.get("sonames") or {}).items()):
                    if not str(res.get("resolved", "")).startswith("prefix:"):
                        findings.append(f"{fid}/{subject}: claims candidate linkage but resolves "
                                        f"{soname} -> {res.get('resolved')}")
            else:
                if link.get("all_under_prefix") is not True:
                    findings.append(f"{fid}/{subject}: an authority {row.get('level')} row does not "
                                    f"resolve every libssl/libcrypto under the authority prefix")

    # Every frozen family is accounted for under both subjects.
    missing = [fid for fid in p1000_ids
               if (fid, "authority") not in by_family_subject
               or (fid, "candidate") not in by_family_subject]
    if missing:
        findings.append(f"{len(missing)} frozen P1000 family(ies) lack a row under both subjects "
                        f"(e.g. {missing[:3]})")

    # Identical build intent: every recipe-backed family has both rows for the same specimen and the
    # same recipe, and each row's subject is the one it claims.
    for name, fid in sorted(canonical_by_name.items()):
        if name not in recipe_families:
            continue
        a = by_family_subject.get((fid, "authority"))
        c = by_family_subject.get((fid, "candidate"))
        if a is None:
            findings.append(f"{fid}: a recipe-backed family has no authority row, so the "
                            f"comparison is not identical-intent")
            continue
        if c is None:
            findings.append(f"{fid}: a recipe-backed family has no candidate row, so the "
                            f"comparison is not identical-intent")
            continue
        if not a.get("has_recipe") or not c.get("has_recipe"):
            findings.append(f"{fid}: a recipe-backed family records a row without its recipe")
        if a.get("recipe_id") != c.get("recipe_id"):
            findings.append(f"{fid}: the authority and candidate rows name different recipes "
                            f"({a.get('recipe_id')!r} vs {c.get('recipe_id')!r}): the build intent "
                            f"is not identical")
        if a.get("specimen_id") != c.get("specimen_id"):
            findings.append(f"{fid}: the authority and candidate rows name different specimens "
                            f"({a.get('specimen_id')!r} vs {c.get('specimen_id')!r})")
        # The same pristine source tree: both subjects must have extracted the same bytes, so the
        # build intent is identical at the source, not only at the recipe.
        ra, rc = a.get("source_root_hash"), c.get("source_root_hash")
        if ra and rc and ra != rc:
            findings.append(f"{fid}: the authority and candidate rows built different pristine "
                            f"source trees ({ra} vs {rc})")

    # The specimens and variants are schema-valid, and each recipe-backed family has a specimen.
    specimen_ids = {str(s.get("specimen_id")) for s in atlas_body.get("specimens") or []}
    for s in atlas_body.get("specimens") or []:
        findings += [f"specimen {s.get('specimen_id')!r}: {p}"
                     for p in downstream_schemas.validate_specimen(s)]
    for v in atlas_body.get("variants") or []:
        findings += [f"variant {v.get('variant_id')!r}: {p}"
                     for p in downstream_schemas.validate_variant(v)]
    for name, fid in sorted(canonical_by_name.items()):
        if name in recipe_families:
            rows = [by_family_subject.get((fid, "authority")),
                    by_family_subject.get((fid, "candidate"))]
            spec = next((r.get("specimen_id") for r in rows if r), None)
            if spec and spec not in specimen_ids:
                findings.append(f"{fid}: names specimen {spec!r}, which is not recorded")

    # The candidate identity names the install the candidate rows linked.
    ident = atlas_body.get("candidate_identity") or {}
    if not str(ident.get("install_prefix", "")).endswith("artifacts/phase2/install"):
        findings.append("candidate_identity.install_prefix is not the candidate drop-in install")
    for field in ("libssl_so_3_sha256", "libcrypto_so_3_sha256"):
        value = str(ident.get(field) or "")
        if value == "unknown" or len(value) != 64:
            findings.append(f"candidate_identity.{field} is not a 64-hex digest")

    # The recorded rule and non-claims are the frozen ones.
    if atlas_body.get("rule") != RULE:
        findings.append("the recorded build/link rule is not the frozen rule")
    if atlas_body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four plus the build/link "
                        "non-claim")

    # Counts are read, not typed.
    derived = _counts(p1000, runs)
    recorded = atlas_body.get("counts") or {}
    for key in ("p1000", "rows", "with_recipe", "no_recipe", "measured_families",
                "candidate_linkage_proven", "authority_linkage_proven",
                "candidate_specific_patch_count"):
        if recorded.get(key) != derived[key]:
            findings.append(f"counts.{key} {recorded.get(key)!r} disagrees with the derived "
                            f"{derived[key]!r}")
    for subject in ("authority", "candidate"):
        for rung in ("configured", "built", "linked", "failed", "not_attempted"):
            got = (recorded.get("by_subject") or {}).get(subject, {}).get(rung)
            want = derived["by_subject"][subject][rung]
            if got != want:
                findings.append(f"counts.by_subject.{subject}.{rung} {got!r} disagrees with the "
                                f"derived {want!r}")
    return findings


def _mutations(atlas_body: dict) -> list[tuple[str, str, dict]]:
    """`(name, needle, mutated_atlas)` for each seeded mutation."""
    out: list[tuple[str, str, dict]] = []
    runs = atlas_body.get("runs") or []
    cand_l4 = next((r for r in runs
                    if r.get("subject") == "candidate" and r.get("level") == L4), None)
    auth_row = next((r for r in runs if r.get("subject") == "authority" and r.get("has_recipe")),
                    None)
    failed_row = next((r for r in runs if r.get("outcome") in ("failed", "not_attempted")), None)

    # (1) a candidate L4 row whose linkage resolves the authority prefix.
    m1 = copy.deepcopy(atlas_body)
    for r in m1["runs"]:
        if (cand_l4 is not None and r.get("run_id") == cand_l4.get("run_id")):
            r["resolved_under_authority"] = True
            r["linkage"]["resolved_under_authority"] = True
            r["linkage"]["all_under_prefix"] = False
            break
    out.append(("candidate_linkage_resolves_authority", "resolves the authority prefix", m1))

    # (2) a recipe-backed family deleted from the authority side: the intent is no longer identical.
    m2 = copy.deepcopy(atlas_body)
    if auth_row is not None:
        m2["runs"] = [r for r in m2["runs"] if r.get("run_id") != auth_row.get("run_id")]
    out.append(("recipe_family_missing_authority_row", "no authority row", m2))

    # (3) a positive candidate-specific patch count.
    m3 = copy.deepcopy(atlas_body)
    for r in m3["runs"]:
        if r.get("subject") == "candidate":
            r["candidate_specific_patch_count"] = 1
            break
    out.append(("positive_candidate_specific_patch_count", "candidate_specific_patch_count", m3))

    # (4) a non-measured row with no residual class.
    m4 = copy.deepcopy(atlas_body)
    if failed_row is not None:
        for r in m4["runs"]:
            if r.get("run_id") == failed_row.get("run_id"):
                r["residual_class"] = None
                break
    out.append(("failed_row_without_residual", "no residual class", m4))

    # (5) a candidate L4 row whose linkage resolves a system library.
    m5 = copy.deepcopy(atlas_body)
    for r in m5["runs"]:
        if cand_l4 is not None and r.get("run_id") == cand_l4.get("run_id"):
            r["linkage"]["all_under_prefix"] = False
            for soname in r["linkage"]["sonames"]:
                r["linkage"]["sonames"][soname]["resolved"] = \
                    f"/usr/lib/x86_64-linux-gnu/{soname}"
            break
    out.append(("candidate_system_libssl", "does not resolve every", m5))

    # (6) a candidate row that built a different pristine source tree than the authority row.
    m6 = copy.deepcopy(atlas_body)
    cand_recipe = next((r for r in m6["runs"]
                        if r.get("subject") == "candidate" and r.get("source_root_hash")), None)
    if cand_recipe is not None:
        cand_recipe["source_root_hash"] = "0" * 64
    out.append(("candidate_different_source_root", "different pristine source trees", m6))
    return out


def build_link_sensitivity_control(families_body: dict, freeze_body: dict,
                                   atlas_body: dict) -> dict:
    """Prove the court can fail: seed six mutations and require each to be caught.

    The honest atlas must yield **zero** findings (specificity), and each seeded mutation -- a
    candidate `L4` row whose linkage resolves the authority, a recipe-backed family missing its
    authority row (non-identical intent), a positive `candidate_specific_patch_count`, a
    non-measured row with no residual class, a candidate `L4` row whose linkage resolves a system
    library, and a candidate row that built a different pristine source tree -- must be caught with
    a finding that names what it is.
    """
    base = build_link_findings(families_body, freeze_body, atlas_body)
    specificity = not base
    control: dict = {"baseline_findings": len(base), "specificity_holds": specificity}
    honest = specificity
    for name, needle, mutated in _mutations(atlas_body):
        caught = any(needle in f for f in build_link_findings(families_body, freeze_body, mutated))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# --------------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------------

def _load_freeze() -> tuple[dict, dict]:
    if not FAMILY_FREEZE.is_file():
        raise SystemExit(f"[downstream-build-link] {rel(FAMILY_FREEZE)} is absent; run 24.4 first")
    freeze_doc = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))
    families_body = {}
    if FAMILIES.is_file():
        families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    return freeze_doc, families_body


def cmd_measure(authority_id: str) -> int:
    freeze_doc, families_body = _load_freeze()
    freeze_body = freeze_doc["body"]
    if len(freeze_body.get("p1000") or []) != 1000:
        print(f"[downstream-build-link] the frozen P1000 carries "
              f"{len(freeze_body.get('p1000') or [])} family(ies), not 1000")
        return 1
    SCRATCH.mkdir(parents=True, exist_ok=True)
    print(f"[downstream-build-link] building the P1000 recipes against both subjects "
          f"(authority {authority_id} + candidate {rel(CANDIDATE_PREFIX)})")
    started = time.monotonic()
    body = derive_atlas(families_body, freeze_body, authority_id)
    census._cleanup(SCRATCH)
    findings = build_link_findings(families_body, freeze_body, body)
    control = build_link_sensitivity_control(families_body, freeze_body, body)
    if findings or not control["honest"]:
        print("[downstream-build-link] the measured atlas fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body, authority_id)
    c = body["counts"]
    print(f"[downstream-build-link] elapsed={time.monotonic() - started:.0f}s "
          f"with_recipe={c['with_recipe']} no_recipe={c['no_recipe']}")
    print(f"  authority configured={c['by_subject']['authority']['configured']} "
          f"built={c['by_subject']['authority']['built']} "
          f"linked={c['by_subject']['authority']['linked']} "
          f"failed={c['by_subject']['authority']['failed']}")
    print(f"  candidate configured={c['by_subject']['candidate']['configured']} "
          f"built={c['by_subject']['candidate']['built']} "
          f"linked={c['by_subject']['candidate']['linked']} "
          f"failed={c['by_subject']['candidate']['failed']}")
    print(f"  candidate_linkage_proven={c['candidate_linkage_proven']} "
          f"candidate_specific_patch_count={c['candidate_specific_patch_count']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check(authority_id: str) -> int:
    del authority_id
    if not (FAMILY_FREEZE.is_file() and OUT.is_file()):
        print(f"[downstream-build-link] {rel(FAMILY_FREEZE)} or {rel(OUT)} is absent")
        return 1
    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    families_body = (json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
                     if FAMILIES.is_file() else {})
    atlas_body = _load_atlas()
    findings = build_link_findings(families_body, freeze_body, atlas_body)
    control = build_link_sensitivity_control(families_body, freeze_body, atlas_body)
    if findings:
        print(f"[downstream-build-link] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = atlas_body.get("counts") or {}
    print(f"[downstream-build-link] with_recipe={c.get('with_recipe')} "
          f"candidate_linked={(c.get('by_subject') or {}).get('candidate', {}).get('linked')} "
          f"linkage_proven={c.get('candidate_linkage_proven')} findings={len(findings)} "
          f"control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_build_link.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_build_link.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. The catalogue is well-formed.
    families = [r["family"] for r in RECIPES]
    if len(set(families)) != len(families):
        failures.append("the recipe catalogue names a family twice")
    for r in RECIPES:
        if not r.get("sha256"):
            failures.append(f"the recipe for {r['family']!r} pins no archive SHA-256")

    # 3. The pure functions behave over the committed evidence.
    if not FAMILY_FREEZE.is_file():
        failures.append(f"{rel(FAMILY_FREEZE)} is absent")
    else:
        freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
        families_body = (json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
                         if FAMILIES.is_file() else {})
        if len(freeze_body.get("p1000") or []) != 1000:
            failures.append("the frozen P1000 does not carry 1000 family(ies)")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            atlas_body = _load_atlas()
            findings = build_link_findings(families_body, freeze_body, atlas_body)
            if findings:
                failures.append(f"the committed atlas has findings: {findings[:3]}")
            control = build_link_sensitivity_control(families_body, freeze_body, atlas_body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[downstream-build-link] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-build-link] self-test ok: the guard refuses a host invocation of this tool "
          "(marker and flag both named), the committed P1000 build/link atlas reproduces with zero "
          "findings, and every seeded mutation (candidate linkage resolving the authority, a "
          "recipe-backed family missing its authority row, a positive candidate-specific patch "
          "count, a non-measured row with no residual class, candidate linkage resolving a "
          "system library, and a candidate row that built a different pristine source tree) is "
          "caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--measure", action="store_true",
                    help="run the real builds and write the atlas (in-container)")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed atlas without rebuilding (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool fetches and compiles, so it is an
    # execution entry point and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check(args.authority)
    return cmd_measure(args.authority)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
