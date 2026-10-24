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

# The declarative template layer: its pristine recipes and its pkg-config shim are part of the
# shared catalogue, so a templated family is measured by exactly the same build/link path as a
# bespoke one.  The module executes nothing at import time (it reads one small JSON file).
import downstream_templates as templates  # noqa: E402

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
MAKE_JOB_COUNT = int(MAKE_JOBS.lstrip("-j") or "1")

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
        "note": "superseded by the b13 CMake override (see _LATE_RECIPE_OVERRIDES)",
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

# The Phase-25 L7 expansion batch: five library families that were previously blocked only because
# the minimal venue lacked cmake/meson and their non-OpenSSL dependency headers. Each is pinned by
# its released archive digest and built against the subject prefix. The recipes carry no
# candidate-specific flag: `{prefix}` is the only substitution, exactly as for every earlier batch.
_L7_EXPANSION_SPECS: tuple[dict, ...] = (
    {
        "family": "jwt", "version": "2.1.3",
        "url": "https://github.com/benmcollins/libjwt/archive/refs/tags/v2.1.3.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "ea13f42713edd113e65c05f9601ba25383f89b34a644b64f30ee0ecbf282dc83",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                      "-DBUILD_EXAMPLES=OFF", "-DBUILD_TESTS=OFF",
                      "-DCMAKE_C_FLAGS=-DHAVE_OPENSSL",
                      "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix}"],
        "make": [], "artifact": "b/libjwt/libjwt.so*", "launch": None,
        "note": ("libjwt 2.1.3 (family jwt) built with CMake against the subject prefix; "
                 "-DHAVE_OPENSSL is required because the CMake build does not run "
                 "configure.ac's AC_DEFINE, and jansson comes from the venue's pkg-config"),
    },
    {
        "family": "libjose", "version": "11",
        "url": "https://github.com/latchset/jose/releases/download/v11/jose-11.tar.xz",
        "archive": "tar.xz", "build_system": "meson",
        "sha256": "e272afe7717e22790c383f3164480627a567c714ccb80c1ee96f62c9929d8225",
        "configure": ["--buildtype=release", "-Dwerror=false"],
        "make": [], "artifact": "b/lib/libjose.so.0*", "launch": None,
        "note": ("jose 11 (family libjose) built with meson/ninja against the subject prefix; "
                 "jansson and zlib come from the venue, libcrypto from the subject"),
    },
    {
        "family": "libzip", "version": "1.11.1",
        "url": "https://libzip.org/download/libzip-1.11.1.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "c0e6fa52a62ba11efd30262290dc6970947aef32e0cc294ee50e9005ceac092a",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DENABLE_OPENSSL=ON",
                      "-DENABLE_GNUTLS=OFF", "-DENABLE_MBEDTLS=OFF",
                      "-DENABLE_COMMONCRYPTO=OFF", "-DENABLE_ZSTD=OFF",
                      "-DBUILD_TOOLS=OFF", "-DBUILD_REGRESS=OFF",
                      "-DBUILD_EXAMPLES=OFF", "-DBUILD_OSSFUZZ=OFF", "-DBUILD_DOC=OFF",
                      "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix}"],
        "make": [], "artifact": "b/lib/libzip.so.5*", "launch": None,
        "note": ("libzip 1.11.1 built with CMake; AES-256 support uses the subject libcrypto "
                 "(the zstd backend is disabled because the venue carries no zstd headers)"),
    },
    {
        "family": "apr-util", "version": "1.6.3",
        "url": "https://archive.apache.org/dist/apr/apr-util-1.6.3.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "2b74d8932703826862ca305b094eef2983c27b39d5c9414442e9976a9acf1983",
        "configure": ["--with-apr=/usr/bin/apr-1-config", "--with-crypto",
                      "--with-openssl={prefix}", "--disable-util-dso"],
        "make": [MAKE_JOBS], "artifact": ".libs/libaprutil-1.so*", "launch": None,
        "note": ("apr-util 1.6.3 with --with-crypto --disable-util-dso: the OpenSSL crypto "
                 "driver is linked into libaprutil-1 and the library carries a libcrypto "
                 "DT_NEEDED; APR comes from the venue's apr-1-config"),
    },
    {
        "family": "fido2", "version": "1.15.0",
        "url": "https://github.com/Yubico/libfido2/archive/refs/tags/1.15.0.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "32e3e431cfe29b45f497300fdb7076971cb77fc584fcfa80084d823a6ed94fbb",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                      "-DBUILD_TOOLS=OFF", "-DBUILD_MANPAGES=OFF",
                      "-DBUILD_EXAMPLES=OFF", "-DBUILD_TESTS=OFF", "-DNFC_LINUX=OFF",
                      "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib "
                      "-Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/src/libfido2.so.1*", "launch": None,
        # libfido2's Linux CMakeLists requires libudev unconditionally (even with NFC off). The
        # venue provides libudev.so.1 but not libudev-dev, so the harness acquires the matching
        # bookworm -dev package by pinned digest and extracts only its header/.pc into the build
        # scratch. This is a venue dependency, not part of the subject or the family source.
        "aux_sources": [
            {
                "url": ("http://deb.debian.org/debian/pool/main/s/systemd/"
                        "libudev-dev_252.39-1~deb12u2_amd64.deb"),
                "sha256": "b8795a05b96799cb25ed3677eef8e8b1f1facdf07ad4527e06ef8f82ca164fbd",
                "archive": "deb", "extract": ["dpkg-deb", "-x"],
                "include_dirs": ["usr/include"],
                "library_dirs": ["usr/lib/x86_64-linux-gnu"],
                "pkgconfig_dirs": ["usr/lib/x86_64-linux-gnu/pkgconfig"],
                "links": {"usr/lib/x86_64-linux-gnu/libudev.so.1":
                          "/usr/lib/x86_64-linux-gnu/libudev.so.1"},
                "note": ("matching bookworm libudev-dev 252.39-1~deb12u2; libudev.so.1 "
                         "itself is the venue's already-installed runtime library"),
            },
        ],
        "note": ("libfido2 1.15.0 built with CMake against the subject prefix (ES256 uses the "
                 "subject libcrypto); libcbor comes from the venue and libudev-dev from the "
                 "pinned auxiliary package above"),
    },
)

# The Phase-25 L7 server batch: three TLS servers/terminators and an FTPS server that the venue's
# minimal image cannot build alone, each pinned by its released archive digest. Every non-OpenSSL
# dependency is a pinned bookworm `.deb` acquired through the same `aux_sources` seam fido2 uses
# (headers/dev symlinks/`.pc`/`-config` scripts), so no distribution OpenSSL can be pulled in and
# the subject prefix remains the only OpenSSL on every link line.
_AUX_MULTIARCH = "usr/lib/x86_64-linux-gnu"
_AUX_MULTIARCH_PC = "usr/lib/x86_64-linux-gnu/pkgconfig"


def _aux_deb(pool: str, filename: str, sha256: str, *, include_dirs: tuple[str, ...] = (),
             library_dirs: tuple[str, ...] = (), pkgconfig_dirs: tuple[str, ...] = (),
             bin_dirs: tuple[str, ...] = (),
             links: dict[str, str] | None = None) -> dict:
    """One pinned bookworm dependency package, extracted under the family scratch."""
    spec: dict = {
        "url": f"http://deb.debian.org/debian/pool/main/{pool}/{filename}",
        "sha256": sha256, "archive": "deb", "extract": ["dpkg-deb", "-x"],
        "note": f"pinned bookworm {filename}",
    }
    for key, value in (("include_dirs", include_dirs), ("library_dirs", library_dirs),
                       ("pkgconfig_dirs", pkgconfig_dirs), ("bin_dirs", bin_dirs),
                       ("links", links)):
        if value:
            spec[key] = dict(value) if key == "links" else list(value)
    return spec


# memcached 1.6.32 links libevent; the image has neither its headers nor its runtime library.
_LIBEVENT_AUX: tuple[dict, ...] = (
    _aux_deb("libe/libevent", "libevent-2.1-7_2.1.12-stable-8_amd64.deb",
             "ca8858a7095ade7776c9f73437812423a45ccd90de2079e8c34830d291df290f"),
    _aux_deb("libe/libevent", "libevent-dev_2.1.12-stable-8_amd64.deb",
             "ed7f550d6cc03f3cf7dfa80d739e13350d8a2cdb25f9dfcbf11fbe66cd1d4b89",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

# hitch 1.8.0 links libev; neither ev.h nor libev.so.4 is in the image.
_LIBEV_AUX: tuple[dict, ...] = (
    _aux_deb("libe/libev", "libev4_4.33-1_amd64.deb",
             "1b35aebfabf4f1dba891c9cc0b7352e8402dac4efef1e34a41359ce5bd68aacf"),
    _aux_deb("libe/libev", "libev-dev_4.33-1_amd64.deb",
             "d317551ed50e70e3c98141b7a215b31c8c334b7a3a610d3337d0dcd540bad0a1",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

# icecast 2.4.4 requires libxml2, libxslt and Ogg Vorbis. The dev packages are extracted with
# their matching runtime libraries (the image carries libxml2 but not libxslt/libogg/libvorbis),
# and libicu-dev supplies the ICU headers Debian's libxml2 is built against. libxslt's
# `xsltconfig.h` lives in the multiarch include directory, named below.
_ICECAST_AUX: tuple[dict, ...] = (
    _aux_deb("libo/libogg", "libogg0_1.3.5-3_amd64.deb",
             "f67acb0477aed0354f411172e37af338f3ac6bd4f3766134a2cf5539884b5a28"),
    _aux_deb("libo/libogg", "libogg-dev_1.3.5-3_amd64.deb",
             "ece2ef4d087d27b77b6c1a240efdb8b32dc2d19f69f7ce7fbb184c83a132d49c",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libv/libvorbis", "libvorbis0a_1.3.7-1_amd64.deb",
             "01c14f9d1109650077a4c5c337c285476a6932d4d448f5a190c2b845724dbf21"),
    _aux_deb("libv/libvorbis", "libvorbisenc2_1.3.7-1_amd64.deb",
             "75dd4d6f904c7db82f5112e60d8efea9e81dfedf94e970c5da7af2b3d81643c0"),
    _aux_deb("libv/libvorbis", "libvorbis-dev_1.3.7-1_amd64.deb",
             "2be095b51700abae4ad89b81560bfa65240745275e0ef6474ab1de857cfeea92",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libx/libxml2", "libxml2_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "4460e39dda10a815881374217cde08474747cfa018358cd8612c14b390eff53b"),
    _aux_deb("libx/libxml2", "libxml2-dev_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "e8ceacf656b1720e7a310e1d159439a356bfcb9f5fb0325907f26aa8590e5f70",
             include_dirs=("usr/include", "usr/include/libxml2"),
             library_dirs=(_AUX_MULTIARCH,), pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libx/libxslt", "libxslt1.1_1.1.35-1+deb12u4_amd64.deb",
             "5bf795dc6374f744906d39a786024d98b2cb6b885c7776f5dc64eb4092b550a6"),
    _aux_deb("libx/libxslt", "libxslt1-dev_1.1.35-1+deb12u4_amd64.deb",
             "f7f5686127331d97a65e2abac1953e32b1ed8eb774cdf1749a849090b2f75ccb",
             include_dirs=("usr/include", "usr/include/x86_64-linux-gnu"),
             library_dirs=(_AUX_MULTIARCH,), pkgconfig_dirs=(_AUX_MULTIARCH_PC,),
             bin_dirs=("usr/bin",)),
    _aux_deb("i/icu", "libicu-dev_72.1-3+deb12u1_amd64.deb",
             "08bd4e3f4bd4fc725cf25e739edf0e7df5ac1826bdac9a7d990eea8f93b2d7a0",
             include_dirs=("usr/include",)),
)

# radsecproxy 1.9.1 and w3m both need a non-OpenSSL library the venue ships only as a runtime
# soname. Each is acquired through the pinned `aux_sources` seam above; nothing in either package
# is OpenSSL, so the subject prefix stays the only OpenSSL on the link line.
_NETTLE_AUX: tuple[dict, ...] = (
    _aux_deb("n/nettle", "libnettle8_3.8.1-2_amd64.deb",
             "45922e6e289ffd92f0f92d2bb9159e84236ff202d552a461bf10e5335b3f0261",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("n/nettle", "nettle-dev_3.8.1-2_amd64.deb",
             "aa8e4331a974f00db23a14389c67dfe66bc359b09b6c2dbfe555230942feb6be",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_W3M_AUX: tuple[dict, ...] = (
    _aux_deb("libg/libgc", "libgc-dev_8.2.2-3_amd64.deb",
             "a7b8a113d5a0152959af593d681282ef4a3177fae826096f530a1d3cf00cdaa9",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("n/ncurses", "libncurses-dev_6.4-4_amd64.deb",
             "2ad228835756feb118bb131b32834bd23a09047e4de408cc5204cbb5dce0e4bb",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

# The Phase-25 L7 client/proxy batch: a RadSec proxy, an IRC bouncer, a mail client and a text
# browser. Each is a pristine released archive pinned by digest and built against the subject
# prefix; the two that need a non-OpenSSL runtime library acquire it through `aux_sources`.
_L7_CLIENT_SPECS: tuple[dict, ...] = (
    {
        "family": "radsecproxy", "version": "1.10.1",
        "url": ("https://github.com/radsecproxy/radsecproxy/releases/download/1.10.1/"
                "radsecproxy-1.10.1.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "a8fd5ca1df5e00ce34c9170a085d311b1da155a8e006f0cce46f6e95caa6af7b",
        "configure": ["--with-openssl={prefix}"], "make": [MAKE_JOBS],
        "artifact": "radsecproxy", "launch": ["-v"],
        "aux_sources": list(_NETTLE_AUX),
        "note": ("radsecproxy 1.10.1 with its TLS (RadSec) transport linked against the subject "
                 "libssl; nettle is the pinned bookworm package above (the F-Ticks MAC hash), "
                 "not an OpenSSL dependency"),
    },
    {
        "family": "znc", "version": "1.10.3",
        "url": "https://znc.in/releases/znc-1.10.3.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "68f3f6641b480c041010c5596e1234043e05c9137eda06233845017603095f5b",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DWANT_OPENSSL=ON",
                      "-DWANT_PYTHON=OFF", "-DWANT_PERL=OFF", "-DWANT_ICU=OFF",
                      "-DWANT_CYRUS=OFF", "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_CXX_FLAGS=-I{prefix}/include",
                      "-DCMAKE_EXE_LINKER_FLAGS=-L{prefix}/lib "
                      "-Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/src/znc", "launch": ["--version"],
        "note": ("ZNC 1.10.3's released tarball (which bundles the submodules its CMake build "
                 "requires) built with its SSL listener against the subject libssl"),
    },
    {
        "family": "s-nail", "version": "14.9.25",
        "url": "https://ftp.sdaoden.eu/s-nail-14.9.25.tar.xz",
        "archive": "tar.xz", "build_system": "make",
        "sha256": "20ff055be9829b69d46ebc400dfe516a40d287d7ce810c74355d6bdc1a28d8a9",
        "configure": None,
        # s-nail has no configure: `make all` runs its own mk/make-config.sh probe, and
        # `CONFIG=MAXIMAL` selects the documented maximal feature set (which includes TLS).
        "make": [MAKE_JOBS, "all", "CONFIG=MAXIMAL",
                 "EXTRA_CFLAGS=-I{prefix}/include",
                 "EXTRA_LDFLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "artifact": ".obj/s-nail", "launch": ["-V"],
        "note": ("s-nail 14.9.25 built by its own make with CONFIG=MAXIMAL; the TLS probe "
                 "compiles and links the subject libssl through EXTRA_CFLAGS/EXTRA_LDFLAGS"),
    },
    {
        "family": "w3m", "version": "0.5.3+git20230121",
        "url": ("http://deb.debian.org/debian/pool/main/w/w3m/"
                "w3m_0.5.3+git20230121.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "configure",
        "sha256": "974d1095a47f1976150a792fe9c5a44cc821c02b6bdd714a37a098386250e03a",
        "configure": ["--with-ssl={prefix}", "--disable-nls", "--enable-image=no"],
        "make": [MAKE_JOBS], "artifact": "w3m", "launch": ["-version"],
        "aux_sources": list(_W3M_AUX),
        "env_extra": {"SSL_CFLAGS": "-I{prefix}/include",
                      "SSL_LIBS": "-L{prefix}/lib -lssl -lcrypto"},
        "note": ("w3m's Debian-maintained pristine snapshot of 0.5.3 (which carries the glibc "
                 "`struct file_handle` fix the 2016 release predates) against the subject libssl; "
                 "libgc and ncurses headers come from the pinned packages above"),
    },
)

_L7_SERVER_SPECS: tuple[dict, ...] = (
    {
        "family": "memcached", "version": "1.6.32",
        "url": "https://memcached.org/files/memcached-1.6.32.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "4ab234219865191e8d1ba57a2f9167d8b573248fa4ff00b4d8296be13d24a82c",
        "configure": ["--enable-tls"], "make": [MAKE_JOBS],
        "artifact": "memcached", "launch": ["-h"],
        "aux_sources": list(_LIBEVENT_AUX),
        "note": ("memcached 1.6.32 with --enable-tls against the subject prefix; libevent comes "
                 "from the pinned bookworm packages above (headers, libevent.so and the runtime "
                 "libevent-2.1.so.7 the configure version probe executes)"),
    },
    {
        "family": "icecast", "version": "2.4.4",
        "url": "https://downloads.xiph.org/releases/icecast/icecast-2.4.4.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "49b5979f9f614140b6a38046154203ee28218d8fc549888596a683ad604e4d44",
        "configure": ["--with-openssl={prefix}", "--without-curl", "--without-speex",
                      "--without-theora", "--disable-yp"],
        "make": [MAKE_JOBS], "artifact": "src/icecast", "launch": ["-v"],
        "aux_sources": list(_ICECAST_AUX),
        "note": ("icecast 2.4.4's own configure links the subject libssl (--with-openssl); the "
                 "XML/XSLT/Vorbis dependencies are the pinned bookworm packages above, and the "
                 "optional curl/speex/theora/YP paths are disabled so the recipe needs no more"),
    },
    {
        "family": "proftpd", "version": "1.3.8b",
        "url": "https://github.com/proftpd/proftpd/archive/refs/tags/v1.3.8b.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "183ab7c6107de271a2959ff268f55c9b6c76b2cf0029e6584fccc019686601e0",
        "configure": ["--enable-openssl", "--with-modules=mod_tls", "--disable-auth-pam"],
        "make": [MAKE_JOBS], "artifact": "proftpd", "launch": ["-v"],
        "note": ("proftpd 1.3.8b with --enable-openssl and mod_tls linked statically into the "
                 "server binary; --disable-auth-pam keeps the build independent of PAM headers"),
    },
    {
        "family": "mini-httpd", "version": "1.30",
        "url": "http://www.acme.com/software/mini_httpd/mini_httpd-1.30.tar.gz",
        "archive": "tar.gz", "build_system": "make",
        "sha256": "9c4481802af8dde2e164062185c279e9274525c3af93d014fdc0b80cf30bca6e",
        "configure": None,
        "make": [MAKE_JOBS, "SSL_TREE={prefix}", "SSL_DEFS=-DUSE_SSL",
                 "SSL_INC=-I{prefix}/include",
                 "SSL_LIBS=-L{prefix}/lib -lssl -lcrypto",
                 # The release predates glibc's <sys/types.h> int64_t declaration; its own
                 # HAVE_INT64T guard is the upstream switch for that, not a source patch.
                 "CFLAGS=-O -DUSE_SSL -I{prefix}/include -ansi -pedantic -U__STRICT_ANSI__ "
                 "-DHAVE_INT64T -Wall"],
        "artifact": "mini_httpd", "launch": ["-h"],
        "note": ("mini_httpd 1.30 built by its own Makefile with the SSL_* definitions pointed at "
                 "the subject prefix; -DHAVE_INT64T selects the upstream int64_t branch instead of "
                 "its pre-C99 typedef"),
    },
    {
        "family": "hitch", "version": "1.8.0",
        "url": "https://hitch-tls.org/source/hitch-1.8.0.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "dfc99484bc7ffea27a3169e84d6c217988eda47b208ab2e5524dc2a5dd158f4e",
        "configure": ["--disable-documentation"], "make": [MAKE_JOBS],
        "artifact": "src/hitch", "launch": ["--version"],
        "aux_sources": list(_LIBEV_AUX),
        "note": ("hitch 1.8.0 from its published dist tarball (which ships the generated "
                 "configure) against the subject libssl; libev comes from the pinned bookworm "
                 "packages above"),
    },
)

# The Phase-25 L7 expansion batch (b4): the client/server utilities the campaign's
# expansion image can build once their non-OpenSSL dependencies are pinned. Each is
# a pristine released archive built against the subject prefix; `aux_sources` carries
# only dependencies the image does not ship, never an OpenSSL.
_PCRE2_AUX: tuple[dict, ...] = (
    _aux_deb("p/pcre2", "libpcre2-8-0_10.42-1_amd64.deb",
             "030db54f4d76cdfe2bf0e8eb5f9efea0233ab3c7aa942d672c7b63b52dbaf935"),
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,), bin_dirs=("usr/bin",)),
)

# u-boot's mkimage shells out to `dtc` to compile its FIT source; the image has no
# device-tree compiler, so the pinned bookworm package is extracted beside it (dtc
# itself needs the pinned libyaml runtime).
_DTC_AUX: tuple[dict, ...] = (
    _aux_deb("liby/libyaml", "libyaml-0-2_0.2.5-1_amd64.deb",
             "207b539919a47c85bcf738677f0ccf5bbac9844f2d3f158696f518be4c4ba6c4",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("d/device-tree-compiler", "device-tree-compiler_1.6.1-4+b1_amd64.deb",
             "f56fbb1e1da6545619dd2a17b7a85b2c4c674bd276d1b844e01a8b9901dd349d",
             bin_dirs=("usr/bin",)),
)

# opendkim needs strlcpy/strlcat (libbsd). Debian's libbsd.so is a linker script
# that names an absolute /usr path and `-lmd`; the extracted development symlink is
# therefore replaced with a plain symlink to the package's own ELF, and libmd's
# headers/runtime are pinned alongside it.
_LIBBSD_AUX: tuple[dict, ...] = (
    _aux_deb("libm/libmd", "libmd0_1.1.0-2+b1_amd64.deb",
             "7244ec3839b61fac0c1884fe08aaa040f26e8f1f35f1f5d3482eacefd30d1b44",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libm/libmd", "libmd-dev_1.1.0-2+b1_amd64.deb",
             "94904db4c531e3a7ec42a1ad0be8a2a9a2b6d2ac8c4e3b1c1d24853ea0be49c8",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libb/libbsd", "libbsd0_0.11.7-2_amd64.deb",
             "bb31cc8b40f962a85b2cec970f7f79cc704a1ae4bad24257a822055404b2c60b",
             library_dirs=(_AUX_MULTIARCH,)),
    {
        "url": ("http://deb.debian.org/debian/pool/main/libb/libbsd/"
                "libbsd-dev_0.11.7-2_amd64.deb"),
        "sha256": "788ec28ca78eab1ba14d2e1a50727efb7276c6b034163dca40931d8ab3d94aab",
        "archive": "deb", "extract": ["dpkg-deb", "-x"],
        "include_dirs": ["usr/include"],
        "library_dirs": [_AUX_MULTIARCH],
        "pkgconfig_dirs": [_AUX_MULTIARCH_PC],
        "links": {"usr/lib/x86_64-linux-gnu/libbsd.so": "libbsd.so.0.11.7"},
        "note": ("pinned bookworm libbsd-dev; its ld script is replaced with a symlink "
                 "to the package's own ELF so the extracted paths are self-contained"),
    },
)

# The u-boot host-tools configuration is generated, not patched: U-Boot's own
# `make tools-only` reads include/config/auto.conf and include/generated/autoconf.h,
# which its Kconfig build normally generates with bison/flex (absent here). The
# pre-build step writes exactly the host-tool switches this recipe asks make for.
_UBOOT_CONFIG = (
    "mkdir -p include/config include/generated && "
    ": > include/config/auto.conf.cmd && "
    "printf 'CONFIG_TOOLS_LIBCRYPTO=y\\nCONFIG_TOOLS_FIT_SIGNATURE=y\\n"
    "CONFIG_TOOLS_FIT_SIGNATURE_MAX_SIZE=0xffffffff\\nCONFIG_TOOLS_FIT_CIPHER=y\\n"
    "CONFIG_TOOLS_FIT_RSASSA_PSS=y\\nCONFIG_TOOLS_SHA256=y\\nCONFIG_TOOLS_SHA1=y\\n"
    "CONFIG_MKIMAGE_DTC_PATH=dtc\\n' > include/config/auto.conf && "
    "printf '#define CONFIG_TOOLS_LIBCRYPTO 1\\n#define CONFIG_TOOLS_FIT_SIGNATURE 1\\n"
    "#define CONFIG_TOOLS_FIT_SIGNATURE_MAX_SIZE 0xffffffff\\n"
    "#define CONFIG_TOOLS_FIT_CIPHER 1\\n#define CONFIG_TOOLS_FIT_RSASSA_PSS 1\\n"
    "#define CONFIG_TOOLS_SHA256 1\\n#define CONFIG_TOOLS_SHA1 1\\n' "
    "> include/generated/autoconf.h && touch include/config/auto.conf"
)

_L7_UTILITY_SPECS: tuple[dict, ...] = (
    {
        "family": "axel", "version": "2.17.14",
        "url": ("https://github.com/axel-download-accelerator/axel/releases/download/"
                "v2.17.14/axel-2.17.14.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "575f73f640ee836a95d27b54aeed216c45bc1e914cad92da6f00b907d1c94925",
        "configure": ["--with-ssl=openssl"], "make": [MAKE_JOBS],
        "artifact": "axel", "launch": ["--version"],
        "note": ("axel 2.17.14 with --with-ssl=openssl: the build environment's CPPFLAGS/"
                 "LDFLAGS/PKG_CONFIG_PATH point at the subject prefix, so its TLS downloader "
                 "links the subject libssl/libcrypto"),
    },
    {
        "family": "apache2-utils", "version": "2.4.63",
        "url": "http://archive.apache.org/dist/httpd/httpd-2.4.63.tar.bz2",
        "archive": "tar.bz2", "build_system": "configure",
        "sha256": "88fc236ab99b2864b248de7d49a008ec2afd7551e64dce8b95f58f32f94c46ab",
        "configure": ["--with-apr=/usr/bin/apr-1-config",
                      "--with-apr-util=/usr/bin/apu-1-config",
                      "--with-ssl={prefix}", "--enable-ssl",
                      "--disable-dav", "--disable-cgi", "--disable-negotiation",
                      "--disable-actions", "--disable-userdir", "--disable-autoindex",
                      "--disable-status", "--disable-asis", "--disable-imagemap",
                      "--disable-env", "--disable-mime-magic"],
        "make": [MAKE_JOBS, "-C", "support", "ab"],
        "artifact": "support/ab", "launch": ["-V"],
        "aux_sources": list(_PCRE2_AUX),
        "note": ("apache2-utils' `ab` from httpd 2.4.63: configure links it with --with-ssl"
                 " against the subject prefix (ab_LIBS = -lssl -lcrypto), and only support/ab "
                 "is built; PCRE2 comes from the pinned bookworm packages"),
    },
    {
        "family": "osslsigncode", "version": "2.9",
        "url": "https://github.com/mtrojnar/osslsigncode/archive/refs/tags/2.9.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "3fe5488e442ad99f91410efeb7b029275366b5df9aa02371dcc89a8f8569ff55",
        "configure": ["-DCMAKE_BUILD_TYPE=Release",
                      "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include"],
        "make": [], "artifact": "b/osslsigncode", "launch": ["--version"],
        "note": ("osslsigncode 2.9 (the tag archive; upstream publishes only binaries as "
                 "release assets) built with CMake against the subject prefix"),
    },
    {
        "family": "u-boot-tools", "version": "2025.01",
        "url": "https://ftp.denx.de/pub/u-boot/u-boot-2025.01.tar.bz2",
        "archive": "tar.bz2", "build_system": "make",
        "sha256": "cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f",
        "configure": None,
        "pre_build": [["sh", "-c", _UBOOT_CONFIG]],
        "make": [MAKE_JOBS, "tools-only", "NO_SDL=1",
                 "HOSTCFLAGS=-I{prefix}/include",
                 "HOSTLDFLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "artifact": "tools/mkimage", "launch": ["-V"],
        "aux_sources": list(_DTC_AUX),
        "note": ("u-boot 2025.01's host tools (mkimage, fit_check_sign) built by tools-only "
                 "with CONFIG_TOOLS_LIBCRYPTO and FIT signing enabled through the generated "
                 "host-tools config; dtc is the pinned bookworm package"),
    },
    {
        "family": "sslsplit", "version": "0.5.5",
        "url": "https://mirror.roe.ch/rel/sslsplit/sslsplit-0.5.5.tar.bz2",
        "archive": "tar.bz2", "build_system": "make",
        "sha256": "ba0473fd01428439e0cf22fae80fdd26d08a0bcf85e17c82177cb0810b700faf",
        "configure": None,
        "make": [MAKE_JOBS, "FEATURES=-DWITHOUT_MIRROR"],
        # sslsplit 0.5.5 calls ERR_GET_FUNC, removed in OpenSSL 3.0 (OpenSSL 3 keeps no
        # function code at all); the define reproduces the 3.x value, and sslsplit uses it
        # only in a diagnostic message. This is a build-environment compatibility switch,
        # not a source patch. WITHOUT_MIRROR drops the pcap mirror (a transparency feature),
        # leaving the TLS interception path this workload drives intact.
        "env_extra": {"CFLAGS": "-DERR_GET_FUNC\\(x\\)=0"},
        "artifact": "sslsplit", "launch": ["-V"],
        "aux_sources": list(_LIBEVENT_AUX),
        "note": ("SSLsplit 0.5.5 built against the subject prefix (OpenSSL 3.0 removed "
                 "ERR_GET_FUNC; the recipe supplies its meaning for 3.x as a compile-time "
                 "compatibility switch) with libevent from the pinned packages"),
    },
    {
        "family": "opendkim", "version": "2.10.3",
        "url": ("https://sourceforge.net/projects/opendkim/files/"
                "opendkim-2.10.3.tar.gz/download"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "43a0ba57bf942095fe159d0748d8933c6b1dd1117caf0273fa9a0003215e681b",
        "configure": ["--with-openssl={prefix}", "--disable-filter",
                      "--disable-live-testing", "--without-db"],
        "make": [MAKE_JOBS],
        # opendkim's configure probes SSL_library_init as a symbol; it is a macro in
        # OpenSSL 3, so the cached answer keeps the shared build path the project itself
        # documents for a shared libssl.
        "env_extra": {"ac_cv_search_SSL_library_init": "-lssl"},
        "artifact": "libopendkim/.libs/libopendkim.so*", "launch": None,
        "aux_sources": list(_LIBBSD_AUX),
        "note": ("opendkim 2.10.3's libopendkim built against the subject libcrypto; the "
                 "filter (and its milter dependency) is disabled, libbsd supplies "
                 "strlcpy/strlcat from the pinned packages"),
    },
)

# The Phase-25 L7 expansion batch (b5): six larger consumers whose OpenSSL paths are service
# detection, a TLS VPN handshake, a TLS control channel, a TLS voice-control listener, XMPP-over-TLS
# and an image digest. Each is a pristine released archive pinned by digest; the non-OpenSSL
# dependencies are pinned bookworm packages acquired through the same `aux_sources` seam, so the
# subject prefix remains the only OpenSSL on every link line.
_QT_MULTIARCH = "usr/lib/x86_64-linux-gnu"
_QT_MULTIARCH_PC = "usr/lib/x86_64-linux-gnu/pkgconfig"
_QT_LIB = "lib/x86_64-linux-gnu"


# nmap 7.95 links libcrypto (its service detection) but bundles liblua; libpcap and PCRE2 are the
# pinned bookworm packages the source archive does not carry.
_NMAP_AUX: tuple[dict, ...] = (
    _aux_deb("p/pcre2", "libpcre2-8-0_10.42-1_amd64.deb",
             "030db54f4d76cdfe2bf0e8eb5f9efea0233ab3c7aa942d672c7b63b52dbaf935",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
    _aux_deb("libp/libpcap", "libpcap0.8_1.10.3-1_amd64.deb",
             "856014904c4d7ec9a9ba864c546d91c059b9bf00c7c89eda6fd0a16045f8faac",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("libp/libpcap", "libpcap-dev_1.10.3-1_amd64.deb",
             "ecce257d786f1734d78cbf8bd41a56b3b86626163e6027904bec31137e78e18c",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
)

# fastd 22 is built by meson and links libcrypto for its ec25519/FHMQVC methods; libuecc, libsodium,
# json-c and bison are the pinned packages its meson build requires.
_FASTD_AUX: tuple[dict, ...] = (
    _aux_deb("libu/libuecc", "libuecc0_7-5_amd64.deb",
             "544fd60d98b79738db938f0f5a86ae5dff0e3a50e8d1441d2ef221b54ee2afa3",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("libu/libuecc", "libuecc-dev_7-5_amd64.deb",
             "0b9834577a8bc0e15b1b10a2fa768b4315ff3a4c94b6e98d80821c968d245835",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
    _aux_deb("libs/libsodium", "libsodium23_1.0.18-1+deb12u1_amd64.deb",
             "bceae6943d6e11fb53ec3f81d9630ec9ed03e51f89364902b05ebe402ae946ec",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("libs/libsodium", "libsodium-dev_1.0.18-1+deb12u1_amd64.deb",
             "96c76e95027592650b20987ceef189aa70c614dff3e6ec13c09b786149145700",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
    _aux_deb("j/json-c", "libjson-c5_0.16-2_amd64.deb",
             "d0e1ed8637d1c26b9720f6057d6355f18378bba5cc2553e459d1632783c00d70",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("j/json-c", "libjson-c-dev_0.16-2_amd64.deb",
             "b91a921675bde7c777930f9f77e49010a754d787219104464ea0fce04a887337",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
    _aux_deb("m/m4", "m4_1.4.19-3_amd64.deb",
             "b2dd7bfca426712416e651bb5ff6dabe7d05e4caebbac61d714dbe261b31e4c3",
             bin_dirs=("usr/bin",)),
    _aux_deb("b/bison", "bison_3.8.2+dfsg-1+b1_amd64.deb",
             "a414afd7519c53bfa33415ba5b951bc8b4906877004c49723ffda50a6033c3e8",
             bin_dirs=("usr/bin",)),
)

# kea 2.6.3 links libcrypto through libkea-cryptolink (its DDNS digests) and libssl through its
# HTTPS control channel; boost headers/system/thread and log4cplus are its non-OpenSSL build
# dependencies.
_KEA_AUX: tuple[dict, ...] = (
    _aux_deb("b/boost1.74", "libboost1.74-dev_1.74.0+ds1-21_amd64.deb",
             "ba14fe04d7f138f874bd3ab3a20c4fd1e9f654e271449b8f3e48d20f942dbb93",
             include_dirs=("usr/include",)),
    _aux_deb("b/boost1.74", "libboost-filesystem1.74.0_1.74.0+ds1-21_amd64.deb",
             "3e80caec26a4ee663dc2e4fdaf10b0f03308284f7e44248290b8dd18de4ca237",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("b/boost1.74", "libboost-filesystem1.74-dev_1.74.0+ds1-21_amd64.deb",
             "b2eef87fefd1533ee91cee61c56c022a2453c85e7f1819d0338ba433a74dade4",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("b/boost1.74", "libboost-system1.74.0_1.74.0+ds1-21_amd64.deb",
             "39afb5f0caec23a152e2e04409e4336a6e33abda453e8a8f661a4a5405fdc4bd",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("b/boost1.74", "libboost-system1.74-dev_1.74.0+ds1-21_amd64.deb",
             "d32a82618c48f9a8570c3f9b0213643be98f91cc4882dd6b0a06be78c75a1428",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("b/boost1.74", "libboost-thread1.74.0_1.74.0+ds1-21_amd64.deb",
             "6fc1f2997cdb0ea76d786a10591ea00559ef663055675f574e406ff2b3bd8912",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("b/boost1.74", "libboost-thread1.74-dev_1.74.0+ds1-21_amd64.deb",
             "7c09f213253419bb32eaa28ffe00be24181e182fb98379710bf3c05b3767fb51",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("l/log4cplus", "liblog4cplus-2.0.5_2.0.8-1_amd64.deb",
             "f33a6fa06ceac7bbc159820b565687a7cf1c56c9861ed66e63b9d7ef10b527d9",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("l/log4cplus", "liblog4cplus-dev_2.0.8-1_amd64.deb",
             "e79899b8d4007ac2f8be76c5cb7a167bcd9071bb97746340e4846fdfccd8df7a",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
)

# mumble-server 1.5.735 is Qt5/protobuf/boost plus libcap; all are pinned bookworm packages. Qt's
# Debian CMake configs expect the multiarch qmake/mkspecs paths, so those two links restore the
# layout the pinned config files name. libdbus-1-3 ships its ELF under /lib, and the dev symlink is
# rewritten to that package's own soname (the distribution symlink names an absolute /lib path).
_MUMBLE_AUX: tuple[dict, ...] = (
    _aux_deb("b/boost1.74", "libboost1.74-dev_1.74.0+ds1-21_amd64.deb",
             "ba14fe04d7f138f874bd3ab3a20c4fd1e9f654e271449b8f3e48d20f942dbb93",
             include_dirs=("usr/include",)),
    _aux_deb("b/boost1.74", "libboost-filesystem1.74.0_1.74.0+ds1-21_amd64.deb",
             "3e80caec26a4ee663dc2e4fdaf10b0f03308284f7e44248290b8dd18de4ca237",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("b/boost1.74", "libboost-filesystem1.74-dev_1.74.0+ds1-21_amd64.deb",
             "b2eef87fefd1533ee91cee61c56c022a2453c85e7f1819d0338ba433a74dade4",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("q/qtbase-opensource-src",
             "qtbase5-dev_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "2b50de948dd43dce43dcd58033ef3bfc4a549b33fc9f9a3818e35a26f979802b",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH, _QT_LIB),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,), bin_dirs=("usr/lib/qt5/bin", "usr/bin")),
    _aux_deb("q/qtbase-opensource-src",
             "qtbase5-dev-tools_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "0d21759a287142eda6c1ec76d0a0be34e64c7f8a67c1dc190f9b0b95f8b58d8a",
             bin_dirs=("usr/lib/qt5/bin",)),
    _aux_deb("q/qtbase-opensource-src", "qt5-qmake_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "6307baf17e4c1027592c5e5ade4de8cafee2fb1698078c1ac3bfba8f1b07e252",
             bin_dirs=("usr/lib/qt5/bin",)),
    _aux_deb("q/qtbase-opensource-src",
             "qt5-qmake-bin_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "f52d1f0ecd08065b922dd4af71696616b62ef3c1fa8bbe01f085c123da74aadb",
             bin_dirs=("usr/lib/qt5/bin",)),
    _aux_deb("q/qtbase-opensource-src",
             "libqt5core5a_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "47e82f69aa0724f33d0873294d66664ef13fe09c0bffb0a1d84f2ad3e2dab58e",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("q/qtbase-opensource-src",
             "libqt5network5_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "6a27a617c0aca0bd9f49237594a7939910e78aaa223611ffd8e25fdc56a319a8",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("q/qtbase-opensource-src",
             "libqt5sql5_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "ba3011af5b6bf58786af82e37cad9a513098f40aa96eb7c0bac5fa490935c7aa",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("q/qtbase-opensource-src",
             "libqt5xml5_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "b6860f228ba3f5144cfe7d252a92a7d0c3d52e8f265475e8873858f77c3cf014",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("q/qtbase-opensource-src",
             "libqt5dbus5_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "1e3499746c85ed916c3374e273a2bc71274d42406360f865cbf92cfd714314f6",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("q/qtbase-opensource-src",
             "libqt5sql5-sqlite_5.15.8+dfsg-11+deb12u3_amd64.deb",
             "965f13a4fb32e3b03475f36905418ae38c5bebcfe1bf23b5fb89d585fbec5a7e",
             library_dirs=(_QT_MULTIARCH,)),
    {
        "url": "https://deb.debian.org/debian/pool/main/q/qtbase-opensource-src/"
               "qtbase5-dev_5.15.8+dfsg-11+deb12u3_amd64.deb",
        "sha256": "2b50de948dd43dce43dcd58033ef3bfc4a549b33fc9f9a3818e35a26f979802b",
        "archive": "deb", "extract": ["dpkg-deb", "-x"],
        "links": {
            f"{_QT_MULTIARCH}/qt5/bin/qmake": "../../../qt5/bin/qmake",
        },
        "note": ("the pinned qtbase5-dev payload again, only to restore the multiarch qmake path "
                 "Debian's Qt5 CMake configs name (qt5-qmake already installs mkspecs under the "
                 "multiarch tree)"),
    },
    _aux_deb("p/protobuf", "libprotobuf32_3.21.12-3+deb12u1_amd64.deb",
             "e9e4e8cf0d2c48e2e3c17308e2093b3856f470b77e0022b7d906fb1b3551f213",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("p/protobuf", "libprotobuf-lite32_3.21.12-3+deb12u1_amd64.deb",
             "441812aa574e1baa4435a9b62c34a39e0fc4177994ccfb35fab5a03ef6ef1e8d",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("p/protobuf", "libprotoc32_3.21.12-3+deb12u1_amd64.deb",
             "27770048715fdebe3dab2f6603ca6667ac72ab474989226d2f70153522286adf",
             library_dirs=(_QT_MULTIARCH,), bin_dirs=("usr/bin",)),
    _aux_deb("p/protobuf", "libprotobuf-dev_3.21.12-3+deb12u1_amd64.deb",
             "2f045f82e4ae0bdfce7f18f1f36613b9cd8c570024b8de68668bc255c32a2d88",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("p/protobuf", "protobuf-compiler_3.21.12-3+deb12u1_amd64.deb",
             "698e96f08152490ee576ead6a9116e1239514de66473305473f67ce2b5408e23",
             bin_dirs=("usr/bin",)),
    _aux_deb("d/double-conversion", "libdouble-conversion3_3.2.1-1_amd64.deb",
             "802b880ed900e4a8d54bab77b7551a7f3408b04891c3e5650fdc2368cc1fbc0a",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("i/icu", "libicu72_72.1-3+deb12u1_amd64.deb",
             "f7f6f99c6d7b025914df2447fc93e11d22c44c0c8bdd8b6f36691c9e7ddcef88",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-8-0_10.42-1_amd64.deb",
             "030db54f4d76cdfe2bf0e8eb5f9efea0233ab3c7aa942d672c7b63b52dbaf935",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-16-0_10.42-1_amd64.deb",
             "53892097cf102ecd8f133ccd3f1f6be6f288c6ffeeeacf6ce081dfee15292675",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("libz/libzstd", "libzstd1_1.5.4+dfsg2-5_amd64.deb",
             "6315b5ac38b724a710fb96bf1042019398cb656718b1522279a5185ed39318fa",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("libb/libb2", "libb2-1_0.98.1-1.1_amd64.deb",
             "322be801ee9051f34cc4f09512222bac1f0918e32da3a2bd12eddc51cd2df653",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("g/glib2.0", "libglib2.0-0_2.74.6-2+deb12u9_amd64.deb",
             "7ff85197685d89e150e342b29a59aab1beee400050ba7da73de81cd999ffee5a",
             library_dirs=(_QT_MULTIARCH, _QT_LIB)),
    _aux_deb("libf/libffi", "libffi8_3.4.4-1_amd64.deb",
             "6d9f6c25c30efccce6d4bceaa48ea86c329a3432abb360a141f76ac223a4c34a",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("u/util-linux", "libmount1_2.38.1-5+deb12u3_amd64.deb",
             "f46e2d6b006951825adde9757790b6609d7c66c7700f9b68f3db913eaac323c3",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("u/util-linux", "libblkid1_2.38.1-5+deb12u3_amd64.deb",
             "5a083377f29191cafcdf0f91ec124349b4a7895b531556633a136e43c6d53943",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("libs/libselinux", "libselinux1_3.4-1+b6_amd64.deb",
             "2b07f5287b9105f40158b56e4d70cc1652dac56a408f3507b4ab3d061eed425f",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("d/dbus", "libdbus-1-3_1.14.10-1~deb12u1_amd64.deb",
             "18ee0ce5fab9f7b671e87da1e9fa18660e36e04a3402f24bdb8635e0ba1d35f6",
             library_dirs=(_QT_MULTIARCH, _QT_LIB)),
    {
        "url": "https://deb.debian.org/debian/pool/main/d/dbus/"
               "libdbus-1-dev_1.14.10-1~deb12u1_amd64.deb",
        "sha256": "967a42e91eaa7d1885721b374a28cb0d30a0e63daaccf5e3594180bec6072c76",
        "archive": "deb", "extract": ["dpkg-deb", "-x"],
        "include_dirs": ["usr/include"],
        "library_dirs": [_QT_MULTIARCH],
        "pkgconfig_dirs": [_QT_MULTIARCH_PC],
        "links": {f"{_QT_MULTIARCH}/libdbus-1.so": "libdbus-1.so.3.32.4"},
        "note": ("pinned bookworm libdbus-1-dev; its `libdbus-1.so` is rewritten to the package's "
                 "own soname (the distribution symlink names an absolute /lib path)"),
    },
    _aux_deb("libc/libcap2", "libcap2_2.66-4+deb12u3+b1_amd64.deb",
             "8d684c673e7483802a5c447834b0df6fce006eb3a7109e1be412f5ad425bb24f",
             library_dirs=(_QT_MULTIARCH, _QT_LIB)),
    _aux_deb("libc/libcap2", "libcap-dev_2.66-4+deb12u3+b1_amd64.deb",
             "897ee64c93b04c4c8eb46551df2277673c1ab95584c765d8d07e3528a6a1c689",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,)),
)

# partclone's torrent_info path is its libcrypto consumer (SHA1); uuid is its one hard build
# dependency. The GitHub tag archive carries no generated `configure`, so the recipe runs
# `autoreconf` with the pinned bookworm autotools (a build step, never a source edit).
_PARTCLONE_AUX: tuple[dict, ...] = (
    _aux_deb("u/util-linux", "uuid-dev_2.38.1-5+deb12u3_amd64.deb",
             "d66c5719adc05b6f5cbac926e093846c865f0b1a2095e6d781df8a7ce1f34cbf",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH, _QT_LIB),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
    _aux_deb("e/e2fsprogs", "libext2fs2_1.47.0-2+b2_amd64.deb",
             "dff731f2318df99da4b8bf5f330f415f95b94c609bac29e7b2edba0a38f22a98",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("e/e2fsprogs", "libext2fs-dev_1.47.0-2+b2_amd64.deb",
             "7b4588f466f93ceb7bcd4df8b1875a84fe46d02af7fb102a3019791ee2ab08c9",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
    _aux_deb("e/e2fsprogs", "libcom-err2_1.47.0-2+b2_amd64.deb",
             "a2bac7015e78fbc0c504df3e441f3a22292f1d2d77f9ccda760057f3690e22f2",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("e/e2fsprogs", "comerr-dev_2.1-1.47.0-2+b2_amd64.deb",
             "e72521fd1b8af99ad99e83af7d87926a4c4d7e8238e61846761f7818220a48a2",
             include_dirs=("usr/include",)),
    _aux_deb("e/e2fsprogs", "libss2_1.47.0-2+b2_amd64.deb",
             "24115749c09b4e259acff1f799faccd1748ff322bd638b09d820729cb3b24579",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("m/m4", "m4_1.4.19-3_amd64.deb",
             "b2dd7bfca426712416e651bb5ff6dabe7d05e4caebbac61d714dbe261b31e4c3",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autoconf", "autoconf_2.71-3_all.deb",
             "7d798ed8c21fc7387127de1dfdb4640003d8ba033ae5a1ff29559610cbd0c323",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/automake-1.16", "automake_1.16.5-1.3_all.deb",
             "f9a5758d87b5389bf2dbb00cc9c48e0cf59bb0ac842c5ce25d41e4bfa3f2f962",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autotools-dev", "autotools-dev_20220109.1_all.deb",
             "4d66dcb9c312566f1ca8d46ef0fb06fa4d4786c20b072c81f9d313b64ef981d0",
             bin_dirs=("usr/bin",)),
    _aux_deb("libt/libtool", "libtool_2.4.7-7~deb12u1_all.deb",
             "1c2e74f06b1d5d9a2c75e04ce87a99a8633058684439504ae8d715a4a088926c",
             bin_dirs=("usr/bin",)),
    _aux_deb("g/gettext", "gettext_0.21-12_amd64.deb",
             "8c1f9d43575373ce311f51d00a13afbb4888d63aa559a93a3472f5d77513b60c",
             bin_dirs=("usr/bin",)),
    _aux_deb("g/gettext", "autopoint_0.21-12_all.deb",
             "9864777e777f1f641858e27396bf7dd53c9b38197b7ac47388995ec60bb9789f",
             bin_dirs=("usr/bin",
             )),
)

# prosody 0.12.4 is Lua; its OpenSSL consumer is LuaSec, built here from source against the subject
# prefix together with its bundled LuaSocket support, and the admitted program is a small harness
# that embeds the Lua 5.4 interpreter and runs prosody's own `prosody`/`prosodyctl` entry scripts.
_PROSODY_AUX: tuple[dict, ...] = (
    _aux_deb("l/lua5.4", "liblua5.4-0_5.4.4-3+deb12u1_amd64.deb",
             "b042e78d02dd8457cf7de253ae89992e50050f450d9bec66843ffb1a14ab23c7",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("l/lua5.4", "liblua5.4-dev_5.4.4-3+deb12u1_amd64.deb",
             "f02e06d3598de40a1df51ea4144668a1c6acb8813d4647a6d89cca0d256179d3",
             include_dirs=("usr/include", "usr/include/x86_64-linux-gnu"),
             library_dirs=(_QT_MULTIARCH,),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
    _aux_deb("l/lua5.4", "lua5.4_5.4.4-3+deb12u1_amd64.deb",
             "8a7221aa9614911f1236cbb1ba85401bb06f9ac66b51e5f98f31fbdeeca99fa7",
             bin_dirs=("usr/bin",)),
    _aux_deb("l/lua-expat", "lua-expat_1.5.1-3_amd64.deb",
             "236310b4aab2d063f3b355fd9e18f2d956137f16560c0e546c484212907eaa82",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("l/luasocket", "lua-socket_3.1.0-1+b1_amd64.deb",
             "63217faf1d497a61e23f8b7a128a494a8db593f4965ead1411429d1a1e46d9dd",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("l/lua-filesystem", "lua-filesystem_1.8.0-3_amd64.deb",
             "679309dc0d8fe34bd4fc7a15b742d7ebb3a26ac3ca2d3527026cda3bc7480fc3",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("i/icu", "libicu72_72.1-3+deb12u1_amd64.deb",
             "f7f6f99c6d7b025914df2447fc93e11d22c44c0c8bdd8b6f36691c9e7ddcef88",
             library_dirs=(_QT_MULTIARCH,)),
    _aux_deb("i/icu", "libicu-dev_72.1-3+deb12u1_amd64.deb",
             "08bd4e3f4bd4fc725cf25e739edf0e7df5ac1826bdac9a7d990eea8f93b2d7a0",
             include_dirs=("usr/include",), library_dirs=(_QT_MULTIARCH,),
             pkgconfig_dirs=(_QT_MULTIARCH_PC,)),
    {
        "url": ("https://github.com/lunarmodules/luasec/archive/refs/tags/v1.3.1.tar.gz"),
        "sha256": "6fb919633a3304a262189f62a369adc4b36bc7113da37af093b069cf1c8d785e",
        "archive": "tar.gz", "extract": ["sh", "-c", "tar xf \"$1\" -C \"$2\"", "sh"],
        "note": ("LuaSec 1.3.1 (the family's OpenSSL consumer); built by the recipe's pre-build "
                 "step against the subject prefix, with its bundled LuaSocket support"),
    },
)

_L7_EXPAND2_SPECS: tuple[dict, ...] = (
    {
        "family": "nmap", "version": "7.95",
        "url": "https://nmap.org/dist/nmap-7.95.tar.bz2",
        "archive": "tar.bz2", "build_system": "configure",
        "sha256": "e14ab530e47b5afd88f1c8a2bac7f89cd8fe6b478e22d255c5b9bddb7a1c5778",
        "configure": ["--with-openssl={prefix}", "--with-liblua=included",
                      "--without-libssh2", "--without-zenmap", "--without-ndiff",
                      "--without-nping", "--without-ncat"],
        "make": [MAKE_JOBS], "artifact": "nmap", "launch": ["--version"],
        "aux_sources": list(_NMAP_AUX),
        "note": ("nmap 7.95 with its service detection and NSE ssl-cert path linked against the "
                 "subject OpenSSL; liblua is nmap's bundled copy, and libpcap/PCRE2 are the pinned "
                 "bookworm packages"),
    },
    {
        "family": "fastd", "version": "22",
        "url": "https://github.com/neocturne/fastd/releases/download/v22/fastd-22.tar.xz",
        "archive": "tar.xz", "build_system": "meson",
        "sha256": "19750b88705d66811b7c21b672537909c19ae6b21350688cbd1a3a54d08a8951",
        "configure": ["--buildtype=release", "--prefix=/usr", "-Dcapabilities=disabled",
                      "-Doffload_l2tp=disabled", "-Dsystemd=disabled"],
        "make": [], "artifact": "b/src/fastd", "launch": ["--version"],
        "aux_sources": list(_FASTD_AUX),
        "env_extra": {"BISON_PKGDATADIR": "{aux}/usr/share/bison",
                      "M4": "{aux}/usr/bin/m4"},
        "note": ("fastd 22 built by meson against the subject libcrypto (its ec25519/FHMQVC "
                 "methods); libuecc, libsodium, json-c and bison are the pinned packages"),
    },
    {
        "family": "kea", "version": "2.6.3",
        "url": "https://downloads.isc.org/isc/kea/2.6.3/kea-2.6.3.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "00241a5955ffd3d215a2c098c4527f9d7f4b203188b276f9a36250dd3d9dd612",
        "configure": ["--with-openssl={prefix}", "--with-log4cplus", "--disable-mysql",
                      "--disable-pgsql", "--localstatedir={root}/.l7-state",
                      "--sysconfdir={root}/.l7-state/etc"],
        "make": [MAKE_JOBS], "artifact": "src/bin/agent/.libs/kea-ctrl-agent",
        "launch": ["-v"],
        "aux_sources": list(_KEA_AUX),
        "note": ("Kea 2.6.3's ctrl-agent with its HTTPS control channel linked against the subject "
                 "libssl; boost and log4cplus are the pinned packages, and the runtime state "
                 "directory is generated under the build tree"),
    },
    {
        "family": "mumble-server", "version": "1.5.735",
        "url": ("https://github.com/mumble-voip/mumble/releases/download/v1.5.735/"
                "mumble-1.5.735.tar.gz"),
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "db8990079f556a877218d471bcf2c24eb5e4520b652f3c20793d0aadedaae6ae",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DBUILD_NUMBER=735",
                      "-Dclient=OFF", "-Dserver=ON", "-Dice=OFF", "-Dzeroconf=OFF",
                      "-Dtests=OFF", "-Dplugins=OFF", "-Doverlay=OFF",
                      "-Dwarnings-as-errors=OFF",
                      "-DCMAKE_PREFIX_PATH={aux}/usr",
                      "-DCMAKE_LIBRARY_PATH={aux}/usr/lib/x86_64-linux-gnu:{aux}/lib/x86_64-linux-gnu",
                      "-DProtobuf_PROTOC_EXECUTABLE={aux}/usr/bin/protoc",
                      "-DProtobuf_INCLUDE_DIR={aux}/usr/include",
                      "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include -I{aux}/usr/include",
                      "-DCMAKE_CXX_FLAGS=-I{prefix}/include -I{aux}/usr/include",
                      "-DCMAKE_CXX_STANDARD_LIBRARIES=-ldbus-1 -lpcre2-16"],
        "make": [], "artifact": "b/mumble-server", "launch": ["--version"],
        "aux_sources": list(_MUMBLE_AUX),
        "note": ("mumble-server 1.5.735's TLS listener linked against the subject libssl; Qt5, "
                 "protobuf, boost and libcap are the pinned bookworm packages"),
    },
    {
        "family": "prosody", "version": "0.12.4",
        "url": "https://prosody.im/downloads/source/prosody-0.12.4.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "47d712273c2f29558c412f6cdaec073260bbc26b7dda243db580330183d65856",
        "configure": ["--lua-version=5.4",
                      "--with-lua-include={aux}/usr/include/lua5.4",
                      "--with-lua-lib={aux}/usr/lib/x86_64-linux-gnu",
                      "--prefix={root}/.l7-install"],
        "make": [MAKE_JOBS],
        "artifact": ".l7-prosody-harness", "launch": ["--version"],
        "aux_sources": list(_PROSODY_AUX),
        "env_extra": {
            "LIBRARY_PATH": ("{prefix}/lib:{aux}/usr/lib/x86_64-linux-gnu:"
                             "{aux}/lib/x86_64-linux-gnu"),
        },
        "pre_build": [["sh", "-c", (
            "set -e; "
            "cd {aux}/luasec-1.3.1 && make linux EXTRA=luasocket DEFS=-DWITH_LUASOCKET "
            "INC_PATH='-I{prefix}/include -I{aux}/usr/include/lua5.4 "
            "-I{aux}/usr/include/x86_64-linux-gnu' "
            "LIB_PATH='-L{prefix}/lib -Wl,-rpath,{prefix}/lib' && "
            "make install DESTDIR={root}/.l7-lua LUAPATH=/share/lua/5.4 LUACPATH=/lib/lua/5.4 && "
            "mkdir -p {root}/.l7-lua/lib/lua/5.4/ssl && "
            "cp {root}/.l7-lua/lib/lua/5.4/ssl.so {root}/.l7-lua/lib/lua/5.4/ssl/core.so && "
            "cc -O2 -o {root}/.l7-prosody-harness {repo}/forensics/tools/l7_prosody.c "
            "-I{prefix}/include -I{aux}/usr/include/lua5.4 "
            "-I{aux}/usr/include/x86_64-linux-gnu "
            "-L{aux}/usr/lib/x86_64-linux-gnu -L{prefix}/lib "
            "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu -Wl,-rpath,{prefix}/lib "
            "-llua5.4 -lssl -lcrypto"
        )]],
        "note": ("Prosody 0.12.4 with LuaSec 1.3.1 built against the subject libssl; the admitted "
                 "program is the recipe's Lua-embedding harness, and the XMPP listener is "
                 "prosody's own entry script run by it"),
    },
    {
        "family": "partclone", "version": "0.3.27",
        "url": ("https://github.com/Thomas-Tsai/partclone/archive/refs/tags/0.3.27.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "933e81dceb9c05bd2cb6027ef115a4422eb35b2bc05ed9a5fd42f637dfba5c17",
        "configure": ["--enable-extfs", "--disable-ntfs", "--disable-xfs",
                      "--disable-reiserfs", "--disable-reiser4", "--disable-hfsp",
                      "--disable-apfs", "--disable-fat", "--disable-exfat",
                      "--disable-f2fs", "--disable-nilfs2", "--disable-ufs",
                      "--disable-vmfs", "--disable-jfs", "--disable-btrfs",
                      "--disable-minix", "--disable-ncursesw", "--disable-fuse"],
        "make": [MAKE_JOBS], "artifact": "src/partclone.extfs", "launch": ["--version"],
        "aux_sources": list(_PARTCLONE_AUX),
        "pre_build": [["sh", "-c", (
            "set -e; "
            "W={root}/.autotools; mkdir -p $W; "
            "printf '#!/bin/sh\\nexec {aux}/usr/bin/aclocal-1.16 "
            "--system-acdir={aux}/usr/share/aclocal-1.16 "
            "--automake-acdir={aux}/usr/share/aclocal-1.16 \"$@\"\\n' > $W/aclocal; "
            "printf '#!/bin/sh\\nexec {aux}/usr/bin/automake-1.16 "
            "--libdir={aux}/usr/share/automake-1.16 \"$@\"\\n' > $W/automake; "
            "printf '#!/bin/sh\\nexec {aux}/usr/bin/libtoolize \"$@\"\\n' > $W/libtoolize; "
            "chmod +x $W/aclocal $W/automake $W/libtoolize; "
            "sed -i 's#/usr/share/autoconf#{aux}/usr/share/autoconf#g' "
            "{aux}/usr/share/autoconf/autom4te.cfg; "
            "autoreconf -fi"
        )]],
        "env_extra": {
            "PATH": "{root}/.autotools:{aux}/usr/bin:" + os.environ.get("PATH", ""),
            "PERL5LIB": "{aux}/usr/share/autoconf:{aux}/usr/share/automake-1.16",
            "ACLOCAL_PATH": "/usr/share/aclocal:{aux}/usr/share/aclocal:{aux}/usr/share/libtool/m4",
            "ACLOCAL": "{root}/.autotools/aclocal",
            "AUTOMAKE": "{root}/.autotools/automake",
            "LIBTOOLIZE": "{root}/.autotools/libtoolize",
            "AUTOPOINT": "true",
            "AUTOCONF": "{aux}/usr/bin/autoconf",
            "AUTOHEADER": "{aux}/usr/bin/autoheader",
            "AUTOM4TE": "{aux}/usr/bin/autom4te",
            "AUTOM4TE_CFG": "{aux}/usr/share/autoconf/autom4te.cfg",
            "AC_MACRODIR": "{aux}/usr/share/autoconf",
            "trailer_m4": "{aux}/usr/share/autoconf/autoconf/trailer.m4",
            "autom4te_perllibdir": "{aux}/usr/share/autoconf",
            "M4": "{aux}/usr/bin/m4",
        },
        "note": ("partclone 0.3.27's partclone.extfs with its torrent_info SHA-1 path linked "
                 "against the subject libcrypto; libext2fs, uuid-dev and the autotools are the "
                 "pinned packages (the tag archive carries no generated configure)"),
    },
)


# The Phase-25 L7 expansion batch (b6): two TLS servers (exim, nsd) and three OpenSSL consumers
# whose build needs a non-subject dependency the venue does not ship as a development package
# (net-snmp, eggdrop, irssi); openssh-server reuses the openssh release and exercises the server
# direction. Every package is a pinned bookworm build; the subject prefix remains the only OpenSSL.
#
# exim 4.100.1 requires PCRE2 and, on Linux, the Berkeley DB hints database (OS/Makefile-Linux
# sets USE_DB=yes), so both headers are acquired; the recipe keeps the release tarball's own
# OS/Makefile-Linux defaults and only writes Local/Makefile (a generated build input).
_L7_EXIM_AUX: tuple[dict, ...] = (
    _aux_deb("p/pcre2", "libpcre2-8-0_10.42-1_amd64.deb",
             "030db54f4d76cdfe2bf0e8eb5f9efea0233ab3c7aa942d672c7b63b52dbaf935",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("d/db5.3", "libdb5.3_5.3.28+dfsg2-1_amd64.deb",
             "7dc5127b8dd0da80e992ba594954c005ae4359d839a24eb65d0d8129b5235c84",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("d/db5.3", "libdb5.3-dev_5.3.28+dfsg2-1_amd64.deb",
             "f792f095deecb4f990f695e0d33f75f70b92491eab649adf91ea8574885d157c",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("m/m4", "m4_1.4.19-3_amd64.deb",
             "b2dd7bfca426712416e651bb5ff6dabe7d05e4caebbac61d714dbe261b31e4c3",
             bin_dirs=("usr/bin",)),
)

# eggdrop 1.9.5 embeds Tcl; the image carries neither tcl.h nor libtcl8.6. `TCLSH=...` is avoided:
# the release's `make config` finds `tclsh8.6` on PATH, which the recipe exposes from the pinned
# tcl8.6 package.
_L7_EGGDROP_AUX: tuple[dict, ...] = (
    _aux_deb("t/tcl8.6", "libtcl8.6_8.6.13+dfsg-2_amd64.deb",
             "976c4235b816635e1756016f3adbabb634e8b97a9f6b97cf901be099e4fd2487",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("t/tcl8.6", "tcl8.6-dev_8.6.13+dfsg-2_amd64.deb",
             "e37b3f8888003ca9a34b85452885662bb9885b17f70cf7dfe4ec821a48328509",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

# irssi 1.4.5 needs GLib (headers, .pc, shared objects), pcre2 and ncurses headers. The image ships
# no GLib at all, so both the pinned runtime package (which carries `libglib-2.0.so.0` and
# `libgmodule-2.0.so.0`) and the dev package are extracted into the family's aux root; the dev
# package's own `libglib-2.0.so`/`libgmodule-2.0.so` symlinks then resolve there. Repointing the
# linker name at a venue path instead left it dangling, so ld silently fell back to the static
# `libglib-2.0.a`, whose private pcre2 dependency is not on irssi's link line and the link failed.
# libpcre2-dev supplies the `libpcre2-8` pkg-config module glib-2.0.pc requires.
_L7_IRSSI_AUX: tuple[dict, ...] = (
    _aux_deb("g/glib2.0", "libglib2.0-0_2.74.6-2+deb12u9_amd64.deb",
             "7ff85197685d89e150e342b29a59aab1beee400050ba7da73de81cd999ffee5a",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("g/glib2.0", "libglib2.0-dev_2.74.6-2+deb12u9_amd64.deb",
             "217766f170553e14884f7d67c0636b833da43c1e4a65dfe41268ba1292001ccd",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("p/pcre2", "libpcre2-8-0_10.42-1_amd64.deb",
             "030db54f4d76cdfe2bf0e8eb5f9efea0233ab3c7aa942d672c7b63b52dbaf935",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("n/ncurses", "libncurses-dev_6.4-4_amd64.deb",
             "2ad228835756feb118bb131b32834bd23a09047e4de408cc5204cbb5dce0e4bb",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

# exim 4.100.1's own release `make` (no configure script): Local/Makefile is a generated build
# input, written from the pristine src/EDITME with the subject prefix and the pinned PCRE2/DB.
_L7_EXIM_LOCAL_MAKEFILE = (
    "set -e; mkdir -p Local; cp src/EDITME Local/Makefile; "
    "sed -i "
    "-e 's|^BIN_DIRECTORY=.*|BIN_DIRECTORY={root}/.l7-install/bin|' "
    "-e 's|^CONFIGURE_FILE=.*|CONFIGURE_FILE={root}/.l7-install/etc/exim.conf|' "
    "-e 's|^SPOOL_DIRECTORY=.*|SPOOL_DIRECTORY={root}/.l7-state/spool|' "
    "-e 's|^# USE_OPENSSL=yes|USE_OPENSSL=yes|' "
    "-e 's|^PCRE2_CONFIG=yes|PCRE2_CONFIG=|' "
    "-e 's|^# PCRE_LIBS=.*|PCRE_LIBS=-L{aux}/usr/lib/x86_64-linux-gnu -lpcre2-8|' "
    "-e 's|^EXIM_USER=$|EXIM_USER=nobody|' "
    "Local/Makefile; "
    "printf '%s\\n' "
    "'INCLUDE=-I{prefix}/include -I{aux}/usr/include' "
    "'TLS_LIBS=-L{prefix}/lib -lssl -lcrypto' "
    "'EXIM_GROUP=nogroup' "
    "'LOG_FILE_PATH={root}/.l7-state/log/%slog' "
    "'LFLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
    "-L{aux}/usr/lib/x86_64-linux-gnu -Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu' "
    ">> Local/Makefile"
)

# The Phase-25 L7 expansion batch (b7): tcpdump, slrn, epic5, bannergrab, httperf and makepasswd.
# The four small utilities are direct libcrypto/libssl consumers; tcpdump's capture needs libpcap
# (with the dbus runtime its Debian build depends on), slrn/epic5 need a terminal library, and
# httperf's upstream repository is autotools-only at the pinned commit.  Every non-OpenSSL
# dependency is a pinned bookworm package acquired through the same `aux_sources` seam.
_L7_TCPDUMP_AUX: tuple[dict, ...] = (
    _aux_deb("libp/libpcap", "libpcap0.8_1.10.3-1_amd64.deb",
             "856014904c4d7ec9a9ba864c546d91c059b9bf00c7c89eda6fd0a16045f8faac",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libp/libpcap", "libpcap0.8-dev_1.10.3-1_amd64.deb",
             "5f66e87262e42cc42a77d6acdb41098e4ff3e6db3bdba1b73189dea5a3afb88c",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             bin_dirs=("usr/bin",)),
    _aux_deb("d/dbus", "libdbus-1-3_1.14.10-1~deb12u1_amd64.deb",
             "18ee0ce5fab9f7b671e87da1e9fa18660e36e04a3402f24bdb8635e0ba1d35f6",
             library_dirs=("lib/x86_64-linux-gnu",)),
)

_L7_SLRN_AUX: tuple[dict, ...] = (
    _aux_deb("s/slang2", "libslang2_2.3.3-3_amd64.deb",
             "5b3cecc829ef229125b340ccd2ca45ced75d24e9aa191912105016b1af94413f",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("s/slang2", "libslang2-dev_2.3.3-3_amd64.deb",
             "2ad29ca0fe5adacff4d7174c5d20a104fc8e0470723e6f7dda2c5cf049bd6631",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("n/ncurses", "libncurses-dev_6.4-4_amd64.deb",
             "2ad228835756feb118bb131b32834bd23a09047e4de408cc5204cbb5dce0e4bb",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

_L7_EPIC5_AUX: tuple[dict, ...] = (
    _aux_deb("n/ncurses", "libncurses-dev_6.4-4_amd64.deb",
             "2ad228835756feb118bb131b32834bd23a09047e4de408cc5204cbb5dce0e4bb",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

# httperf's pinned upstream commit has no generated `configure`; the recipe bootstraps it with the
# same pinned bookworm autotools the partclone recipe uses, rewriting each tool's compiled-in
# `/usr/share` prefix under the extracted auxiliary root exactly once.
_L7_HTTPERF_AUX: tuple[dict, ...] = (
    _aux_deb("m/m4", "m4_1.4.19-3_amd64.deb",
             "b2dd7bfca426712416e651bb5ff6dabe7d05e4caebbac61d714dbe261b31e4c3",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autoconf", "autoconf_2.71-3_all.deb",
             "7d798ed8c21fc7387127de1dfdb4640003d8ba033ae5a1ff29559610cbd0c323",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/automake-1.16", "automake_1.16.5-1.3_all.deb",
             "f9a5758d87b5389bf2dbb00cc9c48e0cf59bb0ac842c5ce25d41e4bfa3f2f962",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autotools-dev", "autotools-dev_20220109.1_all.deb",
             "4d66dcb9c312566f1ca8d46ef0fb06fa4d4786c20b072c81f9d313b64ef981d0",
             bin_dirs=("usr/bin",)),
    _aux_deb("libt/libtool", "libtool_2.4.7-7~deb12u1_all.deb",
             "1c2e74f06b1d5d9a2c75e04ce87a99a8633058684439504ae8d715a4a088926c",
             bin_dirs=("usr/bin",)),
    _aux_deb("g/gettext", "gettext_0.21-12_amd64.deb",
             "8c1f9d43575373ce311f51d00a13afbb4888d63aa559a93a3472f5d77513b60c",
             bin_dirs=("usr/bin",)),
    _aux_deb("g/gettext", "autopoint_0.21-12_all.deb",
             "9864777e777f1f641858e27396bf7dd53c9b38197b7ac47388995ec60bb9789f",
             bin_dirs=("usr/bin",)),
)

_L7_HTTPERF_BOOTSTRAP = (
    "set -e; W={root}/.autotools; mkdir -p $W; "
    "sed -i 's#/usr/share#{aux}/usr/share#g' {aux}/usr/bin/libtoolize; "
    "sed -i 's#/usr/share/autoconf#{aux}/usr/share/autoconf#g' "
    "{aux}/usr/share/autoconf/autom4te.cfg; "
    "sed -i 's#/usr/share/automake-1.16#{aux}/usr/share/automake-1.16#g' "
    "{aux}/usr/bin/aclocal-1.16 {aux}/usr/bin/automake-1.16; "
    "sed -i 's#/usr/share/aclocal#{aux}/usr/share/aclocal#g' {aux}/usr/bin/aclocal-1.16; "
    "sed -i 's#/usr/share/autoconf#{aux}/usr/share/autoconf#g' "
    "{aux}/usr/bin/autoconf {aux}/usr/bin/autoheader; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/aclocal-1.16 "
    "--system-acdir={aux}/usr/share/aclocal-1.16 "
    "--automake-acdir={aux}/usr/share/aclocal-1.16 \"$@\"\\n' > $W/aclocal; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/automake-1.16 "
    "--libdir={aux}/usr/share/automake-1.16 \"$@\"\\n' > $W/automake; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/libtoolize \"$@\"\\n' > $W/libtoolize; "
    "chmod +x $W/aclocal $W/automake $W/libtoolize; "
    "autoreconf -fi"
)

_L7_EXPAND4_SPECS: tuple[dict, ...] = (
    {
        "family": "tcpdump", "version": "4.99.6",
        "url": "https://www.tcpdump.org/release/tcpdump-4.99.6.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "5839921a0f67d7d8fa3dacd9cd41e44c89ccb867e8a6db216d62628c7fd14b09",
        "configure": ["--prefix={root}/.l7-install", "--with-crypto={prefix}",
                      "--disable-local-libpcap"],
        "make": [MAKE_JOBS], "artifact": "tcpdump", "launch": ["--version"],
        "aux_sources": list(_L7_TCPDUMP_AUX),
        "ldflags_extra": ("-Wl,-rpath-link,{aux}/usr/lib/x86_64-linux-gnu "
                          "-Wl,-rpath-link,{aux}/lib/x86_64-linux-gnu"),
        "env_extra": {"PATH": "{aux}/usr/bin:" + os.environ.get("PATH", ""),
                      "LIBCRYPTO_CFLAGS": "-I{prefix}/include",
                      "LIBCRYPTO_LIBS": "-L{prefix}/lib -lcrypto"},
        "pre_build": [["sh", "-c", (
            "set -e; "
            "sed -i 's|^prefix=\"/usr\"|prefix=\"{aux}/usr\"|' "
            "{aux}/usr/bin/pcap-config"
        )]],
        "note": ("tcpdump 4.99.6 with its libcrypto link and the pristine libpcap 1.10.3 build "
                 "(plus the dbus runtime Debian's libpcap needs); the L7 workload captures a local "
                 "TLS handshake and reads the handshake record bytes back"),
    },
    {
        "family": "slrn", "version": "1.0.3a",
        "url": "https://jedsoft.org/releases/slrn/slrn-1.0.3a.tar.bz2",
        "archive": "tar.bz2", "build_system": "configure",
        "sha256": "3ba8a4d549201640f2b82d53fb1bec1250f908052a7983f0061c983c634c2dac",
        "configure": ["--prefix={root}/.l7-install", "--with-ssl={prefix}", "--with-slrnpull",
                      "--with-slanglib={aux}/usr/lib/x86_64-linux-gnu",
                      "--with-slanginc={aux}/usr/include"],
        "make": [MAKE_JOBS], "artifact": "src/objs/slrn", "launch": ["--version"],
        "aux_sources": list(_L7_SLRN_AUX),
        "note": ("slrn 1.0.3a and its slrnpull offline NNTP client built with --with-ssl against "
                 "the subject libssl; slang and ncurses headers are the pinned packages"),
    },
    {
        "family": "epic5", "version": "3.0.3",
        "url": "https://ftp.epicsol.org/pub/epic/EPIC5-PRODUCTION/epic5-3.0.3.tar.xz",
        "archive": "tar.xz", "build_system": "configure",
        "sha256": "63a411215c14040b65b5d728aff10f7523d55e170f6298fb01e1cf958d79d326",
        "configure": ["--prefix={root}/.l7-install", "--with-ssl={prefix}",
                      "--without-libarchive", "--without-perl", "--with-ipv6"],
        "make": [MAKE_JOBS], "artifact": "source/epic5", "launch": ["-v"],
        "aux_sources": list(_L7_EPIC5_AUX),
        "env_extra": {"CFLAGS": "-I{aux}/usr/include"},
        "note": ("epic5 3.0.3's IRC-over-TLS client (type=irc-ssl) linked against the subject "
                 "libssl; ncurses is the pinned package and libarchive/perl are disabled"),
    },
    {
        "family": "bannergrab", "version": "3.5",
        "url": "https://downloads.sourceforge.net/bannergrab/bannergrab-3.5.tgz",
        "archive": "tar.gz", "build_system": "make",
        "sha256": "f9995bc1f750234b08034d4bc8c214ec505690a8d939eeda176da46328a7638d",
        "configure": [],
        "make": ["CFLAGS=-I{prefix}/include -lcrypto -lssl",
                 "LDFLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "artifact": "bannergrab", "launch": ["--version"],
        "note": ("bannergrab 3.5's TLS banner path linked against the subject libssl/libcrypto; "
                 "its Makefile is used verbatim with only the prefix flags supplied"),
    },
    {
        "family": "httperf", "version": "0.9.0+git.de8cd6ad",
        "url": ("https://codeload.github.com/httperf/httperf/tar.gz/"
                "de8cd6ad8a79779a0cb74a4aa2175afa9e24df57"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "ba1c68b8eed4fcdae72e932c8810faf76bde77c50c5791b3a3d88d0f4f7e69b2",
        "configure": ["--prefix={root}/.l7-install"],
        "make": [MAKE_JOBS], "artifact": "src/httperf", "launch": ["--version"],
        "aux_sources": list(_L7_HTTPERF_AUX),
        "pre_build": [["sh", "-c", _L7_HTTPERF_BOOTSTRAP]],
        "env_extra": {
            "PATH": "{root}/.autotools:{aux}/usr/bin:" + os.environ.get("PATH", ""),
            "PERL5LIB": "{aux}/usr/share/autoconf:{aux}/usr/share/automake-1.16",
            "ACLOCAL_PATH": ("/usr/share/aclocal:{aux}/usr/share/aclocal:"
                             "{aux}/usr/share/libtool/m4"),
            "AUTOMAKE": "{root}/.autotools/automake",
            "LIBTOOLIZE": "{root}/.autotools/libtoolize",
            "AUTOCONF": "{aux}/usr/bin/autoconf",
            "AUTOHEADER": "{aux}/usr/bin/autoheader",
            "AUTOM4TE": "{aux}/usr/bin/autom4te",
            "AUTOM4TE_CFG": "{aux}/usr/share/autoconf/autom4te.cfg",
            "AC_MACRODIR": "{aux}/usr/share/autoconf",
            "trailer_m4": "{aux}/usr/share/autoconf/autoconf/trailer.m4",
            "autom4te_perllibdir": "{aux}/usr/share/autoconf",
            "M4": "{aux}/usr/bin/m4",
        },
        "note": ("httperf at upstream commit de8cd6ad (the OpenSSL-3 SSL_CIPHER accessors); its "
                 "repository carries no generated configure, so the pinned autotools bootstrap it"),
    },
    {
        "family": "makepasswd", "version": "0.5.4",
        "url": ("https://codeload.github.com/khorben/makepasswd/tar.gz/"
                "refs/tags/makepasswd_0-5-4"),
        "archive": "tar.gz", "build_system": "make",
        "sha256": "7c68f42f810144c4380c795106a38cbb3cea20816b8903cdbc822cae99996e75",
        "configure": [],
        "make": ["CFLAGSF=-I{prefix}/include",
                 "LDFLAGSF=-L{prefix}/lib -Wl,-rpath,{prefix}/lib -lcrypto"],
        "artifact": "src/makepasswd", "launch": ["--help"],
        "note": ("makepasswd 0.5.4's OpenSSL MD5 digest path (`-e md5`); the release Makefile is "
                 "used verbatim with the prefix's pkg-config replacement variables supplied"),
    },
)

# The Phase-25 L7 expansion batch (b8): two WPA KDF tools, the aircrack-ng cracking path, NRPE
# over TLS and mktorrent's SHA-1 piece hashing.  cowpatty needs libpcap only for its capture
# tool, but its Makefile links it for genpmk too, so the pinned libpcap/dbus aux is used;
# aircrack-ng is autotools-only at this pin and reuses the same autotools bootstrap as httperf;
# NRPE's configure would otherwise invoke the authority's `openssl dhparam`, so DH logic is
# disabled (`--with-need-dh=no`) and the TLS path uses ECDHE.
_L7_EXPAND5_SPECS: tuple[dict, ...] = (
    {
        "family": "cowpatty", "version": "4.8",
        "url": ("https://deb.debian.org/debian/pool/main/c/cowpatty/"
                "cowpatty_4.8.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "make",
        "sha256": "b9f8b724d06d3074c5bf804ed8e64b5dc846aaa6d81b31586b16558930511164",
        "configure": [],
        "make": ["CC=cc",
                 "CFLAGS=-pipe -Wall -DOPENSSL -O2 -I{prefix}/include -I{aux}/usr/include",
                 "LDLIBS=-L{prefix}/lib -L{aux}/usr/lib/x86_64-linux-gnu "
                 "-Wl,-rpath,{prefix}/lib -Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu "
                 "-Wl,-rpath,{aux}/lib/x86_64-linux-gnu -lcrypto -lpcap"],
        "artifact": "genpmk", "launch": ["-V"],
        "aux_sources": list(_L7_TCPDUMP_AUX),
        "note": ("cowpatty 4.8's genpmk built against the subject libcrypto; its WPA PMK "
                 "path uses OpenSSL SHA-1 through PBKDF2-HMAC-SHA1, and libpcap is the pinned "
                 "package its shared utils link needs"),
    },
    {
        "family": "hcxtools", "version": "6.2.7",
        "url": ("https://deb.debian.org/debian/pool/main/h/hcxtools/"
                "hcxtools_6.2.7.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "make",
        "sha256": "c9d69b5ddcf61c3deff687fad6c17197970cc75c5dbc7706b31c138bf0c784e1",
        "configure": [],
        "make": ["hcxpmktool", "CC=cc",
                 "OPENSSL_LIBS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib -lcrypto",
                 "OPENSSL_CFLAGS=-I{prefix}/include"],
        "artifact": "hcxpmktool", "launch": ["--version"],
        "note": ("hcxtools 6.2.7's hcxpmktool built against the subject libcrypto; its PMK "
                 "derivation uses OpenSSL EVP PBKDF2-HMAC-SHA1, and the prefix ships no "
                 "openssl.pc so OPENSSL_LIBS/OPENSSL_CFLAGS are supplied directly"),
    },
    {
        "family": "aircrack-ng", "version": "1.7",
        "url": ("https://deb.debian.org/debian/pool/main/a/aircrack-ng/"
                "aircrack-ng_1.7.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "05a704e3c8f7792a17315080a21214a4448fd2452c1b0dd5226a3a55f90b58c3",
        "configure": ["--prefix={root}/.l7-install",
                      "--with-libpcap-include={aux}/usr/include",
                      "--with-libpcap-lib={aux}/usr/lib/x86_64-linux-gnu"],
        "make": [MAKE_JOBS, "install"],
        "artifact": ".libs/aircrack-ng", "launch": ["--help"],
        "aux_sources": list(_L7_HTTPERF_AUX) + list(_L7_TCPDUMP_AUX),
        "pre_build": [["sh", "-c", _L7_HTTPERF_BOOTSTRAP]],
        "env_extra": {
            "PATH": "{root}/.autotools:{aux}/usr/bin:" + os.environ.get("PATH", ""),
            "PERL5LIB": "{aux}/usr/share/autoconf:{aux}/usr/share/automake-1.16",
            "ACLOCAL_PATH": ("/usr/share/aclocal:{aux}/usr/share/aclocal:"
                             "{aux}/usr/share/libtool/m4"),
            "AUTOMAKE": "{root}/.autotools/automake",
            "LIBTOOLIZE": "{root}/.autotools/libtoolize",
            "AUTOCONF": "{aux}/usr/bin/autoconf",
            "AUTOHEADER": "{aux}/usr/bin/autoheader",
            "AUTOM4TE": "{aux}/usr/bin/autom4te",
            "AUTOM4TE_CFG": "{aux}/usr/share/autoconf/autom4te.cfg",
            "AC_MACRODIR": "{aux}/usr/share/autoconf",
            "trailer_m4": "{aux}/usr/share/autoconf/autoconf/trailer.m4",
            "autom4te_perllibdir": "{aux}/usr/share/autoconf",
            "M4": "{aux}/usr/bin/m4",
        },
        "note": ("aircrack-ng 1.7's WPA key-cracking path linked against the subject "
                 "libcrypto; the pinned release is autotools-only, so the httperf bootstrap "
                 "regenerates configure, and libpcap is the pinned package its capture tools "
                 "link"),
    },
    {
        "family": "nrpe", "version": "4.1.0",
        "url": ("https://deb.debian.org/debian/pool/main/n/nagios-nrpe/"
                "nagios-nrpe_4.1.0.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "500c1845ddbb57e1df8098d107c860498dbad1ea9e4a42c2d59e8d0c19a87259",
        "configure": ["--prefix={root}/.l7-install", "--with-ssl={prefix}",
                      "--with-ssl-inc={prefix}", "--with-ssl-lib={prefix}/lib",
                      "--with-need-dh=no", "--with-nrpe-user=nobody",
                      "--with-nrpe-group=nogroup",
                      "--with-piddir={root}/.l7-install/var",
                      "--with-logdir={root}/.l7-install/var"],
        "make": ["all", MAKE_JOBS],
        "artifact": "src/nrpe", "launch": ["-V"],
        "note": ("NRPE 4.1.0's daemon and check_nrpe plugin linked against the subject "
                 "libssl; --with-need-dh=no avoids configure's `openssl dhparam` invocation "
                 "(the authority-applicable TLS path is ECDHE), and the daemon runs as nobody"),
    },
    {
        "family": "mktorrent", "version": "1.1",
        "url": ("https://deb.debian.org/debian/pool/main/m/mktorrent/"
                "mktorrent_1.1.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "make",
        "sha256": "d0f47500192605d01b5a2569c605e51ed319f557d24cfcbcb23a26d51d6138c9",
        "configure": [],
        "make": ["USE_OPENSSL=1", "CC=cc",
                 "CFLAGS=-O2 -Wall -I{prefix}/include",
                 "LDFLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib",
                 "LDLIBS=-lcrypto"],
        "artifact": "mktorrent", "launch": ["-h"],
        "note": ("mktorrent 1.1 built with USE_OPENSSL=1 so every piece hash is OpenSSL "
                 "SHA-1; the workload asserts the exact info hash and its change for a "
                 "modified file"),
    },
)

_L7_EXPAND3_SPECS: tuple[dict, ...] = (
    {
        "family": "exim", "version": "4.100.1",
        "url": "https://ftp.exim.org/pub/exim/exim4/exim-4.100.1.tar.xz",
        "archive": "tar.xz", "build_system": "make",
        "sha256": "e9fb41f6724a5b136d64c9d19dbc5f26494af879a3e7e3190f91639eaa79fa0d",
        "configure": [], "make": [MAKE_JOBS],
        "artifact": "build-Linux-x86_64/exim", "launch": ["--version"],
        "aux_sources": list(_L7_EXIM_AUX),
        "pre_build": [["sh", "-c", _L7_EXIM_LOCAL_MAKEFILE]],
        "note": ("Exim 4.100.1 built from the pristine release with USE_OPENSSL=yes; the SMTP "
                 "daemon's STARTTLS path links the subject libssl, and PCRE2/Berkeley DB are the "
                 "pinned packages its mandatory regex and hints-database paths need"),
    },
    {
        "family": "nsd", "version": "4.10.1",
        "url": "https://www.nlnetlabs.nl/downloads/nsd/nsd-4.10.1.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "c0190f923f0095995f2e6331dacd92c6e1f4d578b880d61690602b43a5acfd84",
        "configure": ["--with-ssl={prefix}", "--with-libevent={aux}/usr",
                      "--prefix={root}/.l7-install"],
        "make": [MAKE_JOBS], "artifact": "nsd", "launch": ["-v"],
        "aux_sources": list(_LIBEVENT_AUX),
        "note": ("NSD 4.10.1's DNS-over-TLS listener (tls-service-key/tls-service-pem) linked "
                 "against the subject libssl; libevent is the pinned bookworm package"),
    },
    {
        "family": "net-snmp", "version": "5.9.4",
        "url": ("https://downloads.sourceforge.net/project/net-snmp/net-snmp/5.9.4/"
                "net-snmp-5.9.4.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "8b4de01391e74e3c7014beb43961a2d6d6fa03acc34280b9585f4930745b0544",
        "configure": ["--with-openssl={prefix}", "--with-defaults", "--disable-shared",
                      "--without-pcre", "--disable-embedded-perl", "--without-perl-modules",
                      "--without-python-modules",
                      "--with-persistent-directory={root}/.l7-state",
                      "--with-logfile={root}/.l7-state/snmpd.log",
                      "--with-sys-contact=nobody@l7.test", "--with-sys-location=l7",
                      "--with-default-snmp-version=3"],
        "make": [MAKE_JOBS], "artifact": "agent/snmpd", "launch": ["-v"],
        "env_extra": {"OPENSSL_CFLAGS": "-I{prefix}/include",
                      "OPENSSL_LIBS": "-L{prefix}/lib -lssl -lcrypto"},
        "note": ("net-snmp 5.9.4's agent and snmpget with the USM authentication path built on "
                 "the subject libcrypto (SHA-1 HMAC); the prefix ships no openssl.pc, so the "
                 "recipe supplies OPENSSL_CFLAGS/OPENSSL_LIBS as the admitted workaround"),
    },
    {
        "family": "eggdrop", "version": "1.9.5",
        "url": ("https://github.com/eggheads/eggdrop/releases/download/v1.9.5/"
                "eggdrop-1.9.5.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "e26918ea8a64d9857579c5b60c661a337f20773edd83086b356525beb581736a",
        "configure": ["--with-tclinc={aux}/usr/include/tcl8.6/tcl.h",
                      "--with-tcllib={aux}/usr/lib/x86_64-linux-gnu/libtcl8.6.so",
                      "--with-sslinc={prefix}/include", "--with-ssllib={prefix}/lib"],
        "make": ["config", "all"], "artifact": "eggdrop", "launch": ["-v"],
        "aux_sources": list(_L7_EGGDROP_AUX),
        "env_extra": {"PATH": "{aux}/usr/bin:" + os.environ.get("PATH", "")},
        "note": ("eggdrop 1.9.5's IRC-over-TLS client links the subject libssl; Tcl is the "
                 "pinned package, and `make config` (the release's module selection) is part of "
                 "the recipe's single make invocation"),
    },
    {
        "family": "irssi", "version": "1.4.5",
        "url": "https://github.com/irssi/irssi/releases/download/1.4.5/irssi-1.4.5.tar.xz",
        "archive": "tar.xz", "build_system": "configure",
        "sha256": "72a951cb0ad622785a8962801f005a3a412736c7e7e3ce152f176287c52fe062",
        "configure": ["--with-perl=no", "--with-proxy", "--prefix={root}/.l7-install"],
        "make": [MAKE_JOBS], "artifact": "src/fe-text/irssi", "launch": ["--version"],
        "aux_sources": list(_L7_IRSSI_AUX),
        "env_extra": {"OPENSSL_CFLAGS": "-I{prefix}/include",
                      "OPENSSL_LIBS": "-L{prefix}/lib -lssl -lcrypto"},
        "note": ("irssi 1.4.5's IRC-over-TLS client links the subject libssl; GLib (with its "
                 "pcre2 dependency) and ncurses headers are the pinned packages"),
    },
    {
        "family": "openssh-server", "version": "9.9p1",
        "url": "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p1.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "b343fbcdbff87f15b1986e6e15d6d4fc9a7d36066be6b7fb507087ba8f966c02",
        "configure": ["--with-ssl-dir={prefix}", "--without-openssl-header-check",
                      "--without-pam", "--without-selinux", "--without-libedit",
                      "--without-ldns", "--without-kerberos5",
                      "--with-privsep-user=nobody", "--with-privsep-path={root}/.l7-privsep",
                      "--silent"],
        "make": [MAKE_JOBS, "ssh", "sshd", "sshd-session", "ssh-keygen"],
        "artifact": "sshd", "launch": ["-V"],
        "note": ("OpenSSH 9.9p1's sshd (the server direction of the same release the client-only "
                 "openssh family builds) linked against the subject libcrypto; the privsep user "
                 "is the venue's nobody, and sshd-session is the split helper 9.9 requires"),
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
    # The Phase-25 L7 expansion batch (cmake/meson/autotools families that the expansion venue
    # admits). Each recipe is pristine and carries its own pinned archive digest.
    for spec in _L7_EXPANSION_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 server batch: memcached, icecast, proftpd, mini-httpd and hitch. Each is a
    # pristine released archive built against the subject prefix, with any non-OpenSSL dependency
    # acquired through the pinned `aux_sources` seam.
    # The Phase-25 L7 client/proxy batch: radsecproxy, znc, s-nail and w3m. Pristine released
    # archives built against the subject prefix, with any non-OpenSSL dependency acquired through
    # the pinned `aux_sources` seam.
    for spec in _L7_CLIENT_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    for spec in _L7_SERVER_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 utility batch: axel, ab (apache2-utils), osslsigncode,
    # u-boot-tools, sslsplit and opendkim. Pristine released archives built against
    # the subject prefix, with any non-OpenSSL dependency pinned through aux_sources.
    for spec in _L7_UTILITY_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 expansion batch (b5): nmap, fastd, kea, mumble-server, prosody and
    # partclone. Same pristine-source/aux seam; `{root}`, `{aux}` and `{repo}` are substituted
    # alongside `{prefix}` for the recipes whose build or runtime state lives in the tree.
    for spec in _L7_EXPAND2_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 expansion batch (b6): exim, nsd, net-snmp, eggdrop, irssi and
    # openssh-server. Same pristine-source/aux seam; `{root}` is the extracted tree the build
    # writes its generated inputs and runtime state into.
    for spec in _L7_EXPAND3_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 expansion batch (b7): tcpdump, slrn, epic5, bannergrab, httperf and
    # makepasswd.  Same pristine-source/aux seam; httperf's autotools bootstrap is a generated
    # build input, and tcpdump's libpcap-config is repointed under the extracted aux root.
    for spec in _L7_EXPAND4_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 expansion batch (b8): cowpatty, hcxtools, aircrack-ng, nrpe and
    # mktorrent.  Same pristine-source/aux seam; aircrack-ng regenerates its configure with the
    # pinned autotools, and NRPE disables its dhparam-generating configure step.
    for spec in _L7_EXPAND5_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 expansion batch (b9): six LIBRARY-only families. Each is a pristine
    # released archive built against the subject prefix with the expansion venue's toolchain;
    # none ships an executable, so the runtime atlas' harnesses are their admitted consumers.
    for spec in _L7_EXPAND6_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 expansion batch (b10): six more LIBRARY-only consumers, built from their
    # pristine Debian source archives against the subject prefix. lua-luaossl and lua-sec are Lua
    # modules whose admitted program is a small Lua harness; getdns, libu2f-server, duo_unix and
    # dcap-tunnel-ssl are C libraries/plugins driven by the runtime harnesses.
    for spec in _L7_EXPAND7_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 expansion batch (b11): three more consumers whose pristine Debian source
    # builds against the subject prefix. gensio's ssl gensio, jimtcl's aio SSL extension and
    # sofia-sip's tport TLS transport are the OpenSSL paths; each harness is admitted in the
    # runtime atlas.
    for spec in _L7_EXPAND8_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 expansion batch (b12): libtpms, libre, arm-trusted-firmware-tools,
    # libnetconf2 and liboauth2. Same pristine-source/aux seam; libnetconf2's libssh/libyang
    # and liboauth2's cjose/libcurl are pinned bookworm packages, never a distribution OpenSSL.
    for spec in _L7_EXPAND9_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 expansion batch (b13): elinks, lynx, lftp and swtpm. The two text browsers
    # and lftp are uppercase HTTPS consumers driven by the local fixture; swtpm's TPM2 command
    # interface is driven over its own socket. Lynx/lftp take the pinned ncurses/readline
    # development packages through the auxiliary seam because the venue ships neither header.
    for spec in _L7_EXPAND10_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 template-layer continuation's bespoke-workload recipes (see
    # `_L7_ONBOARD_SPECS`).  Same pristine acquire/configure/make path and the same single
    # `{prefix}` substitution as every other recipe.
    for spec in _L7_ONBOARD_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 onboarding batch (b14): nine bespoke-workload recipes plus one template
    # row (hcxkeys).  Same pristine-source/aux seam and the same single `{prefix}` substitution.
    for spec in _L7_ONBOARD_SPECS_B:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # Batch c1: three package-split rows (icecast2, libevent-openssl-2.1-7, libaprutil1),
    # each configured against the subject prefix exactly like its sibling.
    for spec in _L7_ONBOARD_SPECS_C:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 onboarding batch (b15): ten consumers with a deterministic local
    # workload.  Same pristine-source/aux seam; yara and bruteforce-salted-openssl regenerate
    # their configure with the pinned bookworm autotools, and ircii takes ncurses/tinfo headers
    # through the auxiliary seam.
    for spec in _L7_ONBOARD_SPECS_D:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The Phase-25 L7 onboarding batch (b16): ten more consumers, each with its own pristine
    # source and a deterministic loopback workload.
    for spec in _L7_ONBOARD_SPECS_E:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The declarative template cohort.  Each entry is a small config row (URL + SHA-256 +
    # build-system fields + a bucket workload) rather than a bespoke recipe; the same pristine
    # acquire/configure/make path is used, and `{prefix}` is still the only substitution.
    for spec in templates.recipe_specs():
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # Two recipes the earlier venue recorded as blocked are buildable in the expansion image:
    # libssh ships only CMakeLists.txt (cmake is present), and lighttpd ships configure.ac (the
    # pinned autotools shim regenerates its configure). The subject prefix is still the only
    # OpenSSL; the late overrides replace the stale "still blocked" notes and build systems.
    for rec in recipes:
        late = _LATE_RECIPE_OVERRIDES.get(rec["family"])
        if late:
            rec.update(late)
    # The c2 split rows are appended after every parent recipe (and its late override) exists,
    # so each row is a byte-for-byte copy of the admitted parent build intent.
    by_family = {rec["family"]: rec for rec in recipes}
    for new, base, overrides in _L7_SPLIT_RECIPES:
        rec = copy.deepcopy(by_family[base])
        rec.update({"family": new, "recipe_id": f"recipe:{new}:{rec['version']}"})
        rec.update(overrides)
        recipes.append(rec)
    ima = copy.deepcopy(_L7_IMA_SPEC)
    ima["recipe_id"] = f"recipe:ima-evm-utils:{ima['version']}"
    recipes.append(ima)
    # The S33 corpus batch: CMS/S/MIME, PKCS#12, OCSP, X.509 verification, raw-key,
    # legacy-ENGINE, DTLS, TLS-transport and session surface.
    for spec in _S23_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    for spec in _S36_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The S44 corpus batch: pristine upstreams driven by one non-interactive TLS or crypto
    # operation.  Each carries its own pinned archive digest and the subject prefix is the only
    # OpenSSL on the link line; non-OpenSSL dependencies come through the pinned aux seam.
    for spec in _S44_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # The S46 corpus batch: pristine upstreams with a pinned archive digest.  The subject prefix is
    # the only OpenSSL on the link line; non-OpenSSL dependencies come through the auxiliary seam.
    for spec in _S46_SPECS:
        rec = dict(spec)
        rec["recipe_id"] = f"recipe:{rec['family']}:{rec['version']}"
        recipes.append(rec)
    # S46 package rows of S46/earlier parents: same archive and build intent, package artifact.
    by_family = {rec["family"]: rec for rec in recipes}
    for new, base, overrides in _S46_SPLIT_RECIPES:
        rec = copy.deepcopy(by_family[base])
        rec.update({"family": new, "recipe_id": f"recipe:{new}:{rec['version']}"})
        rec.update(overrides)
        recipes.append(rec)
    return tuple(recipes)



# The Phase-25 L7 expansion batch (b9): six LIBRARY-only families whose build systems the
# expansion venue admits (CMake, autotools and meson). Each archive is pinned by digest; the
# subject prefix is the only OpenSSL and `{prefix}` the only substitution.
_L7_EXPAND6_SPECS: tuple[dict, ...] = (
    {
        "family": "libwebsockets", "version": "4.3.3",
        "url": "https://github.com/warmcat/libwebsockets/archive/refs/tags/v4.3.3.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "6fd33527b410a37ebc91bb64ca51bdabab12b076bc99d153d7c5dd405e4bdf90",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DLWS_WITH_SSL=ON",
                      "-DLWS_WITHOUT_TESTAPPS=ON", "-DLWS_WITH_MINIMAL_EXAMPLES=OFF",
                      "-DLWS_WITH_STATIC=OFF", "-DLWS_WITH_SHARED=ON",
                      "-DLWS_WITH_LIBUV=OFF", "-DLWS_WITH_PLUGINS=OFF",
                      "-DOPENSSL_ROOT_DIR={prefix}", "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib "
                      "-Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/lib/libwebsockets.so*", "launch": None,
        "note": ("libwebsockets 4.3.3 built with CMake against the subject prefix; its TLS "
                 "client and server paths use the subject libssl (the test apps are disabled "
                 "because the workload is the harness)"),
    },
    {
        "family": "libstrophe", "version": "0.13.1",
        "url": ("https://github.com/strophe/libstrophe/releases/download/0.13.1/"
                "libstrophe-0.13.1.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "a1319f2bbd8e2669359e6a74afa416fa4d52c103b82d89d1e5f56bda3f80cefa",
        "configure": ["--prefix={root}/.l7-install", "--disable-static", "--enable-shared"],
        "make": [MAKE_JOBS], "artifact": ".libs/libstrophe.so*", "launch": None,
        "env_extra": {"openssl_CFLAGS": "-I{prefix}/include",
                      "openssl_LIBS": ("-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
                                       "-lssl -lcrypto")},
        "note": ("libstrophe 0.13.1 built with its shipped configure; the prefix ships no "
                 "openssl.pc, so PKG_CHECK_MODULES is satisfied through the module's "
                 "openssl_CFLAGS/openssl_LIBS override and the TLS backend is the subject "
                 "libssl (expat is the venue's XML parser)"),
    },
    {
        "family": "libcoap", "version": "4.3.5",
        "url": "https://github.com/obgm/libcoap/archive/refs/tags/v4.3.5.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "a417ed26ec6c95c041b42353b5b6fad1602e2bf42a6e26c09863450e227b7b5f",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                      "-DENABLE_DTLS=ON", "-DDTLS_BACKEND=openssl", "-DENABLE_OSCORE=OFF",
                      "-DENABLE_TESTS=OFF", "-DENABLE_EXAMPLES=OFF", "-DENABLE_DOCS=OFF",
                      "-DOPENSSL_ROOT_DIR={prefix}", "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib "
                      "-Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/libcoap-3.so*", "launch": None,
        "note": ("libcoap 4.3.5 built with CMake, DTLS/TLS on the OpenSSL backend so CoAP over "
                 "TLS uses the subject libssl; tests, examples and documentation are disabled"),
    },
    {
        "family": "libesmtp", "version": "1.1.0",
        "url": "https://github.com/libesmtp/libesmtp/archive/refs/tags/v1.1.0.tar.gz",
        "archive": "tar.gz", "build_system": "meson",
        "sha256": "32bc3614ca12d21c7d933f32d43410e8744b6f91fdca7732da9877a385e4e6c3",
        "configure": ["--buildtype=release", "-Dwerror=false", "-Dlwres=disabled",
                      "-Dxdg=false", "-Dpthreads=enabled", "-Dtls=enabled"],
        "make": [], "artifact": "b/libesmtp.so*", "launch": None,
        # libesmtp's meson build takes its TLS dependency from `dependency('openssl')`, and the
        # subject prefix ships libssl.pc/libcrypto.pc but no openssl.pc. The shim is a build
        # input under the extracted tree, not a source edit; the same file is written for both
        # subjects and points only at that subject's prefix.
        "pre_build": [["sh", "-c",
                       "mkdir -p {root}/.l7-pc && printf 'Name: OpenSSL\n"
                       "Description: subject OpenSSL prefix\nVersion: 3.0.0\n"
                       "Libs: -L{prefix}/lib -Wl,-rpath,{prefix}/lib -lssl -lcrypto\n"
                       "Cflags: -I{prefix}/include\n' > {root}/.l7-pc/openssl.pc"]],
        "env_extra": {"PKG_CONFIG_PATH": "{prefix}/lib/pkgconfig:{root}/.l7-pc"},
        "note": ("libesmtp 1.1.0 built with meson/ninja; its STARTTLS path links the subject "
                 "libssl through a prefix shim openssl.pc (the prefix ships no openssl.pc)"),
    },
    {
        "family": "minizip-ng", "version": "4.0.10",
        "url": "https://github.com/zlib-ng/minizip-ng/archive/refs/tags/4.0.10.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "c362e35ee973fa7be58cc5e38a4a6c23cc8f7e652555daf4f115a9eb2d3a6be7",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                      "-DMZ_OPENSSL=ON", "-DMZ_ZLIB=ON", "-DMZ_BZIP2=ON", "-DMZ_LZMA=ON",
                      "-DMZ_ZSTD=OFF", "-DMZ_PKCRYPT=ON", "-DMZ_WZAES=ON", "-DMZ_COMPAT=ON",
                      "-DMZ_BUILD_TESTS=OFF", "-DMZ_BUILD_UNIT_TESTS=OFF",
                      "-DOPENSSL_ROOT_DIR={prefix}", "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib "
                      "-Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/libminizip.so*", "launch": None,
        "note": ("minizip-ng 4.0.10 built with CMake; WinZip AES encryption uses the subject "
                 "libcrypto (zstd is disabled because the venue carries no zstd headers)"),
    },
    {
        "family": "libtins", "version": "4.5",
        "url": "https://github.com/mfontanini/libtins/archive/refs/tags/v4.5.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "6ff5fe1ada10daef8538743dccb9c9b3e19d05d028ffdc24838e62ff3fc55841",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DLIBTINS_ENABLE_PCAP=OFF",
                      "-DLIBTINS_ENABLE_WPA2=ON", "-DLIBTINS_ENABLE_DOT11=ON",
                      "-DLIBTINS_ENABLE_CXX11=ON", "-DLIBTINS_BUILD_EXAMPLES=OFF",
                      "-DLIBTINS_BUILD_TESTS=OFF", "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_CXX_FLAGS=-I{prefix}/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib "
                      "-Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/lib/libtins.so*", "launch": None,
        "note": ("libtins 4.5 with its WPA2 decryption path enabled; the PMK derivation uses "
                 "the subject libcrypto's PBKDF2/HMAC (libpcap capture is disabled: the "
                 "workload needs no capture device)"),
    },
)

# The Phase-25 L7 expansion batch (b10): six library-only consumers. Each archive is the
# pristine Debian upstream source, pinned by digest; the subject prefix is the only OpenSSL.
_LUA54_AUX: tuple[dict, ...] = (
    _aux_deb("l/lua5.4", "liblua5.4-0_5.4.4-3+deb12u1_amd64.deb",
             "b042e78d02dd8457cf7de253ae89992e50050f450d9bec66843ffb1a14ab23c7",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("l/lua5.4", "liblua5.4-dev_5.4.4-3+deb12u1_amd64.deb",
             "f02e06d3598de40a1df51ea4144668a1c6acb8813d4647a6d89cca0d256179d3",
             include_dirs=("usr/include", "usr/include/x86_64-linux-gnu"),
             library_dirs=(_AUX_MULTIARCH,), pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_LUA_SOCKET_AUX: tuple[dict, ...] = (
    _aux_deb("l/luasocket", "lua-socket_3.1.0-1+b1_amd64.deb",
             "63217faf1d497a61e23f8b7a128a494a8db593f4965ead1411429d1a1e46d9dd",
             library_dirs=(_AUX_MULTIARCH,)),
)

_LIBU2F_AUX: tuple[dict, ...] = (
    _aux_deb("j/json-c", "libjson-c5_0.16-2_amd64.deb",
             "d0e1ed8637d1c26b9720f6057d6355f18378bba5cc2553e459d1632783c00d70",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("j/json-c", "libjson-c-dev_0.16-2_amd64.deb",
             "b91a921675bde7c777930f9f77e49010a754d787219104464ea0fce04a887337",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("h/help2man", "help2man_1.49.3_amd64.deb",
             "9b17251751ee4e813df789ba39c25841b9e26bf44206fd53ce4d34bc2d761eed",
             bin_dirs=("usr/bin",)),
    _aux_deb("g/gengetopt", "gengetopt_2.23+dfsg1-1_amd64.deb",
             "b6cc627f20a806625603fa9f97071b4b7da662338e1f22829ffc92867e36695a",
             bin_dirs=("usr/bin",)),
)

_DCAP_AUTOTOOLS: tuple[dict, ...] = (
    _aux_deb("m/m4", "m4_1.4.19-3_amd64.deb",
             "b2dd7bfca426712416e651bb5ff6dabe7d05e4caebbac61d714dbe261b31e4c3",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autoconf", "autoconf_2.71-3_all.deb",
             "7d798ed8c21fc7387127de1dfdb4640003d8ba033ae5a1ff29559610cbd0c323",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/automake-1.16", "automake_1.16.5-1.3_all.deb",
             "f9a5758d87b5389bf2dbb00cc9c48e0cf59bb0ac842c5ce25d41e4bfa3f2f962",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autotools-dev", "autotools-dev_20220109.1_all.deb",
             "4d66dcb9c312566f1ca8d46ef0fb06fa4d4786c20b072c81f9d313b64ef981d0",
             bin_dirs=("usr/bin",)),
    _aux_deb("libt/libtool", "libtool_2.4.7-7~deb12u1_all.deb",
             "1c2e74f06b1d5d9a2c75e04ce87a99a8633058684439504ae8d715a4a088926c",
             bin_dirs=("usr/bin",)),
    _aux_deb("libt/libtool", "libltdl-dev_2.4.7-7~deb12u1_amd64.deb",
             "60ad26b3007d4304a1141649d4e764a27735ff4f1835a62c845d51bd734932b0",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("g/gettext", "gettext_0.21-12_amd64.deb",
             "8c1f9d43575373ce311f51d00a13afbb4888d63aa559a93a3472f5d77513b60c",
             bin_dirs=("usr/bin",)),
    _aux_deb("g/gettext", "autopoint_0.21-12_all.deb",
             "9864777e777f1f641858e27396bf7dd53c9b38197b7ac47388995ec60bb9789f",
             bin_dirs=("usr/bin",)),
)

_L7_EXPAND7_SPECS: tuple[dict, ...] = (
    {
        "family": "getdns", "version": "1.7.3",
        "url": "https://deb.debian.org/debian/pool/main/g/getdns/getdns_1.7.3.orig.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "f1404ca250f02e37a118aa00cf0ec2cbe11896e060c6d369c6761baea7d55a2c",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DENABLE_SHARED=ON",
                      "-DENABLE_STATIC=OFF", "-DBUILD_TESTING=OFF",
                      "-DENABLE_STUB_ONLY=ON", "-DUSE_LIBIDN2=OFF",
                      "-DBUILD_LIBEV=OFF", "-DBUILD_LIBEVENT2=OFF", "-DBUILD_LIBUV=OFF",
                      "-DBUILD_EXAMPLES=OFF", "-DBUILD_GETDNS_QUERY=OFF",
                      "-DBUILD_GETDNS_SERVER_MON=OFF", "-DBUILD_STUBBY=OFF",
                      "-DOPENSSL_ROOT_DIR={prefix}", "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib "
                      "-Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/libgetdns.so*", "launch": None,
        "note": ("getdns 1.7.3 with the stub-only resolver and the poll event loop; its DoT client "
                 "uses the subject libssl, and the test apps are disabled because the workload is "
                 "the harness"),
    },
    {
        "family": "libu2f-server", "version": "1.1.0",
        "url": ("https://deb.debian.org/debian/pool/main/libu/libu2f-server/"
                "libu2f-server_1.1.0.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "configure",
        "sha256": "8dcd3caeacebef6e36a42462039fd035e45fa85653dcb2013f45e15aad49a277",
        "configure": ["--prefix={root}/.l7-install", "--disable-static", "--enable-shared",
                      "--disable-tests"],
        "make": ["-j4", "-C", "u2f-server", "CFLAGS=-O2 -DFALSE=0 -DTRUE=1"],
        "artifact": "u2f-server/.libs/libu2f-server.so*", "launch": None,
        "aux_sources": list(_LIBU2F_AUX),
        "note": ("libu2f-server 1.1.0 with its P-256/ES256 verification path linked to the subject "
                 "libcrypto; json-c is the pinned parser and the two command-line helpers satisfy "
                 "its configure-time checks"),
    },
    {
        "family": "lua-luaossl", "version": "20220711",
        "url": ("https://deb.debian.org/debian/pool/main/l/lua-luaossl/"
                "lua-luaossl_20220711.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "f16c4cd2c880f270c1c73daa0a4bfdd11ae3155b92a2086863731e06d241300b",
        "make": ["-f", "GNUmakefile", "all", "install5.4", "LUA_APIS=5.4",
                 "prefix={root}/.l7-install",
                 "LUA54_CPPFLAGS=-I{aux}/usr/include/lua5.4 "
                 "-I{aux}/usr/include/x86_64-linux-gnu",
                 "LUAC54=true", "CPPFLAGS=-I{prefix}/include",
                 "LDFLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "artifact": "src/5.4/openssl.so", "launch": None,
        "aux_sources": list(_LUA54_AUX),
        "note": ("lua-luaossl 20220711 built for Lua 5.4 against the subject libssl/libcrypto; the "
                 "admitted workload is the Lua digest/HMAC harness"),
    },
    {
        "family": "lua-sec", "version": "1.3.2",
        "url": "https://deb.debian.org/debian/pool/main/l/lua-sec/lua-sec_1.3.2.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "97293092ba385ab390decb6678bc8cbeffd5899bfbc49eb7ef4aa00f5e31c3d4",
        "make": ["linux", "EXTRA=luasocket", "DEFS=-DWITH_LUASOCKET",
                 "INC_PATH=-I{aux}/usr/include/lua5.4 "
                 "-I{aux}/usr/include/x86_64-linux-gnu -I{prefix}/include",
                 "LIB_PATH=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "artifact": "src/ssl.so", "launch": None,
        "aux_sources": list(_LUA54_AUX) + list(_LUA_SOCKET_AUX),
        "note": ("LuaSec 1.3.2 built for Lua 5.4 against the subject libssl, with its bundled "
                 "LuaSocket support; the admitted workload is the Lua TLS client harness"),
    },
    {
        "family": "duo_unix", "version": "1.11.3",
        "url": "https://deb.debian.org/debian/pool/main/d/duo-unix/duo-unix_1.11.3.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "0fe0f85a834f6522070cb77edb29e77d853eb13932744b98b7b7d9657513f124",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--with-pam=no"],
        "make": ["-j4"], "artifact": "login_duo/login_duo", "launch": None,
        "note": ("duo_unix 1.11.3's libduo HMAC-SHA1 request signing against the subject libcrypto; "
                 "login_duo is the linked executable, and PAM is disabled because the workload "
                 "drives libduo directly"),
    },
    {
        "family": "dcap-tunnel-ssl", "version": "2.47.14",
        "url": "https://deb.debian.org/debian/pool/main/d/dcap/dcap_2.47.14.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "dda98990d93cded815ee425101674ad2f48438fff76b3d4d5d3f91e380e9cc49",
        "configure": ["--prefix={root}/.l7-install"],
        "make": ["-j4", "-C", "plugins/ssl"],
        "artifact": "plugins/ssl/.libs/libsslTunnel.so", "launch": None,
        "aux_sources": list(_DCAP_AUTOTOOLS),
        "pre_build": [["sh", "-c", (
            "set -e; "
            "W={root}/.autotools; mkdir -p $W; "
            "printf '#!/bin/sh\\nexec {aux}/usr/bin/aclocal-1.16 "
            "--system-acdir={aux}/usr/share/aclocal-1.16 "
            "--automake-acdir={aux}/usr/share/aclocal-1.16 \"$@\"\\n' > $W/aclocal; "
            "printf '#!/bin/sh\\nexec {aux}/usr/bin/automake-1.16 "
            "--libdir={aux}/usr/share/automake-1.16 \"$@\"\\n' > $W/automake; "
            "printf '#!/bin/sh\\nexec {aux}/usr/bin/libtoolize \"$@\"\\n' > $W/libtoolize; "
            "chmod +x $W/aclocal $W/automake $W/libtoolize; "
            "sed -i 's#/usr/share/autoconf#{aux}/usr/share/autoconf#g' "
            "{aux}/usr/share/autoconf/autom4te.cfg; "
            "mkdir -p {aux}/usr/share/libtool/m4; "
            "cp {aux}/usr/share/aclocal/libtool.m4 {aux}/usr/share/aclocal/lt*.m4 "
            "{aux}/usr/share/libtool/m4/; "
            "touch NEWS; "
            "autoreconf -fi"
        )]],
        "env_extra": {
            "_lt_pkgdatadir": "{aux}/usr/share/libtool",
            "PATH": "{root}/.autotools:{aux}/usr/bin:" + os.environ.get("PATH", ""),
            "PERL5LIB": "{aux}/usr/share/autoconf:{aux}/usr/share/automake-1.16",
            "ACLOCAL_PATH": "/usr/share/aclocal:{aux}/usr/share/aclocal:"
                            "{aux}/usr/share/libtool/m4",
            "ACLOCAL": "{root}/.autotools/aclocal",
            "AUTOMAKE": "{root}/.autotools/automake",
            "LIBTOOLIZE": "{root}/.autotools/libtoolize",
            "AUTOPOINT": "true",
            "AUTOCONF": "{aux}/usr/bin/autoconf",
            "AUTOHEADER": "{aux}/usr/bin/autoheader",
            "AUTOM4TE": "{aux}/usr/bin/autom4te",
            "AUTOM4TE_CFG": "{aux}/usr/share/autoconf/autom4te.cfg",
            "AC_MACRODIR": "{aux}/usr/share/autoconf",
            "trailer_m4": "{aux}/usr/share/autoconf/autoconf/trailer.m4",
            "autom4te_perllibdir": "{aux}/usr/share/autoconf",
            "M4": "{aux}/usr/bin/m4",
        },
        "note": ("dcap-tunnel-ssl 2.47.14's libsslTunnel plugin, the family's actual OpenSSL "
                 "consumer, built against the subject libssl; the source has no generated "
                 "configure, so the pinned bookworm autotools bootstrap it as a build input"),
    },
)

# The Phase-25 L7 expansion batch (b11): three consumers whose pristine Debian source builds
# against the subject prefix. gensio's ssl gensio, jimtcl's aio SSL extension and sofia-sip's
# tport TLS transport are the OpenSSL paths driven by the runtime harnesses.
_L7_EXPAND8_SPECS: tuple[dict, ...] = (
    {
        "family": "gensio", "version": "2.8.6",
        "url": "https://deb.debian.org/debian/pool/main/g/gensio/gensio_2.8.6.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "3220816c23f34a4ccaea91eb8859c56233bcd8b2379b5f0e2b7c50074aa03cfb",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--with-ssl=yes", "--with-tcl=no", "--with-python=no",
                      "--with-swig=no"],
        "make": ["-j4"], "artifact": "lib/.libs/libgensio.so*", "launch": None,
        "ldflags_extra": "-Wl,-rpath,{prefix}/lib",
        "note": ("gensio 2.8.6's ssl gensio (lib/gensio_ssl.c) built against the subject "
                 "libssl; the admitted workload is the loopback TLS request/response harness"),
    },
    {
        "family": "jimtcl", "version": "0.81+dfsg0",
        "url": ("https://deb.debian.org/debian/pool/main/j/jimtcl/"
                "jimtcl_0.81+dfsg0.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "ab7eb3680ba0d16f4a9eb1e05b7fcbb7d23438e25185462c55cd032a1954a985",
        "configure": ["--prefix={root}/.l7-install", "--ssl", "--shared"],
        "make": ["-j4"], "artifact": "libjim.so*", "launch": None,
        "env_extra": {"PKG_CONFIG_PATH": "{prefix}/lib/pkgconfig"},
        "ldflags_extra": "-Wl,-rpath,{prefix}/lib",
        "note": ("jimtcl 0.81 with the aio extension's OpenSSL SSL support (jim-aio.c) built "
                 "against the subject libssl; the admitted workload is the TLS server harness"),
    },
    {
        "family": "sofia-sip", "version": "1.12.11+20110422.1",
        "url": ("https://deb.debian.org/debian/pool/main/s/sofia-sip/"
                "sofia-sip_1.12.11+20110422.1.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "bfa615962e55688db441ae0c17d77a0831f4f50ee5ca45b0c75c7ebaf7eb95ab",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}"],
        "make": ["-j4"], "artifact": "libsofia-sip-ua/.libs/libsofia-sip-ua.so*",
        "launch": None, "ldflags_extra": "-Wl,-rpath,{prefix}/lib",
        "note": ("sofia-sip 1.12.11's tport TLS transport (libsofia-sip-ua/tport/tport_tls.c) "
                 "built against the subject libssl; the admitted workload is the SIP-over-TLS "
                 "tport harness"),
    },
)

# The Phase-25 L7 expansion batch (b12): five more pristine-source consumers. libtpms 0.9.2 and
# liboauth2 1.4.5.4 need a generated `configure`; the same pinned autotools packages dcap-tunnel-ssl
# already uses provide it. libnetconf2 links libssh/libyang and liboauth2 links cjose/libcurl from
# pinned bookworm packages extracted through `aux_sources`; none of them provides an OpenSSL.
_LIBSSH_AUX: tuple[dict, ...] = (
    _aux_deb("libs/libssh", "libssh-4_0.10.6-0+deb12u2_amd64.deb",
             "2158d90ac21364655fe0372b23341fa3f871146bf3525f7dffef6dfa8f28448a",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libs/libssh", "libssh-dev_0.10.6-0+deb12u2_amd64.deb",
             "c5dff9b2b855677e6451e35ab6f7e9a467c4c36a3d76c30526f9f66b0f978df7",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_LIBYANG_AUX: tuple[dict, ...] = (
    _aux_deb("liby/libyang2", "libyang2_2.1.30-2_amd64.deb",
             "a2d950fa7729dedad0d7bc581b67a185180bec49d03b38cf1917f3869b8bc618",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("liby/libyang2", "libyang2-dev_2.1.30-2_amd64.deb",
             "419f94a3b360b71987e3810e09553b36a6e1e4d583cd2cd2132ccf41911544c0",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    # libyang's public headers include <pcre2.h>; the runtime library is the venue's.
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_CJOSE_AUX: tuple[dict, ...] = (
    _aux_deb("c/cjose", "libcjose0_0.6.2.1-1+deb12u1_amd64.deb",
             "f62f0a16704103dfcff1b6b9423839655bb5f1f7a84dd90e14f00cebf483107b",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("c/cjose", "libcjose-dev_0.6.2.1-1+deb12u1_amd64.deb",
             "97ffc1c18565f835b47914e904f261c0aee849a5c356dad8f60f5cc5fd792de7",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

# liboauth2 1.4.5.4's configure requires a libcurl development entry point; the venue carries the
# runtime library but no headers or `.pc`.
_LIBCURL_AUX: tuple[dict, ...] = (
    _aux_deb("c/curl", "libcurl4_7.88.1-10+deb12u15_amd64.deb",
             "3042904de01f9c4fbdcf1452b8f81abedcf2b015f9b9deba109063322b5bd68b",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("c/curl", "libcurl4-openssl-dev_7.88.1-10+deb12u15_amd64.deb",
             "dbd69b15ecb49331f53fbc3483b0508997e2fab551e48c53951391f254b73890",
             include_dirs=("usr/include", "usr/include/x86_64-linux-gnu"),
             library_dirs=(_AUX_MULTIARCH,), pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

# The dcap-tunnel-ssl autotools shim, reused verbatim: the pinned aclocal/automake wrappers keep
# the extracted macros and libtool files off the venue's missing autotools installation.
_AUTORECONF_PRE_BUILD = [["sh", "-c", (
    "set -e; "
    "W={root}/.l7-autotools; mkdir -p $W; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/aclocal-1.16 "
    "--system-acdir={aux}/usr/share/aclocal-1.16 -I {aux}/usr/share/aclocal "
    "-I /usr/share/aclocal --automake-acdir={aux}/usr/share/aclocal-1.16 "
    "\"$@\"\\n' > $W/aclocal; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/automake-1.16 "
    "--libdir={aux}/usr/share/automake-1.16 \"$@\"\\n' > $W/automake; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/libtoolize \"$@\"\\n' > $W/libtoolize; "
    "chmod +x $W/aclocal $W/automake $W/libtoolize; "
    "sed -i 's#/usr/share/autoconf#{aux}/usr/share/autoconf#g' "
    "{aux}/usr/share/autoconf/autom4te.cfg; "
    "mkdir -p {aux}/usr/share/libtool/m4; "
    "cp {aux}/usr/share/aclocal/libtool.m4 {aux}/usr/share/aclocal/lt*.m4 "
    "{aux}/usr/share/libtool/m4/; "
    "touch NEWS; "
    "autoreconf -fi"
)]]

_AUTORECONF_ENV = {
    "_lt_pkgdatadir": "{aux}/usr/share/libtool",
    "M4": "{aux}/usr/bin/m4",
    "AUTOM4TE": "{aux}/usr/bin/autom4te",
    "AUTOCONF": "{aux}/usr/bin/autoconf",
    "AUTOHEADER": "{aux}/usr/bin/autoheader",
    "ACLOCAL": "{root}/.l7-autotools/aclocal",
    "AUTOMAKE": "{root}/.l7-autotools/automake",
    "LIBTOOLIZE": "{root}/.l7-autotools/libtoolize",
    "AC_MACRODIR": "{aux}/usr/share/autoconf",
    "AUTOM4TE_CFG": "{aux}/usr/share/autoconf/autom4te.cfg",
    "autom4te_perllibdir": "{aux}/usr/share/autoconf",
    "trailer_m4": "{aux}/usr/share/autoconf/autoconf/trailer.m4",
    "PATH": "{root}/.l7-autotools:{aux}/usr/bin:" + os.environ.get("PATH", ""),
    "PERL5LIB": "{aux}/usr/share/autoconf:{aux}/usr/share/automake-1.16",
}

_L7_EXPAND9_SPECS: tuple[dict, ...] = (
    {
        "family": "libtpms", "version": "0.9.2",
        "url": ("https://deb.debian.org/debian/pool/main/libt/libtpms/"
                "libtpms_0.9.2.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "460047f880c5a17dfb8f5c92668fd2f0c508279d4cc3de0a779c21a09f966766",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl", "--with-tpm2"],
        "make": ["-j4"], "artifact": "src/.libs/libtpms.so*", "launch": None,
        "aux_sources": list(_DCAP_AUTOTOOLS),
        "pre_build": _AUTORECONF_PRE_BUILD, "env_extra": dict(_AUTORECONF_ENV),
        "note": ("libtpms 0.9.2 with TPM2 and the OpenSSL crypto library; the admitted workload "
                 "drives TPM2_Startup/GetCapability/GetRandom through TPMLIB_Process"),
    },
    {
        "family": "libre", "version": "1.1.0",
        "url": "https://deb.debian.org/debian/pool/main/libr/libre/libre_1.1.0.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "82afc903a6b1e436b357f05eb11560ec681712291dd9c83c408465c895f28b5d",
        "make": ["-j4", "SYSROOT_ALT={prefix}", "PREFIX={root}/.l7-install"],
        "artifact": "libre.so*", "launch": None,
        "note": ("libre 1.1.0's tls/tcp backend (src/tls/openssl) with USE_OPENSSL from the "
                 "subject prefix; the admitted workload is a loopback TLS session + wrong-CA "
                 "reject"),
    },
    {
        "family": "arm-trusted-firmware-tools", "version": "2.8.0+dfsg",
        "url": ("https://deb.debian.org/debian/pool/main/a/arm-trusted-firmware/"
                "arm-trusted-firmware_2.8.0+dfsg.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "make", "configure": None,
        "sha256": "a4ecc35e0b893fe8682c075fc1bdb858de87e4cb18fbed9a1597e2c9f6d320de",
        "pre_build": [["make", "-C", "tools/cert_create", "OPENSSL_DIR={prefix}"]],
        "make": ["-C", "tools/fiptool", "OPENSSL_DIR={prefix}"],
        "artifact": "tools/fiptool/fiptool", "launch": None,
        "note": ("TF-A 2.8.0's cert_create and fiptool built against the subject libcrypto; the "
                 "admitted workload signs a certificate chain, verifies it, and rejects a "
                 "tampered certificate and a tampered FIP"),
    },
    {
        "family": "libnetconf2", "version": "2.0.24",
        "url": ("https://deb.debian.org/debian/pool/main/libn/libnetconf2/"
                "libnetconf2_2.0.24.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "78ffa0bd85823abd321a1dbb09c1ead36612f2a12049638a14bb081567f86ade",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DENABLE_TESTS=OFF",
                      "-DENABLE_SSH=ON", "-DENABLE_TLS=ON", "-DENABLE_COVERAGE=OFF",
                      "-DCMAKE_INSTALL_PREFIX={root}/.l7-install",
                      "-DOPENSSL_ROOT_DIR={prefix}", "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_INCLUDE_PATH={aux}/usr/include",
                      "-DCMAKE_LIBRARY_PATH={aux}/usr/lib/x86_64-linux-gnu",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include -I{aux}/usr/include"],
        "make": [], "artifact": "b/libnetconf2.so*", "launch": None,
        "aux_sources": list(_LIBSSH_AUX) + list(_LIBYANG_AUX),
        "note": ("libnetconf2 2.0.24 with SSH and TLS enabled: its TLS session client uses the "
                 "subject libssl, while libssh 0.10.6 and libyang 2.1.30 are the pinned "
                 "bookworm dependencies (neither provides an OpenSSL on the link line)"),
    },
    {
        "family": "liboauth2", "version": "1.4.5.4",
        "url": ("https://deb.debian.org/debian/pool/main/libo/liboauth2/"
                "liboauth2_1.4.5.4.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "a7ab1fee6d9c88501e22ca73e28365aaaac298c811b01beacb3bf7e1cddbe9e5",
        "configure": ["--prefix={root}/.l7-install", "--with-apache=no",
                      "--with-memcache=no", "--with-redis=no"],
        "make": ["-j4"], "artifact": ".libs/liboauth2.so*", "launch": None,
        "aux_sources": (list(_DCAP_AUTOTOOLS) + list(_CJOSE_AUX) + list(_LIBCURL_AUX)),
        "pre_build": _AUTORECONF_PRE_BUILD, "env_extra": dict(_AUTORECONF_ENV),
        "note": ("liboauth2 1.4.5.4's JOSE path: cjose 0.6.2.1 performs JWS/JWE with the subject "
                 "libcrypto while liboauth2 hashes with the subject EVP interface; libcurl is "
                 "the pinned development entry point its configure requires"),
    },
)

# Pinned ncurses/readline development packages for the text browsers and lftp. The venue ships
# neither header, and both are pure terminal libraries (they provide no OpenSSL).
_NCURSES_AUX: tuple[dict, ...] = (
    _aux_deb("n/ncurses", "libncurses-dev_6.4-4_amd64.deb",
             "2ad228835756feb118bb131b32834bd23a09047e4de408cc5204cbb5dce0e4bb",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("n/ncurses", "libtinfo-dev_6.4-4_amd64.deb",
             "e1935c2006661f1cda0bfd35f12ea30f9d64a110f30a074d512efe6c9466bf86",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

_READLINE_AUX: tuple[dict, ...] = (
    _aux_deb("r/readline", "libreadline-dev_8.2-1.3_amd64.deb",
             "23b2f03bc073dcd3ac4638675ddccbda2e8d7348bb83dd648c55dfb8077e8672",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

# swtpm's non-OpenSSL dependency closure: glib/gobject/gio (json-glib) and the pinned libtpms the
# TPM2 backend calls. None of them provides libssl/libcrypto; libtpms0 is itself a consumer and
# resolves to the subject libcrypto at run time.
_SWTPM_AUX: tuple[dict, ...] = (
    _aux_deb("g/glib2.0", "libglib2.0-dev_2.74.6-2+deb12u9_amd64.deb",
             "217766f170553e14884f7d67c0636b833da43c1e4a65dfe41268ba1292001ccd",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("g/glib2.0", "libglib2.0-0_2.74.6-2+deb12u9_amd64.deb",
             "7ff85197685d89e150e342b29a59aab1beee400050ba7da73de81cd999ffee5a",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("p/pcre2", "libpcre2-8-0_10.42-1_amd64.deb",
             "030db54f4d76cdfe2bf0e8eb5f9efea0233ab3c7aa942d672c7b63b52dbaf935",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libf/libffi", "libffi-dev_3.4.4-1_amd64.deb",
             "89fb890aee5148f4d308a46cd8980a54fd44135f068f05b38a6ad06800bf6df3",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libf/libffi", "libffi8_3.4.4-1_amd64.deb",
             "6d9f6c25c30efccce6d4bceaa48ea86c329a3432abb360a141f76ac223a4c34a",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("j/json-glib", "libjson-glib-dev_1.6.6-1_amd64.deb",
             "7af7f57f8b4e12f03a4ef3dc2a631d3c32f5d7bc26ac4319a7f813207f9339d6",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("j/json-glib", "libjson-glib-1.0-0_1.6.6-1_amd64.deb",
             "b8d407ece57b0dc2e6d2895625a2485b1eb49294b8db0fdb780fb8211fe9e635",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libt/libtpms", "libtpms-dev_0.9.2-3.2_amd64.deb",
             "c605656a04aa0fad233866a5e9cdfe50b25ccb3accf65cc808fa3c7ec210d8af",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libt/libtpms", "libtpms0_0.9.2-3.2_amd64.deb",
             "6748109482aeabfa564b33ddd158aab8e26dabf5943389b372d9dd6c7d5564d4",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libt/libtasn1-6", "libtasn1-6-dev_4.19.0-2+deb12u1_amd64.deb",
             "7fec7d9df23aa7de25a36c5752cefd8d1e45fbfa0889150de9384281a4329bf7",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libt/libtasn1-6", "libtasn1-6_4.19.0-2+deb12u1_amd64.deb",
             "2c27c613b69be248d09432839ea3d3382f6ee27fabaa65987aa2d884cd00afda",
             library_dirs=(_AUX_MULTIARCH,)),
)

# swtpm's configure requires the test tools expect/gawk/socat/netstat and gio-2.0's private
# Requires name mount/libselinux. None is part of the runtime path; the shims only satisfy
# configure's probes, and the two stub .pc files carry no libraries. gawk maps to the venue's
# /usr/bin/awk because setup generates its Makefiles with it.
_SWTPM_PRE_BUILD = [
    ["sh", "-c", (
        "set -e; "
        "mkdir -p m4 {root}/.l7-bin {root}/.l7-pc; "
        "printf '#!/bin/sh\\nexec /usr/bin/awk \"$@\"\\n' > {root}/.l7-bin/gawk; "
        "for t in netstat expect socat; do "
        "printf '#!/bin/sh\\nexit 0\\n' > {root}/.l7-bin/$t; done; "
        "chmod +x {root}/.l7-bin/*; "
        "printf 'prefix=/nonexistent\\nName: mount\\nDescription: mount\\nVersion: 2.38\\n"
        "Libs:\\nCflags:\\n' > {root}/.l7-pc/mount.pc; "
        "printf 'prefix=/nonexistent\\nName: libselinux\\nDescription: libselinux\\n"
        "Version: 3.4\\nLibs:\\nCflags:\\n' > {root}/.l7-pc/libselinux.pc"
    )],
    *_AUTORECONF_PRE_BUILD,
]

_SWTPM_ENV: dict[str, str] = dict(_AUTORECONF_ENV)
_SWTPM_ENV["PATH"] = ("{root}/.l7-autotools:{root}/.l7-bin:{aux}/usr/bin:"
                      + os.environ.get("PATH", ""))
_SWTPM_ENV["PKG_CONFIG_PATH"] = ("{root}/.l7-pc:{aux}/usr/lib/x86_64-linux-gnu/pkgconfig:"
                                 "{prefix}/lib/pkgconfig")

# The Phase-25 L7 expansion batch (b13).
_L7_EXPAND10_SPECS: tuple[dict, ...] = (
    {
        "family": "elinks", "version": "0.16.1",
        "url": ("https://github.com/rkd77/elinks/releases/download/v0.16.1/"
                "elinks-0.16.1.tar.xz"),
        "archive": "tar.xz", "build_system": "configure",
        "sha256": "825f65819d39c4890f81b5bb6f3a4197542e58908d40a5c52ff8d5ecf5bf8fae",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--without-gnutls", "--without-zlib", "--without-bzlib",
                      "--without-lzma", "--without-gpm", "--without-libev",
                      "--disable-nls"],
        "make": ["-j4"], "artifact": "src/elinks", "launch": ["-version"],
        "note": ("ELinks 0.16.1's HTTPS client path (src/network/ssl) linked against the subject "
                 "libssl; the admitted workload dumps a local HTTPS page and rejects an unrelated "
                 "CA"),
    },
    {
        "family": "lynx", "version": "2.9.2",
        "url": ("https://deb.debian.org/debian/pool/main/l/lynx/"
                "lynx_2.9.2.orig.tar.bz2"),
        "archive": "tar.bz2", "build_system": "configure",
        "sha256": "7374b89936d991669e101f4e97f2c9592036e1e8cdaa7bafc259a77ab6fb07ce",
        "configure": ["--prefix={root}/.l7-install", "--with-ssl={prefix}",
                      "--with-screen=ncursesw", "--with-curses-dir={aux}/usr",
                      "--disable-nls", "--without-bzlib", "--without-zlib"],
        "make": ["-j4"], "artifact": "src/lynx", "launch": ["-version"],
        "aux_sources": list(_NCURSES_AUX),
        "ldflags_extra": ("-Wl,-rpath,{prefix}/lib "
                          "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu"),
        "note": ("Lynx 2.9.2's HTTPS client (src/HTSSL.c) linked against the subject libssl; "
                 "ncursesw is the pinned terminal library and the admitted workload is a "
                 "`-dump` of a local HTTPS page"),
    },
    {
        "family": "lftp", "version": "4.9.3",
        "url": ("https://deb.debian.org/debian/pool/main/l/lftp/"
                "lftp_4.9.3.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "configure",
        "sha256": "96e7199d7935be33cf6b1161e955b2aab40ab77ecdf2a19cea4fc1193f457edc",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--without-gnutls", "--without-expat", "--with-readline={aux}/usr"],
        "make": ["-j4"], "artifact": "src/lftp", "launch": ["--version"],
        "aux_sources": list(_NCURSES_AUX) + list(_READLINE_AUX),
        "ldflags_extra": ("-Wl,-rpath,{prefix}/lib "
                          "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu"),
        "note": ("lftp 4.9.3 with --with-openssl (src/lftp_ssl.cc): the admitted workload gets a "
                 "file over a verified local HTTPS session and rejects an unrelated CA; "
                 "readline/ncurses are the pinned terminal libraries"),
    },
    {
        "family": "swtpm", "version": "0.7.1",
        "url": "https://deb.debian.org/debian/pool/main/s/swtpm/swtpm_0.7.1.orig.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "6ce3e1555275e3a387dfbc04ee3bf61ff24371736e3527293bdae00c2a4ab937",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl", "--without-cuse",
                      "--without-selinux", "--without-seccomp", "--without-gnutls"],
        "make": ["-j4"], "artifact": "src/swtpm/.libs/libswtpm_libtpms.so*",
        "launch": ["--version"],
        "aux_sources": (list(_SWTPM_AUX) + list(_DCAP_AUTOTOOLS)),
        "pre_build": _SWTPM_PRE_BUILD, "env_extra": dict(_SWTPM_ENV),
        "ldflags_extra": ("-Wl,-rpath,{prefix}/lib "
                          "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu"),
        "note": ("swtpm 0.7.1's TPM2 socket front end linked against the subject libcrypto; "
                 "libtpms, glib and json-glib are pinned bookworm packages and the admitted "
                 "workload drives TPM2_Startup/GetRandom over swtpm's TCP data channel"),
    },
    {
        "family": "httping", "version": "2.5",
        "url": "https://deb.debian.org/debian/pool/main/h/httping/httping_2.5.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make",
        "sha256": "be6bd3e5426f85545b6fa23f447dbb97fd7cc2704b8e2faf38b8690943211d9d",
        "configure": None, "make": ["SSL=yes", "httping"], "artifact": "httping",
        "launch": ["-V"],
        "env_extra": {"CFLAGS": "-I{prefix}/include"},
        "ldflags_extra": "-L{prefix}/lib -Wl,-rpath,{prefix}/lib",
        "note": ("httping 2.5 built with SSL=yes (its configure probe cannot see the prefix on "
                 "its own); the admitted workload pings a local HTTPS page and a plain-TCP "
                 "listener must fail the TLS handshake"),
    },
)

# The Phase-25 template-layer continuation: eight further consumers built from pristine pinned
# archives against the subject prefix. `ldnsutils` and `nagios-plugins-http` are declarative
# template rows; these are the families whose workload cannot be expressed by a bucket template
# and therefore carry a bespoke admitted harness. No candidate-specific patch is applied.
_L7_ONBOARD_SPECS: tuple[dict, ...] = (
    {
        "family": "git-crypt", "version": "0.8.0+git8c7a90ff",
        "url": ("https://github.com/AGWA/git-crypt/archive/"
                "8c7a90ff38fc9daf41e5f6ccb3f105ee82782231.tar.gz"),
        "archive": "tar.gz", "build_system": "make",
        "sha256": "c33a86f71a0ded430977cfad116060c0dc1217ccb685b9af315fe5ef4a228b59",
        "configure": None,
        "make": ["-j4", "CXXFLAGS=-I{prefix}/include -O2 -std=c++11",
                 "LDFLAGS=-L{prefix}/lib -lcrypto -Wl,-rpath,{prefix}/lib"],
        "artifact": "git-crypt", "launch": ["--version"],
        "note": ("git-crypt 0.8.0 (pinned commit archive) links the subject libcrypto; the "
                 "admitted workload initialises a repository, encrypts, locks, unlocks and "
                 "rejects a key from a different repository"),
    },
    {
        "family": "s2n-tls", "version": "1.5.5",
        "url": "https://github.com/aws/s2n-tls/archive/refs/tags/v1.5.5.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "6316e1ad2c8ef5807519758bb159d314b9fef31d79ae27bc8f809104b978bb04",
        "configure": ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DSEARCH_LIBCRYPTO=ON",
                      "-DS2N_USE_CRYPTO_SHARED_LIBS=ON", "-DBUILD_TESTING=ON",
                      "-DS2N_INSTALL_S2NC_S2ND=ON"],
        "make": [], "artifact": "b/bin/s2nd", "launch": ["--help"],
        "note": ("s2n-tls 1.5.5's s2nd TLS server linked to the subject libcrypto; the "
                 "admitted workload completes a verified TLS exchange and rejects an unrelated "
                 "CA"),
    },
    {
        "family": "openldap", "version": "2.6.8",
        "url": ("https://www.openldap.org/software/download/OpenLDAP/openldap-release/"
                "openldap-2.6.8.tgz"),
        "archive": "tar.gz", "build_system": "make",
        "sha256": "48969323e94e3be3b03c6a132942dcba7ef8d545f2ad35401709019f696c3c4e",
        "configure": None,
        "pre_build": [["./configure", "--with-tls=openssl", "--without-cyrus-sasl",
                       "--disable-slurpd", "--disable-backends", "--enable-mdb",
                       "--disable-overlays", "--disable-debug"],
                      ["make", "-C", "include"],
                      ["make", "-j4", "-C", "libraries"],
                      ["make", "-j4", "-C", "clients/tools"]],
        "make": ["-j4", "-C", "servers/slapd"],
        "artifact": "servers/slapd/slapd", "launch": ["-VV"],
        "env_extra": {"CPPFLAGS": "-I{prefix}/include",
                      "LDFLAGS": "-L{prefix}/lib -Wl,-rpath,{prefix}/lib"},
        "note": ("OpenLDAP 2.6.8's slapd over ldaps:// and the shipped ldapmodify/ldapsearch "
                 "clients, all linked against the subject libssl/libcrypto; an unrelated CA is "
                 "rejected"),
    },
    {
        "family": "srt", "version": "1.5.4",
        "url": "https://github.com/Haivision/srt/archive/refs/tags/v1.5.4.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "d0a8b600fe1b4eaaf6277530e3cfc8f15b8ce4035f16af4a5eb5d4b123640cdd",
        "configure": ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DUSE_ENCLIB=openssl",
                      "-DENABLE_ENCRYPTION=ON", "-DENABLE_APPS=ON",
                      "-DENABLE_TESTING=OFF", "-DUSE_OPENSSL_PC=OFF"],
        "make": [], "artifact": "b/srt-live-transmit", "launch": ["-h"],
        "note": ("SRT 1.5.4's live transmitter with its OpenSSL AES-CTR/HMAC encryption path "
                 "linked to the subject libcrypto; the admitted workload round-trips over "
                 "loopback with a passphrase and rejects a mismatched passphrase"),
    },
    {
        "family": "slowhttptest", "version": "1.9.0",
        "url": ("https://github.com/shekyan/slowhttptest/archive/refs/tags/v1.9.0.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "a3910b9b844e05ee55838aa17beddc6aa9d6c5c0012eab647a21cc9ccd6c8749",
        "configure": [], "make": ["-j4"],
        "artifact": "src/slowhttptest", "launch": ["-h"],
        "env_extra": {"CPPFLAGS": "-I{prefix}/include",
                      "LDFLAGS": "-L{prefix}/lib -Wl,-rpath,{prefix}/lib"},
        "note": ("slowhttptest 1.9.0's HTTPS client path links the subject libssl; the admitted "
                 "workload completes a TLS slow-read exchange and a plaintext peer is rejected"),
    },
    {
        "family": "cyrus-sasl-scram", "version": "2.1.28",
        "url": ("https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-2.1.28/"
                "cyrus-sasl-2.1.28.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "7ccfc6abd01ed67c1a0924b353e526f1b766b21f42d4562ee635a8ebfc5bb38c",
        "configure": ["--with-openssl={prefix}", "--disable-static", "--enable-shared",
                      "--disable-otp", "--disable-ldapdb", "--without-pam", "--disable-sql"],
        "make": [MAKE_JOBS], "artifact": "plugins/.libs/libscram.so*", "launch": None,
        "note": ("cyrus-sasl 2.1.28's SCRAM plugin linked to the subject libcrypto; the admitted "
                 "client/server harness authenticates with SCRAM-SHA-256 and rejects a wrong "
                 "password"),
    },
    {
        "family": "sipsak", "version": "0.9.8.1",
        "url": ("https://github.com/nils-ohlmeier/sipsak/releases/download/0.9.8.1/"
                "sipsak-0.9.8.1.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "c6faa022cd8c002165875d4aac83b7a2b59194f0491802924117fc6ac980c778",
        "configure": ["--prefix={root}/.l7-install"],
        "make": [MAKE_JOBS], "artifact": "sipsak", "launch": ["-V"],
        "env_extra": {"CPPFLAGS": "-I{prefix}/include",
                      "LDFLAGS": "-L{prefix}/lib -Wl,-rpath,{prefix}/lib"},
        "note": ("sipsak 0.9.8.1 links the subject libcrypto for its SIP MD5 digest "
                 "authentication; the admitted workload authenticates against a local SIP peer "
                 "and a wrong password is rejected"),
    },
    {
        "family": "cyrus-sasl-digestmd5", "version": "2.1.28",
        "url": ("https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-2.1.28/"
                "cyrus-sasl-2.1.28.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "7ccfc6abd01ed67c1a0924b353e526f1b766b21f42d4562ee635a8ebfc5bb38c",
        "configure": ["--with-openssl={prefix}", "--disable-static", "--enable-shared",
                      "--disable-otp", "--disable-ldapdb", "--without-pam", "--disable-sql"],
        "make": [MAKE_JOBS], "artifact": "plugins/.libs/libdigestmd5.so*", "launch": None,
        "note": ("cyrus-sasl 2.1.28's DIGEST-MD5 plugin linked to the subject libcrypto; the "
                 "admitted client/server harness authenticates with DIGEST-MD5 and rejects a "
                 "wrong password"),
    },
)

# The Phase-25 L7 onboarding batch (c1, 2026-10-22): three package-split rows of upstreams this
# venue already builds (icecast2 from icecast 2.4.4, libevent-openssl-2.1-7 from libevent
# 2.1.12, libaprutil1 from apr-util 1.6.3).  Each is a real Alpine package entry in the frozen
# 1000-family corpus and is measured as its own row against its own build with the upstream's
# own OpenSSL mechanism.
#
# lighttpd 1.4.79 was vetted in the same batch and NOT admitted: its meson build links the
# subject correctly (mod_openssl, verified TLS GET of a fixture) and measures L7-functional
# against the authority openssl-3.6.4-production, but the candidate closes every handshake
# (mod_openssl reports "SSL routines::internal error"; the client sees SSL LENGTH_MISMATCH)
# while the same client against the authority completes.  h2o 2.2.6 shows the same shape
# (authority completes the handshake; the candidate closes it mid-handshake).  Both are
# candidate-side divergences recorded for repair, not compatibility results.

# --------------------------------------------------------------------------------------------
# Phase-25 L7 onboarding batch (b15).
#
# Ten consumers whose OpenSSL path can be driven by a deterministic local workload.  Every
# archive is pinned by digest and built against exactly one subject prefix; non-OpenSSL
# dependencies come from pinned bookworm packages through the aux seam, so the subject prefix
# remains the only OpenSSL on the link line.  yara and bruteforce-salted-openssl ship no
# generated `configure`, so the recipe regenerates it with the same pinned autotools the
# lighttpd recipe uses (a build input, never a source edit).
_ONBOARD_AUTOTOOLS_AUX: tuple[dict, ...] = (
    _aux_deb("m/m4", "m4_1.4.19-3_amd64.deb",
             "b2dd7bfca426712416e651bb5ff6dabe7d05e4caebbac61d714dbe261b31e4c3",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autoconf", "autoconf_2.71-3_all.deb",
             "7d798ed8c21fc7387127de1dfdb4640003d8ba033ae5a1ff29559610cbd0c323",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/automake-1.16", "automake_1.16.5-1.3_all.deb",
             "f9a5758d87b5389bf2dbb00cc9c48e0cf59bb0ac842c5ce25d41e4bfa3f2f962",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autotools-dev", "autotools-dev_20220109.1_all.deb",
             "4d66dcb9c312566f1ca8d46ef0fb06fa4d4786c20b072c81f9d313b64ef981d0",
             bin_dirs=("usr/bin",)),
    _aux_deb("libt/libtool", "libtool_2.4.7-7~deb12u1_all.deb",
             "1c2e74f06b1d5d9a2c75e04ce87a99a8633058684439504ae8d715a4a088926c",
             bin_dirs=("usr/bin",)),
)

# The pinned autotools are extracted under the aux root; these wrappers point them at that
# root (their installed scripts hardcode /usr/share).  The generated files are build inputs.
_ONBOARD_AUTOTOOLS_BOOTSTRAP = (
    "set -e; W={root}/.autotools; mkdir -p $W; "
    "sed -i 's#/usr/share#{aux}/usr/share#g' {aux}/usr/bin/libtoolize; "
    "sed -i 's#/usr/share/autoconf#{aux}/usr/share/autoconf#g' "
    "{aux}/usr/share/autoconf/autom4te.cfg; "
    "sed -i 's#/usr/share/automake-1.16#{aux}/usr/share/automake-1.16#g' "
    "{aux}/usr/bin/aclocal-1.16 {aux}/usr/bin/automake-1.16; "
    "sed -i 's#/usr/share/aclocal#{aux}/usr/share/aclocal#g' {aux}/usr/bin/aclocal-1.16; "
    "sed -i 's#/usr/share/autoconf#{aux}/usr/share/autoconf#g' "
    "{aux}/usr/bin/autoconf {aux}/usr/bin/autoheader; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/aclocal-1.16 "
    "--system-acdir={aux}/usr/share/aclocal-1.16 "
    "--automake-acdir={aux}/usr/share/aclocal-1.16 \"$@\"\\n' > $W/aclocal; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/automake-1.16 "
    "--libdir={aux}/usr/share/automake-1.16 \"$@\"\\n' > $W/automake; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/libtoolize \"$@\"\\n' > $W/libtoolize; "
    "chmod +x $W/aclocal $W/automake $W/libtoolize; "
    "autoreconf -fi"
)

_ONBOARD_AUTOTOOLS_ENV = {
    "PATH": "{root}/.autotools:{aux}/usr/bin:" + os.environ.get("PATH", ""),
    "PERL5LIB": "{aux}/usr/share/autoconf:{aux}/usr/share/automake-1.16",
    "ACLOCAL_PATH": "/usr/share/aclocal:{aux}/usr/share/aclocal",
    "AUTOM4TE": "{aux}/usr/bin/autom4te",
    "AUTOM4TE_CFG": "{aux}/usr/share/autoconf/autom4te.cfg",
    "AC_MACRODIR": "{aux}/usr/share/autoconf",
    "M4": "{aux}/usr/bin/m4",
    "trailer_m4": "{aux}/usr/share/autoconf/autoconf/trailer.m4",
    "autom4te_perllibdir": "{aux}/usr/share/autoconf",
    "AUTOCONF": "{aux}/usr/bin/autoconf",
    "AUTOHEADER": "{aux}/usr/bin/autoheader",
    "AUTOMAKE": "{root}/.autotools/automake",
    "ACLOCAL": "{root}/.autotools/aclocal",
    "LIBTOOLIZE": "{root}/.autotools/libtoolize",
}

# ssldump 1.8 needs libpcap, libnet and json-c (and the dbus runtime Debian's libpcap links).
_ONBOARD_SSLDUMP_AUX: tuple[dict, ...] = (
    _aux_deb("libp/libpcap", "libpcap0.8_1.10.3-1_amd64.deb",
             "856014904c4d7ec9a9ba864c546d91c059b9bf00c7c89eda6fd0a16045f8faac",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libp/libpcap", "libpcap0.8-dev_1.10.3-1_amd64.deb",
             "5f66e87262e42cc42a77d6acdb41098e4ff3e6db3bdba1b73189dea5a3afb88c",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             bin_dirs=("usr/bin",)),
    _aux_deb("d/dbus", "libdbus-1-3_1.14.10-1~deb12u1_amd64.deb",
             "18ee0ce5fab9f7b671e87da1e9fa18660e36e04a3402f24bdb8635e0ba1d35f6",
             library_dirs=("lib/x86_64-linux-gnu",)),
    _aux_deb("d/dbus", "libdbus-1-dev_1.14.10-1~deb12u1_amd64.deb",
             "967a42e91eaa7d1885721b374a28cb0d30a0e63daaccf5e3594180bec6072c76",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libn/libnet", "libnet1_1.1.6+dfsg-3.2_amd64.deb",
             "9e0677a92de3df272e3a87a4e1591a71cb8c03fdea2bac68908ac4177066bb7f",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libn/libnet", "libnet1-dev_1.1.6+dfsg-3.2_amd64.deb",
             "7cdbdbfe6d45dcff469667d8c990b02006964b556ee97bc60b70a149f1a07e7a",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("j/json-c", "libjson-c5_0.16-2_amd64.deb",
             "d0e1ed8637d1c26b9720f6057d6355f18378bba5cc2553e459d1632783c00d70",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("j/json-c", "libjson-c-dev_0.16-2_amd64.deb",
             "b91a921675bde7c777930f9f77e49010a754d787219104464ea0fce04a887337",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

# ircii needs a terminal library and the termcap compatibility header.
_ONBOARD_IRCII_AUX: tuple[dict, ...] = (
    _aux_deb("n/ncurses", "libncurses-dev_6.4-4_amd64.deb",
             "2ad228835756feb118bb131b32834bd23a09047e4de408cc5204cbb5dce0e4bb",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("n/ncurses", "libtinfo-dev_6.4-4_amd64.deb",
             "e1935c2006661f1cda0bfd35f12ea30f9d64a110f30a074d512efe6c9466bf86",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             links={"usr/lib/x86_64-linux-gnu/libtermcap.so": "libtinfo.so"}),
)

# xmlsec1's OpenSSL backend needs libxml2 (with the ICU headers Debian's libxml2 requires).
_ONBOARD_XMLSEC_AUX: tuple[dict, ...] = (
    _aux_deb("libx/libxml2", "libxml2_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "4460e39dda10a815881374217cde08474747cfa018358cd8612c14b390eff53b",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libx/libxml2", "libxml2-dev_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "e8ceacf656b1720e7a310e1d159439a356bfcb9f5fb0325907f26aa8590e5f70",
             include_dirs=("usr/include", "usr/include/libxml2"),
             library_dirs=(_AUX_MULTIARCH,), pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("i/icu", "libicu-dev_72.1-3+deb12u1_amd64.deb",
             "08bd4e3f4bd4fc725cf25e739edf0e7df5ac1826bdac9a7d990eea8f93b2d7a0",
             include_dirs=("usr/include",)),
)

# libevhtp's TLS path links the split libevent_openssl/core/extra/pthreads shared objects, each
# of which is its own Debian runtime package (the monolithic package carries only libevent.so).
_ONBOARD_LIBEVENT_AUX: tuple[dict, ...] = tuple(_LIBEVENT_AUX) + (
    _aux_deb("libe/libevent", "libevent-core-2.1-7_2.1.12-stable-8_amd64.deb",
             "4cebf4a24fb222ddbc5569df9960c5ff2da8b7ed71a02e13c79a59dcaf3b518a",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libe/libevent", "libevent-extra-2.1-7_2.1.12-stable-8_amd64.deb",
             "d9a04bd914fa70b9cd0c8f098c23d9e7b372ad69624901fbde4bc34c9af34c18",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libe/libevent", "libevent-pthreads-2.1-7_2.1.12-stable-8_amd64.deb",
             "798bbe7f492e176c287fc211e4a670eb64b10952720a036927357980d9a4a4b0",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libe/libevent", "libevent-openssl-2.1-7_2.1.12-stable-8_amd64.deb",
             "95e143ffc207f890f0069df588c1fcdca2962a209062859e3e7750680510f293",
             library_dirs=(_AUX_MULTIARCH,)),
)

# Apache's static mod_ssl build probes PCRE2 through its own -config script.
_ONBOARD_HTTPD_AUX: tuple[dict, ...] = (
    _aux_deb("p/pcre2", "libpcre2-8-0_10.42-1_amd64.deb",
             "030db54f4d76cdfe2bf0e8eb5f9efea0233ab3c7aa942d672c7b63b52dbaf935",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,), bin_dirs=("usr/bin",)),
)

_L7_ONBOARD_SPECS_D: tuple[dict, ...] = (
    {
        "family": "vsftpd", "version": "3.0.5",
        "url": "https://security.appspot.com/downloads/vsftpd-3.0.5.tar.gz",
        "archive": "tar.gz", "build_system": "make",
        "sha256": "26b602ae454b0ba6d99ef44a09b6b9e0dfa7f67228106736df1f278c70bc91d3",
        "configure": None,
        "pre_build": [["sed", "-i", "s/^#undef VSF_BUILD_SSL/#define VSF_BUILD_SSL/",
                       "builddefs.h"]],
        "make": [MAKE_JOBS,
                 "CFLAGS=-O2 -fPIE -fstack-protector --param=ssp-buffer-size=4 -Wall -W "
                 "-Wshadow -Wformat-security -D_FORTIFY_SOURCE=2 -I{prefix}/include",
                 "LINK=-Wl,-s -L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "artifact": "vsftpd", "launch": None,
        "note": ("vsftpd 3.0.5's control/data SSL path linked to the subject libssl; the admitted "
                 "workload logs in over AUTH TLS, protects the data channel and retrieves the "
                 "fixture, while a client trusting an unrelated CA is refused.  The recipe enables "
                 "upstream's disabled VSF_BUILD_SSL in builddefs.h as a build input."),
    },
    {
        "family": "apache2-bin", "version": "2.4.62",
        "url": "https://archive.apache.org/dist/httpd/httpd-2.4.62.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "3e2404d762a2da03560d7ada379ba1599d32f04a0d70ad6ff86f44325f2f062d",
        "configure": ["--with-ssl={prefix}", "--enable-ssl", "--enable-mods-static=ssl",
                      "--with-apr=/usr/bin/apr-1-config",
                      "--with-apr-util=/usr/bin/apu-1-config",
                      "--with-pcre={aux}/usr/bin/pcre2-config",
                      "--disable-authn-file", "--disable-authz-user",
                      "--disable-authz-groupfile", "--disable-authz-host",
                      "--disable-auth-digest", "--with-mpm=event"],
        "make": [MAKE_JOBS], "artifact": "httpd", "launch": ["-v"],
        "aux_sources": list(_ONBOARD_HTTPD_AUX),
        "note": ("Apache httpd 2.4.62 with mod_ssl compiled statically into the measured binary; "
                 "the admitted workload serves the fixture over verified TLS and a client trusting "
                 "an unrelated CA rejects the server certificate."),
    },
    {
        "family": "neon", "version": "0.34.0",
        "url": "https://notroj.github.io/neon/neon-0.34.0.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "2e3ee8535039966c80764f539d5c9bfee1651a17e2f36e5ca462632181253977",
        "configure": ["--with-ssl=openssl", "--with-expat", "--enable-shared",
                      "--disable-static"],
        "make": [MAKE_JOBS], "artifact": "src/.libs/libneon.so*", "launch": None,
        "env_extra": {"ne_cv_libsfor_SSL_library_init": "-lssl"},
        "note": ("libneon 0.34.0's OpenSSL TLS client linked to the subject libssl; the admitted "
                 "harness fetches the fixture over verified TLS and an unrelated CA is refused."),
    },
    {
        "family": "cjose", "version": "0.8.1",
        "url": "https://github.com/cisco/cjose/archive/refs/tags/0.8.1.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "1ee864ba216cfc2c38726b80b082abcee2772569241a6a822c6bd8d3fd35b8ae",
        "configure": ["--with-openssl={prefix}", "--disable-static"],
        "make": [MAKE_JOBS], "artifact": "src/.libs/libcjose.so*", "launch": None,
        "note": ("cjose 0.8.1's JWS HS256 path linked to the subject libcrypto; the admitted "
                 "harness signs, imports and verifies a compact JWS and rejects a tampered "
                 "signature and a wrong key."),
    },
    {
        "family": "ssldump", "version": "1.8",
        "url": "https://github.com/adulau/ssldump/archive/refs/tags/v1.8.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "fa1bb14034385487cc639fb32c12a5da0f8fbfee4603f4e101221848e46e72b3",
        "configure": ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_PREFIX_PATH={prefix};{aux}/usr",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include -I{aux}/usr/include",
                      "-DCMAKE_EXE_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
                      "-L{aux}/usr/lib/x86_64-linux-gnu -L{aux}/lib/x86_64-linux-gnu "
                      "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu "
                      "-Wl,-rpath,{aux}/lib/x86_64-linux-gnu -Wl,-l:libdbus-1.so.3"],
        "make": [], "artifact": "b/ssldump", "launch": ["-v"],
        "aux_sources": list(_ONBOARD_SSLDUMP_AUX),
        "note": ("ssldump 1.8's TLS record parser linked to the subject libcrypto; the admitted "
                 "workload captures a live loopback handshake and prints its ClientHello and "
                 "ServerHello, while a plaintext exchange yields no handshake record."),
    },
    {
        "family": "yara", "version": "4.5.2",
        "url": "https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.2.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "1f87056fcb10ee361936ee7b0548444f7974612ebb0e681734d8de7df055d1ec",
        "configure": ["--with-crypto", "--disable-magic", "--disable-cuckoo"],
        "make": [MAKE_JOBS], "artifact": ".libs/libyara.so*", "launch": ["--version"],
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "aux_sources": list(_ONBOARD_AUTOTOOLS_AUX),
        "note": ("YARA 4.5.2's hash module linked to the subject libcrypto; the admitted workload "
                 "matches a rule against the fixture's SHA-256 and a wrong digest does not match."),
    },
    {
        "family": "bruteforce-salted-openssl", "version": "1.4.2",
        "url": ("https://github.com/glv2/bruteforce-salted-openssl/archive/refs/tags/"
                "1.4.2.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "324092e60833329a13756b43c51269c1bd4a8cd339490217746ae0ee534efbac",
        "configure": [], "make": [MAKE_JOBS],
        "artifact": "bruteforce-salted-openssl", "launch": ["-h"],
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "aux_sources": list(_ONBOARD_AUTOTOOLS_AUX),
        "note": ("bruteforce-salted-openssl 1.4.2's EVP decrypt path linked to the subject "
                 "libcrypto; the admitted workload recovers the password from a pinned salted "
                 "ciphertext and a word list without it yields no candidate."),
    },
    {
        "family": "ircii", "version": "20240918",
        "url": "https://ircii.warped.com/ircii-20240918.tar.bz2",
        "archive": "tar.bz2", "build_system": "configure",
        "sha256": "f4b9b380ba5143261a3ef219abfdef749c44ce4f669908da60bc3997af649ca9",
        "configure": [],
        "make": [MAKE_JOBS,
                 "CFLAGS=-pipe -g -O2 -I{prefix}/include -I{aux}/usr/include",
                 "INCLUDES=-I. -I{root}/include -I{aux}/usr/include",
                 "LDFLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
                 "-L{aux}/usr/lib/x86_64-linux-gnu -Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu"],
        "artifact": "irc", "launch": ["-v"],
        "aux_sources": list(_ONBOARD_IRCII_AUX),
        "note": ("ircII 20240918's OpenSSL client (source/ssl.c) linked to the subject libssl; "
                 "the admitted workload registers and joins the fixture channel over verified "
                 "TLS, while a client trusting an unrelated CA never registers."),
    },
    {
        "family": "libevhtp", "version": "1.2.18",
        "url": "https://github.com/criticalstack/libevhtp/archive/refs/tags/1.2.18.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "316ede0d672be3ae6fe489d4ac1c8c53a1db7d4fe05edaff3c7c853933e02795",
        "configure": ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_PREFIX_PATH={prefix};{aux}/usr",
                      "-DEVHTP_DISABLE_SSL=OFF", "-DEVHTP_DISABLE_REGEX=ON",
                      "-DBUILD_SHARED_LIBS=ON",
                      "-DLIBEVENT_INCLUDE_DIR={aux}/usr/include",
                      "-DLIBEVENT_LIBRARY={aux}/usr/lib/x86_64-linux-gnu/libevent.so",
                      "-DLIBEVENT_CORE={aux}/usr/lib/x86_64-linux-gnu/libevent_core.so",
                      "-DLIBEVENT_EXTRA={aux}/usr/lib/x86_64-linux-gnu/libevent_extra.so",
                      "-DLIBEVENT_THREAD={aux}/usr/lib/x86_64-linux-gnu/libevent_pthreads.so",
                      "-DLIBEVENT_SSL={aux}/usr/lib/x86_64-linux-gnu/libevent_openssl.so",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include -I{aux}/usr/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
                      "-L{aux}/usr/lib/x86_64-linux-gnu "
                      "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu"],
        "make": [], "artifact": "b/libevhtp.so*", "launch": None,
        "aux_sources": list(_ONBOARD_LIBEVENT_AUX),
        "note": ("libevhtp 1.2.18's TLS server path linked to the subject libssl; the admitted "
                 "harness serves the fixture over verified TLS and an unrelated CA is refused."),
    },
    {
        "family": "libxmlsec1", "version": "1.3.12",
        "url": "https://github.com/lsh123/xmlsec/releases/download/1.3.12/xmlsec1-1.3.12.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "24045199af12d93fe5fdbbbf7e386e823e4842071e9432e2b90ac108b889a923",
        "configure": ["--with-openssl={prefix}", "--with-default-crypto=openssl",
                      "--enable-apps", "--disable-apps-crypto-dl", "--disable-crypto-dl"],
        "make": [MAKE_JOBS],
        "artifact": "src/openssl/.libs/libxmlsec1-openssl.so*", "launch": None,
        "aux_sources": list(_ONBOARD_XMLSEC_AUX),
        "note": ("xmlsec1 1.3.12's OpenSSL backend linked to the subject libcrypto; the admitted "
                 "xmlsec1 CLI signs a document with RSA-SHA256, verifies it, and rejects a "
                 "tampered document."),
    },
)

_L7_ONBOARD_SPECS_C: tuple[dict, ...] = (
    {
        "family": "icecast2", "version": "2.4.4",
        "url": "https://downloads.xiph.org/releases/icecast/icecast-2.4.4.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "49b5979f9f614140b6a38046154203ee28218d8fc549888596a683ad604e4d44",
        "configure": ["--with-openssl={prefix}", "--without-curl", "--without-speex",
                      "--without-theora", "--disable-yp"],
        "make": [MAKE_JOBS], "artifact": "src/icecast", "launch": ["-v"],
        "aux_sources": list(_ICECAST_AUX),
        "note": ("the icecast2 package row of icecast 2.4.4: its HTTPS listener serves the "
                 "fixture over the subject libssl and rejects an unrelated CA"),
    },
    {
        "family": "libevent-openssl-2.1-7", "version": "2.1.12-stable",
        "url": ("https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/"
                "libevent-2.1.12-stable.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb",
        "configure": ["--disable-samples", "--disable-libevent-regress"],
        "make": [MAKE_JOBS], "artifact": ".libs/libevent_openssl*.so*", "launch": None,
        "note": ("the libevent_openssl package row of libevent 2.1.12: a TLS1.3 bufferevent "
                 "round trip against the fixture CA, with an unrelated-CA reject"),
    },
    {
        "family": "libaprutil1", "version": "1.6.3",
        "url": "https://archive.apache.org/dist/apr/apr-util-1.6.3.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "2b74d8932703826862ca305b094eef2983c27b39d5c9414442e9976a9acf1983",
        "configure": ["--with-apr=/usr/bin/apr-1-config", "--with-crypto",
                      "--with-openssl={prefix}", "--disable-util-dso"],
        "make": [MAKE_JOBS], "artifact": ".libs/libaprutil-1.so*", "launch": None,
        "note": ("the libaprutil1 package row of apr-util 1.6.3: the OpenSSL crypto driver "
                 "plus a libssl handshake over an apr_socket, with a mutated-digest control"),
    },
)

# The Phase-25 L7 onboarding batch (b14): ten further consumers, each built from a pristine
# released archive against the subject prefix. `hcxkeys` is a declarative template row; the
# others carry a bespoke workload because their observable is a protocol decision (DoT, TLS
# echo, MQTT CONNACK, Icecast SOURCE, AMQP TLS open) or a file transform (PDF encryption, EFI
# signature list). Non-OpenSSL dependencies are pinned bookworm packages through `aux_sources,
# exactly as the earlier batches do, so the subject prefix remains the only OpenSSL.
_L7_ONBOARD_SPECS_B: tuple[dict, ...] = (
    {
        "family": "nmap-ncat", "version": "7.95",
        "url": "https://nmap.org/dist/nmap-7.95.tar.bz2",
        "archive": "tar.bz2", "build_system": "configure",
        "sha256": "e14ab530e47b5afd88f1c8a2bac7f89cd8fe6b478e22d255c5b9bddb7a1c5778",
        "configure": ["--with-openssl={prefix}", "--without-zenmap", "--without-nping",
                      "--without-nmap-update"],
        "make": [MAKE_JOBS, "build-ncat"],
        "artifact": "ncat/ncat", "launch": ["--version"],
        "note": ("Ncat 7.95's TLS transport linked to the subject libssl; the admitted workload "
                 "completes a verified TLS exchange carrying the payload and rejects an "
                 "unrelated CA"),
    },
    {
        "family": "unbound", "version": "1.22.0",
        "url": "https://www.nlnetlabs.nl/downloads/unbound/unbound-1.22.0.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "c5dd1bdef5d5685b2cedb749158dd152c52d44f65529a34ac15cd88d4b1b3d43",
        "configure": ["--with-ssl={prefix}", "--with-libevent=no", "--disable-sha1",
                      "--disable-ecdsa", "--disable-gost", "--without-pythonmodule",
                      "--without-pyunbound", "--disable-dnstap"],
        "make": [MAKE_JOBS], "artifact": "unbound", "launch": ["-V"],
        "note": ("Unbound 1.22.0's DNS-over-TLS forwarder path linked to the subject libssl: a "
                 "local TLS resolver serves a fixture zone and a forwarding resolver retrieves "
                 "it over DoT, while a resolver trusting only an unrelated CA cannot"),
    },
    {
        "family": "qpdf", "version": "11.9.1",
        "url": "https://github.com/qpdf/qpdf/releases/download/v11.9.1/qpdf-11.9.1.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "2ba4d248f9567a27c146b9772ef5dc93bd9622317978455ffe91b259340d13d1",
        "configure": ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DBUILD_DOC=OFF",
                      "-DBUILD_STATIC_LIBS=OFF", "-DREQUIRE_CRYPTO_OPENSSL=ON",
                      "-DDEFAULT_CRYPTO=openssl",
                      "-DCMAKE_C_FLAGS=-I{aux}/usr/include -I{aux}/usr/include/x86_64-linux-gnu",
                      "-DCMAKE_CXX_FLAGS=-I{aux}/usr/include "
                      "-I{aux}/usr/include/x86_64-linux-gnu"],
        "make": [], "artifact": "b/libqpdf/libqpdf.so*", "launch": ["--version"],
        "aux_sources": [
            _aux_deb("libj/libjpeg-turbo", "libjpeg62-turbo_2.1.5-2_amd64.deb",
                     "95ec30140789a342add8f8371ed018924de51b539056522b66f207b25cba9cad",
                     library_dirs=(_AUX_MULTIARCH,)),
            _aux_deb("libj/libjpeg-turbo", "libjpeg62-turbo-dev_2.1.5-2_amd64.deb",
                     "10485411f751c24472c43b28fe24ab6389fedb027d496bbc2c831496f750ab01",
                     include_dirs=("usr/include", "usr/include/x86_64-linux-gnu"),
                     library_dirs=(_AUX_MULTIARCH,), pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
        ],
        "note": ("qpdf 11.9.1's OpenSSL crypto provider (explicitly selected, REQUIRE_CRYPTO_OPENSSL) "
                 "encrypts a PDF with AES-256, reports the R=6 encryption parameters, decrypts it "
                 "with the right password and rejects the wrong one"),
    },
    {
        "family": "nagios-plugins-smtp", "version": "2.4.0",
        "url": "https://www.monitoring-plugins.org/download/monitoring-plugins-2.4.0.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "e5dfd4ad8fde0a40da50aab3aff6d9a27020b8f283e332bc4da6ef9914f4028c",
        "configure": ["--with-openssl={prefix}", "--without-pgsql", "--without-mysql",
                      "--without-ldap", "--without-dbi", "--without-radius",
                      "--without-libcurl", "--without-ssh", "--without-snmp",
                      "--without-nagios-xml", "--disable-nls"],
        "make": [MAKE_JOBS], "artifact": "plugins/check_smtp", "launch": ["-V"],
        "note": ("check_smtp 2.4.0's STARTTLS path linked to the subject libssl: a local SMTP "
                 "peer negotiates STARTTLS and the check succeeds, while a peer that does not "
                 "advertise STARTTLS is rejected"),
    },
    {
        "family": "efitools", "version": "1.9.2",
        "url": ("https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git/snapshot/"
                "efitools-1.9.2.tar.gz"),
        "archive": "tar.gz", "build_system": "make",
        "sha256": "0f315b36e7d1ba74bfc97ab9f304f0a3072c47578bbe5e42594acae381f9acfe",
        "configure": None,
        "make": [MAKE_JOBS, "sign-efi-sig-list", "cert-to-efi-sig-list",
                 "CC=gcc -L{prefix}/lib -Wl,-rpath,{prefix}/lib",
                 "CFLAGS=-O2 -g -fpic -fshort-wchar -fno-strict-aliasing "
                 "-fno-merge-constants -fno-stack-protector -ffreestanding -fno-stack-check "
                 "-DGNU_EFI_USE_MS_ABI -DEFI_FUNCTION_WRAPPER -mno-red-zone "
                 "-DCONFIG_x86_64 -fno-toplevel-reorder -I{aux}/usr/include -I{prefix}/include",
                 "INCDIR=-I{root}/include/ -I{aux}/usr/include -I{aux}/usr/include/efi "
                 "-I{aux}/usr/include/efi/x86_64 -I{aux}/usr/include/efi/protocol"],
        "artifact": "sign-efi-sig-list", "launch": ["-h"],
        "aux_sources": [
            _aux_deb("g/gnu-efi", "gnu-efi_3.0.15-1_amd64.deb",
                     "1e668cebcb94678b39a69e5c7b8f1d1eb51fd4eb251643491a8c249ae6fa0c36",
                     include_dirs=("usr/include",)),
        ],
        "note": ("efitools' EFI signature-list path linked to the subject libcrypto: a certificate "
                 "is encoded as an ESL and signed into an authenticated variable update, while a "
                 "key that does not match the certificate is rejected"),
    },
    {
        "family": "libpaho-mqtt", "version": "1.3.13",
        "url": "https://github.com/eclipse-paho/paho.mqtt.c/archive/refs/tags/v1.3.13.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "47c77e95609812da82feee30db435c3b7c720d4fd3147d466ead126e657b6d9c",
        "configure": ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DPAHO_BUILD_SHARED=TRUE",
                      "-DPAHO_BUILD_STATIC=FALSE", "-DPAHO_BUILD_SAMPLES=FALSE",
                      "-DPAHO_ENABLE_TESTING=FALSE", "-DPAHO_WITH_SSL=TRUE"],
        "make": [], "artifact": "b/src/libpaho-mqtt3cs.so*", "launch": None,
        "note": ("paho.mqtt.c's TLS client linked to the subject libssl; the admitted harness "
                 "completes MQTT CONNECT/CONNACK over TLS and rejects an unrelated CA"),
    },
    {
        "family": "nagios-plugins-ldap", "version": "2.4.0",
        "url": "https://www.monitoring-plugins.org/download/monitoring-plugins-2.4.0.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "e5dfd4ad8fde0a40da50aab3aff6d9a27020b8f283e332bc4da6ef9914f4028c",
        "configure": ["--with-openssl={prefix}", "--without-pgsql", "--without-mysql",
                      "--without-dbi", "--without-radius", "--without-libcurl",
                      "--without-ssh", "--without-snmp", "--without-nagios-xml",
                      "--disable-nls"],
        "make": [MAKE_JOBS], "artifact": "plugins/check_ldap", "launch": ["-V"],
        "note": ("check_ldap 2.4.0's LDAPS path linked to the subject libssl: a local LDAP peer "
                 "accepts the simple bind and search, while the wrong password is rejected"),
    },
    {
        "family": "srtp", "version": "2.6.0",
        "url": "https://github.com/cisco/libsrtp/archive/refs/tags/v2.6.0.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "bf641aa654861be10570bfc137d1441283822418e9757dc71ebb69a6cf84ea6b",
        "configure": ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DENABLE_OPENSSL=ON",
                      "-DLIBSRTP_TEST_APPS=OFF", "-DBUILD_SHARED_LIBS=ON"],
        "make": [], "artifact": "b/libsrtp2.so*", "launch": None,
        "note": ("libsrtp's OpenSSL crypto backend; the admitted harness protects an RTP packet "
                 "with AES-CM-128/HMAC-SHA1, unprotects it, and rejects a session with the wrong "
                 "key"),
    },
    {
        "family": "rabbitmq-c", "version": "0.15.0",
        "url": "https://github.com/alanxz/rabbitmq-c/archive/refs/tags/v0.15.0.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "7b652df52c0de4d19ca36c798ed81378cba7a03a0f0c5d498881ae2d79b241c2",
        "configure": ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DBUILD_SHARED_LIBS=ON",
                      "-DBUILD_EXAMPLES=OFF", "-DBUILD_TESTS=OFF", "-DBUILD_TOOLS=OFF",
                      "-DENABLE_SSL_SUPPORT=ON"],
        "make": [], "artifact": "b/librabbitmq/librabbitmq.so*", "launch": None,
        "note": ("rabbitmq-c's SSL socket linked to the subject libssl; the admitted harness "
                 "completes the TLS connection to a local peer and rejects an unrelated CA"),
    },
)

# lighttpd 1.4.76's release tarball carries `configure.ac` but no generated `configure`, and
# its TLS module is normally a dlopen'd `mod_openssl.so` (so the main executable imports no
# OpenSSL symbol). The recipe bootstraps the tarball's own configure with the pinned bookworm
# autotools, builds the static server (`LIGHTTPD_STATIC=yes`, the upstream-supported mode that
# compiles mod_openssl into `src/lighttpd`), and takes PCRE2 from the same pinned-package seam.
# The source tree stays pristine: the bootstrap writes generated build files only, exactly as
# the partclone/httperf recipes do.
_LIGHTTPD_AUX: tuple[dict, ...] = (
    _aux_deb("p/pcre2", "libpcre2-8-0_10.42-1_amd64.deb",
             "030db54f4d76cdfe2bf0e8eb5f9efea0233ab3c7aa942d672c7b63b52dbaf935",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("m/m4", "m4_1.4.19-3_amd64.deb",
             "b2dd7bfca426712416e651bb5ff6dabe7d05e4caebbac61d714dbe261b31e4c3",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autoconf", "autoconf_2.71-3_all.deb",
             "7d798ed8c21fc7387127de1dfdb4640003d8ba033ae5a1ff29559610cbd0c323",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/automake-1.16", "automake_1.16.5-1.3_all.deb",
             "f9a5758d87b5389bf2dbb00cc9c48e0cf59bb0ac842c5ce25d41e4bfa3f2f962",
             bin_dirs=("usr/bin",)),
    _aux_deb("a/autotools-dev", "autotools-dev_20220109.1_all.deb",
             "4d66dcb9c312566f1ca8d46ef0fb06fa4d4786c20b072c81f9d313b64ef981d0",
             bin_dirs=("usr/bin",)),
    _aux_deb("libt/libtool", "libtool_2.4.7-7~deb12u1_all.deb",
             "1c2e74f06b1d5d9a2c75e04ce87a99a8633058684439504ae8d715a4a088926c",
             bin_dirs=("usr/bin",)),
)

_LIGHTTPD_BOOTSTRAP = (
    "set -e; mkdir -p m4; W={root}/.autotools; mkdir -p $W; "
    "sed -i 's#/usr/share#{aux}/usr/share#g' {aux}/usr/bin/libtoolize; "
    "sed -i 's#/usr/share/autoconf#{aux}/usr/share/autoconf#g' "
    "{aux}/usr/share/autoconf/autom4te.cfg; "
    "sed -i 's#/usr/share/automake-1.16#{aux}/usr/share/automake-1.16#g' "
    "{aux}/usr/bin/aclocal-1.16 {aux}/usr/bin/automake-1.16; "
    "sed -i 's#/usr/share/aclocal#{aux}/usr/share/aclocal#g' {aux}/usr/bin/aclocal-1.16; "
    "sed -i 's#/usr/share/autoconf#{aux}/usr/share/autoconf#g' "
    "{aux}/usr/bin/autoconf {aux}/usr/bin/autoheader; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/aclocal-1.16 "
    "--system-acdir={aux}/usr/share/aclocal-1.16 "
    "--automake-acdir={aux}/usr/share/aclocal-1.16 \"$@\"\\n' > $W/aclocal; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/automake-1.16 "
    "--libdir={aux}/usr/share/automake-1.16 \"$@\"\\n' > $W/automake; "
    "printf '#!/bin/sh\\nexec {aux}/usr/bin/libtoolize \"$@\"\\n' > $W/libtoolize; "
    "chmod +x $W/aclocal $W/automake $W/libtoolize; "
    "autoreconf -fi; "
    # Upstream's static-server mode requires src/plugin-static.h (INSTALL: "create "
    # src/plugin-static.h with list of modules as PLUGIN_INIT(mod_foo)"). It is a generated
    # build input, not a source edit: the list is exactly the modules src/Makefile.am compiles
    # under `if LIGHTTPD_STATIC` for this configuration (the optional blocks stay disabled).
    "printf '%s\\n' "
    "'PLUGIN_INIT(mod_access)' 'PLUGIN_INIT(mod_accesslog)' 'PLUGIN_INIT(mod_ajp13)' "
    "'PLUGIN_INIT(mod_alias)' 'PLUGIN_INIT(mod_auth)' "
    "'PLUGIN_INIT(mod_authn_file)' 'PLUGIN_INIT(mod_cgi)' 'PLUGIN_INIT(mod_deflate)' "
    "'PLUGIN_INIT(mod_dirlisting)' 'PLUGIN_INIT(mod_evhost)' 'PLUGIN_INIT(mod_expire)' "
    "'PLUGIN_INIT(mod_extforward)' 'PLUGIN_INIT(mod_fastcgi)' 'PLUGIN_INIT(mod_indexfile)' "
    "'PLUGIN_INIT(mod_openssl)' 'PLUGIN_INIT(mod_proxy)' 'PLUGIN_INIT(mod_redirect)' "
    "'PLUGIN_INIT(mod_rewrite)' 'PLUGIN_INIT(mod_rrdtool)' 'PLUGIN_INIT(mod_scgi)' "
    "'PLUGIN_INIT(mod_setenv)' 'PLUGIN_INIT(mod_simple_vhost)' 'PLUGIN_INIT(mod_sockproxy)' "
    "'PLUGIN_INIT(mod_ssi)' 'PLUGIN_INIT(mod_staticfile)' 'PLUGIN_INIT(mod_status)' "
    "'PLUGIN_INIT(mod_userdir)' 'PLUGIN_INIT(mod_vhostdb)' "
    "'PLUGIN_INIT(mod_webdav)'"
    " > src/plugin-static.h"
)

_LIGHTTPD_ENV = {
    "PATH": "{root}/.autotools:{aux}/usr/bin:" + os.environ.get("PATH", ""),
    "PERL5LIB": "{aux}/usr/share/autoconf:{aux}/usr/share/automake-1.16",
    "ACLOCAL_PATH": "/usr/share/aclocal:{aux}/usr/share/aclocal:{aux}/usr/share/libtool/m4",
    "ACLOCAL": "{root}/.autotools/aclocal",
    "AUTOMAKE": "{root}/.autotools/automake",
    "LIBTOOLIZE": "{root}/.autotools/libtoolize",
    "AUTOPOINT": "true",
    "AUTOCONF": "{aux}/usr/bin/autoconf",
    "AUTOHEADER": "{aux}/usr/bin/autoheader",
    "AUTOM4TE": "{aux}/usr/bin/autom4te",
    "AUTOM4TE_CFG": "{aux}/usr/share/autoconf/autom4te.cfg",
    "AC_MACRODIR": "{aux}/usr/share/autoconf",
    "trailer_m4": "{aux}/usr/share/autoconf/autoconf/trailer.m4",
    "autom4te_perllibdir": "{aux}/usr/share/autoconf",
    "M4": "{aux}/usr/bin/m4",
    # Upstream's supported static-server mode: compiles every enabled module (including
    # mod_openssl) into the executable, so the artifact itself names libssl/libcrypto.
    "LIGHTTPD_STATIC": "yes",
}

_LATE_RECIPE_OVERRIDES: dict[str, dict] = {
    "lighttpd": {
        "build_system": "configure",
        "configure": ["--with-openssl={prefix}", "--with-pcre2"],
        "make": [MAKE_JOBS],
        "artifact": "src/lighttpd",
        "aux_sources": list(_LIGHTTPD_AUX),
        "pre_build": [["sh", "-c", _LIGHTTPD_BOOTSTRAP]],
        "env_extra": dict(_LIGHTTPD_ENV),
        "note": ("lighttpd 1.4.76 with its TLS module: the release tarball ships configure.ac "
                 "only, so the recipe bootstraps it with the pinned bookworm autotools, takes "
                 "PCRE2 from its pinned package, and builds the statically-linked server so "
                 "mod_openssl is part of the measured executable. No source is edited."),
    },
    "libssh": {
        "build_system": "cmake",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DCMAKE_INSTALL_PREFIX={root}/.l7-install",
                      "-DWITH_GSSAPI=OFF", "-DWITH_ZLIB=ON", "-DWITH_PCAP=OFF",
                      "-DWITH_SERVER=OFF", "-DBUILD_EXAMPLES=OFF", "-DUNIT_TESTING=OFF"],
        "make": [], "artifact": "b/lib/libssh.so*", "launch": None,
        # S44 re-pin: www.libssh.org is unreachable from the court (curl exit 7, reproduced after
        # S42).  The Debian pool carries the identical upstream 0.10.6 release archive; the
        # observed SHA-256 is byte-for-byte the value `_CENSUS_PINS` already asserts.
        "url": "https://deb.debian.org/debian/pool/main/libs/libssh/libssh_0.10.6.orig.tar.xz",
        "archive": "tar.xz",
        "sha256": "1861d498f5b6f1741b6abc73e608478491edcf9c9d4b6630eef6e74596de9dc1",
        "note": ("libssh 0.10.6 (Debian pool re-pin, S44) built by CMake against the subject "
                 "libssl/libcrypto; the admitted workload imports a pinned RSA private key and "
                 "checks its exported public blob"),
    },
    "sslscan": {
        # S44 re-pin: the upstream GitHub tag archive was lost to a transient DNS failure.  The
        # Debian pool's 2.1.5 orig archive is the same bytes (the observed digest equals the pin).
        "url": "https://deb.debian.org/debian/pool/main/s/sslscan/sslscan_2.1.5.orig.tar.gz",
        "archive": "tar.gz",
        "sha256": "b36616b1d59f3276af6ff9495ab8178ec6812393582fb3c094c56cc873efe956",
        "note": ("sslscan 2.1.5 (Debian pool re-pin, S44) scans the authority's local TLS1.3 "
                 "server and confirms TLS1.3 is disabled on a TLS1.2-only server"),
    },
}

# --------------------------------------------------------------------------------------------
# Phase-25 L7 split-row batch (c2, 2026-10-22).
#
# Ten frozen-P1000 families that are package rows of an upstream this venue already builds and
# already drives with an admitted workload.  Each row is the same pristine archive, the same
# build intent and the same `{prefix}` substitution as its parent; only the package's own
# artifact (and, for cyrus-sasl-md5, the mechanism the harness selects) differs.  No candidate
# is patched and no new source is introduced.  `libfsverity` and `monitoring-plugins` are
# declared in the template layer's family registry instead, because their workload is a bucket.
# --------------------------------------------------------------------------------------------
# The Phase-25 L7 onboarding batch (b16): ten consumers with a deterministic local workload.
# Same pristine-source/aux seam; each recipe names only the non-OpenSSL packages its own build
# needs, and the subject prefix remains the only OpenSSL on the link line.
# --------------------------------------------------------------------------------------------

_B16_AUTOTOOLS_AUX: tuple[dict, ...] = tuple(_ONBOARD_AUTOTOOLS_AUX) + (
    _aux_deb("libt/libtool", "libltdl-dev_2.4.7-7~deb12u1_amd64.deb",
             "60ad26b3007d4304a1141649d4e764a27735ff4f1835a62c845d51bd734932b0",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libt/libtool", "libltdl7_2.4.7-7~deb12u1_amd64.deb",
             "8070b550321d4bd1c298f52f75374898d39112b709026d2ea5362ef1277b775a",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("b/bison", "bison_3.8.2+dfsg-1+b1_amd64.deb",
             "a414afd7519c53bfa33415ba5b951bc8b4906877004c49723ffda50a6033c3e8",
             bin_dirs=("usr/bin",)),
    _aux_deb("f/flex", "flex_2.6.4-8_amd64.deb",
             "6e356fec04533fb809a1d332ac74cd5f10e86841694e2fde69fcb1ef35ecbde5",
             bin_dirs=("usr/bin",)),
)

_B16_PCRE_AUX: tuple[dict, ...] = (
    _aux_deb("p/pcre3", "libpcre3_8.39-15_amd64.deb",
             "993ea623ce5b42d67f653f2faaa7ef15e7c9d72bfcb93e22a1eaff7aa3532303",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/pcre3", "libpcre3-dev_8.39-15_amd64.deb",
             "a2bd77ac61b2dbbbc6cac3f7238780a591cf23774f9f0b1fc79d1c07b6d7f0c4",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             bin_dirs=("usr/bin",), links={"usr/include/pcre": "."}),
)

_B16_NCURSES_AUX: tuple[dict, ...] = (
    _aux_deb("n/ncurses", "libncurses-dev_6.4-4_amd64.deb",
             "2ad228835756feb118bb131b32834bd23a09047e4de408cc5204cbb5dce0e4bb",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_B16_SSCG_AUX: tuple[dict, ...] = (
    _aux_deb("t/talloc", "libtalloc2_2.4.0-f2_amd64.deb",
             "2cbba68ca13003a0da794f5bcc44d95d0a191514fdd2d2764858b37215f0867c",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("t/talloc", "libtalloc-dev_2.4.0-f2_amd64.deb",
             "f2d37c120625bedd410b2d53e1c866855cbabae0138b5b004c6a8cac901c1296",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("p/popt", "libpopt0_1.19+dfsg-1_amd64.deb",
             "6f94b488255acd996254f775c77ff3956557c61f860a3c9caeaf65457554194f",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/popt", "libpopt-dev_1.19+dfsg-1_amd64.deb",
             "0f1c2bcc8270f6f06a3f351efd43296ad4793fe1daf641b7d9f0428dc7d141a2",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("h/help2man", "help2man_1.49.3_amd64.deb",
             "9b17251751ee4e813df789ba39c25841b9e26bf44206fd53ce4d34bc2d761eed",
             bin_dirs=("usr/bin",)),
    _aux_deb("libl/liblocale-gettext-perl",
             "liblocale-gettext-perl_1.07-5_amd64.deb",
             "fe524a9de7ed6b2a1465693f12d5f7be2d2d9f6d6e6bf028f17109263e173dc8"),
)

_B16_UV_AUX: tuple[dict, ...] = (
    _aux_deb("libu/libuv1", "libuv1_1.44.2-1+deb12u1_amd64.deb",
             "204f0e13354b44e6d19317887a53dab6f26696e8d95838db970b81f2a393f7fd",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libu/libuv1", "libuv1-dev_1.44.2-1+deb12u1_amd64.deb",
             "7cf6e1d98c3a39084bd7f62e4769c36a303f7af53f70811ba94edb3f17526a10",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_B16_OGG_AUX: tuple[dict, ...] = (
    _aux_deb("libo/libogg", "libogg0_1.3.5-3_amd64.deb",
             "f67acb0477aed0354f411172e37af338f3ac6bd4f3766134a2cf5539884b5a28",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libo/libogg", "libogg-dev_1.3.5-3_amd64.deb",
             "ece2ef4d087d27b77b6c1a240efdb8b32dc2d19f69f7ce7fbb184c83a132d49c",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_B16_NGHTTP2_AUX: tuple[dict, ...] = tuple(_LIBEV_AUX) + (
    _aux_deb("c/c-ares", "libc-ares2_1.18.1-3_amd64.deb",
             "087fd5c2ac883202e1786ab45617cdab7f77bc7f060d58cca177ddf6b6c3fa73",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("c/c-ares", "libc-ares-dev_1.18.1-3_amd64.deb",
             "fd031e01ade61a16e9d71776e6d235c637c0514f88b241a27b5e51af5aa39dc2",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libx/libxml2", "libxml2_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "4460e39dda10a815881374217cde08474747cfa018358cd8612c14b390eff53b"),
    _aux_deb("libx/libxml2", "libxml2-dev_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "e8ceacf656b1720e7a310e1d159439a356bfcb9f5fb0325907f26aa8590e5f70",
             include_dirs=("usr/include", "usr/include/libxml2"),
             library_dirs=(_AUX_MULTIARCH,), pkgconfig_dirs=(_AUX_MULTIARCH_PC,),
             bin_dirs=("usr/bin",)),
    _aux_deb("i/icu", "libicu-dev_72.1-3+deb12u1_amd64.deb",
             "08bd4e3f4bd4fc725cf25e739edf0e7df5ac1826bdac9a7d990eea8f93b2d7a0",
             include_dirs=("usr/include",)),
)

_B16_CHARYBDIS_ENV = dict(_ONBOARD_AUTOTOOLS_ENV,
                          CFLAGS="-include time.h -D_GNU_SOURCE",
                          BISON_PKGDATADIR="{aux}/usr/share/bison")

# charybdis ships configure.ac only, and its own autogen.sh drives aclocal/automake for the
# root and for librb.  The pinned autotools need the same /usr/share rewrite and wrapper
# creation the other autotools recipes use; only the shared bootstrap's final
# `autoreconf -fi` is omitted, because charybdis's autogen.sh performs that step itself.
_B16_CHARYBDIS_BOOTSTRAP = (_ONBOARD_AUTOTOOLS_BOOTSTRAP.rsplit("autoreconf -fi", 1)[0]
                            + "true")

_L7_ONBOARD_SPECS_E: tuple[dict, ...] = (
    {
        "family": "sscg", "version": "4.0.3",
        "url": "https://deb.debian.org/debian/pool/main/s/sscg/sscg_4.0.3.orig.tar.xz",
        "archive": "tar.xz", "build_system": "meson",
        "sha256": "08123b2c73e41df3a744fa01c7b737942a248e6510ff57f3c19b14fc55fe9bed",
        "configure": ["--prefix={root}/.l7-install"], "make": [],
        "artifact": "b/sscg", "launch": ["--version"],
        "aux_sources": list(_B16_SSCG_AUX),
        "env_extra": {"PERL5LIB": "{aux}/usr/lib/x86_64-linux-gnu/perl5/5.36"},
        "note": ("sscg 4.0.3 mints a CA and a service certificate through the subject libcrypto; "
                 "the admitted workload verifies the chain and an unrelated CA fails"),
    },
    {
        "family": "shellinabox", "version": "2.21+really2.21",
        "url": ("https://deb.debian.org/debian/pool/main/s/shellinabox/"
                "shellinabox_2.21+really2.21.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "autotools",
        "sha256": "2ba4f142181a1e69734a1974afc01af353ea8aaf6840dd41503cb59855b3db80",
        "configure": ["--prefix={root}/.l7-install", "--enable-ssl",
                      "--disable-runtime-loading"], "make": [MAKE_JOBS],
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV, LIBS="-lssl -lcrypto"),
        "aux_sources": list(_B16_AUTOTOOLS_AUX),
        "artifact": "shellinaboxd", "launch": ["--version"],
        "note": ("shellinabox 2.21 serves its web terminal over a verified TLS listener; a "
                 "client trusting an unrelated CA is rejected"),
    },
    {
        "family": "charybdis", "version": "4.1.2",
        "url": ("https://github.com/atheme/charybdis/archive/refs/tags/"
                "charybdis-4.1.2.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "a3f4e572877c5a3abdab3af652746c0682f0c41b3f9e3c9866315f5d03f2bb57",
        "configure": ["--prefix={root}/.l7-install", "--enable-openssl={prefix}"],
        "make": [MAKE_JOBS],
        "pre_build": [["sh", "-c", _B16_CHARYBDIS_BOOTSTRAP], ["sh", "autogen.sh"]],
        "env_extra": dict(_B16_CHARYBDIS_ENV),
        "aux_sources": list(_B16_AUTOTOOLS_AUX),
        "artifact": "librb/src/.libs/librb.so*", "launch": ["--version"],
        "note": ("charybdis 4.1.2 listens with a TLS listener; the admitted workload completes "
                 "the IRC greeting over a verified TLS session, and an unrelated CA is refused"),
    },
    {
        "family": "afflib", "version": "3.7.20",
        "url": "https://deb.debian.org/debian/pool/main/a/afflib/afflib_3.7.20.orig.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "7264d705ff53185f0847c69abdfce072779c0b907257e087a6372c7608108f65",
        "configure": ["--prefix={root}/.l7-install", "--disable-python"],
        "make": [MAKE_JOBS],
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "aux_sources": list(_B16_AUTOTOOLS_AUX),
        "artifact": "lib/.libs/libafflib.so*", "launch": None,
        "note": ("AFFLIB 3.7.20's affsign signs an AFF image with the subject libcrypto; the "
                 "admitted workload verifies it and a tampered image no longer verifies"),
    },
    {
        "family": "httest", "version": "2.4.23",
        "url": "https://deb.debian.org/debian/pool/main/h/httest/httest_2.4.23.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "91906cc7191b5f1b71500fb13d5822ce3b6c9c702c85234e2f5ac2abc7f4ab12",
        "configure": ["--prefix={root}/.l7-install", "--with-ssl={prefix}"],
        "make": [MAKE_JOBS],
        "env_extra": {"CFLAGS": "-fcommon"},
        "aux_sources": list(_B16_PCRE_AUX),
        "artifact": "src/httest", "launch": ["--version"],
        "note": ("httest 2.4.23 drives an HTTPS request over a verified TLS session with its "
                 "own CA option; an unrelated CA is refused"),
    },
    {
        "family": "sipp", "version": "3.7.3",
        "url": "https://github.com/SIPp/sipp/releases/download/v3.7.3/sipp-3.7.3.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "f7cf9ced5e2915c6aa8d88b48a32869ce5bc1f23b0b8da0de4df928db4925bf7",
        "configure": ["-DUSE_SSL=1", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_C_FLAGS=-I{aux}/usr/include",
                      "-DCMAKE_CXX_FLAGS=-I{aux}/usr/include -Wno-stringop-overflow "
                      "-Wno-array-bounds"],
        "make": [],
        "aux_sources": list(_B16_NCURSES_AUX),
        "artifact": "b/sipp", "launch": ["-v"],
        "note": ("SIPp 3.7.3 completes a SIP call between its own UAS and UAC over verified "
                 "TLS; an unrelated CA is refused"),
    },
    {
        "family": "dma", "version": "0.14",
        "url": "https://deb.debian.org/debian/pool/main/d/dma/dma_0.14.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make",
        "sha256": "a36e77a59dd288a582dbeed7166ac4212e39120323bac75c74d7923e1d7b63e8",
        "configure": None,
        "make": [MAKE_JOBS, "YACC=bison -y", "LEX=flex"],
        "env_extra": {"BISON_PKGDATADIR": "{aux}/usr/share/bison",
                      "M4": "{aux}/usr/bin/m4"},
        "aux_sources": list(_B16_AUTOTOOLS_AUX),
        "artifact": "dma", "launch": ["-h"],
        "note": ("DMA 0.14 submits a message to a local SMTPS peer over verified TLS; an "
                 "unrelated CA is refused and no message is delivered"),
    },
    {
        "family": "h2o", "version": "2.2.6",
        "url": "https://github.com/h2o/h2o/archive/refs/tags/v2.2.6.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "f8cbc1b530d85ff098f6efc2c3fdbc5e29baffb30614caac59d5c710f7bda201",
        "configure": ["-DWITH_BUNDLED_SSL=OFF", "-DWITH_MRUBY=OFF",
                      "-DWITH_PICOTLS=OFF", "-DCMAKE_BUILD_TYPE=Release",
                      "-DCMAKE_C_FLAGS=-I{aux}/usr/include"],
        "make": [],
        "aux_sources": list(_B16_UV_AUX),
        "artifact": "b/h2o", "launch": ["--version"],
        "note": ("h2o 2.2.6 serves the fixture over a verified TLS listener; a client trusting "
                 "an unrelated CA is rejected"),
    },
    {
        "family": "libshout", "version": "2.4.6",
        "url": "https://downloads.xiph.org/releases/libshout/libshout-2.4.6.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "39cbd4f0efdfddc9755d88217e47f8f2d7108fa767f9d58a2ba26a16d8f7c910",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--with-ogg={aux}/usr"],
        "make": [MAKE_JOBS],
        "aux_sources": list(_B16_OGG_AUX),
        "artifact": "src/.libs/libshout.so*", "launch": None,
        "note": ("libshout 2.4.6 streams to an Icecast source endpoint over verified TLS; a "
                 "client trusting an unrelated CA is refused"),
    },
    {
        "family": "nghttp2", "version": "1.64.0",
        "url": ("https://github.com/nghttp2/nghttp2/releases/download/v1.64.0/"
                "nghttp2-1.64.0.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "20e73f3cf9db3f05988996ac8b3a99ed529f4565ca91a49eb0550498e10621e8",
        "configure": ["--prefix={root}/.l7-install", "--enable-app", "--with-openssl",
                      "--with-libxml2", "--with-jansson", "--with-libev",
                      "--without-libevent-openssl"],
        "make": [MAKE_JOBS],
        "pkgconfig_shim": True,
        "aux_sources": list(_B16_NGHTTP2_AUX),
        "artifact": "src/.libs/nghttp", "launch": ["--version"],
        "note": ("nghttp2 1.64.0's nghttp client fetches from its own nghttpd over verified "
                 "TLS; a client trusting an unrelated CA is refused"),
    },
)

_L7_SPLIT_RECIPES: tuple[tuple[str, str, dict], ...] = (
    ("libcjose0", "cjose", {
        "artifact": "src/.libs/libcjose.so*",
        "note": ("the libcjose0 package row of cjose 0.8.1: the same JWS HS256 harness signs, "
                 "imports and verifies a compact JWS, and rejects a tampered signature and a "
                 "wrong key"),
    }),
    ("libgetdns10", "getdns", {
        "artifact": "b/libgetdns.so*",
        "note": ("the libgetdns10 package row of getdns 1.7.3: the same DNS-over-TLS client "
                 "harness retrieves the fixture A record and rejects an unrelated CA"),
    }),
    ("asterisk-srtp", "srtp", {
        "artifact": "b/libsrtp2.so*",
        "note": ("the asterisk-srtp package row of libsrtp 2.6.0: the same AES-CM/HMAC "
                 "protect/unprotect harness rejects a session with the wrong key"),
    }),
    ("epic5-lite", "epic5", {
        "artifact": "source/epic5",
        "note": ("the epic5-lite package row of epic5 3.0.3: the same IRC-over-TLS client "
                 "registers and joins the fixture channel and refuses the unrelated CA"),
    }),

    ("httpd", "apache2-bin", {
        "artifact": "httpd",
        "note": ("the httpd package row of Apache 2.4.62: static mod_ssl serves the fixture "
                 "over verified TLS and an unrelated CA is refused"),
    }),
    ("librabbitmq", "rabbitmq-c", {
        "artifact": "b/librabbitmq/librabbitmq.so*",
        "note": ("the librabbitmq package row of rabbitmq-c 0.15.0: the same TLS socket "
                 "harness completes the connection and rejects an unrelated CA"),
    }),

    # S44 package rows of upstreams this catalogue already builds and drives.  Each row is the
    # same pristine archive, the same build intent and the same admitted workload; only the
    # distribution's own package name (and, where the package names it, artifact pattern) differs.
    ("h2o-evloop0.13", "h2o", {
        "artifact": "b/h2o",
        "note": ("the h2o-evloop0.13 package row of h2o 2.2.6: the same verified TLS "
                 "listener serves the fixture and rejects an unrelated CA"),
    }),
    ("libafflib0v5", "afflib", {
        "artifact": "lib/.libs/libafflib.so*",
        "note": ("the libafflib0v5 package row of AFFLIB 3.7.20: the same affsign "
                 "sign/verify workload and tampered-image rejection"),
    }),
    ("apache2-ssl", "apache2-bin", {
        "artifact": "httpd",
        "note": ("the apache2-ssl package row of Apache 2.4.62: the same statically-linked "
                 "mod_ssl httpd serves the fixture over verified TLS"),
    }),
    ("nagios-plugins-tcp", "monitoring-plugins", {
        "artifact": "plugins/check_tcp",
        "note": ("the nagios-plugins-tcp package row of monitoring-plugins 2.4.0: check_tcp's "
                 "own --ssl path completes the TLS handshake with the fixture and refuses a "
                 "plaintext peer"),
    }),
)

# S46 package rows are split from parents that the S46 batch itself appends, so they are applied
# after `_S46_SPECS` (see `_build_catalogue`).
_S46_SPLIT_RECIPES: tuple[tuple[str, str, dict], ...] = (
    ("cyrus-sasl-ntlm", "cyrus-sasl-scram", {
        "artifact": "plugins/.libs/libntlm.so*",
        "configure": ["--with-openssl={prefix}", "--disable-static", "--enable-shared",
                      "--disable-otp", "--disable-ldapdb", "--without-pam", "--disable-sql",
                      "--enable-ntlm"],
        "note": ("the cyrus-sasl-ntlm package row of cyrus-sasl 2.1.28: the NTLM plugin's "
                 "MD4/HMAC-MD5 path linked to the subject libcrypto"),
    }),
    ("unbound-anchor", "unbound", {
        "artifact": "unbound-anchor",
        "note": ("the unbound-anchor package row of Unbound 1.22.0: the root trust-anchor "
                 "update path through the subject libcrypto"),
    }),
    ("krb5-k5tls", "krb5", {
        "artifact": "src/plugins/tls/k5tls.so",
        "configure": ["--with-crypto-impl=openssl", "--disable-static", "--enable-k5tls"],
        "note": ("the krb5-k5tls package row of MIT krb5 1.20.1: the OpenSSL-backed k5tls "
                 "plugin linked to the subject libssl"),
    }),
    ("canl-c-examples", "canl-c", {
        "artifact": ".libs/client",
        "note": ("the canl-c-examples package row of canl-c 3.0.0: the shipped client "
                 "example performs proxy-certificate operations through the subject libcrypto"),
    }),
    ("libdigidoc-tools", "libdigidoc2", {
        "artifact": "b/libdigidoc/cdigidoc",
        "note": ("the libdigidoc-tools package row of libdigidoc 3.10.5: the cdigidoc tool "
                 "signs and verifies a container with the subject libcrypto"),
    }),
    ("ewf-tools", "libewf", {
        "artifact": "ewftools/.libs/ewfverify",
        "note": ("the ewf-tools package row of libewf 20140813: ewfverify recomputes the "
                 "image digest with the subject libcrypto"),
    }),
    ("libfsapfs-utils", "libfsapfs1", {
        "artifact": "fsapfstools/fsapfsinfo",
        "note": ("the libfsapfs-utils package row of libfsapfs 20201107: the image-information "
                 "tool through the subject libcrypto"),
    }),
    ("perl-crypt-ssleay", "libcrypt-ssleay-perl", {
        "artifact": "blib/arch/auto/Crypt/SSLeay/SSLeay.so",
        "note": ("the CPAN-name row of Crypt::SSLeay 0.73_06: the same XS TLS client "
                 "handshake and unrelated-CA reject"),
    }),
)

# ima-evm-utils 1.4 is the only new upstream in this batch: its `evmctl` signs and verifies a
# file's extended-attribute digest with the subject libcrypto.  The release ships configure.ac
# only, so the pinned bookworm autotools regenerate `configure` as a build input (never a source
# edit).  keyutils is the one non-OpenSSL dependency and comes from pinned bookworm packages.
_L7_IMA_AUX: tuple[dict, ...] = (
    _aux_deb("k/keyutils", "libkeyutils1_1.6.3-2_amd64.deb",
             "cfac89e6a7a54ff3c6a4f843310e25efeddaa771baeae470bd98bd588c373563",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("k/keyutils", "libkeyutils-dev_1.6.3-2_amd64.deb",
             "b26aa6df93bbf977f3b945ea7329cb89cc800b93cc0e4a3542c964f3e387d64a",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

_L7_IMA_SPEC: dict = {
    "family": "ima-evm-utils", "version": "1.4",
    "url": "https://deb.debian.org/debian/pool/main/i/ima-evm-utils/ima-evm-utils_1.4.orig.tar.gz",
    "archive": "tar.gz", "build_system": "autotools",
    "sha256": "fcf85b31d6292051b3679e5f17ffa7f89b6898957aad0f59aa4e9878884b27d1",
    "configure": ["--disable-tests"], "make": [MAKE_JOBS],
    "artifact": "src/.libs/evmctl", "launch": ["--version"],
    "aux_sources": list(_ONBOARD_AUTOTOOLS_AUX) + list(_L7_IMA_AUX),
    "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
    "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
    "note": ("ima-evm-utils 1.4's evmctl signs a file's IMA digest with the subject libcrypto "
             "and verifies it; a modified file no longer verifies"),
}


# --------------------------------------------------------------------------------------------
# S23 downstream corpus batch: PKCS#12 / CMS / PKCS#7 / OCSP / X.509 verification /
# raw-key / legacy-ENGINE / DTLS / session / TLS-transport surface.
#
# Every entry is a pristine released archive pinned by the digest this subphase actually
# observed.  The non-OpenSSL dependencies are pinned bookworm packages (headers and the
# matching runtime) or CPAN/upstream archives; none of them provides or replaces libssl or
# libcrypto.  `{prefix}` is the only subject substitution.
# --------------------------------------------------------------------------------------------


def _s23_deb(pool: str, filename: str, sha256: str, *, include_dirs: tuple[str, ...] = (),
             library_dirs: tuple[str, ...] = (), pkgconfig_dirs: tuple[str, ...] = (),
             bin_dirs: tuple[str, ...] = (), links: dict[str, str] | None = None) -> dict:
    """One pinned bookworm package, fetched over https from the same pool bytes."""
    spec: dict = {
        "url": f"https://deb.debian.org/debian/pool/main/{pool}/{filename}",
        "sha256": sha256, "archive": "deb", "extract": ["dpkg-deb", "-x"],
        "note": f"pinned bookworm {filename}",
    }
    for key, value in (("include_dirs", include_dirs), ("library_dirs", library_dirs),
                       ("pkgconfig_dirs", pkgconfig_dirs), ("bin_dirs", bin_dirs),
                       ("links", links)):
        if value:
            spec[key] = dict(value) if key == "links" else list(value)
    return spec


# Pure-Perl build dependencies plus the three XS modules the modules under test require.
# The pure-Perl packages are inert with respect to OpenSSL; the XS modules are rebuilt
# against the subject from their pristine sources in the recipe's pre-build step.
_S23_PERL_AUX: tuple[dict, ...] = (
    _s23_deb("libc/libcrypt-openssl-guess-perl",
             "libcrypt-openssl-guess-perl_0.15-2_all.deb",
             "839036eef0525e233feb97cae40d01040d6ef56806221a0dc727b077c5f88f19"),
    _s23_deb("libc/libcrypt-urandom-perl", "libcrypt-urandom-perl_0.36-3_all.deb",
             "d938ab3b3cce3b6628856fe37172da3bc1b6e9fb3a8383bef54fc46691e83231"),
    _s23_deb("libe/libextutils-cchecker-perl",
             "libextutils-cchecker-perl_0.12-1_all.deb",
             "19c435e04b5b97ad0ffb2f5346b4995c4f15600f407d7dce5f43002cf74d39aa"),
    _s23_deb("libe/libextutils-pkgconfig-perl",
             "libextutils-pkgconfig-perl_1.16-5_all.deb",
             "a6e03e69681611db003d0b2916f6f535f70900f9adf8b634e162dd3253034ad8"),
    _s23_deb("libc/libconvert-asn1-perl", "libconvert-asn1-perl_0.34-1_all.deb",
             "13270108fcda40778f680bb997764996e0e7a138b26401a4b44e71e9cde3cda3"),
    {
        "url": ("https://deb.debian.org/debian/pool/main/libc/"
                "libcrypt-openssl-bignum-perl/"
                "libcrypt-openssl-bignum-perl_0.09.orig.tar.gz"),
        "sha256": "234e72fb8396d45527e6fd45e43759c5c3f3a208cf8f29e6a22161a996fd42dc",
        "archive": "tar.gz", "extract": ["tar", "xf"],
        "note": "Crypt::OpenSSL::Bignum 0.09 source (rebuilt against the subject)",
    },
    {
        "url": ("https://deb.debian.org/debian/pool/main/libc/"
                "libcrypt-openssl-random-perl/"
                "libcrypt-openssl-random-perl_0.15.orig.tar.gz"),
        "sha256": "f0876faa1ba3111e39b86aa730c603211eff2905e460c72a57b61e8cf475cef4",
        "archive": "tar.gz", "extract": ["tar", "xf"],
        "note": "Crypt::OpenSSL::Random 0.15 source (rebuilt against the subject)",
    },
    {
        "url": ("https://deb.debian.org/debian/pool/main/libc/"
                "libcrypt-openssl-rsa-perl/"
                "libcrypt-openssl-rsa-perl_0.33.orig.tar.gz"),
        "sha256": "bdbe630f6d6f540325746ad99977272ac8664ff81bd19f0adaba6d6f45efd864",
        "archive": "tar.gz", "extract": ["tar", "xf"],
        "note": "Crypt::OpenSSL::RSA 0.33 source (PKCS10 runtime dependency)",
    },
)

# The build-time environment: the pure-Perl packages live under the pinned deb roots; the
# XS dependencies are built first and copied into the family tree so the runtime PERL5LIB
# is self-contained (the runtime tool cannot name `{aux}` in a program environment).
_S23_PERL_BUILD_ENV = {
    "OPENSSL_PREFIX": "{prefix}",
    "LD_LIBRARY_PATH": "{prefix}/lib",
    "PERL5LIB": ("{aux}/usr/share/perl5:{aux}/usr/lib/x86_64-linux-gnu/perl5/5.36:"
                 "{root}/.perl-deps/lib:{root}/.perl-deps/arch"),
}

_S23_PERL_PREBUILD = (
    "set -e; "
    "export PERL5LIB={aux}/usr/share/perl5:{aux}/usr/lib/x86_64-linux-gnu/perl5/5.36; "
    "mkdir -p {root}/.perl-deps/lib {root}/.perl-deps/arch; "
    "cp -a {aux}/usr/share/perl5/. {root}/.perl-deps/lib/; "
    "for d in {aux}/Crypt-OpenSSL-Bignum-0.09 {aux}/Crypt-OpenSSL-Random-0.15 "
    "{aux}/Crypt-OpenSSL-RSA-0.33; do "
    "if [ -d \"$d\" ]; then "
    "(cd \"$d\" && perl Makefile.PL && make && "
    "cp -a blib/lib/. {root}/.perl-deps/lib/ && cp -a blib/arch/. {root}/.perl-deps/arch/); "
    "fi; done; "
    "export PERL5LIB=$PERL5LIB:{root}/.perl-deps/lib:{root}/.perl-deps/arch; "
    "perl Makefile.PL"
)


def _s23_perl_spec(family: str, version: str, url: str, sha256: str, so_path: str,
                   note: str, extra_env: dict | None = None) -> dict:
    env = dict(_S23_PERL_BUILD_ENV)
    if extra_env:
        env.update(extra_env)
    return {
        "family": family, "version": version, "url": url, "archive": "tar.gz",
        "sha256": sha256, "build_system": "make", "configure": None,
        "pre_build": [["sh", "-c", _S23_PERL_PREBUILD]],
        "make": [MAKE_JOBS], "artifact": so_path, "launch": None,
        "aux_sources": list(_S23_PERL_AUX), "env_extra": env, "note": note,
    }


_S23_PERL_SPECS: tuple[dict, ...] = (
    _s23_perl_spec(
        "perl-net-ssleay", "1.92",
        ("https://deb.debian.org/debian/pool/main/libn/libnet-ssleay-perl/"
         "libnet-ssleay-perl_1.92.orig.tar.gz"),
        "47c2f2b300f2e7162d71d699f633dd6a35b0625a00cbda8c50ac01144a9396a9",
        "blib/arch/auto/Net/SSLeay/SSLeay.so",
        "Net::SSLeay 1.92: the direct libssl API (SSL_CTX/SSL, SNI, verification, "
        "session get/set and reuse) exercised by the admitted client workload."),
    _s23_perl_spec(
        "perl-crypt-smime", "0.28",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-smime-perl/"
         "libcrypt-smime-perl_0.28.orig.tar.gz"),
        "ca90ecacfef620f8a2f1723c5bc3307a0079c0c6f5170849a9896b20280d1c2d",
        "blib/arch/auto/Crypt/SMIME/SMIME.so",
        "Crypt::SMIME 0.28: CMS sign/verify and encrypt/decrypt (S/MIME) through the "
        "subject libcrypto.",
        {"LIBCRYPTO_CFLAGS": "-I{prefix}/include",
         "LIBCRYPTO_LIBS": "-L{prefix}/lib -lcrypto"}),
    _s23_perl_spec(
        "perl-crypt-openssl-x509", "1.9.14",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-x509-perl/"
         "libcrypt-openssl-x509-perl_1.9.14.orig.tar.gz"),
        "49c575257e6408ad5a89011e5b5800d598f9ccafdf42e71004ed81cb2f44ee7a",
        "blib/arch/auto/Crypt/OpenSSL/X509/X509.so",
        "Crypt::OpenSSL::X509 1.9.14: X.509 parsing, extensions and store verification "
        "against the subject libcrypto."),
    _s23_perl_spec(
        "perl-crypt-openssl-rsa", "0.33",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-rsa-perl/"
         "libcrypt-openssl-rsa-perl_0.33.orig.tar.gz"),
        "bdbe630f6d6f540325746ad99977272ac8664ff81bd19f0adaba6d6f45efd864",
        "blib/arch/auto/Crypt/OpenSSL/RSA/RSA.so",
        "Crypt::OpenSSL::RSA 0.33: RSA key generation, PKCS#1 sign/verify and public "
        "encryption through the subject libcrypto."),
    _s23_perl_spec(
        "libcrypt-openssl-ec-perl", "1.32",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-ec-perl/"
         "libcrypt-openssl-ec-perl_1.32.orig.tar.gz"),
        "575a6bb6d7694d4a4b73a9125db92b479c9ad2a66f44674ac2fd3c4413a2c19a",
        "blib/arch/auto/Crypt/OpenSSL/EC/EC.so",
        "Crypt::OpenSSL::EC 1.32: EC key generation, ECDSA sign/verify and ECDH "
        "derive through the subject libcrypto."),
    _s23_perl_spec(
        "libcrypt-openssl-pkcs10-perl", "0.19",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-pkcs10-perl/"
         "libcrypt-openssl-pkcs10-perl_0.19.orig.tar.gz"),
        "3452afd311a79ceece6a9f6e579cb7cd08b2e8ad7e347778557d3c1a1f2bfd57",
        "blib/arch/auto/Crypt/OpenSSL/PKCS10/PKCS10.so",
        "Crypt::OpenSSL::PKCS10 0.19: CSR construction and X509_REQ signature "
        "verification through the subject libcrypto."),
    _s23_perl_spec(
        "perl-crypt-openssl-aes", "0.23",
        "https://cpan.metacpan.org/authors/id/T/TI/TIMLEGGE/Crypt-OpenSSL-AES-0.23.tar.gz",
        "a70bc89c8d5eabde9b83dec7131b756c247b5c1fb8980f23a42bdd47751d4887",
        "blib/arch/auto/Crypt/OpenSSL/AES/AES.so",
        "Crypt::OpenSSL::AES 0.23: the low-level AES_encrypt/AES_decrypt interface "
        "through the subject libcrypto."),
    _s23_perl_spec(
        "perl-crypt-openssl-dsa", "0.20",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-dsa-perl/"
         "libcrypt-openssl-dsa-perl_0.20.orig.tar.gz"),
        "e4575d787d44e49b3b59cc39eda2e461fe0606dd0e87d3a9c3df5011b133e702",
        "blib/arch/auto/Crypt/OpenSSL/DSA/DSA.so",
        "Crypt::OpenSSL::DSA 0.20: legacy DSA key generation and sign/verify through "
        "the subject libcrypto."),
    _s23_perl_spec(
        "perl-crypt-openssl-bignum", "0.09",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-bignum-perl/"
         "libcrypt-openssl-bignum-perl_0.09.orig.tar.gz"),
        "234e72fb8396d45527e6fd45e43759c5c3f3a208cf8f29e6a22161a996fd42dc",
        "blib/arch/auto/Crypt/OpenSSL/Bignum/Bignum.so",
        "Crypt::OpenSSL::Bignum 0.09: the BN_* arbitrary-precision interface through "
        "the subject libcrypto."),
    _s23_perl_spec(
        "perl-crypt-openssl-random", "0.15",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-random-perl/"
         "libcrypt-openssl-random-perl_0.15.orig.tar.gz"),
        "f0876faa1ba3111e39b86aa730c603211eff2905e460c72a57b61e8cf475cef4",
        "blib/arch/auto/Crypt/OpenSSL/Random/Random.so",
        "Crypt::OpenSSL::Random 0.15: RAND_bytes/RAND_add through the subject "
        "libcrypto."),
    # S44 package rows: the Debian source package's own name for the exact modules above.
    # The corpus carries both the CPAN-style name and the distribution package name as separate
    # families; the archive, build intent and harness are byte-identical, so these rows are the
    # same upstream consumer under its package name (the established split-row rule).
    _s23_perl_spec(
        "libcrypt-openssl-bignum-perl", "0.09",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-bignum-perl/"
         "libcrypt-openssl-bignum-perl_0.09.orig.tar.gz"),
        "234e72fb8396d45527e6fd45e43759c5c3f3a208cf8f29e6a22161a996fd42dc",
        "blib/arch/auto/Crypt/OpenSSL/Bignum/Bignum.so",
        "the libcrypt-openssl-bignum-perl package row of Crypt::OpenSSL::Bignum 0.09: "
        "BN add/mul/mod_exp/mod_inverse through the subject libcrypto."),
    _s23_perl_spec(
        "libcrypt-openssl-random-perl", "0.15",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-random-perl/"
         "libcrypt-openssl-random-perl_0.15.orig.tar.gz"),
        "f0876faa1ba3111e39b86aa730c603211eff2905e460c72a57b61e8cf475cef4",
        "blib/arch/auto/Crypt/OpenSSL/Random/Random.so",
        "the libcrypt-openssl-random-perl package row of Crypt::OpenSSL::Random 0.15: "
        "RAND_bytes and RAND_status through the subject libcrypto."),
    _s23_perl_spec(
        "libcrypt-openssl-rsa-perl", "0.33",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-rsa-perl/"
         "libcrypt-openssl-rsa-perl_0.33.orig.tar.gz"),
        "bdbe630f6d6f540325746ad99977272ac8664ff81bd19f0adaba6d6f45efd864",
        "blib/arch/auto/Crypt/OpenSSL/RSA/RSA.so",
        "the libcrypt-openssl-rsa-perl package row of Crypt::OpenSSL::RSA 0.33: RSA "
        "keygen, sign/verify and public encrypt/decrypt through the subject libcrypto."),
    _s23_perl_spec(
        "libcrypt-openssl-dsa-perl", "0.20",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-dsa-perl/"
         "libcrypt-openssl-dsa-perl_0.20.orig.tar.gz"),
        "e4575d787d44e49b3b59cc39eda2e461fe0606dd0e87d3a9c3df5011b133e702",
        "blib/arch/auto/Crypt/OpenSSL/DSA/DSA.so",
        "the libcrypt-openssl-dsa-perl package row of Crypt::OpenSSL::DSA 0.20: DSA "
        "keygen, sign/verify and PEM roundtrip through the subject libcrypto."),
    _s23_perl_spec(
        "libcrypt-openssl-x509-perl", "1.9.14",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-x509-perl/"
         "libcrypt-openssl-x509-perl_1.9.14.orig.tar.gz"),
        "49c575257e6408ad5a89011e5b5800d598f9ccafdf42e71004ed81cb2f44ee7a",
        "blib/arch/auto/Crypt/OpenSSL/X509/X509.so",
        "the libcrypt-openssl-x509-perl package row of Crypt::OpenSSL::X509 1.9.14: "
        "X.509 parse, fingerprint, extensions and issuer linkage through the subject "
        "libcrypto."),
    _s23_perl_spec(
        "libcrypt-smime-perl", "0.28",
        ("https://deb.debian.org/debian/pool/main/libc/libcrypt-smime-perl/"
         "libcrypt-smime-perl_0.28.orig.tar.gz"),
        "ca90ecacfef620f8a2f1723c5bc3307a0079c0c6f5170849a9896b20280d1c2d",
        "blib/arch/auto/Crypt/SMIME/SMIME.so",
        "the libcrypt-smime-perl package row of Crypt::SMIME 0.28: CMS sign/check and "
        "encrypt/decrypt through the subject libcrypto.",
        {"LIBCRYPTO_CFLAGS": "-I{prefix}/include",
         "LIBCRYPTO_LIBS": "-L{prefix}/lib -lcrypto"}),
)

_S23_BINUTILS_AUX: tuple[dict, ...] = (
    _s23_deb("b/binutils", "binutils-dev_2.40-2_amd64.deb",
             "35066c624bd9d9f3d7fb9fee8f98556482a4fd0bbbf4a00a285fa877da350257",
             include_dirs=("usr/include",)),
)

_S23_HTTP_PARSER_AUX: tuple[dict, ...] = (
    _s23_deb("h/http-parser", "libhttp-parser2.9_2.9.4-5_amd64.deb",
             "98045b047b8f3ccfdd7930983797df3e316112e1cd4d161fc793260e31183b59",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("h/http-parser", "libhttp-parser-dev_2.9.4-5_amd64.deb",
             "036f9364d02f90a9f524493fcbf5f84c878760b4a81e828d8ebb5d06f20330ab",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_S23_GNUEFI_AUX: tuple[dict, ...] = (
    _s23_deb("g/gnu-efi", "gnu-efi_3.0.15-1_amd64.deb",
             "1e668cebcb94678b39a69e5c7b8f1d1eb51fd4eb251643491a8c249ae6fa0c36",
             include_dirs=("usr/include",)),
)

_S23_LIBBSON_AUX: tuple[dict, ...] = (
    _s23_deb("m/mongo-c-driver", "libbson-1.0-0_1.23.1-1+deb12u3_amd64.deb",
             "9b97d0468fdb7567a3cbbc6c29459a32e51f54d6e3f3f2ee7d119f3f8587cd36",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("m/mongo-c-driver", "libbson-dev_1.23.1-1+deb12u3_amd64.deb",
             "6a35de95dc99961a9a224e52a0f1a83e3e61bd59cb270f517433398be7489ec5",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_S23_KRB5_AUX: tuple[dict, ...] = (
    _s23_deb("k/krb5", "libkrb5-dev_1.20.1-2+deb12u5_amd64.deb",
             "98703cfcafb6377414ca5a0de9a309c7b324337e6ecf8c86157a14b85cebcb66",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             bin_dirs=("usr/bin",)),
    _s23_deb("k/krb5", "krb5-multidev_1.20.1-2+deb12u5_amd64.deb",
             "c47364fbcdffdc9efd239daef34e46b6ed817669d9ca587dcb99273a0860a91d",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             bin_dirs=("usr/bin",)),
    _s23_deb("k/krb5", "libkrb5-3_1.20.1-2+deb12u5_amd64.deb",
             "c90801be09701af221b54dd502a59cb378b7284ff31e480738baca317d2f7653",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("k/krb5", "libgssapi-krb5-2_1.20.1-2+deb12u5_amd64.deb",
             "d8b87aea91b956b416c01a28c44ff6228315ae3b73de40acddac3dc5043607d2",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("k/krb5", "libk5crypto3_1.20.1-2+deb12u5_amd64.deb",
             "7b6e47d15c5c9cdcd456137533d8308aeba608a54cec73b28bd59bfc4b54cf06",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("k/krb5", "libkrb5support0_1.20.1-2+deb12u5_amd64.deb",
             "8b9c05f2d8d461a10d657b118f572af5bf8fd6c8f93dcef81e852c5ab0f428ab",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("e/e2fsprogs", "libcom-err2_1.47.0-2+b2_amd64.deb",
             "a2bac7015e78fbc0c504df3e441f3a22292f1d2d77f9ccda760057f3690e22f2",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("e/e2fsprogs", "comerr-dev_2.1-1.47.0-2+b2_amd64.deb",
             "e72521fd1b8af99ad99e83af7d87926a4c4d7e8238e61846761f7818220a48a2",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("libu/libunistring", "libunistring2_1.0-2_amd64.deb",
             "d466bbfe011d764d793c1d9d777cad9c7cf65b938e11598f27408171ad95a951",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("libu/libunistring", "libunistring-dev_1.0-2_amd64.deb",
             "df35c1dcc9881de67b4d618fcc1c4e677e3e49d1017aab75aebcf8f9935c508d",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("libx/libxslt", "libxslt1.1_1.1.35-1+deb12u4_amd64.deb",
             "5bf795dc6374f744906d39a786024d98b2cb6b885c7776f5dc64eb4092b550a6",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("libx/libxml2", "libxml2_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "4460e39dda10a815881374217cde08474747cfa018358cd8612c14b390eff53b",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("libx/libxslt", "xsltproc_1.1.35-1+deb12u4_amd64.deb",
             "e251d7f33b02205ce1f6133115ccb399ca7f10635313b1300a976d3eb96320cd",
             bin_dirs=("usr/bin",), library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("libx/libxml2", "libxml2-utils_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "84a26b289dd6075b8334f252bc445023dc64102e557645284fdbc1bebed21a1a",
             bin_dirs=("usr/bin",), library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("d/docbook-xsl", "docbook-xsl_1.79.2+dfsg-7_all.deb",
             "b0f710af8f8095ab4749327047ee139dd1dce245eeed2325f148a8fdd1169ab2"),
    _s23_deb("d/docbook-xml", "docbook-xml_4.5-12_all.deb",
             "7c618a4f14a12bbd2659f658e58ea8de7f88b1802e14da2d639c460922d18a69"),
)

_S23_SPECS: tuple[dict, ...] = _S23_PERL_SPECS + (
    {
        "family": "php", "version": "8.2.32",
        "url": ("https://deb.debian.org/debian/pool/main/p/php8.2/"
                "php8.2_8.2.32.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "autotools",
        "sha256": "e02aa173c236c12791696254d607da680e6d5516f8f5c2339642de7c4f944bd2",
        "configure": ["--prefix={root}/.l7-install", "--disable-all", "--enable-openssl",
                      "--with-openssl={prefix}", "--enable-cli", "--disable-cgi",
                      "--disable-phpdbg", "--without-pear", "--without-libxml",
                      "--without-sqlite3", "--without-pdo-sqlite", "--disable-dom",
                      "--disable-simplexml", "--disable-xml", "--disable-xmlreader",
                      "--disable-xmlwriter", "--disable-xmlrpc"],
        "make": [MAKE_JOBS], "artifact": "sapi/cli/php", "launch": ["-v"],
        "note": ("PHP 8.2.32's OpenSSL extension: the admitted script reads and writes "
                 "PKCS#12, signs/verifies and encrypts/decrypts CMS/PKCS#7, and verifies "
                 "a chain with openssl_x509_checkpurpose."),
    },
    {
        "family": "ruby", "version": "3.1.2",
        "url": "https://deb.debian.org/debian/pool/main/r/ruby3.1/ruby3.1_3.1.2.orig.tar.xz",
        "archive": "tar.xz", "build_system": "autotools",
        "sha256": "350013ef6640f15c42eae48d25c035999dcbb32e4be038d27ad891cb48d685a5",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl-dir={prefix}",
                      "--with-static-linked-ext", "--with-ext=openssl,digest",
                      "--disable-install-doc", "--without-gmp", "--without-valgrind"],
        "make": [MAKE_JOBS], "artifact": "ruby", "launch": ["-v"],
        "note": ("Ruby 3.1.2 with ext/openssl statically linked into the interpreter: the "
                 "admitted script exercises PKCS#12, PKCS#7 and OCSP, X.509 store/CRL "
                 "verification, raw Ed25519 keys and TLS session reuse."),
    },
    {
        "family": "strongswan", "version": "5.9.8",
        "url": ("https://deb.debian.org/debian/pool/main/s/strongswan/"
                "strongswan_5.9.8.orig.tar.bz2"),
        "archive": "tar.bz2", "build_system": "autotools",
        "sha256": "d3303a43c0bd7b75a12b64855e8edcb53696f06190364f26d1533bde1f2e453c",
        "configure": ["--prefix={root}/.l7-install", "--disable-defaults", "--enable-pki",
                      "--enable-openssl", "--enable-pem", "--enable-x509",
                      "--enable-constraints", "--enable-revocation", "--enable-pkcs1",
                      "--enable-pkcs8", "--enable-pkcs12", "--enable-sha1",
                      "--enable-sha2", "--enable-random", "--enable-hmac",
                      "--enable-aes", "--enable-gcm", "--enable-rsa", "--enable-ecdsa",
                      "--enable-dsa", "--enable-mgf1", "--enable-shared",
                      "--disable-static"],
        "make": [MAKE_JOBS], "artifact": "src/libstrongswan/plugins/openssl/.libs/"
        "libstrongswan-openssl.so", "launch": ["--version"],
        "note": ("strongSwan 5.9.8's pki utility with the OpenSSL crypto plugin: PKCS#12 "
                 "export/import, CMS-signed CRL creation, X.509 issue/verify and constraint/"
                 "revocation checks through the subject libcrypto."),
    },
    {
        "family": "dcmtk", "version": "3.6.7",
        "url": ("https://deb.debian.org/debian/pool/main/d/dcmtk/"
                "dcmtk_3.6.7.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "17705dcdb2047d1266bb4e92dbf4aa6d4967819e8e3e94f39b7df697661b4860",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DDCMTK_WITH_OPENSSL=ON",
                      "-DDCMTK_WITH_ZLIB=ON", "-DDCMTK_WITH_TIFF=OFF",
                      "-DDCMTK_WITH_PNG=OFF", "-DDCMTK_WITH_LIBXML=OFF",
                      "-DDCMTK_WITH_ICONV=OFF", "-DDCMTK_WITH_WRAP=OFF",
                      "-DDCMTK_WITH_SNDFILE=OFF", "-DDCMTK_WITH_OPENJPEG=OFF",
                      "-DDCMTK_WITH_ICU=OFF", "-DBUILD_APPS=ON",
                      "-DBUILD_SHARED_LIBS=OFF", "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include",
                      "-DCMAKE_CXX_FLAGS=-I{prefix}/include",
                      "-DCMAKE_EXE_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/bin/dcmsign", "launch": ["--help"],
        "note": ("DCMTK 3.6.7's dcmsign signs and verifies a DICOM dataset with CMS "
                 "SignedData through the subject libcrypto."),
    },
    {
        "family": "coturn", "version": "4.6.3",
        "url": "https://github.com/coturn/coturn/archive/refs/tags/4.6.3.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "dc3a529fd9956dc8771752a7169c5ad4c18b9deef3ec96049de30fabf1637704",
        "configure": ["--prefix={root}/.l7-install", "--disable-sqlite",
                      "--disable-mysql", "--disable-pgsql", "--disable-mongo",
                      "--disable-redis", "--disable-systemd"],
        "make": [MAKE_JOBS], "artifact": "bin/turnserver", "launch": ["--version"],
        "aux_sources": list(_LIBEVENT_AUX),
        "note": ("coturn 4.6.1's TURN server and uclient with the OpenSSL TLS/DTLS "
                 "transport; libevent is the pinned bookworm package."),
    },
    {
        "family": "poco", "version": "1.11.0",
        "url": "https://deb.debian.org/debian/pool/main/p/poco/poco_1.11.0.orig.tar.bz2",
        "archive": "tar.bz2", "build_system": "cmake",
        "sha256": "b08cf73926fa92a6c8f3c712e8fb217d5d0c2fa5248ec0281f251fe1e925d2f1",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                      "-DENABLE_NETSSL=ON", "-DENABLE_CRYPTO=ON", "-DENABLE_NET=ON",
                      "-DENABLE_UTIL=ON", "-DENABLE_XML=OFF", "-DENABLE_JSON=OFF",
                      "-DENABLE_DATA=OFF", "-DENABLE_MONGODB=OFF", "-DENABLE_REDIS=OFF",
                      "-DENABLE_PAGECOMPILER=OFF", "-DENABLE_TESTS=OFF",
                      "-DENABLE_SAMPLES=OFF", "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_CXX_FLAGS=-I{prefix}/include",
                      "-DCMAKE_EXE_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/lib/libPocoNetSSL.so*", "launch": None,
        "note": ("Poco 1.11.0 NetSSL: HTTPS client/server through the subject libssl and "
                 "X.509 verification through the subject libcrypto."),
    },
    {
        "family": "libgit2", "version": "1.5.1",
        "url": ("https://deb.debian.org/debian/pool/main/libg/libgit2/"
                "libgit2_1.5.1+ds.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "cmake",
        "sha256": "96369433500bb528f036c16be9921bd437c098b745f1aaeccb91290815518970",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                      "-DBUILD_CLI=OFF", "-DBUILD_TESTS=OFF", "-DBUILD_CLAR=OFF",
                      "-DUSE_SSH=OFF", "-DUSE_HTTPS=ON", "-DUSE_NTLMCLIENT=OFF",
                      "-DUSE_HTTP_PARSER=system", "-DREGEX_BACKEND=pcre2",
                      "-DHTTP_PARSER_INCLUDE_DIR={aux}/usr/include",
                      "-DHTTP_PARSER_LIBRARY={aux}/usr/lib/x86_64-linux-gnu/libhttp_parser.so",
                      "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_PREFIX_PATH={prefix};{aux}/usr",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include -I{aux}/usr/include",
                      "-DCMAKE_EXE_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
                      "-L{aux}/usr/lib/x86_64-linux-gnu "
                      "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu"],
        "make": [], "artifact": "b/libgit2.so*", "launch": None,
        "aux_sources": list(_PCRE2_AUX) + list(_S23_HTTP_PARSER_AUX),
        "note": ("libgit2 1.5.1's HTTPS transport: the admitted harness fetches a local "
                 "smart-HTTP repository over verified TLS and rejects an unrelated CA via "
                 "its X.509 certificate callback."),
    },
    {
        "family": "libmongocrypt", "version": "1.7.2",
        "url": ("https://deb.debian.org/debian/pool/main/libm/libmongocrypt/"
                "libmongocrypt_1.7.2.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "a25440a5fa805dc94a4d04aecf91698eebbae23cc045efc96da238f07c85a73f",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DENABLE_SHARED=ON",
                      "-DBUILD_TESTING=ON", "-DMONGOCRYPT_ENABLE_DECIMAL128=OFF",
                      "-DCMAKE_PREFIX_PATH={aux}/usr",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include -I{aux}/usr/include",
                      "-DCMAKE_EXE_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
                      "-L{aux}/usr/lib/x86_64-linux-gnu"
                      " -Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu"],
        "make": [], "artifact": "b/libmongocrypt.so*", "launch": None,
        "aux_sources": list(_S23_LIBBSON_AUX),
        "note": ("libmongocrypt 1.7.2's crypto layer (AES-GCM, HMAC, RSA, random) through "
                 "the subject libcrypto; libbson is the pinned bookworm build input."),
    },
    {
        "family": "libengine-pkcs11-openssl", "version": "0.4.12",
        "url": ("https://deb.debian.org/debian/pool/main/libp/libp11/"
                "libp11_0.4.12.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "1e1a2533b3fcc45fde4da64c9c00261b1047f14c3f911377ebd1b147b3321cfd",
        "configure": ["--prefix={root}/.l7-install", "--disable-static",
                      "OPENSSL_CFLAGS=-I{prefix}/include",
                      "OPENSSL_LIBS=-L{prefix}/lib -lssl -lcrypto"],
        "make": [MAKE_JOBS], "artifact": "src/.libs/pkcs11.so", "launch": None,
        "note": ("libp11 0.4.12's legacy pkcs11 ENGINE: the admitted harness loads it "
                 "through ENGINE_by_id/dynamic and drives ENGINE_init/ctrl through the "
                 "subject libcrypto."),
    },
    {
        "family": "krb5", "version": "1.20.1",
        "url": "https://deb.debian.org/debian/pool/main/k/krb5/krb5_1.20.1.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "704aed49b19eb5a7178b34b2873620ec299db08752d6a8574f95d41879ab8851",
        "pre_build": [["sh", "-c", (
            "cd src && ./configure --prefix={root}/.l7-install "
            "--with-crypto-impl=openssl --disable-static"
        )]],
        "make": [MAKE_JOBS, "-C", "src", "YACC=bison -y", "LEX=flex"],
        "artifact": "src/lib/crypto/libk5crypto.so.3.1",
        "launch": None,
        "aux_sources": list(_B16_AUTOTOOLS_AUX),
        "env_extra": {"BISON_PKGDATADIR": "{aux}/usr/share/bison",
                      "M4": "{aux}/usr/bin/m4"},
        "note": ("MIT krb5 1.20.1's PKINIT path: the admitted workload runs a local KDC "
                 "with an X.509 principal and obtains a ticket through PKINIT CMS with "
                 "the subject libcrypto."),
    },
    {
        "family": "postfix", "version": "3.7.11",
        "url": "https://deb.debian.org/debian/pool/main/p/postfix/postfix_3.7.11.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "8451fb343692b23cba105b6a194a27a6f32ff21bd2c3bb2fed5ac50d0631deda",
        "pre_build": [["sh", "-c", (
            "mkdir -p {root}/.l7-bin {root}/.s36-postfix; "
            "printf 'mail_owner = daemon\\ndefault_privs = mail\\nsetgid_group = nogroup\\n"
            "smtp_tls_security_level = verify\\n' > {root}/.s36-postfix/main.cf; "
            "printf '#!/bin/sh\\ncase \"$1\" in -r) echo 6.1.0;; -s) echo Linux;; "
            "*) exec /usr/bin/uname \"$@\";; esac\\n' > {root}/.l7-bin/uname; "
            "chmod +x {root}/.l7-bin/uname"
        )], ["make", "makefiles",
              "CCARGS=-DUSE_TLS -DHAS_DB -I{prefix}/include -I{aux}/usr/include",
              "AUXLIBS=-L{prefix}/lib -lssl -lcrypto "
              "-L{aux}/usr/lib/x86_64-linux-gnu -ldb"]],
        "make": [MAKE_JOBS], "artifact": "src/posttls-finger/posttls-finger",
        "launch": ["-h"],
        "aux_sources": list(_L7_EXIM_AUX),
        "env_extra": {"PATH": "{root}/.l7-bin:{aux}/usr/bin:" + os.environ.get("PATH", ""),
                      "LD_LIBRARY_PATH": ""},
        "note": ("Postfix 3.7.11's TLS engine and posttls-finger: the admitted workload "
                 "completes STARTTLS against a local SMTP peer, verifies the chain and "
                 "rejects an unrelated CA."),
    },
    {
        "family": "gftp-text", "version": "2.9.1~beta",
        "url": "https://deb.debian.org/debian/pool/main/g/gftp/gftp_2.9.1~beta.orig.tar.xz",
        "archive": "tar.xz", "build_system": "autotools",
        "sha256": "79c727a0c7720e0e49dac4fc760a686d10ff78a496e1e3e644b45d3e76e1eecd",
        "configure": ["--prefix={root}/.l7-install", "--disable-gtkport", "--disable-nls"],
        "make": [MAKE_JOBS], "artifact": "src/text/gftp-text", "launch": ["--version"],
        "aux_sources": list(_L7_IRSSI_AUX),
        "env_extra": {"SSL_CFLAGS": "-I{prefix}/include",
                      "SSL_LIBS": "-L{prefix}/lib -lssl -lcrypto"},
        "note": ("gftp 2.9.1's text client: the admitted workload logs in to a local "
                 "FTPS peer with AUTH TLS and retrieves the fixture, rejecting an "
                 "unrelated CA."),
    },
    {
        "family": "libcpp-httplib0.11", "version": "0.11.4",
        "url": ("https://github.com/yhirose/cpp-httplib/archive/refs/tags/"
                "v0.11.4.tar.gz"),
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "28f76b875a332fb80972c3212980c963f0a7d2e11a8fe94a8ed0d847b9a2256f",
        "pre_build": [["sh", "-c", (
            "set -e; g++ -std=c++11 -O2 -o {root}/.l7-httplib-harness "
            "{repo}/forensics/tools/l7_httplib.cpp -I{root} -I{prefix}/include "
            "-L{prefix}/lib -Wl,-rpath,{prefix}/lib -lssl -lcrypto -lpthread"
        )]],
        "make": ["-f", "/dev/null", "--eval=all:;@true", "all"], "artifact": ".l7-httplib-harness",
        "launch": ["--help"],
        "note": ("cpp-httplib 0.11.4's header-only SSLServer/SSLClient; the admitted "
                 "harness runs both ends over verified TLS and rejects an unrelated CA."),
    },
    {
        "family": "libcxxtools10", "version": "3.0.0",
        "url": "https://deb.debian.org/debian/pool/main/c/cxxtools/cxxtools_3.0.0.orig.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "07b18037fb0983f6292f5c8d53e2369e9e7a9711df2c9ad50838aacbc8c62f7c",
        "configure": ["--prefix={root}/.l7-install", "--with-ssl=yes",
                      "--disable-static"],
        "make": [MAKE_JOBS], "artifact": "src/.libs/libcxxtools.so*", "launch": None,
        "note": ("cxxtools 3.0.0's SSL socket layer (TcpSocket/TcpServer sslConnect/"
                 "sslAccept and peer-certificate verification) through the subject "
                 "libssl."),
    },
    {
        "family": "gss-ntlmssp", "version": "1.2.0",
        "url": ("https://deb.debian.org/debian/pool/main/g/gss-ntlmssp/"
                "gss-ntlmssp_1.2.0.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "372cb7f26aca0760c90d245c1039766588650f207f129858cc72a103bf38ba11",
        "configure": ["--prefix={root}/.l7-install", "--disable-static",
                      "--disable-nls", "--without-wbclient",
                      "--with-xml-catalog-path={root}/.xmlcatalog.xml"],
        "pre_build": [["sh", "-c", (
            "printf '%s' '<catalog xmlns=\"urn:oasis:names:tc:entity:xmlns:xml:catalog\">"
            "<rewriteURI uriStartString=\"http://docbook.sourceforge.net/release/xsl/current/\" "
            "rewritePrefix=\"file://{aux}/usr/share/xml/docbook/stylesheet/docbook-xsl/\"/>"
            "<rewriteURI uriStartString=\"http://www.oasis-open.org/docbook/xml/4.4/\" "
            "rewritePrefix=\"file://{aux}/usr/share/xml/docbook/schema/dtd/4.4/\"/>"
            "</catalog>' > {root}/.xmlcatalog.xml"
        )]],
        "make": [MAKE_JOBS], "artifact": ".libs/gssntlmssp.so", "launch": None,
        "aux_sources": list(_S23_KRB5_AUX),
        "note": ("gss-ntlmssp 1.2.0: the NTLM GSSAPI mechanism's MD4/DES/RC4/MD5 path "
                 "through the subject libcrypto, driven by a local initiator/acceptor "
                 "exchange."),
    },
)


_S36_SPECS: tuple[dict, ...] = (
    {
        # S36: a mail client whose own S/MIME implementation is linked against the
        # subject libssl/libcrypto (mutt's classic S/MIME uses PKCS#7/CMS through
        # OpenSSL; the admitted workload drives its SMTPS submission path over a
        # verified TLS session).
        "family": "mutt", "version": "2.2.13",
        "url": "https://deb.debian.org/debian/pool/main/m/mutt/mutt_2.2.13.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "eb23faddc1cc97d867693f3a4a9f30949ad93765ad5b6fdae2797a4001c58efb",
        "configure": ["--prefix={root}/.l7-install", "--with-ssl={prefix}",
                      "--enable-imap", "--enable-pop", "--enable-smtp",
                      "--enable-smime", "--disable-gpgme", "--disable-doc",
                      "--disable-nls", "--without-sasl"],
        "make": [MAKE_JOBS], "artifact": "mutt", "launch": ["-v"],
        "aux_sources": list(_B16_NCURSES_AUX),
        "note": ("Mutt 2.2.13's SMTP-over-TLS submission path and its classic S/MIME "
                 "PKCS#7/CMS implementation through the subject libssl/libcrypto; the "
                 "admitted workload submits a message to a local SMTPS peer and rejects "
                 "an unrelated CA."),
    },
)


# --------------------------------------------------------------------------------------------
# S44 corpus batch (2026-10-24)
#
# The families below were the next tractable rows in the frozen P1000 with no admitted recipe:
# each has a pristine published source archive, builds with the venue's toolchain against the
# subject prefix, and exposes a CLI that performs one non-interactive TLS or crypto operation.
# Families whose only entry point is an interactive daemon, a kernel capability, a USB/smartcard
# device or a distribution meta-package were skipped and are itemised in the S44 receipt.
# --------------------------------------------------------------------------------------------
_S44_SPECS: tuple[dict, ...] = (
    {
        # A RELP sender/receiver pair from the library's own test programs.  Both ends
        # negotiate mutual TLS through librelp's OpenSSL backend, so the workload is a real
        # TLS session between two consumers in the same pristine tree.
        "family": "librelp", "version": "1.13.0",
        "url": "https://deb.debian.org/debian/pool/main/libr/librelp/librelp_1.13.0.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "58e976e31795d7309cf2d9f37fdc93522daa4a322f5012d7879fed9ebfa40068",
        "configure": ["--prefix={root}/.l7-install", "--disable-tls",
                      "--enable-tls-openssl", "--disable-static"],
        "make": [MAKE_JOBS],
        "artifact": "src/.libs/librelp.so*", "launch": None,
        "env_extra": {"OPENSSL_CFLAGS": "-I{prefix}/include",
                      "OPENSSL_LIBS": ("-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
                                       "-lssl -lcrypto")},
        "note": ("librelp 1.13.0's own RELP send/receive pair negotiates mutual TLS "
                 "through the subject libssl and carries a message; a sender trusting "
                 "an unrelated CA is refused"),
    },
    {
        # Hydra's https-get module is an OpenSSL client: it completes a TLS handshake and sends
        # HTTP Basic credentials.  The workload's fixture answers 401 for the wrong password and
        # 200 for the right one, so the finding is a real TLS-authenticated decision.
        "family": "hydra", "version": "9.5",
        "url": "https://deb.debian.org/debian/pool/main/h/hydra/hydra_9.5.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "a3969a8cd7dbd1f805f756df980beda83c53778087d8e6ffcb8aa28693f407d5",
        "configure": ["--prefix={prefix}", "--disable-xhydra"],
        "make": [MAKE_JOBS, "LDFLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "artifact": "hydra", "launch": ["-h"],
        "note": ("hydra 9.5's https-get module authenticates over the subject libssl; the "
                 "admitted workload finds the fixture credential and misses a wrong one"),
    },
    {
        # Ncrack's HTTP(S) module is a second, independent OpenSSL client (nsock + the ncrack
        # HTTP engine).  Its services database is a build-tree data file, so NCRACKDIR points at
        # the extracted root.
        "family": "ncrack", "version": "0.7+debian",
        "url": ("https://deb.debian.org/debian/pool/main/n/ncrack/"
                "ncrack_0.7+debian.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "configure",
        "sha256": "117096d9e25a8308f1f1a012e573f7575c36592d842555482b4cf53b7065bd21",
        "configure": ["--with-openssl={prefix}", "--without-openssl-header-check"],
        "env_extra": {"LDFLAGS": "-L{prefix}/lib -Wl,-rpath,{prefix}/lib"},
        "make": [MAKE_JOBS, "LDFLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
                             "-Lnbase -Lnsock/src -Lopensshlib -Wl,--allow-multiple-definition"],
        "artifact": "ncrack", "launch": ["-h"],
        "note": ("ncrack 0.7's HTTPS module authenticates through the subject libssl; the "
                 "admitted workload finds the fixture credential and misses a wrong one"),
    },
    {
        # ircd-hybrid's TLS listener: the daemon refuses root, so the workload drops to `nobody`
        # and stages the install prefix the binary expects.  The evidence is its own IRC greeting
        # over a verified TLS session, with an unrelated CA rejected.
        "family": "ircd-hybrid", "version": "8.2.46",
        "url": ("https://deb.debian.org/debian/pool/main/i/ircd-hybrid/"
                "ircd-hybrid_8.2.46+dfsg.1.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "c16dc92536fd6519a85b7aa35f061bbb40b366cd449866fa2ff90ac88881aef7",
        "configure": ["--prefix={root}/.l7-install", "--with-tls=openssl"],
        "make": [MAKE_JOBS],
        "artifact": "src/ircd", "launch": ["-v"],
        "note": ("ircd-hybrid 8.2.46's TLS listener greets a verified loopback client over the "
                 "subject libssl; an unrelated CA is refused"),
    },
    {
        # Medusa's http module with -s is an OpenSSL client (medusa-thread-ssl.c).  Its modules
        # are loaded from src/modsrc through MEDUSA_MODULE_PATH.
        "family": "medusa", "version": "2.3",
        "url": "https://deb.debian.org/debian/pool/main/m/medusa/medusa_2.3.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "7ad4b4ed8acecd42fa48fc31fad6e255a8ee894c66615509196f5b9173e3f891",
        "configure": ["--prefix={root}/.l7-install", "--with-ssl={prefix}"],
        "make": [MAKE_JOBS],
        "artifact": "src/medusa", "launch": ["-V"],
        "note": ("medusa 2.3's HTTP module over TLS finds the fixture credential through the "
                 "subject libssl and misses a wrong one"),
    },
)


# --------------------------------------------------------------------------------------------
# S46 corpus batch (2026-10-24)
#
# The next tractable rows in the frozen P1000.  Every archive is a pristine published release
# pinned by the digest this subphase observed; non-OpenSSL dependencies come from pinned bookworm
# packages through the auxiliary seam, so the subject prefix is the only OpenSSL on the link line.
# A family the venue cannot drive deterministically keeps its build/link row (no `PROGRAMS` entry)
# rather than fabricating a workload.
# --------------------------------------------------------------------------------------------

_S46_TCL_AUX: tuple[dict, ...] = (
    _aux_deb("t/tcl8.6", "libtcl8.6_8.6.13+dfsg-2_amd64.deb",
             "976c4235b816635e1756016f3adbabb634e8b97a9f6b97cf901be099e4fd2487",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("t/tcl8.6", "tcl8.6_8.6.13+dfsg-2_amd64.deb",
             "4d539bdd459ea9fd5be25bf46c3c928ae5eb9cfdb5a1bf7ca25cacc596327d9d",
             bin_dirs=("usr/bin",)),
    _aux_deb("t/tcl8.6", "tcl8.6-dev_8.6.13+dfsg-2_amd64.deb",
             "e37b3f8888003ca9a34b85452885662bb9885b17f70cf7dfe4ec821a48328509",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

_S46_POPT_AUX: tuple[dict, ...] = (
    _aux_deb("p/popt", "libpopt0_1.19+dfsg-1_amd64.deb",
             "6f94b488255acd996254f775c77ff3956557c61f860a3c9caeaf65457554194f",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/popt", "libpopt-dev_1.19+dfsg-1_amd64.deb",
             "0f1c2bcc8270f6f06a3f351efd43296ad4793fe1daf641b7d9f0428dc7d141a2",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_S46_BSD_AUX: tuple[dict, ...] = (
    _aux_deb("libm/libmd", "libmd0_1.0.4-2_amd64.deb",
             "03539fd30c509e27101d13a56e52eda9062bdf1aefe337c07ab56def25a13eab",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libm/libmd", "libmd-dev_1.0.4-2_amd64.deb",
             "fc755a2552c03653cb51575bf70d1aa0874f78d86fbc8ff7fb246b1c9e7e31c5",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("libb/libbsd", "libbsd0_0.11.7-2_amd64.deb",
             "bb31cc8b40f962a85b2cec970f7f79cc704a1ae4bad24257a822055404b2c60b",
             library_dirs=(_AUX_MULTIARCH,)),
    {"url": ("https://deb.debian.org/debian/pool/main/libb/libbsd/"
              "libbsd-dev_0.11.7-2_amd64.deb"),
     "sha256": "788ec28ca78eab1ba14d2e1a50727efb7276c6b034163dca40931d8ab3d94aab",
     "archive": "deb", "extract": ["dpkg-deb", "-x"],
     "include_dirs": ["usr/include"], "library_dirs": [_AUX_MULTIARCH],
     "pkgconfig_dirs": [_AUX_MULTIARCH_PC],
     "links": {"usr/lib/x86_64-linux-gnu/libbsd.so": "libbsd.so.0.11.7"},
     "note": "pinned bookworm libbsd-dev; its ld script is replaced with a symlink"},
)

_S46_LIBXML2_AUX: tuple[dict, ...] = (
    _aux_deb("libx/libxml2", "libxml2_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "4460e39dda10a815881374217cde08474747cfa018358cd8612c14b390eff53b",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libx/libxml2", "libxml2-dev_2.9.14+dfsg-1.3~deb12u6_amd64.deb",
             "e8ceacf656b1720e7a310e1d159439a356bfcb9f5fb0325907f26aa8590e5f70",
             include_dirs=("usr/include", "usr/include/libxml2"),
             library_dirs=(_AUX_MULTIARCH,), pkgconfig_dirs=(_AUX_MULTIARCH_PC,),
             bin_dirs=("usr/bin",)),
)

_S46_BISON_FLEX_AUX: tuple[dict, ...] = (
    _aux_deb("b/bison", "bison_3.8.2+dfsg-1+b1_amd64.deb",
             "a414afd7519c53bfa33415ba5b951bc8b4906877004c49723ffda50a6033c3e8",
             bin_dirs=("usr/bin",)),
    _aux_deb("f/flex", "flex_2.6.4-8.2_amd64.deb",
             "da3fd55dbb6aff4f7b3187580813e0ef707d0c596402e37c8fd144df60003636",
             bin_dirs=("usr/bin",)),
    _aux_deb("libt/libtool", "libtool-bin_2.4.7-7~deb12u1_amd64.deb",
             "f7994513ca6b138b49e8814067c9c0fe565da503ec27b64b4095b890ffb12faf",
             bin_dirs=("usr/bin",)),
)

_S46_CONFUSE_AUX: tuple[dict, ...] = (
    _aux_deb("libc/libconfuse", "libconfuse2_3.3-3_amd64.deb",
             "bdfc3f22a513cc7040d2164572100a286592e7b9971c5d8b6d742065a4105249",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("libc/libconfuse", "libconfuse-dev_3.3-3_amd64.deb",
             "66e6947aef970dbb18a9a5420b23f4b5095881fd2214d8d51b099daea534bab9",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_S46_FDM_AUX: tuple[dict, ...] = (
    *list(_S46_BISON_FLEX_AUX),
    _aux_deb("p/pcre2", "libpcre2-8-0_10.42-1_amd64.deb",
             "030db54f4d76cdfe2bf0e8eb5f9efea0233ab3c7aa942d672c7b63b52dbaf935",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/pcre2", "libpcre2-dev_10.42-1_amd64.deb",
             "f0ff485a26daae8f742a1566426f0d98f06cdaf19ee0cc24764e09eff1c99257",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
    _aux_deb("t/tdb", "libtdb1_1.4.8-2_amd64.deb",
             "8732969f56ad8f3bdc4e789602682f7c067f9ccd03dfd622118df817c52437d0",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("t/tdb", "libtdb-dev_1.4.8-2_amd64.deb",
             "830e5e526fdfc5daa9cefdea7365622e7f0cc531417603a9359c2a9c50a832f5",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_S46_PERL_AUX: tuple[dict, ...] = (
    *list(_S23_PERL_AUX),
    _s23_deb("libn/libnet-dns-perl", "libnet-dns-perl_1.36-1_all.deb",
             "2d5f9cf243c04f41e7c906bad882e67407a3593cf52caf2d814483f0f92f90fc",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("libn/libnet-ssleay-perl", "libnet-ssleay-perl_1.92-2+b1_amd64.deb",
             "33b84b99b0374dcc8bf4a339554b06c035189359deb9f0aab431d16b170ca52a",
             library_dirs=(_AUX_MULTIARCH,)),
    _s23_deb("libd/libdigest-hmac-perl", "libdigest-hmac-perl_1.04+dfsg-2_all.deb",
             "840aeda60f5eb20b483943b4ef9f2dc901f5884484b05edc02c935eeb287974d"),
)

_S46_SWIG_AUX: tuple[dict, ...] = (
    _aux_deb("s/swig", "swig4.0_4.1.0-0.2_amd64.deb",
             "fad70d1d34431a6d12f7fed3f7df8bf1a089a618b7b34c775cafaa95ad211c2d",
             bin_dirs=("usr/bin",)),
    _aux_deb("p/python3.11", "libpython3.11-dev_3.11.2-6+deb12u8_amd64.deb",
             "01a8eddeb8505bb6e2c01209cda66b41fb5ebeaa64e69d0e25f7131915f1cd32",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

_S46_CANL_AUX: tuple[dict, ...] = tuple(_S46_BISON_FLEX_AUX) + tuple(_ONBOARD_AUTOTOOLS_AUX)

_S46_STUBBY_AUX: tuple[dict, ...] = (
    _aux_deb("liby/libyaml", "libyaml-0-2_0.2.5-1_amd64.deb",
             "207b539919a47c85bcf738677f0ccf5bbac9844f2d3f158696f518be4c4ba6c4",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("liby/libyaml", "libyaml-dev_0.2.5-1_amd64.deb",
             "429a3853453346d971b7a6abc3a9dde4a7bb37ead65685de0eb031871b33b8e2",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,)),
)

_S46_DAVIX_AUX: tuple[dict, ...] = tuple(_S46_LIBXML2_AUX) + tuple(_LIBCURL_AUX)

_S46_CKERMIT_AUX: tuple[dict, ...] = (
    _aux_deb("p/pam", "libpam0g_1.5.2-6+deb12u2_amd64.deb",
             "a06f889caf9e97ccf04dedec0905573916bc6ec3366ade2c6ef8900047fd5cc1",
             library_dirs=(_AUX_MULTIARCH,)),
    _aux_deb("p/pam", "libpam0g-dev_1.5.2-6+deb12u2_amd64.deb",
             "acee39196e2e3ccf51fd7ccdf1247d7a4bd061cd6fd17c277eccbdcc87d6b6f1",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
)

_S46_SPECS: tuple[dict, ...] = (
    {
        "family": "stubby", "version": "1.7.3",
        "url": "https://deb.debian.org/debian/pool/main/g/getdns/getdns_1.7.3.orig.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "f1404ca250f02e37a118aa00cf0ec2cbe11896e060c6d369c6761baea7d55a2c",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DENABLE_SHARED=ON",
                      "-DENABLE_STATIC=OFF", "-DBUILD_TESTING=OFF",
                      "-DENABLE_STUB_ONLY=ON", "-DUSE_LIBIDN2=OFF",
                      "-DBUILD_LIBEV=OFF", "-DBUILD_LIBEVENT2=OFF", "-DBUILD_LIBUV=OFF",
                      "-DBUILD_EXAMPLES=OFF", "-DBUILD_GETDNS_QUERY=OFF",
                      "-DBUILD_GETDNS_SERVER_MON=OFF", "-DBUILD_STUBBY=ON",
                      "-DOPENSSL_ROOT_DIR={prefix}", "-DCMAKE_PREFIX_PATH={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include -I{aux}/usr/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/stubby", "launch": ["-V"],
        "aux_sources": list(_S46_STUBBY_AUX),
        "note": ("getdns 1.7.3's stubby DNS-over-TLS client linked to the subject libssl"),
    },
    {
        "family": "ckermit", "version": "402~beta08",
        "url": "https://deb.debian.org/debian/pool/main/c/ckermit/ckermit_402~beta08.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "f611a290866bacfd4fe0a4f9321261686351efd8f97a9c76698f3ef431a7b397",
        "make": ["linux+ssl", "SSLINC=-I{prefix}/include -I{aux}/usr/include",
                 "SSLLIB=-L{prefix}/lib -L{aux}/usr/lib/x86_64-linux-gnu "
                 "-Wl,-rpath,{prefix}/lib -Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu"],
        "artifact": "wermit", "launch": ["-V"],
        "aux_sources": list(_S46_CKERMIT_AUX),
        "note": ("C-Kermit 10.0's HTTPS client path (ck_ssl.c) linked to the subject libssl"),
    },
    {
        "family": "xar", "version": "1.8.0.498",
        "url": "https://deb.debian.org/debian/pool/main/x/xar/xar_1.8.0.498.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "9cee4f80b96cf592ccc545a4fdd51e4da4a5bd3b4734901637d67b043eff3c75",
        "pre_build": [["sh", "-c", ("sed -i 's#/usr#{aux}/usr#g' {aux}/usr/bin/xml2-config; "
                                       "cd xar && ./configure --prefix={root}/.l7-install "
                                       "--with-openssl={prefix} && make -j4")]],
        "make": ["-C", "xar"], "artifact": "xar/xar", "launch": ["--version"],
        "aux_sources": list(_S46_LIBXML2_AUX),
        "note": ("xar 1.8.0's signed-archive path through the subject libcrypto"),
    },
    {
        "family": "imx-code-signing-tool", "version": "3.3.1+dfsg",
        "url": ("https://deb.debian.org/debian/pool/main/i/imx-code-signing-tool/"
                "imx-code-signing-tool_3.3.1+dfsg.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "make", "configure": None,
        "sha256": "1f804b078d45344f099b543bde712c205ee80a4b231bff99f68c625e60ced9d1",
        "make": ["-C", "code/cst", "OPENSSL_PATH={prefix}"],
        "artifact": "code/cst/release/linux64/cst", "launch": ["--help"],
        "note": ("NXP CST 3.3.1 signs an HAB CSF image with the subject libcrypto"),
    },
    {
        "family": "canl-c", "version": "3.0.0",
        "url": "https://deb.debian.org/debian/pool/main/c/canl-c/canl-c_3.0.0.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "3d397ea2a8144f5945449919d599add6238da87fba2134407585d48c86db9796",
        "pre_build": [["sh", "-c", ("sed -i 's#/usr/share#{aux}/usr/share#g' "
                                       "{aux}/usr/bin/libtoolize; ./configure --prefix={root}/.l7-install")]],
        "make": [MAKE_JOBS], "artifact": ".libs/libcanl_c.so*", "launch": None,
        "aux_sources": list(_S46_CANL_AUX),
        "env_extra": {"PATH": "{aux}/usr/bin:" + os.environ.get("PATH", ""),
                      "M4": "{aux}/usr/bin/m4",
                      "LIBTOOL": "{aux}/usr/bin/libtool"},
        "ldflags_extra": "-Wl,-rpath,{prefix}/lib",
        "note": ("canl-c 3.0.0's X.509 proxy-certificate path through the subject libcrypto"),
    },
    {
        "family": "libdigidoc2", "version": "3.10.5",
        "url": "https://deb.debian.org/debian/pool/main/libd/libdigidoc/libdigidoc_3.10.5.orig.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "f635bbce14936b5a7d1eeac9623874ba56982c15b07c2ccd3f9865138932835b",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX={root}/.l7-install",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_DISABLE_FIND_PACKAGE_Doxygen=ON",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include -I{aux}/usr/include "
                      "-I{aux}/usr/include/libxml2",
                      "-DCMAKE_CXX_FLAGS=-I{prefix}/include -I{aux}/usr/include "
                      "-I{aux}/usr/include/libxml2",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/libdigidoc/libdigidoc.so*", "launch": None,
        "aux_sources": list(_S46_LIBXML2_AUX),
        "note": ("libdigidoc 3.10.5's XAdES/BDoc signing path linked to the subject libcrypto"),
    },
    {
        "family": "libewf", "version": "20140813",
        "url": "https://deb.debian.org/debian/pool/main/libe/libewf/libewf_20140813.orig.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "dbfdf1bbea5944b014c2311cce4615d92b2b6b91c8401eef8640de9f3e75845b",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--without-libfuse", "--disable-python", "--disable-static"],
        "make": [MAKE_JOBS], "artifact": "libewf/.libs/libewf.so*", "launch": None,
        "aux_sources": list(_ONBOARD_AUTOTOOLS_AUX),
        "pre_build": [["sh", "-c", ("find . \( -name aclocal.m4 -o -name configure -o -name Makefile.in "
                                       "-o -name config.h.in \) -print0 | xargs -0 touch")]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "note": ("libewf 20140813's digest/encryption path through the subject libcrypto"),
    },
    {
        "family": "yafc", "version": "1.3.7",
        "url": "https://deb.debian.org/debian/pool/main/y/yafc/yafc_1.3.7.orig.tar.xz",
        "archive": "tar.xz", "build_system": "configure",
        "sha256": "4b3ebf62423f21bdaa2449b66d15e8d0bb04215472cb63a31d473c3c3912c1e0",
        "configure": ["--prefix={root}/.l7-install", "--without-ssh",
                      "--with-openssl={prefix}"],
        "make": [MAKE_JOBS], "artifact": "src/yafc", "launch": ["--version"],
        "aux_sources": list(_S46_BSD_AUX),
        "note": ("yafc 1.3.7's FTPS client path linked to the subject libssl"),
    },
    {
        "family": "kore", "version": "4.1.0",
        "url": "https://deb.debian.org/debian/pool/main/k/kore/kore_4.1.0.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "b7d73b005fde0ea01c356a54e4bbd8a209a4dff9cf315802a127ce7267efbe61",
        "make": [MAKE_JOBS, "OPENSSL_PATH={prefix}",
                 "CFLAGS=-Wall -Wno-error -Wno-missing-prototypes "
                 "-Wno-missing-declarations -Wno-deprecated-declarations "
                 "-I{prefix}/include"],
        "artifact": "kore", "launch": ["-v"],
        "note": ("Kore 4.1.0's TLS listener linked to the subject libssl"),
    },
    {
        "family": "davix", "version": "0.8.4",
        "url": "https://deb.debian.org/debian/pool/main/d/davix/davix_0.8.4.orig.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "519d56f746e86ea3fd615bc49e559b520df07e051e1ca3d8c092067958f3b2b7",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX={root}/.l7-install",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DEMBEDDED_LIBCURL=OFF",
                      "-DLIBXML2_INCLUDE_DIR={aux}/usr/include/libxml2",
                      "-DLIBXML2_LIBRARY={aux}/usr/lib/x86_64-linux-gnu/libxml2.so",
                      "-DCMAKE_CXX_FLAGS=-I{prefix}/include -I{aux}/usr/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib "
                      "-L{aux}/usr/lib/x86_64-linux-gnu"],
        "make": [], "artifact": "bin/davix-get", "launch": ["--version"],
        "aux_sources": list(_S46_DAVIX_AUX),
        "note": ("davix 0.8.4's HTTPS client (davix-get) linked to the subject libssl"),
    },
    {
        "family": "xilinx-bootgen", "version": "2022.2",
        "url": "https://deb.debian.org/debian/pool/main/x/xilinx-bootgen/xilinx-bootgen_2022.2.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "af1d494e30f357b46868ad4580f78bef7c660b5a32a10308c3bc8ae452a9eaba",
        "make": [MAKE_JOBS,
                 "LIBS=-L{prefix}/lib -lssl -lcrypto -ldl -lpthread -Wl,-rpath,{prefix}/lib",
                 "INCLUDE_USER=-I{prefix}/include"],
        "artifact": "bootgen", "launch": ["-help"],
        "note": ("Xilinx Bootgen 2022.2 signs boot images with the subject libcrypto"),
    },
    {
        "family": "perl-net-dns-sec", "version": "1.20",
        "url": ("https://deb.debian.org/debian/pool/main/libn/libnet-dns-sec-perl/"
                "libnet-dns-sec-perl_1.20.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "f5e495e575cda03a8b72fa07c20ad57bb3a767dc9408ad0329ef62c3637a6865",
        "pre_build": [["sh", "-c", ("mkdir -p {root}/.perl-deps/lib {root}/.perl-deps/arch; "
                                       "cp -a {aux}/usr/share/perl5/. {root}/.perl-deps/lib/; "
                                       "cp -a {aux}/usr/lib/x86_64-linux-gnu/perl5/5.36/. "
                                       "{root}/.perl-deps/arch/ 2>/dev/null || true; "
                                       "export PERL5LIB={aux}/usr/share/perl5:{aux}/usr/lib/x86_64-linux-gnu/perl5/5.36:{root}/.perl-deps/lib:{root}/.perl-deps/arch; "
                                       "perl Makefile.PL OPENSSL_PREFIX={prefix}")]],
        "make": [MAKE_JOBS], "artifact": "blib/arch/auto/Net/DNS/SEC/SEC.so", "launch": None,
        "aux_sources": list(_S46_PERL_AUX),
        "env_extra": {"LD_LIBRARY_PATH": "{prefix}/lib"},
        "note": ("Net::DNS::SEC 1.20's DNSSEC signing/validation through the subject libcrypto"),
    },
    {
        "family": "libcrypt-ssleay-perl", "version": "0.73.06",
        "url": ("https://deb.debian.org/debian/pool/main/libc/libcrypt-ssleay-perl/"
                "libcrypt-ssleay-perl_0.73.06.orig.tar.gz"),
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "f8ecca45c87eb91325992b13f0594f808e6f1bc4c3b9a7f141b9a838384d252c",
        "pre_build": [["sh", "-c", ("mkdir -p {root}/.perl-deps/lib {root}/.perl-deps/arch; "
                                       "cp -a {aux}/usr/share/perl5/. {root}/.perl-deps/lib/; "
                                       "cp -a {aux}/usr/lib/x86_64-linux-gnu/perl5/5.36/. "
                                       "{root}/.perl-deps/arch/ 2>/dev/null || true; "
                                       "export PERL5LIB={aux}/usr/share/perl5:{aux}/usr/lib/x86_64-linux-gnu/perl5/5.36:{root}/.perl-deps/lib:{root}/.perl-deps/arch; "
                                       "perl Makefile.PL OPENSSL_PREFIX={prefix}")]],
        "make": [MAKE_JOBS], "artifact": "blib/arch/auto/Crypt/SSLeay/SSLeay.so", "launch": None,
        "aux_sources": list(_S46_PERL_AUX),
        "env_extra": {"LD_LIBRARY_PATH": "{prefix}/lib"},
        "note": ("Crypt::SSLeay 0.73_06's XS TLS client linked to the subject libssl"),
    },
    {
        "family": "tcl-tls", "version": "1.7.22",
        "url": "https://deb.debian.org/debian/pool/main/t/tcltls/tcltls_1.7.22.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "e84e2b7a275ec82c4aaa9d1b1f9786dbe4358c815e917539ffe7f667ff4bc3b4",
        "configure": ["--prefix={root}/.l7-install", "--with-ssl-dir={prefix}",
                      "--enable-deterministic",
                      "--with-tcl={aux}/usr/lib/x86_64-linux-gnu/tcl8.6",
                      "--with-tclinclude={aux}/usr/include"],
        "make": [MAKE_JOBS], "artifact": "tcltls.so", "launch": None,
        "aux_sources": list(_S46_TCL_AUX),
        "pre_build": [["sh", "-c", ("sed -i 's#/usr#{aux}/usr#g' "
                                       "{aux}/usr/lib/x86_64-linux-gnu/tcl8.6/tclConfig.sh; "
                                       "sed -i 's#/usr#{aux}/usr#g' "
                                       "{aux}/usr/lib/tcl8.6/tclConfig.sh")]],
        "env_extra": {"PATH": "{aux}/usr/bin:" + os.environ.get("PATH", ""),
                      "TCL_LIBRARY": "{aux}/usr/share/tcltk/tcl8.6"},
        "ldflags_extra": "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
        "note": ("TclTLS 1.7.22's TLS client channel linked to the subject libssl"),
    },
    {
        "family": "fdm", "version": "1.9+git20181219",
        "url": ("https://deb.debian.org/debian/pool/main/f/fdm/"
                "fdm_1.9+git20181219.orig.tar.xz"),
        "archive": "tar.xz", "build_system": "autotools",
        "sha256": "055fcd7c654efa97b94c68087537bf59347fa9383f7cd8578ec54f1953cbffe0",
        "configure": ["--prefix={root}/.l7-install", "--enable-pcre"],
        "make": [MAKE_JOBS], "artifact": "fdm", "launch": ["-V"],
        "aux_sources": list(_S46_FDM_AUX),
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "note": ("fdm 1.9's IMAPS/POP3S fetch path through the subject libssl"),
    },
    {
        "family": "nsca-ng-client", "version": "1.6",
        "url": "https://deb.debian.org/debian/pool/main/n/nsca-ng/nsca-ng_1.6.orig.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "4454de9ea043954687f9b6d912c7fded1713899126944b8ad153340b7c331bcb",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--enable-client", "--enable-server"],
        "make": [MAKE_JOBS], "artifact": "src/client/send_nsca", "launch": ["-h"],
        "aux_sources": tuple(_S46_CONFUSE_AUX) + tuple(_ONBOARD_AUTOTOOLS_AUX),
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "note": ("nsca-ng 1.6's TLS check submission client linked to the subject libssl"),
    },
    {
        "family": "nsca-ng-server", "version": "1.6",
        "url": "https://deb.debian.org/debian/pool/main/n/nsca-ng/nsca-ng_1.6.orig.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "4454de9ea043954687f9b6d912c7fded1713899126944b8ad153340b7c331bcb",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--enable-client", "--enable-server"],
        "make": [MAKE_JOBS], "artifact": "src/server/nsca-ng", "launch": ["-h"],
        "aux_sources": tuple(_S46_CONFUSE_AUX) + tuple(_ONBOARD_AUTOTOOLS_AUX),
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "note": ("nsca-ng 1.6's TLS check receiver linked to the subject libssl"),
    },
    {
        "family": "sbsigntool", "version": "0.9.4",
        "url": "https://deb.debian.org/debian/pool/main/s/sbsigntool/sbsigntool_0.9.4.orig.tar.xz",
        "archive": "tar.xz", "build_system": "autotools",
        "sha256": "016d7db322492b09f2f8a3bc02aa2b643db3ca0f31f9efa630c3e8ddef9484e8",
        "configure": ["--prefix={root}/.l7-install", "--with-efi-include={aux}/usr/include"],
        "make": [MAKE_JOBS], "artifact": "src/sbsign", "launch": ["--version"],
        "aux_sources": tuple(_S46_BISON_FLEX_AUX) + tuple(_ONBOARD_AUTOTOOLS_AUX) + (
            _aux_deb("b/binutils", "binutils-dev_2.40-2_amd64.deb",
                     "35066c624bd9d9f3d7fb9fee8f98556482a4fd0bbbf4a00a285fa877da350257",
                     include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),
            _aux_deb("g/gnu-efi", "gnu-efi_3.0.15-1_amd64.deb",
                     "1e668cebcb94678b39a69e5c7b8f1d1eb51fd4eb251643491a8c249ae6fa0c36",
                     include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,)),),
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "note": ("sbsigntool 0.9.4 signs a PE image with the subject libcrypto"),
    },
    {
        "family": "conserver-client", "version": "8.2.7",
        "url": "https://deb.debian.org/debian/pool/main/c/conserver/conserver_8.2.7.orig.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "b88f1880f4090b42370e075ca9c8a6062fb553ee33f155b204714c43dc71cef3",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--without-pam"],
        "make": [MAKE_JOBS], "artifact": "console/console", "launch": ["-V"],
        "aux_sources": list(_ONBOARD_AUTOTOOLS_AUX),
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "note": ("conserver 8.2.7's TLS console client linked to the subject libssl"),
    },
    {
        "family": "conserver-server", "version": "8.2.7",
        "url": "https://deb.debian.org/debian/pool/main/c/conserver/conserver_8.2.7.orig.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "sha256": "b88f1880f4090b42370e075ca9c8a6062fb553ee33f155b204714c43dc71cef3",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--without-pam"],
        "make": [MAKE_JOBS], "artifact": "conserver/conserver", "launch": ["-V"],
        "aux_sources": list(_ONBOARD_AUTOTOOLS_AUX),
        "pre_build": [["sh", "-c", _ONBOARD_AUTOTOOLS_BOOTSTRAP]],
        "env_extra": dict(_ONBOARD_AUTOTOOLS_ENV),
        "note": ("conserver 8.2.7's TLS console server linked to the subject libssl"),
    },
    {
        "family": "sqlcipher", "version": "4.6.1",
        "url": "https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v4.6.1.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "d8f9afcbc2f4b55e316ca4ada4425daf3d0b4aab25f45e11a802ae422b9f53a3",
        "configure": ["--prefix={root}/.l7-install", "--with-crypto-lib=openssl",
                      "--disable-static"],
        "make": [MAKE_JOBS, "sqlcipher"], "artifact": "sqlcipher", "launch": ["--version"],
        "aux_sources": list(_S46_TCL_AUX),
        "pre_build": [["sh", "-c", ("mkdir -p {root}/.l7-bin; "
            "printf '#!/bin/sh\\nTCL_LIBRARY=%s TCLLIBPATH=%s exec %s \"$@\"\\n' "
            "'{aux}/usr/share/tcltk/tcl8.6' '{aux}/usr/share/tcltk/tcl8.6/tcl8' "
            "'{aux}/usr/bin/tclsh8.6' > {root}/.l7-bin/tclsh; "
            "chmod +x {root}/.l7-bin/tclsh")]],
        "env_extra": {"PATH": "{root}/.l7-bin:{aux}/usr/bin:" + os.environ.get("PATH", ""),
                      "TCL_LIBRARY": "{aux}/usr/share/tcltk/tcl8.6",
                      "LD_LIBRARY_PATH": "{aux}/usr/lib/x86_64-linux-gnu:{prefix}/lib"},
        "note": ("SQLCipher 4.6.1's AES-256 page encryption through the subject libcrypto"),
    },
    {
        "family": "apk-tools", "version": "2.14.4",
        "url": ("https://gitlab.alpinelinux.org/alpine/apk-tools/-/archive/v2.14.4/"
                "apk-tools-v2.14.4.tar.gz"),
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "c8ad16bddfae988392ad067a244cfdaf643eb7d6761b73450739585ca76f9a25",
        "pre_build": [["sh", "-c", (
            "mkdir -p .l7-pc; printf 'prefix={prefix}\\n"
            "Name: openssl\\nDescription: subject shim\\n"
            "Version: 3\\nLibs: -L{prefix}/lib -lssl -lcrypto\\n"
            "Cflags: -I{prefix}/include\\n' > .l7-pc/openssl.pc")]],
        "make": [MAKE_JOBS], "artifact": "src/apk", "launch": ["--version"],
        "env_extra": {"PKG_CONFIG_PATH": "{root}/.l7-pc:{prefix}/lib/pkgconfig"},
        "note": ("apk-tools 2.14.4's package-signature verification through the subject libcrypto"),
    },
    {
        "family": "ixwebsocket-libs", "version": "11.4.5",
        "url": ("https://github.com/machinezone/IXWebSocket/archive/refs/tags/"
                "v11.4.5.tar.gz"),
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "c5fc225edec32bf7d583e55347ef2c9c4940d005c13ef5e848354a85602f5fd6",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DUSE_TLS=ON", "-DUSE_OPEN_SSL=ON",
                      "-DUSE_MBED_TLS=OFF", "-DBUILD_TESTING=OFF",
                      "-DBUILD_SHARED_LIBS=ON",
                      "-DCMAKE_INSTALL_PREFIX={root}/.l7-install",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_CXX_FLAGS=-I{prefix}/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/libixwebsocket.so*", "launch": None,
        "note": ("IXWebSocket 11.4.5's TLS client/server linked to the subject libssl"),
    },
    {
        "family": "python3-m2crypto", "version": "0.38.0",
        "url": "https://deb.debian.org/debian/pool/main/m/m2crypto/m2crypto_0.38.0.orig.tar.xz",
        "archive": "tar.xz", "build_system": "make", "configure": None,
        "sha256": "29dd19418ed7d04605287dd5c33dd473ea3bc9f9a9528841c5998b10b581aec4",
        "pre_build": [["sh", "-c", ("mkdir -p {root}/.l7-bin; ln -sf {aux}/usr/bin/swig4.0 {root}/.l7-bin/swig; "
                                       "python3 setup.py build_ext --inplace --openssl={prefix}")]],
        "make": ["-f", "/dev/null", "--eval=all:;@true", "all"],
        "artifact": "M2Crypto/_m2crypto*.so", "launch": None,
        "aux_sources": list(_S46_SWIG_AUX),
        "env_extra": {"PATH": "{root}/.l7-bin:{aux}/usr/bin:" + os.environ.get("PATH", ""),
                      "LD_LIBRARY_PATH": "{prefix}/lib",
                      "CPPFLAGS": "-I{prefix}/include -I{aux}/usr/include/python3.11",
                      "LDFLAGS": "-L{prefix}/lib -L{aux}/usr/lib/x86_64-linux-gnu "
                                 "-Wl,-rpath,{prefix}/lib"},
        "note": ("M2Crypto 0.38.0's SWIG binding to the subject libssl/libcrypto"),
    },
    {
        "family": "python3-scrypt", "version": "0.8.20",
        "url": "https://deb.debian.org/debian/pool/main/p/python-scrypt/python-scrypt_0.8.20.orig.tar.gz",
        "archive": "tar.gz", "build_system": "make", "configure": None,
        "sha256": "abd83b85b1a4317e41be1109a9d8cf97354ce0d62c8b15a0f60534082afe36f5",
        "pre_build": [["sh", "-c", "python3 setup.py build_ext --inplace"]],
        "make": ["-f", "/dev/null", "--eval=all:;@true", "all"],
        "artifact": "_scrypt*.so", "launch": None,
        "aux_sources": list(_S46_SWIG_AUX),
        "env_extra": {"PATH": "{aux}/usr/bin:" + os.environ.get("PATH", ""),
                      "LD_LIBRARY_PATH": "{prefix}/lib",
                      "CFLAGS": "-I{prefix}/include -I{aux}/usr/include/python3.11",
                      "LDFLAGS": "-L{prefix}/lib -L{aux}/usr/lib/x86_64-linux-gnu "
                                 "-Wl,-rpath,{prefix}/lib"},
        "note": ("py-scrypt 0.8.20's scrypt KDF linked to the subject libcrypto"),
    },
    {
        "family": "libddsc0debian", "version": "0.10.2",
        "url": "https://deb.debian.org/debian/pool/main/c/cyclonedds/cyclonedds_0.10.2.orig.tar.gz",
        "archive": "tar.gz", "build_system": "cmake",
        "sha256": "ac59ee08975cd25a1fb414ddeb0183fb8636b12d49cea80373013bea59465b43",
        "configure": ["-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTING=OFF",
                      "-DENABLE_SSL=ON", "-DENABLE_SECURITY=ON",
                      "-DCMAKE_INSTALL_PREFIX={root}/.l7-install",
                      "-DCMAKE_PREFIX_PATH={prefix}", "-DOPENSSL_ROOT_DIR={prefix}",
                      "-DCMAKE_C_FLAGS=-I{prefix}/include",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-L{prefix}/lib -Wl,-rpath,{prefix}/lib"],
        "make": [], "artifact": "b/lib/libddsc.so*", "launch": None,
        "note": ("CycloneDDS 0.10.2's TLS/security plugin linked to the subject libssl"),
    },
    {
        "family": "libfsapfs1", "version": "20201107",
        "url": "https://deb.debian.org/debian/pool/main/libf/libfsapfs/libfsapfs_20201107.orig.tar.gz",
        "archive": "tar.gz", "build_system": "configure",
        "sha256": "dc0543b86779a3c0b46913d780a9fd7fdb7af86e1fea61c54f0d1d0209a18f15",
        "configure": ["--prefix={root}/.l7-install", "--with-openssl={prefix}",
                      "--disable-static"],
        "make": [MAKE_JOBS], "artifact": "libfsapfs/.libs/libfsapfs.so*", "launch": None,
        "note": ("libfsapfs 20201107's APFS image verification through the subject libcrypto"),
    },
)

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


def _prepare_aux(recipe: dict, work: Path) -> tuple[dict, str | None]:
    """Acquire and extract a recipe's pinned auxiliary dependency packages.

    A recipe may name `aux_sources` (a non-subject dependency the venue does not ship as a
    development package). Each is fetched by URL, refused unless its bytes match the authored
    SHA-256, extracted under the family's scratch directory, and exposed to the build through
    include/library/pkg-config paths. The subject OpenSSL is still the only OpenSSL: nothing here
    provides or replaces libssl/libcrypto.
    """
    specs = recipe.get("aux_sources") or []
    if not specs:
        return {}, None
    aux_root = work / "aux"
    include_dirs: list[str] = []
    library_dirs: list[str] = []
    pkgconfig_dirs: list[str] = []
    bin_dirs: list[str] = []
    rewritten_pc: set[str] = set()
    for spec in specs:
        aux_root.mkdir(parents=True, exist_ok=True)
        name = str(spec["url"]).rsplit("/", 1)[-1]
        archive = aux_root / name
        fetch = census._fetch(str(spec["url"]), archive)
        if not fetch["ok"] or not archive.is_file():
            return {}, (f"fetching the auxiliary package {name} failed: "
                        f"{census._error_line(fetch)}")
        observed = sha256_file(archive)
        if observed != spec["sha256"]:
            return {}, (f"the auxiliary package {name} digest {observed} does not match the "
                        f"pinned {spec['sha256']}")
        root = aux_root / "root"
        root.mkdir(parents=True, exist_ok=True)
        extract_cmd = list(spec.get("extract") or ["tar", "xf"])
        # ``tar xf <archive> <dir>`` would look for a member named <dir>; a source tarball
        # auxiliary dependency is extracted *into* the shared aux root instead.
        if extract_cmd[:2] == ["tar", "xf"]:
            extract_argv = [*extract_cmd, str(archive), "-C", str(root)]
        else:
            extract_argv = [*extract_cmd, str(archive), str(root)]
        extract = census._run(extract_argv, timeout=STEP_TIMEOUT)
        if not extract["ok"]:
            return {}, (f"extracting the auxiliary package {name} failed: "
                        f"{census._error_line(extract)}")
        include_dirs += [str(root / d) for d in spec.get("include_dirs") or []]
        library_dirs += [str(root / d) for d in spec.get("library_dirs") or []]
        bin_dirs += [str(root / d) for d in spec.get("bin_dirs") or []]
        for rel_dir in spec.get("pkgconfig_dirs") or []:
            pc_dir = root / rel_dir
            # The package's .pc names /usr as its prefix; move it under the extracted root so the
            # compiler and linker see exactly the pinned header and development symlink.
            for pc in sorted(pc_dir.glob("*.pc")):
                # One shared package directory can be named by several specs (the same
                # `usr/lib/<arch>/pkgconfig`); each .pc must be rewritten exactly once or the
                # second substitution would prefix the already-rewritten prefix again.
                if str(pc) in rewritten_pc:
                    continue
                # A development package may ship a .pc symlink whose target is in a package
                # this recipe does not pin; it carries no information we use.
                if not pc.exists():
                    continue
                rewritten_pc.add(str(pc))
                pc.write_text(pc.read_text(encoding="utf-8").replace("/usr", f"{root}/usr"),
                              encoding="utf-8")
            pkgconfig_dirs.append(str(pc_dir))
        for link, target in (spec.get("links") or {}).items():
            link_path = root / link
            link_path.parent.mkdir(parents=True, exist_ok=True)
            if link_path.is_symlink() or link_path.is_file():
                link_path.unlink()
            elif link_path.is_dir():
                # A package may already place a directory at the path a link must replace (the
                # multiarch Qt mkspecs); the pinned link is the complete replacement.
                shutil.rmtree(link_path)
            link_path.symlink_to(str(target))
    return {"include_dirs": include_dirs, "library_dirs": library_dirs,
            "pkgconfig_dirs": pkgconfig_dirs, "bin_dirs": bin_dirs}, None


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
    # A recipe may name pinned auxiliary dependency packages the venue does not ship as
    # development headers (fido2's libudev-dev). They are acquired by digest and added to the
    # build environment; the subject prefix remains the only OpenSSL.
    # A template recipe may name a ``pkgconfig_shim``: several upstream configure scripts probe
    # with `pkg-config libssl`, while the candidate drop-in install ships no openssl.pc.  The shim
    # is a generated build input (never a source patch) and is written identically for both
    # subjects, so the identical-build-intent rule is preserved.
    if recipe.get("pkgconfig_shim"):
        shim = templates.write_pkgconfig_shim(work, prefix)
        env["PKG_CONFIG_PATH"] = os.pathsep.join([str(shim), env["PKG_CONFIG_PATH"]])

    aux, aux_err = _prepare_aux(recipe, work)
    if aux_err:
        return _subject_row(
            fam, recipe, subject, level=L1, outcome="failed", residual="unavailable",
            failure_class="acquire-failure", reason=aux_err,
            specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
            evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                      f"source:{recipe['url']}#{archive_sha}"],
            steps=steps, canvas=None, limits=limits, prefix=prefix,
            source_root_hash=root_hash)
    if aux.get("include_dirs"):
        env["CPPFLAGS"] += "".join(f" -I{d}" for d in aux["include_dirs"])
    if aux.get("library_dirs"):
        env["LDFLAGS"] += "".join(f" -L{d}" for d in aux["library_dirs"])
    if aux.get("pkgconfig_dirs"):
        env["PKG_CONFIG_PATH"] = os.pathsep.join(
            [*aux["pkgconfig_dirs"], env["PKG_CONFIG_PATH"]])
    # A package whose `configure` probes a dependency by *running* a linked program (memcached's
    # libevent version check) needs that dependency loadable at probe time, and a package whose
    # build invokes a dependency's own `-config` script (icecast's xslt-config) needs it on PATH.
    if aux.get("library_dirs"):
        env["LD_LIBRARY_PATH"] = os.pathsep.join(
            [*aux["library_dirs"], str(prefix / "lib"),
             env.get("LD_LIBRARY_PATH", "")]).rstrip(os.pathsep)
    if aux.get("bin_dirs"):
        env["PATH"] = os.pathsep.join([*aux["bin_dirs"], env.get("PATH", "")])
    # A recipe may extend the link environment (24.17's isync override adds -Wl,-rpath-link so the
    # subject lib dir resolves libssl's transitive libcrypto dependency). Substituted identically for
    # both subjects, so the identical-build-intent rule holds.
    if recipe.get("ldflags_extra"):
        env["LDFLAGS"] = env["LDFLAGS"] + " " + str(recipe["ldflags_extra"]).format(
            prefix=prefix, root=root, aux=work / "aux" / "root", repo=REPO_ROOT)
    # A recipe may extend the environment with prefix-derived variables (24.18's admitted recipes
    # carry the consumer's own `OPENSSL_CFLAGS`/`OPENSSL_LIBS` override, because the candidate install
    # ships no `openssl.pc` while the authority does). Substituted identically for both subjects, so
    # the identical-build-intent rule holds.
    for key, val in (recipe.get("env_extra") or {}).items():
        env[str(key)] = str(val).format(prefix=prefix, root=root,
                                        aux=work / "aux" / "root", repo=REPO_ROOT)

    level = L1
    build_system = str(recipe["build_system"])
    build_dir = str(recipe.get("build_dir") or "b")

    # A recipe may need generated build inputs before its own configure/make runs
    # (u-boot-tools seeds the host-tools Kconfig files its bison/flex-free build
    # cannot generate here). These are build outputs, never source edits, and the
    # same argv is run for both subjects.
    for step in recipe.get("pre_build") or []:
        body = {"prefix": prefix, "root": root, "aux": work / "aux" / "root",
                "repo": REPO_ROOT}
        argv = [str(a).format(**body) for a in step]
        pre = stage("pre-build", census._run(argv, cwd=root, env=env))
        if not pre["ok"]:
            return _subject_row(
                fam, recipe, subject, level=L1, outcome="failed", residual="unbuildable",
                failure_class="configure-failure",
                reason=f"the pre-build step failed: {census._error_line(pre)}",
                specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
                evidence=[f"family:{fam.get('family_id')}",
                          f"recipe:{recipe['recipe_id']}",
                          f"source:{recipe['url']}#{archive_sha}"],
                steps=steps, canvas=None, limits=limits, prefix=prefix,
                source_root_hash=root_hash)

    if build_system in ("autotools", "configure"):
        argv = ["./configure"] + [a.format(prefix=prefix, root=root,
                                           aux=work / "aux" / "root",
                                           repo=REPO_ROOT)
                                  for a in recipe["configure"]]
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
    elif build_system == "cmake":
        argv = (["cmake", "-S", ".", "-B", build_dir]
                + [a.format(prefix=prefix, root=root, aux=work / "aux" / "root",
                            repo=REPO_ROOT)
                   for a in recipe.get("configure") or []])
        # An auxiliary package exposes a development symlink under the extracted root; CMake's
        # pkg-config module emits `-ludev` but not the producing `-L`, so the shared-link flags
        # must name it explicitly (the recipe's own flags remain the defaults for subprocesses).
        if aux.get("library_dirs"):
            link_flags = (f"-L{prefix}/lib -Wl,-rpath,{prefix}/lib"
                          + "".join(f" -L{d}" for d in aux["library_dirs"]))
            argv.append(f"-DCMAKE_SHARED_LINKER_FLAGS={link_flags}")
        conf = stage("configure", census._run(argv, cwd=root, env=env))
        if not conf["ok"]:
            return _subject_row(
                fam, recipe, subject, level=L1, outcome="failed", residual="unbuildable",
                failure_class="configure-failure",
                reason=f"cmake configure failed: {census._error_line(conf)}",
                specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
                evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                          f"source:{recipe['url']}#{archive_sha}"],
                steps=steps, canvas=None, limits=limits, prefix=prefix,
                source_root_hash=root_hash)
        level = L2
    elif build_system == "meson":
        argv = (["meson", "setup", build_dir]
                + [a.format(prefix=prefix, root=root, aux=work / "aux" / "root",
                            repo=REPO_ROOT)
                   for a in recipe.get("configure") or []])
        conf = stage("configure", census._run(argv, cwd=root, env=env))
        if not conf["ok"]:
            return _subject_row(
                fam, recipe, subject, level=L1, outcome="failed", residual="unbuildable",
                failure_class="configure-failure",
                reason=f"meson setup failed: {census._error_line(conf)}",
                specimen_id=specimen_id, variant_id=variant_id, source_sha256=archive_sha,
                evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                          f"source:{recipe['url']}#{archive_sha}"],
                steps=steps, canvas=None, limits=limits, prefix=prefix,
                source_root_hash=root_hash)
        level = L2
    # Any other recipe is the established plain-`make` form: no configure step, the recipe's
    # own make argv runs directly in the extracted tree.

    if build_system == "cmake":
        make_argv = ["cmake", "--build", build_dir, "--parallel", str(MAKE_JOB_COUNT)]
    elif build_system == "meson":
        make_argv = ["ninja", "-C", build_dir]
    else:
        make_argv = ["make"] + [a.format(prefix=prefix, root=root, aux=work / "aux" / "root",
                                         repo=REPO_ROOT) for a in recipe["make"]]
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


def _acquisition_failure_rows(fam: dict, recipe: dict, reason: str, limits: dict,
                              prefix: Path) -> list[dict]:
    """Both subject rows for a family whose pristine source could not be acquired or opened.

    The reason names the source host and URL, so an unreachable upstream is diagnosable from the
    atlas alone. Level `L0`/`not_attempted`/`acquire-failure` is the honest classification: no
    build was attempted because there was no source tree to build.
    """
    name = str(fam.get("canonical_name"))
    return [
        _subject_row(
            fam, recipe, subject, level=L0, outcome="not_attempted", residual="unavailable",
            failure_class="acquire-failure", reason=reason,
            specimen_id=f"specimen:{name}:{recipe['version']}",
            variant_id=f"variant:{name}:{recipe['version']}:pristine",
            source_sha256=None,
            evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                      f"source:{recipe['url']}"],
            steps=None, canvas=None, limits=limits, prefix=prefix)
        for subject in ("authority", "candidate")
    ]


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
    try:
        fetch = census._fetch(recipe["url"], archive)
    except Exception as exc:  # noqa: BLE001 - an unreachable host must not abort the court
        fetch = {"ok": False, "rc": None,
                 "error": f"{type(exc).__name__}: {exc}",
                 "url": recipe["url"]}
    if not fetch["ok"] or not archive.is_file():
        # No source: both subjects are honestly `not_attempted`/acquire-failure. The specimen is
        # still recorded with the recipe's pinned digest -- the intended released tarball.
        rows = [
            _subject_row(
                fam, recipe, subject, level=L0, outcome="not_attempted", residual="unavailable",
                failure_class="acquire-failure",
                reason=(f"fetching the pristine source from {recipe['url']} failed: "
                        f"{census._error_line(fetch)}"),
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
                reason=(f"the fetched {name} {recipe['version']} archive from {recipe['url']} "
                        f"has digest {observed}, which does not match the pinned "
                        f"{recipe['sha256']}"),
                specimen_id=f"specimen:{name}:{recipe['version']}",
                variant_id=f"variant:{name}:{recipe['version']}:pristine",
                source_sha256=observed,
                evidence=[f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                          f"source:{recipe['url']}#{observed}"],
                steps=[dict(fetch, name="fetch")], canvas=None, limits=limits, prefix=auth_prefix)
            for subject in ("authority", "candidate")
        ]
        return rows, _specimen(fam, recipe, observed), _variant(fam, recipe)

    try:
        rows = []
        for subject, prefix, defined in (("authority", auth_prefix, auth_defined),
                                         ("candidate", cand_prefix, cand_defined)):
            rows.append(_measure_subject(fam, recipe, observed, archive, subject, prefix, defined,
                                         auth_prefix, limits))
    except Exception as exc:  # noqa: BLE001 - acquisition failure is a measured outcome
        # Unpacking, extraction or environment preparation raised: the family is an acquire
        # failure naming its source host, and the caller continues with the next family.
        reason = (f"acquiring or preparing the pristine source from {recipe['url']} failed: "
                  f"{type(exc).__name__}: {exc}")
        return (_acquisition_failure_rows(fam, recipe, reason, limits, auth_prefix),
                _specimen(fam, recipe, observed), _variant(fam, recipe))
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


def derive_atlas(families_body: dict, freeze_body: dict, authority_id: str,
                 *, only: set[str] | None = None,
                 reuse: dict | None = None,
                 allow_superseded: bool = False) -> dict:
    """Measure the whole P1000 under both subjects and return the atlas `body`.

    `only`/`reuse` are the evidence-reuse seam: with a committed atlas whose candidate identity
    is byte-identical to the current candidate install, the unchanged families keep their
    previously measured rows and only `only` is rebuilt.  `allow_superseded` is the explicit
    escape hatch for a candidate rebuild (it never claims a match): the reused rows remain bound
    to the committed identity, which is recorded in `evidence_reuse.superseded_identity`.
    """
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
    reuse_runs: dict[tuple[str, str], dict] = {}
    reuse_specimens: dict[str, dict] = {}
    reuse_variants: dict[str, dict] = {}
    reused_families: list[str] = []
    superseded: dict[str, dict] = {}
    committed_identity: dict = {}
    if reuse:
        current = candidate_identity()
        committed = reuse.get("candidate_identity") or {}
        committed_identity = copy.deepcopy(committed)
        for field in ("libssl_so_3_sha256", "libcrypto_so_3_sha256", "install_prefix"):
            if str(current.get(field)) != str(committed.get(field)):
                if not allow_superseded:
                    raise SystemExit(
                        f"[downstream-build-link] --reuse-committed refuses the committed atlas: "
                        f"its candidate_identity.{field} is not the current candidate install")
                superseded[field] = {"committed": str(committed.get(field)),
                                     "current": str(current.get(field))}
        for r in reuse.get("runs") or []:
            reuse_runs[(str(r.get("family_id")), str(r.get("subject")))] = r
        reuse_specimens = {str(s.get("specimen_id")): s for s in reuse.get("specimens") or []}
        reuse_variants = {str(v.get("variant_id")): v for v in reuse.get("variants") or []}
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
        if (only is not None and name not in only
                and (str(entry.get("family_id")), "authority") in reuse_runs
                and (str(entry.get("family_id")), "candidate") in reuse_runs
                and reuse_runs[(str(entry.get("family_id")), "authority")].get("recipe_id")
                == recipe["recipe_id"]
                and reuse_runs[(str(entry.get("family_id")), "candidate")].get("recipe_id")
                == recipe["recipe_id"]):
            rows.append(copy.deepcopy(reuse_runs[(str(entry.get("family_id")), "authority")]))
            rows.append(copy.deepcopy(reuse_runs[(str(entry.get("family_id")), "candidate")]))
            if superseded:
                # Durable provenance: the marker survives into the next atlas so a subsequent
                # incremental run cannot silently relabel these rows as current-candidate evidence.
                for row in rows[-2:]:
                    row["reused_from_candidate_identity"] = committed_identity
            spec = reuse_specimens.get(f"specimen:{name}:{recipe['version']}")
            var = reuse_variants.get(f"variant:{name}:{recipe['version']}:pristine")
            if spec:
                specimens.append(copy.deepcopy(spec))
            if var:
                variants.append(copy.deepcopy(var))
            reused_families.append(name)
            continue
        try:
            fam_rows, specimen, variant = measure_family(
                fam, recipe, auth_prefix, CANDIDATE_PREFIX, auth_defined, cand_defined, limits)
        except Exception as exc:  # noqa: BLE001 - a family failure must not abort the court
            # A failed acquisition or a missing/undecodable source tree is a measured outcome for
            # this family, not a reason to abandon the remaining 999. Both subjects are recorded
            # as `acquire-failure` naming the source host and URL, and the court continues.
            reason = (f"acquiring or building {recipe['url']} failed before a pristine source "
                      f"tree existed: {type(exc).__name__}: {exc}")
            rows.extend(_acquisition_failure_rows(fam, recipe, reason, limits, auth_prefix))
            specimens.append(_specimen(fam, recipe))
            variants.append(_variant(fam, recipe))
            print(f"  [p1000 {entry.get('p1000_rank'):>4}] {name:<12} acquire-failure "
                  f"{reason[:70]}"[:150], flush=True)
            continue
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
    current_identity = candidate_identity()
    carried = {}
    for r in rows:
        marker = r.get("reused_from_candidate_identity")
        if marker and marker != current_identity:
            carried[tuple(sorted(marker.items()))] = marker
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
        "evidence_reuse": ({
            "mode": ("committed-rows-carried-forward"
                     if (superseded or carried) else "committed-rows"),
            "families_reused": len(reused_families),
            "reused_families": sorted(reused_families),
            "candidate_identity_match": not (superseded or carried),
            "superseded_identity": superseded or (list(carried.values()) or None),
        } if reuse else None),
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


def cmd_measure(authority_id: str, only: set[str] | None = None,
                reuse: dict | None = None, allow_superseded: bool = False) -> int:
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
    body = derive_atlas(families_body, freeze_body, authority_id, only=only, reuse=reuse,
                        allow_superseded=allow_superseded)
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

    # 3. Acquisition failure is a measured outcome, not a court abort: a missing source tree is
    #    `None` (never a raised `FileNotFoundError`) and the failure rows name the source host while
    #    accounting for both subjects under the closed vocabulary.
    if census._single_source_root(Path("/nonexistent-acquire-self-test/src")) is not None:
        failures.append("a missing source tree did not report `None`")
    recipe = {"family": "__selftest__", "version": "0", "recipe_id": "selftest",
              "url": "https://unreachable.invalid/__selftest__.tar.gz", "archive": "tar.gz"}
    fam = {"family_id": "__selftest__", "canonical_name": "__selftest__",
           "openssl_linkage": "direct", "directness_class": "direct", "_rank": 0}
    acquire_rows = _acquisition_failure_rows(
        fam, recipe, "fetching the pristine source from https://unreachable.invalid/ failed",
        {"memory_max": "?", "pids_max": "?"}, Path("/p"))
    if {r["subject"] for r in acquire_rows} != {"authority", "candidate"}:
        failures.append("an acquisition failure does not account for both subjects")
    for r in acquire_rows:
        if r.get("failure_class") != "acquire-failure" or "unreachable.invalid" not in str(
                r.get("reason")):
            failures.append("an acquisition failure neither names its class nor its source host")
        problems = downstream_schemas.validate_run(r)
        if problems:
            failures.append(f"an acquisition failure row is schema-invalid: {problems[:2]}")

    # 4. The pure functions behave over the committed evidence.
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
          "(marker and flag both named), a missing source tree is an `acquire-failure` naming its "
          "host rather than a raised exception, the committed P1000 build/link atlas reproduces "
          "with zero findings, and every seeded mutation (candidate linkage resolving the authority, a "
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
    ap.add_argument("--only", default="",
                    help="comma-separated families to rebuild; the rest are reused")
    ap.add_argument("--reuse-committed", action="store_true",
                    help="reuse unchanged families' rows from the committed atlas")
    ap.add_argument("--reuse-previous-candidate", action="store_true",
                    help=("with --reuse-committed, allow rows bound to a different (previous) "
                          "candidate install and record the mismatch explicitly"))
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
    only = {s.strip() for s in str(args.only).split(",") if s.strip()} or None
    reuse = _load_atlas() if args.reuse_committed and OUT.is_file() else None
    return cmd_measure(args.authority, only=only, reuse=reuse,
                       allow_superseded=bool(args.reuse_previous_candidate))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
