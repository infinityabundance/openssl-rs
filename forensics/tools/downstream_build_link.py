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

# irssi 1.4.5 needs GLib (headers and .pc) and ncurses headers. The image carries the GLib runtime
# library but not its development symlink, so the pinned dev package's `libglib-2.0.so` is repointed
# at the already-installed runtime (same 2.74.6 build); libpcre2-dev supplies the `libpcre2-8`
# pkg-config module glib-2.0.pc requires.
_L7_IRSSI_AUX: tuple[dict, ...] = (
    _aux_deb("g/glib2.0", "libglib2.0-dev_2.74.6-2+deb12u9_amd64.deb",
             "217766f170553e14884f7d67c0636b833da43c1e4a65dfe41268ba1292001ccd",
             include_dirs=("usr/include",), library_dirs=(_AUX_MULTIARCH,),
             pkgconfig_dirs=(_AUX_MULTIARCH_PC,),
             links={"usr/lib/x86_64-linux-gnu/libglib-2.0.so":
                    "/lib/x86_64-linux-gnu/libglib-2.0.so.0"}),
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
        extract = census._run([*(spec.get("extract") or ["tar", "xf"]), str(archive),
                               str(root)], timeout=STEP_TIMEOUT)
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


def derive_atlas(families_body: dict, freeze_body: dict, authority_id: str,
                 *, only: set[str] | None = None,
                 reuse: dict | None = None) -> dict:
    """Measure the whole P1000 under both subjects and return the atlas `body`.

    `only`/`reuse` are the evidence-reuse seam: with a committed atlas whose candidate identity
    is byte-identical to the current candidate install, the unchanged families keep their
    previously measured rows and only `only` is rebuilt.  The reused rows are copied verbatim and
    the body records the reuse and the committed artefact digest it came from.
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
    if reuse:
        current = candidate_identity()
        committed = reuse.get("candidate_identity") or {}
        for field in ("libssl_so_3_sha256", "libcrypto_so_3_sha256", "install_prefix"):
            if str(current.get(field)) != str(committed.get(field)):
                raise SystemExit(
                    f"[downstream-build-link] --reuse-committed refuses the committed atlas: its "
                    f"candidate_identity.{field} is not the current candidate install")
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
            spec = reuse_specimens.get(f"specimen:{name}:{recipe['version']}")
            var = reuse_variants.get(f"variant:{name}:{recipe['version']}:pristine")
            if spec:
                specimens.append(copy.deepcopy(spec))
            if var:
                variants.append(copy.deepcopy(var))
            reused_families.append(name)
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
        "evidence_reuse": ({
            "mode": "committed-rows",
            "families_reused": len(reused_families),
            "reused_families": sorted(reused_families),
            "candidate_identity_match": True,
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
                reuse: dict | None = None) -> int:
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
    body = derive_atlas(families_body, freeze_body, authority_id, only=only, reuse=reuse)
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
    ap.add_argument("--only", default="",
                    help="comma-separated families to rebuild; the rest are reused")
    ap.add_argument("--reuse-committed", action="store_true",
                    help="reuse unchanged families' rows from the committed atlas")
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
    return cmd_measure(args.authority, only=only, reuse=reuse)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
