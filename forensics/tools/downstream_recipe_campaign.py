#!/usr/bin/env python3
"""openssl-rs — Phase-24.18 the recipe-admission campaign: the empirical admission record.

Why this exists
---------------
24.16 partitioned the 1,000 counted families by their deepest blocker and named the dominant mover:
`no-admitted-recipe`. 24.17 acted on the recipe-backed blockers and admitted a first bounded batch
(eight recipe-less families). This subphase attacks the **breadth** mover directly: it runs a
bounded, reproducible **admission campaign** over the recipe-less counted families -- it selects a
candidate list deterministically from the committed evidence, finds each candidate's official
release tarball, pins its URL and SHA-256, extracts it, **classifies its build system empirically**
(does it ship a generated `configure`? a plain `Makefile`? only CMake/meson/autogen?), and admits
only the venue-buildable ones into the shared recipe catalogue under the **identical-build-intent**
rule. This tool is the **record** of that campaign.

The admission criterion is empirical, not a claim
-------------------------------------------------
A recipe is admissible when its pinned release tarball ships a build entry point the venue can
execute (a generated `configure`, or a plain `Makefile`) and needs no tool the venue lacks. The
venue is fixed: a C compiler, `make`, `pkg-config`, `zlib` -- and no autoconf/automake/libtool, no
cmake, no meson/ninja, no scdoc, no libnl3. The record is the families **actually built** against
both subjects; a candidate the venue cannot build carries the exact reason, and a recipe that was
not built is never admitted.

The priority rule (a heuristic, honestly labelled)
--------------------------------------------------
The candidate list is deterministic and reproducible: the recipe-less counted families in the
**frozen 24.16 recipe queue** order (source breadth descending, then distro breadth descending, then
popularity descending, then canonical name ascending, then family_id ascending), which is a
**heuristic** ranking over frozen breadth signals, preferring well-known direct OpenSSL consumers
with stable upstream release tarballs. It is **not** a measurement of buildability: the campaign's
yield is a property of this venue and this batch, not of the whole 980.

The identical-build-intent rule
-------------------------------
One recipe per family, and the same `acquire -> configure -> make` argv (and the same prefix-derived
environment) is run for both subjects with the single substitution `{prefix}` = the subject's OpenSSL
install prefix. No candidate-specific source patch is applied; `candidate_specific_patch_count` is 0.
The working source tree is the released tarball unmodified.

What is measured, and what is not
---------------------------------
`before` is the pre-campaign blocker summary, captured once (before the planes are re-measured) and
preserved as a committed input, so the record does not carry a figure against planes that no longer
exist. `after` is re-derived from the committed (re-measured) planes through 24.16's own code path.
The `movement` is the subtraction of two measured figures. The `attempts` are the campaign's own
record: every family tried, admitted or not, with its outcome and (for a non-admitted family) the
reason. A passing record is an **instrument**: it says what was admitted and what the planes then
measured, not that the population now passes.

It executes nothing: it reads committed Phase-24 planes, the preserved pre-campaign baseline and its
own authored attempt record, and writes one derived record, so it is declared `metadata_only` in
`forensics/downstream/container.json` and `evidence_determinism.py` regenerates it host-side. The
recipes it admits are built by `downstream_build_link.py`, which imports this module's catalogue.

Outputs
-------
  forensics/downstream/recipe-campaign.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
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
    write_json,
)

# The Docker-only execution guard. Called first in `main`; this tool executes nothing, but it is a
# Phase-24 entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The 24.16 analysis, so the `after` partition is re-derived through the same code path 24.16
# produced it with, and the two can never drift.
import downstream_blockers as blockers  # noqa: E402

from downstream_schemas import BLOCKER_CLASSES, EXECUTION_LEVEL_RANK  # noqa: E402

OUT = REPO_ROOT / "forensics" / "downstream" / "recipe-campaign.json"
# The preserved pre-campaign baseline: the 24.16 blocker summary captured once, before the planes are
# re-measured, and committed, so the record's `before` is a measured input rather than a figure the
# record carries against planes that no longer exist.
BASELINE = REPO_ROOT / "forensics" / "downstream" / "recipe-campaign-baseline.json"
GENERATOR = "forensics/tools/downstream_recipe_campaign.py"

BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
P1000_RUN = REPO_ROOT / "forensics" / "downstream" / "p1000-run.json"
SHARED_BLOCKERS = blockers.OUT

L4 = "L4-linked"
L3 = "L3-built"

# ---------------------------------------------------------------------------------------------------
# the authored attempt record (the campaign's own measurement, one entry per attempted family)
# ---------------------------------------------------------------------------------------------------
#
# Each entry records the family, the pinned release tarball (URL + SHA-256), the build system
# classified **empirically** from the extracted tree, whether the recipe was admitted, the outcome
# and (for a non-admitted family) the failure class and the reason, the level the venue reached under
# each subject, and -- for an admitted family -- the recipe (argv templates with the single `{prefix}`
# substitution and the prefix-derived environment). `env_extra` carries the consumer's own
# `OPENSSL_CFLAGS`/`OPENSSL_LIBS` override, the same explicit-prefix mechanism the argv-template
# recipes use, because the candidate install ships no `openssl.pc` (the authority does) and a consumer
# that only queries pkg-config `openssl` would otherwise be measured unequally.
#
# The tuple was generated from the campaign probe's observed results (fetch, extract, classify,
# build against both subjects), so the SHA-256 pins and outcomes are the probe's observed values
# rather than transcribed.
ATTEMPTS: tuple[dict, ...] = (
    {'family': 'iperf3', 'canonical_name': 'iperf3', 'version': '3.17.1', 'tarball_url': 'https://downloads.es.net/pub/iperf/iperf-3.17.1.tar.gz', 'archive': 'tar.gz', 'sha256': '84404ca8431b595e86c473d8f23d8bb102810001f15feaf610effd3b318788aa', 'build_system': 'configure', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'configure', 'configure': ['--with-openssl={prefix}'], 'make': ['-j8'], 'artifact': 'src/.libs/libiperf.so*', 'launch': None, 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 'libarchive', 'canonical_name': 'libarchive', 'version': '3.7.7', 'tarball_url': 'https://github.com/libarchive/libarchive/releases/download/v3.7.7/libarchive-3.7.7.tar.gz', 'archive': 'tar.gz', 'sha256': '4cc540a3e9a1eebdefa1045d2e4184831100667e6d7d5b315bb1cbc951f8ddff', 'build_system': 'configure', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'configure', 'configure': ['--with-openssl', '--without-xml2', '--without-expat', '--without-lz4', '--without-zstd', '--without-lzo2', '--without-bz2lib', '--without-lzma', '--without-iconv', '--disable-acl', '--without-nettle'], 'make': ['-j8'], 'artifact': '.libs/libarchive.so*', 'launch': None, 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 'tnftp', 'canonical_name': 'tnftp', 'version': '20230507', 'tarball_url': 'https://ftp.netbsd.org/pub/NetBSD/misc/tnftp/tnftp-20230507.tar.gz', 'archive': 'tar.gz', 'sha256': 'be0134394bd7d418a3b34892b0709eeb848557e86474e1786f0d1a887d3a6580', 'build_system': 'configure', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'configure', 'configure': ['--disable-editcomplete'], 'make': ['-j8'], 'artifact': 'src/tnftp', 'launch': None, 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 'fetchmail', 'canonical_name': 'fetchmail', 'version': '6.5.0', 'tarball_url': 'https://downloads.sourceforge.net/project/fetchmail/branch_6.5/fetchmail-6.5.0.tar.xz', 'archive': 'tar.xz', 'sha256': '42611aea4861a5311e5116843f01c203dceadf440bf2eb1b4a43a445f2977668', 'build_system': 'configure', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'configure', 'configure': ['--with-ssl={prefix}', '--without-hesiod', '--disable-nls', '--without-kerberos'], 'make': ['-j8'], 'artifact': 'fetchmail', 'launch': ['--version'], 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 'hiredis-ssl', 'canonical_name': 'hiredis-ssl', 'version': '1.3.0', 'tarball_url': 'https://github.com/redis/hiredis/archive/refs/tags/v1.3.0.tar.gz', 'archive': 'tar.gz', 'sha256': '25cee4500f359cf5cad3b51ed62059aadfc0939b05150c1f19c7e2829123631c', 'build_system': 'make', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'make', 'configure': None, 'make': ['-j8', 'USE_SSL=1'], 'artifact': 'libhiredis_ssl.so*', 'launch': None, 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 'tinc', 'canonical_name': 'tinc', 'version': '1.0.36', 'tarball_url': 'https://www.tinc-vpn.org/packages/tinc-1.0.36.tar.gz', 'archive': 'tar.gz', 'sha256': '40f73bb3facc480effe0e771442a706ff0488edea7a5f2505d4ccb2aa8163108', 'build_system': 'configure', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'configure', 'configure': ['--with-openssl', '--disable-lzo', '--disable-zlib'], 'make': ['-j8'], 'artifact': 'src/tincd', 'launch': ['--version'], 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 's-nail', 'canonical_name': 's-nail', 'version': '14.9.25', 'tarball_url': 'https://ftp.sdaoden.eu/s-nail-14.9.25.tar.xz', 'archive': 'tar.xz', 'sha256': '20ff055be9829b69d46ebc400dfe516a40d287d7ce810c74355d6bdc1a28d8a9', 'build_system': 'make', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'link-failure', 'reason': "dt_needed=['libc.so.6'] imported=0 resolved=False", 'observed': {'authority': 'L3-built', 'candidate': 'L3-built'}, 'recipe': None},
    {'family': 'libcoap', 'canonical_name': 'libcoap', 'version': '4.3.5', 'tarball_url': 'https://github.com/obgm/libcoap/releases/download/v4.3.5/libcoap-4.3.5.tar.gz', 'archive': 'tar.gz', 'sha256': 'a417ed26ec6c95c041b42353b5b6fad1602e2bf42a6e26c09863450e227b7b5f', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'mosquitto', 'canonical_name': 'mosquitto', 'version': '2.0.20', 'tarball_url': 'https://mosquitto.org/files/source/mosquitto-2.0.20.tar.gz', 'archive': 'tar.gz', 'sha256': 'ebd07d89d2a446a7f74100ad51272e4a8bf300b61634a7812e19f068f2759de8', 'build_system': 'make', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'make', 'configure': None, 'make': ['-j8', '-C', 'lib', 'WITH_TLS=yes', 'WITH_BUNDLED_DEPS=yes'], 'artifact': 'lib/libmosquitto.so*', 'launch': None, 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 'proxytunnel', 'canonical_name': 'proxytunnel', 'version': '1.12.2', 'tarball_url': 'https://github.com/proxytunnel/proxytunnel/archive/refs/tags/v1.12.2.tar.gz', 'archive': 'tar.gz', 'sha256': 'edb33a74ba49e745b55b790f123366c8336729947225f4b5d816f1f90551ecfe', 'build_system': 'make', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'make', 'configure': None, 'make': ['-j8', 'SSL_LIBS=-L{prefix}/lib -lssl -lcrypto'], 'artifact': 'proxytunnel', 'launch': ['-h'], 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 'lftp', 'canonical_name': 'lftp', 'version': '4.9.3', 'tarball_url': 'https://lftp.yar.ru/ftp/lftp-4.9.3.tar.xz', 'archive': 'tar.xz', 'sha256': '96e7199d7935be33cf6b1161e955b2aab40ab77ecdf2a19cea4fc1193f457edc', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for library containing res_search... none required', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'rhash', 'canonical_name': 'rhash', 'version': '1.4.5', 'tarball_url': 'https://github.com/rhash/RHash/archive/refs/tags/v1.4.5.tar.gz', 'archive': 'tar.gz', 'sha256': '6db837e7bbaa7c72c5fd43ca5af04b1d370c5ce32367b9f6a1f7b49b2338c09a', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': '', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'medusa', 'canonical_name': 'medusa', 'version': '2.2', 'tarball_url': 'https://github.com/jmk-foofus/medusa/archive/refs/tags/2.2.tar.gz', 'archive': 'tar.gz', 'sha256': 'b4c07f4d8d6e1e4b2c60d91e429ffe20d52afa80fea8c401ac548967d1fe194a', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'build-failure', 'reason': 'mv -f $depbase.Tpo $depbase.Po', 'observed': {'authority': 'L2-configured', 'candidate': 'L2-configured'}, 'recipe': None},
    {'family': 'memcached', 'canonical_name': 'memcached', 'version': '1.6.32', 'tarball_url': 'https://memcached.org/files/memcached-1.6.32.tar.gz', 'archive': 'tar.gz', 'sha256': '4ab234219865191e8d1ba57a2f9167d8b573248fa4ff00b4d8296be13d24a82c', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking whether __SUNPRO_C is declared... no', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'fdm', 'canonical_name': 'fdm', 'version': '2.2', 'tarball_url': 'https://github.com/nicm/fdm/releases/download/2.2/fdm-2.2.tar.gz', 'archive': 'tar.gz', 'sha256': '53aad117829834e21c1b9bf20496a1aa1c0e0fb98fe7735e1e73314266fb6c16', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for sys/queue.h... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'nmh', 'canonical_name': 'nmh', 'version': '1.8', 'tarball_url': 'https://download.savannah.nongnu.org/releases/nmh/nmh-1.8.tar.gz', 'archive': 'tar.gz', 'sha256': '366ce0ce3f9447302f5567009269c8bb3882d808f33eefac85ba367e875c8615', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for library containing connect... none required', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'rsync', 'canonical_name': 'rsync', 'version': '3.3.0', 'tarball_url': 'https://download.samba.org/pub/rsync/src/rsync-3.3.0.tar.gz', 'archive': 'tar.gz', 'sha256': '7399e9a6708c32d678a72a63219e96f23be0be2336e50fd1348498d07041df90', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'Configure found the following issues:', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'shairport-sync', 'canonical_name': 'shairport-sync', 'version': '4.3.3', 'tarball_url': 'https://github.com/mikebrady/shairport-sync/releases/download/4.3.3/shairport-sync-4.3.3.tar.gz', 'archive': 'tar.gz', 'sha256': '444bf77fe495d11d0c3b8212ea7a6ae44d6b2084c3600cea0629497a3e5f0209', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'openiked', 'canonical_name': 'openiked', 'version': '7.3', 'tarball_url': 'https://github.com/openiked/openiked-portable/releases/download/7.3/openiked-7.3.tar.gz', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'mupdf', 'canonical_name': 'mupdf', 'version': '1.25.1', 'tarball_url': 'https://mupdf.com/downloads/archive/mupdf-1.25.1-source.tar.gz', 'archive': 'tar.gz', 'sha256': '81aa1361252418cc45347b4ac075532096957a7ab772e20e046f3bb418d7263c', 'build_system': 'make', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'build-failure', 'reason': '    CC build/release/source/tools/pdfinfo.o', 'observed': {'authority': 'L4-linked', 'candidate': 'L2-configured'}, 'recipe': None},
    {'family': 'uwsgi', 'canonical_name': 'uwsgi', 'version': '2.0.28', 'tarball_url': 'https://github.com/unbit/uwsgi/archive/refs/tags/2.0.28.tar.gz', 'archive': 'tar.gz', 'sha256': '4bb0762c5becb0414352cca664957206df4d6847e9a1c472e87708dc2cdad610', 'build_system': 'make', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'build-failure', 'reason': '    4 | #include <Python.h>', 'observed': {'authority': 'L2-configured', 'candidate': 'L2-configured'}, 'recipe': None},
    {'family': 'nghttp2', 'canonical_name': 'nghttp2', 'version': '1.64.0', 'tarball_url': 'https://github.com/nghttp2/nghttp2/releases/download/v1.64.0/nghttp2-1.64.0.tar.gz', 'archive': 'tar.gz', 'sha256': '20e73f3cf9db3f05988996ac8b3a99ed529f4565ca91a49eb0550498e10621e8', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': "configure: error: invalid package name: `openssl? '", 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'coturn', 'canonical_name': 'coturn', 'version': '4.6.2', 'tarball_url': 'https://github.com/coturn/coturn/archive/refs/tags/4.6.2.tar.gz', 'archive': 'tar.gz', 'sha256': '13f2a38b66cffb73d86b5ed24acba4e1371d738d758a6039e3a18f0c84c176ad', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'Sockets code is fine: no sin_len field present', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'nsd', 'canonical_name': 'nsd', 'version': '4.10.0', 'tarball_url': 'https://www.nlnetlabs.nl/downloads/nsd/nsd-4.10.0.tar.gz', 'archive': 'tar.gz', 'sha256': '6317d7f5e3f01c33912f313d66a33dd1ace1cdf7f19d5c590b2e430d8ca4605f', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for pid_t... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'unbound', 'canonical_name': 'unbound', 'version': '1.22.0', 'tarball_url': 'https://nlnetlabs.nl/downloads/unbound/unbound-1.22.0.tar.gz', 'archive': 'tar.gz', 'sha256': 'c5dd1bdef5d5685b2cedb749158dd152c52d44f65529a34ac15cd88d4b1b3d43', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for EC_KEY_new... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'tor', 'canonical_name': 'tor', 'version': '0.4.8.13', 'tarball_url': 'https://dist.torproject.org/tor-0.4.8.13.tar.gz', 'archive': 'tar.gz', 'sha256': '9baf26c387a2820b3942da572146e6eb77c2bc66862af6297cd02a074e6fba28', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for clock_gettime... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'pgbouncer', 'canonical_name': 'pgbouncer', 'version': '1.23.1', 'tarball_url': 'https://www.pgbouncer.org/downloads/files/1.23.1/pgbouncer-1.23.1.tar.gz', 'archive': 'tar.gz', 'sha256': '1963b497231d9a560a62d266e4a2eae6881ab401853d93e5d292c3740eec5084', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for getrandom... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'libpq', 'canonical_name': 'libpq', 'version': '17.2', 'tarball_url': 'https://ftp.postgresql.org/pub/source/v17.2/postgresql-17.2.tar.bz2', 'archive': 'tar.bz2', 'sha256': '82ef27c0af3751695d7f64e2d963583005fbb6a0c3df63d0e4b42211d7021164', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking whether to build with LZ4 support... no', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'clamav', 'canonical_name': 'clamav', 'version': '1.4.1', 'tarball_url': 'https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.4.1/clamav-1.4.1.tar.gz', 'archive': 'tar.gz', 'sha256': 'a318e780ac39a6b3d6c46971382f96edde97ce48b8e361eb80e63415ed416ad8', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'unrealircd', 'canonical_name': 'unrealircd', 'version': '6.1.9', 'tarball_url': 'https://www.unrealircd.org/downloads/unrealircd-6.1.9.tar.gz', 'archive': 'tar.gz', 'sha256': 'bcfcf037d8ee427aea057d26c03993cd065d343c22be1e15b9ed023276fab6d8', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'configure: WARNING: unrecognized options: --with-openssl, --disable-curl', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'ncrack', 'canonical_name': 'ncrack', 'version': '0.7', 'tarball_url': 'https://nmap.org/ncrack/dist/ncrack-0.7.tar.gz', 'archive': 'tar.gz', 'sha256': 'f3f971cd677c4a0c0668cb369002c581d305050b3b0411e18dd3cb9cc270d14a', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking whether vsnprintf returns correct values on overflow... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'ssmtp', 'canonical_name': 'ssmtp', 'version': '2.64', 'tarball_url': 'https://ftp.debian.org/debian/pool/main/s/ssmtp/ssmtp_2.64.orig.tar.bz2', 'archive': 'tar.bz2', 'sha256': '22c37dc90c871e8e052b2cab0ad219d010fa938608cd66b21c8f3c759046fa36', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'link-failure', 'reason': "dt_needed=['libc.so.6'] imported=0 resolved=False", 'observed': {'authority': 'L3-built', 'candidate': 'L3-built'}, 'recipe': None},
    {'family': 'libshout', 'canonical_name': 'libshout', 'version': '2.4.6', 'tarball_url': 'https://downloads.xiph.org/releases/libshout/libshout-2.4.6.tar.gz', 'archive': 'tar.gz', 'sha256': '39cbd4f0efdfddc9755d88217e47f8f2d7108fa767f9d58a2ba26a16d8f7c910', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for inet_pton... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'libstrophe', 'canonical_name': 'libstrophe', 'version': '0.13.1', 'tarball_url': 'https://github.com/strophe/libstrophe/releases/download/0.13.1/libstrophe-0.13.1.tar.gz', 'archive': 'tar.gz', 'sha256': 'a1319f2bbd8e2669359e6a74afa416fa4d52c103b82d89d1e5f56bda3f80cefa', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for snprintf... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'librdkafka', 'canonical_name': 'librdkafka', 'version': '2.6.0', 'tarball_url': 'https://github.com/confluentinc/librdkafka/archive/refs/tags/v2.6.0.tar.gz', 'archive': 'tar.gz', 'sha256': 'abe0212ecd3e7ed3c4818a4f2baf7bf916e845e902bb15ae48834ca2d36ac745', 'build_system': 'configure', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'configure', 'configure': ['--enable-ssl'], 'make': ['-j8'], 'artifact': 'src/librdkafka.so*', 'launch': None, 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 'pam-u2f', 'canonical_name': 'pam-u2f', 'version': '1.3.0', 'tarball_url': 'https://developers.yubico.com/pam-u2f/Releases/pam_u2f-1.3.0.tar.gz', 'archive': 'tar.gz', 'sha256': '72360c6875485eb4df409da8f8f52b17893f05e4d998529c238814480e115220', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking whether to build static libraries... no', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'rpki-client', 'canonical_name': 'rpki-client', 'version': '9.2', 'tarball_url': 'https://ftp.nluug.nl/pub/OpenBSD/rpki-client/rpki-client-9.2.tar.gz', 'archive': 'tar.gz', 'sha256': 'e8e073c271250adf4f665d1c9a98eee1ae589e8e3bbedb2c106a3bd94dee96cc', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for openssl/ssl.h... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'sqlcipher', 'canonical_name': 'sqlcipher', 'version': '4.6.0', 'tarball_url': 'https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v4.6.0.tar.gz', 'archive': 'tar.gz', 'sha256': '879fb030c36bc5138029af6aa3ae3f36c28c58e920af05ac7ca78a5915b2fa3c', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'build-failure', 'reason': 'make: *** [Makefile:815: has_tclsh84] Error 1', 'observed': {'authority': 'L2-configured', 'candidate': 'L2-configured'}, 'recipe': None},
    {'family': 'wpa_supplicant', 'canonical_name': 'wpa_supplicant', 'version': '2.11', 'tarball_url': 'https://w1.fi/releases/wpa_supplicant-2.11.tar.gz', 'archive': 'tar.gz', 'sha256': '912ea06f74e30a8e36fbb68064d6cdff218d8d591db0fc5d75dee6c81ac7fc0a', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'hostapd', 'canonical_name': 'hostapd', 'version': '2.11', 'tarball_url': 'https://w1.fi/releases/hostapd-2.11.tar.gz', 'archive': 'tar.gz', 'sha256': '2b3facb632fd4f65e32f4bf82a76b4b72c501f995a4f62e330219fe7aed1747a', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'hydra', 'canonical_name': 'hydra', 'version': '9.5', 'tarball_url': 'https://github.com/vanhauser-thc/thc-hydra/archive/refs/tags/v9.5.tar.gz', 'archive': 'tar.gz', 'sha256': '9dd193b011fdb3c52a17b0da61a38a4148ffcad731557696819d4721d1bee76b', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'link-failure', 'reason': "dt_needed=['libc.so.6', 'libm.so.6', 'libz.so.1'] imported=0 resolved=False", 'observed': {'authority': 'L3-built', 'candidate': 'L3-built'}, 'recipe': None},
    {'family': 'libesmtp', 'canonical_name': 'libesmtp', 'version': '1.0.6', 'tarball_url': 'https://ftp.debian.org/debian/pool/main/libe/libesmtp/libesmtp_1.0.6.orig.tar.bz2', 'archive': 'tar.bz2', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'sofia-sip', 'canonical_name': 'sofia-sip', 'version': '1.13.17', 'tarball_url': 'https://sourceforge.net/projects/sofia-sip/files/sofia-sip/1.13.17/sofia-sip-1.13.17.tar.gz/download', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'syslog-ng', 'canonical_name': 'syslog-ng', 'version': '4.8.1', 'tarball_url': 'https://github.com/syslog-ng/syslog-ng/releases/download/syslog-ng-4.8.1/syslog-ng-4.8.1.tar.gz', 'archive': 'tar.gz', 'sha256': 'e8b8b98c60a5b68b25e3462c4104c35d05b975e6778d38d8a81b8ff7c0e64c5b', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for clock_gettime... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'thrift', 'canonical_name': 'thrift', 'version': '0.21.0', 'tarball_url': 'https://dlcdn.apache.org/thrift/0.21.0/thrift-0.21.0.tar.gz', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'squid', 'canonical_name': 'squid', 'version': '6.12', 'tarball_url': 'http://www.squid-cache.org/Versions/v6/squid-6.12.tar.gz', 'archive': 'tar.gz', 'sha256': '20d6c79214f75b5f889952ed79e1ab8b8c3f909b079671d77bb558a6f0b28625', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'link-failure', 'reason': "dt_needed=['libc.so.6', 'libgcc_s.so.1', 'libm.so.6', 'libstdc++.so.6'] imported=0 resolved=False", 'observed': {'authority': 'L3-built', 'candidate': 'L3-built'}, 'recipe': None},
    {'family': 'netdata', 'canonical_name': 'netdata', 'version': '2.1.1', 'tarball_url': 'https://github.com/netdata/netdata/releases/download/v2.1.1/netdata-v2.1.1.tar.gz', 'archive': 'tar.gz', 'sha256': '2a38166c639fb04bc42f95d3aa57a524ff85ab11e629a7f958536160eeddeb36', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'w3m', 'canonical_name': 'w3m', 'version': '0.5.3', 'tarball_url': 'https://downloads.sourceforge.net/project/w3m/w3m/w3m-0.5.3.tar.gz', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'nmap', 'canonical_name': 'nmap', 'version': '7.95', 'tarball_url': 'https://nmap.org/dist/nmap-7.95.tar.gz', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'dnsdist', 'canonical_name': 'dnsdist', 'version': '1.9.7', 'tarball_url': 'https://downloads.powerdns.com/releases/dnsdist-1.9.7.tar.gz', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'pdns', 'canonical_name': 'pdns', 'version': '4.9.4', 'tarball_url': 'https://downloads.powerdns.com/releases/pdns-4.9.4.tar.gz', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'mariadb', 'canonical_name': 'mariadb', 'version': '11.4.4', 'tarball_url': 'https://archive.mariadb.org/mariadb-11.4.4/source/mariadb-11.4.4.tar.gz', 'archive': 'tar.gz', 'sha256': '96fbd2e6e93fb7e8b373eea75d85b6fea57c0e111a02090cbbefed52599dc77b', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'grpc', 'canonical_name': 'grpc', 'version': '1.67.1', 'tarball_url': 'https://github.com/grpc/grpc/archive/refs/tags/v1.67.1.tar.gz', 'archive': 'tar.gz', 'sha256': 'd74f8e99a433982a12d7899f6773e285c9824e1d9a173ea1d1fb26c9bd089299', 'build_system': 'make', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'build-failure', 'reason': "and the third_party directory doesn't have them:", 'observed': {'authority': 'L2-configured', 'candidate': 'L2-configured'}, 'recipe': None},
    {'family': 'libwebsockets', 'canonical_name': 'libwebsockets', 'version': '4.3.3', 'tarball_url': 'https://github.com/warmcat/libwebsockets/archive/refs/tags/v4.3.3.tar.gz', 'archive': 'tar.gz', 'sha256': '6fd33527b410a37ebc91bb64ca51bdabab12b076bc99d153d7c5dd405e4bdf90', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'mongo-c-driver', 'canonical_name': 'mongo-c-driver', 'version': '1.28.1', 'tarball_url': 'https://github.com/mongodb/mongo-c-driver/releases/download/1.28.1/mongo-c-driver-1.28.1.tar.gz', 'archive': 'tar.gz', 'sha256': 'a93259840f461b28e198311e32144f5f8dc9fbd74348029f2793774d781bb7da', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'libgit2', 'canonical_name': 'libgit2', 'version': '1.8.4', 'tarball_url': 'https://github.com/libgit2/libgit2/archive/refs/tags/v1.8.4.tar.gz', 'archive': 'tar.gz', 'sha256': '49d0fc50ab931816f6bfc1ac68f8d74b760450eebdb5374e803ee36550f26774', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'libzip', 'canonical_name': 'libzip', 'version': '1.11.1', 'tarball_url': 'https://libzip.org/download/libzip-1.11.1.tar.gz', 'archive': 'tar.gz', 'sha256': 'c0e6fa52a62ba11efd30262290dc6970947aef32e0cc294ee50e9005ceac092a', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'cowpatty', 'canonical_name': 'cowpatty', 'version': '4.8', 'tarball_url': 'https://github.com/joswr1ght/cowpatty/archive/refs/tags/v4.8.tar.gz', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'john', 'canonical_name': 'john', 'version': '1.9.0-jumbo-1', 'tarball_url': 'https://www.openwall.com/john/k/john-1.9.0-jumbo-1.tar.gz', 'archive': 'tar.gz', 'sha256': '8b40499a20fdd66d5f651b439bf9846367182bb93e8bff3fd39ba267576dd317', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'dsniff', 'canonical_name': 'dsniff', 'version': '2.4b1', 'tarball_url': 'https://www.monkey.org/~dugsong/dsniff/dsniff-2.4b1.tar.gz', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'sslscan', 'canonical_name': 'sslscan', 'version': '2.1.5', 'tarball_url': 'https://github.com/rbsec/sslscan/archive/refs/tags/2.1.5.tar.gz', 'archive': 'tar.gz', 'sha256': 'b36616b1d59f3276af6ff9495ab8178ec6812393582fb3c094c56cc873efe956', 'build_system': 'make', 'admitted': True, 'outcome': 'admitted', 'failure_class': None, 'reason': None, 'observed': {'authority': 'L4-linked', 'candidate': 'L4-linked'}, 'recipe': {'build_system': 'make', 'configure': None, 'make': ['-j8'], 'artifact': 'sslscan', 'launch': ['--version'], 'env_extra': {'OPENSSL_CFLAGS': '-I{prefix}/include', 'OPENSSL_LIBS': '-L{prefix}/lib -lssl -lcrypto', 'OPENSSL_PREFIX': '{prefix}'}}},
    {'family': 'ssldump', 'canonical_name': 'ssldump', 'version': '1.9', 'tarball_url': 'https://github.com/adulau/ssldump/archive/refs/tags/v1.9.tar.gz', 'archive': 'tar.gz', 'sha256': 'c81ce58d79b6e6edb8d89822a85471ef51cfa7d63ad812df6f470b5d14ff6e48', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'exim', 'canonical_name': 'exim', 'version': '4.98', 'tarball_url': 'https://ftp.exim.org/pub/exim/exim4/exim-4.98.tar.xz', 'archive': 'tar.xz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'postfix', 'canonical_name': 'postfix', 'version': '3.9.0', 'tarball_url': 'https://de.postfix.org/ftpmirror/official/postfix-3.9.0.tar.gz', 'archive': 'tar.gz', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (6) Could not resolve host: de.postfix.org', 'observed': None, 'recipe': None},
    {'family': 'apache2-ssl', 'canonical_name': 'apache2-ssl', 'version': '2.4.62', 'tarball_url': 'https://dlcdn.apache.org/httpd/httpd-2.4.62.tar.bz2', 'archive': 'tar.bz2', 'sha256': None, 'build_system': 'fetch-failed', 'admitted': False, 'outcome': 'fetch-failed', 'failure_class': 'acquire-failure', 'reason': 'curl: (22) The requested URL returned error: 404', 'observed': None, 'recipe': None},
    {'family': 'tcpdump', 'canonical_name': 'tcpdump', 'version': '4.99.5', 'tarball_url': 'https://www.tcpdump.org/release/tcpdump-4.99.5.tar.gz', 'archive': 'tar.gz', 'sha256': '8c75856e00addeeadf70dad67c9ff3dd368536b2b8563abf6854d7c764cd3adb', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking for setlinebuf... yes', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'xrdp', 'canonical_name': 'xrdp', 'version': '0.10.1', 'tarball_url': 'https://github.com/neutrinolabs/xrdp/releases/download/v0.10.1/xrdp-0.10.1.tar.gz', 'archive': 'tar.gz', 'sha256': 'a2535f4420080630e20f0639c30c244170003ab998cc82d7913c2be856622f83', 'build_system': 'configure', 'admitted': False, 'outcome': 'rejected', 'failure_class': 'configure-failure', 'reason': 'checking type of array argument to getgroups... gid_t', 'observed': {'authority': 'L1-admitted-source', 'candidate': 'L1-admitted-source'}, 'recipe': None},
    {'family': 'freerdp', 'canonical_name': 'freerdp', 'version': '3.9.0', 'tarball_url': 'https://github.com/FreeRDP/FreeRDP/archive/refs/tags/3.9.0.tar.gz', 'archive': 'tar.gz', 'sha256': 'a1d2946c67037bf6bb8aa2f0441c7cacd5e92c835d776cecffb4fcdbaa45ec4f', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
    {'family': 'x11vnc', 'canonical_name': 'x11vnc', 'version': '0.9.16', 'tarball_url': 'https://github.com/LibVNC/x11vnc/archive/refs/tags/0.9.16.tar.gz', 'archive': 'tar.gz', 'sha256': '885e5b5f5f25eec6f9e4a1e8be3d0ac71a686331ee1cfb442dba391111bd32bd', 'build_system': 'unsupported', 'admitted': False, 'outcome': 'not-venue-buildable', 'failure_class': 'recipe-build-system-unsupported', 'reason': 'no ./configure and no Makefile at the source root', 'observed': None, 'recipe': None},
)


def admitted_recipe_specs() -> tuple[dict, ...]:
    """The admitted recipes, in the shape `downstream_build_link._build_catalogue` consumes.

    Derived from `ATTEMPTS` (only the entries marked admitted), with a `recipe_id` and a note. This
    is the single source of truth for the shared recipe catalogue, so the catalogue and the campaign
    record cannot disagree about which families were admitted.
    """
    out: list[dict] = []
    for a in ATTEMPTS:
        if not a["admitted"]:
            continue
        r = dict(a["recipe"])
        out.append({
            "family": a["family"],
            "version": a["version"],
            "url": a["tarball_url"],
            "archive": a["archive"],
            "sha256": a["sha256"],
            "build_system": r["build_system"],
            "configure": r.get("configure"),
            "make": r["make"],
            "artifact": r["artifact"],
            "launch": r.get("launch"),
            "env_extra": r.get("env_extra"),
            "recipe_id": f"recipe:{a['family']}:{a['version']}",
            "note": (f"{a['family']} {a['version']} links the subject OpenSSL (24.18 admission "
                     f"campaign; build system {r['build_system']} classified empirically)"),
        })
    out.sort(key=lambda d: str(d["family"]))
    return tuple(out)


ADMITTED = admitted_recipe_specs()
ADMITTED_FAMILIES = frozenset(r["family"] for r in ADMITTED)

NON_CLAIMS: list[str] = [
    "a selected population is not a random sample: the 1,000 counted families are selected from "
    "frozen ranking evidence, so their blocker shares do not generalise to all downstream software",
    "1000/1000 is not a security proof: a full pass is not a guarantee that any consumer is safe, "
    "and the analysis makes no statement about an unmeasured consumer",
    "a build is not a functional proof: reaching the configured/built/linked rungs is not behaving, "
    "and only the functional levels are behavioural evidence",
    "direct and transitive consumers are different evidence: the two are never summed",
    "the campaign's yield is a property of this venue and this batch, not of the whole 980: the "
    "attempted families are a bounded, heuristic-ordered batch (well-known direct OpenSSL consumers "
    "with stable release tarballs), and the venue admits only a compiler, make, pkg-config and zlib, "
    "so the admission rate does not extrapolate to the recipe-less population",
]

RULE: dict = {
    "id": "downstream-recipe-campaign/1",
    "name": "the recipe-admission campaign",
    "priority_rule": (
        "the recipe-less counted families in the frozen 24.16 recipe-queue order -- source breadth "
        "descending, then distro breadth descending, then popularity descending, then canonical name "
        "ascending, then family_id ascending -- preferring well-known direct OpenSSL consumers with "
        "stable upstream release tarballs. It is a **heuristic** ranking over frozen breadth signals, "
        "never a measurement of buildability"
    ),
    "admission_criterion": (
        "a recipe is admissible when its pinned release tarball ships a build entry point the venue "
        "can execute (a generated `configure`, or a plain `Makefile`) and needs no tool the venue "
        "lacks; the venue is fixed (a C compiler, make, pkg-config, zlib -- and no "
        "autoconf/automake/libtool, no cmake, no meson/ninja, no scdoc, no libnl3). A recipe is "
        "admitted only if it was actually built against both subjects; a non-admitted candidate "
        "carries the exact reason"
    ),
    "identical_intent": (
        "one recipe per family; the same acquire -> configure -> make argv (and the same prefix-derived "
        "environment) is run for both subjects with the single substitution {prefix} = the subject's "
        "OpenSSL install prefix and no other difference; a generated build file is not a source patch, "
        "and candidate_specific_patch_count is 0"
    ),
    "local_only": (
        "the campaign fetches each candidate's released tarball, extracts it and builds it inside the "
        "admitted court container under its cgroup caps and the build/link tool's own wall-clock "
        "bounds; scratch is under /work/court and removed afterwards. Nothing is fetched or compiled "
        "outside the venue"
    ),
    "normalisation": (
        "the record is a pure function of committed inputs: the attempt pins and classifications are "
        "authored evidence fixed at capture, the levels are re-read from the committed re-measured "
        "build/link atlas, and the movement is the subtraction of two measured blocker summaries"
    ),
    "movement": (
        "the per-metric difference between the re-derived `after` blocker summary and the preserved "
        "pre-campaign `before`, over the frozen P1000, computed as a subtraction of two measured "
        "figures: the family count with an admitted recipe, the measurable count, the candidate-linked "
        "count and the DROP_IN_PASS count (plus the `no-admitted-recipe` and resolved class counts)"
    ),
    "honesty_labels": [
        "the priority rule is a heuristic ranking, never a measurement of buildability",
        "the campaign's yield is a property of this venue and this batch, not of the whole 980",
        "a build/link is not a functional proof",
    ],
}


# ---------------------------------------------------------------------------------------------------
# reading the committed planes (pure; the court re-reads the same files)
# ---------------------------------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def _missing_inputs() -> list[str]:
    required = [SHARED_BLOCKERS, BUILD_LINK_ATLAS, P1000_RUN, BASELINE, blockers.FAMILY_FREEZE,
                blockers.FAMILIES]
    return [rel(p) for p in required if not p.is_file()]


def _baseline() -> dict | None:
    if not BASELINE.is_file():
        return None
    try:
        return _load_json(BASELINE)
    except (json.JSONDecodeError, OSError):
        return None


def load_inputs() -> dict:
    """Every committed plane this record reads and the court re-reads."""
    bi = blockers.load_inputs()
    return {
        **bi,
        "shared_blockers_body": _load_json(SHARED_BLOCKERS),
        "build_link_body": _load_json(BUILD_LINK_ATLAS),
        "p1000_body": _load_json(P1000_RUN),
        "baseline_body": _baseline(),
    }


# ---------------------------------------------------------------------------------------------------
# the derivation
# ---------------------------------------------------------------------------------------------------

def _class_counts(partition: dict) -> dict:
    counts = {c: 0 for c in BLOCKER_CLASSES}
    for cls in partition.values():
        counts[cls] = counts.get(cls, 0) + 1
    return counts


def _summarise(analysis: dict) -> dict:
    """The comparable figures of one blocker analysis: the class counts and the funnel rungs."""
    partition = analysis.get("partition") or {}
    counts = analysis.get("counts") or {}
    funnel = {f["step"]: f["families"] for f in analysis.get("funnel") or []}
    class_counts = _class_counts(partition)
    return {
        "class_counts": class_counts,
        "families": counts.get("families"),
        "measurable_families": counts.get("measurable_families"),
        "recipe_backed_families": counts.get("recipe_backed_families"),
        "recipe_less_families": counts.get("recipe_less_families"),
        "linked": funnel.get("linked"),
        "drop_in_pass": funnel.get("drop-in-pass"),
    }


def _atlas_levels(build_link_body: dict) -> dict:
    """`(family, subject) -> level` and `(family, subject) -> linkage_proven` from the atlas."""
    levels: dict[tuple[str, str], str] = {}
    linkage: dict[tuple[str, str], bool] = {}
    for r in build_link_body.get("runs") or []:
        key = (str(r.get("canonical_name")), str(r.get("subject")))
        levels[key] = r.get("level")
        linkage[key] = bool(r.get("linkage_proven"))
    return {"levels": levels, "linkage": linkage}


def derive_campaign(inputs: dict) -> dict:
    """The whole record: rule, attempts, admitted recipes, counts and movement."""
    analysis = blockers.derive_blockers(inputs)
    after = _summarise(analysis)
    before = inputs.get("baseline_body")
    if not before:
        before = dict(_summarise(inputs["shared_blockers_body"]),
                      source="24.17 pre-campaign planes (not captured)")
    else:
        before = dict(before)
        before.setdefault("source", "24.17 pre-campaign planes, captured as recipe-campaign-baseline")

    atlas = _atlas_levels(inputs["build_link_body"])
    levels = atlas["levels"]
    linkage = atlas["linkage"]

    attempts: list[dict] = []
    admitted_recipes: list[dict] = []
    for a in ATTEMPTS:
        fam = a["family"]
        observed = a.get("observed") or {}
        auth_level = levels.get((fam, "authority"), observed.get("authority"))
        cand_level = levels.get((fam, "candidate"), observed.get("candidate"))
        rec = {
            "family": fam, "canonical_name": fam, "version": a["version"],
            "tarball_url": a["tarball_url"], "sha256": a.get("sha256"),
            "build_system": a.get("build_system"), "admitted": bool(a["admitted"]),
            "outcome": a.get("outcome"), "failure_class": a.get("failure_class"),
            "reason": a.get("reason"),
            "authority_level": auth_level, "candidate_level": cand_level,
        }
        attempts.append(rec)
        if a["admitted"]:
            admitted_recipes.append({
                "family": fam, "version": a["version"], "url": a["tarball_url"],
                "sha256": a.get("sha256"), "build_system": a.get("build_system"),
                "artifact": (a.get("recipe") or {}).get("artifact"),
                "recipe_id": f"recipe:{fam}:{a['version']}",
                "authority_level": auth_level, "candidate_level": cand_level,
                "linkage_proven": linkage.get((fam, "candidate"), False),
            })
    admitted_recipes.sort(key=lambda d: str(d["family"]))

    def count_level(subject: str, rung: str) -> int:
        return sum(1 for r in admitted_recipes
                   if EXECUTION_LEVEL_RANK.get(str(r.get(f"{subject}_level")), -1)
                   >= EXECUTION_LEVEL_RANK[rung])

    counts = {
        "attempted": len(attempts),
        "admitted": len(admitted_recipes),
        "rejected": len(attempts) - len(admitted_recipes),
        "built": count_level("candidate", L3),
        "linked": count_level("candidate", L4),
        "authority_linked": count_level("authority", L4),
        "per_subject": {
            subject: {
                "configured": count_level(subject, "L2-configured"),
                "built": count_level(subject, L3),
                "linked": count_level(subject, L4),
            } for subject in ("authority", "candidate")
        },
        "yield": {
            "admitted_per_attempted": f"{len(admitted_recipes)}/{len(attempts)}",
            "linked_per_attempted": f"{count_level('candidate', L4)}/{len(attempts)}",
            "admission_rate": round(len(admitted_recipes) / len(attempts), 4) if attempts else 0.0,
        },
    }

    movement: dict[str, dict] = {}
    for metric in ("recipe_backed_families", "measurable_families", "linked", "drop_in_pass",
                   "no_admitted_recipe", "resolved_none"):
        if metric == "no_admitted_recipe":
            b = int((before.get("class_counts") or {}).get("no-admitted-recipe") or 0)
            a = int((after.get("class_counts") or {}).get("no-admitted-recipe") or 0)
        elif metric == "resolved_none":
            b = int((before.get("class_counts") or {}).get("none") or 0)
            a = int((after.get("class_counts") or {}).get("none") or 0)
        else:
            b = int(before.get(metric) or 0)
            a = int(after.get(metric) or 0)
        movement[metric] = {"before": b, "after": a, "delta": a - b}

    return {
        "rule": RULE,
        "before": before,
        "after": after,
        "movement": movement,
        "attempts": attempts,
        "admitted_recipes": admitted_recipes,
        "counts": counts,
        "non_claims": NON_CLAIMS,
    }


# ---------------------------------------------------------------------------------------------------
# findings and the sensitivity control (the court's own checks over the committed record)
# ---------------------------------------------------------------------------------------------------

def campaign_findings(inputs: dict, body: dict) -> list[str]:
    """Every way the recorded campaign fails its own derivation.

    The conditions: every attempt is accounted for; every admitted recipe was really built (the
    committed atlas shows both subjects linked it); a non-admitted family carries a reason; the
    admitted recipes are exactly the `ATTEMPTS` marked admitted; the movement is the subtraction of
    the preserved before and the derived after; and the counts are derived rather than typed.
    """
    out: list[str] = []
    derived = derive_campaign(inputs)

    if body.get("rule") != RULE:
        out.append("the recorded rule is not the frozen campaign rule")
    if body.get("non_claims") != NON_CLAIMS:
        out.append("the recorded non_claims are not the campaign non-claims")
    if body.get("before") != derived["before"]:
        out.append("the recorded `before` does not reproduce from the preserved baseline")
    if body.get("after") != derived["after"]:
        out.append("the recorded `after` does not reproduce from the committed planes")
    if body.get("movement") != derived["movement"]:
        out.append("the recorded `movement` does not reproduce from before/after")
    if body.get("attempts") != derived["attempts"]:
        out.append("the recorded `attempts` do not reproduce from the attempt record")
    if body.get("admitted_recipes") != derived["admitted_recipes"]:
        out.append("the recorded `admitted_recipes` do not reproduce from the attempt record")
    if body.get("counts") != derived["counts"]:
        out.append("the recorded `counts` do not reproduce from the record")

    recorded = body.get("attempts") or []
    if len(recorded) != len(ATTEMPTS):
        out.append(f"the record accounts for {len(recorded)} attempts but {len(ATTEMPTS)} were made")
    want = [a["family"] for a in ATTEMPTS]
    got = [r.get("family") for r in recorded]
    if got != want:
        out.append("the recorded attempts do not account for every attempted family once, in order")

    # Every admitted recipe was really built against both subjects.
    atlas = _atlas_levels(inputs["build_link_body"])
    levels = atlas["levels"]
    linkage = atlas["linkage"]
    for r in body.get("admitted_recipes") or []:
        fam = r.get("family")
        a = levels.get((fam, "authority"))
        c = levels.get((fam, "candidate"))
        if a != L4:
            out.append(f"admitted recipe {fam!r} did not reach {L4} against the authority "
                       f"(recorded {a!r})")
        if c != L4:
            out.append(f"admitted recipe {fam!r} did not reach {L4} against the candidate "
                       f"(recorded {c!r})")
        if not linkage.get((fam, "candidate"), False):
            out.append(f"admitted recipe {fam!r} did not prove candidate linkage")

    # Admission set equals the ATTEMPTS marked admitted.
    want_adm = sorted(a["family"] for a in ATTEMPTS if a["admitted"])
    got_adm = sorted(r["family"] for r in body.get("admitted_recipes") or [])
    if want_adm != got_adm:
        out.append("the admitted recipes are not exactly the attempts marked admitted")
    if {r["family"] for r in ADMITTED} != set(want_adm):
        out.append("the module catalogue is not exactly the attempts marked admitted")

    # A non-admitted family carries a reason.
    for r in body.get("attempts") or []:
        if not r.get("admitted") and not (r.get("reason") or r.get("failure_class")):
            out.append(f"non-admitted family {r.get('family')!r} carries no reason and no failure "
                       f"class")

    # The movement is the arithmetic of the two measured summaries, never typed.
    for metric, m in (body.get("movement") or {}).items():
        if m.get("delta") != int(m.get("after") or 0) - int(m.get("before") or 0):
            out.append(f"movement[{metric}].delta {m.get('delta')!r} is not after - before")
    # A 'typed' count disagrees with the derived one.
    if (body.get("counts") or {}).get("linked") != derived["counts"]["linked"]:
        out.append("counts.linked is not the derived count")
    return out


def campaign_sensitivity_control(inputs: dict, body: dict) -> dict:
    """Prove the record can fail: seed five mutations and require each caught."""
    base = campaign_findings(inputs, body)
    specificity = not base

    def caught(mutated: dict) -> int:
        return len(campaign_findings(inputs, mutated))

    # 1. A rejected family marked admitted with no recipe.
    m1 = copy.deepcopy(body)
    for a in m1.get("attempts") or []:
        if not a.get("admitted"):
            a["admitted"] = True
            break

    # 2. An admitted recipe dropped from the record.
    m2 = copy.deepcopy(body)
    if m2.get("admitted_recipes"):
        m2["admitted_recipes"].pop()

    # 3. A movement figure that disagrees with the planes.
    m3 = copy.deepcopy(body)
    if m3.get("movement"):
        first = sorted(m3["movement"])[0]
        m3["movement"][first]["delta"] = int(m3["movement"][first]["delta"]) + 7

    # 4. A non-admitted family stripped of its reason.
    m4 = copy.deepcopy(body)
    for a in m4.get("attempts") or []:
        if not a.get("admitted"):
            a["reason"] = None
            a["failure_class"] = None
            break

    # 5. A typed count that disagrees with the derivation.
    m5 = copy.deepcopy(body)
    m5["counts"]["linked"] = int(m5["counts"].get("linked") or 0) + 9

    return {
        "baseline_findings": len(base),
        "specificity_holds": specificity,
        "caught_rejected_marked_admitted": caught(m1),
        "caught_admitted_recipe_dropped": caught(m2),
        "caught_movement_disagrees": caught(m3),
        "caught_non_admitted_no_reason": caught(m4),
        "caught_typed_count": caught(m5),
        "honest": bool(specificity and all(caught(m) for m in (m1, m2, m3, m4, m5))),
    }


# ---------------------------------------------------------------------------------------------------
# the artefact
# ---------------------------------------------------------------------------------------------------

def _inputs_list() -> list[InputRef]:
    return [
        InputRef(name="recipe-campaign-baseline", path=BASELINE),
        InputRef(name="shared-blockers", path=SHARED_BLOCKERS),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="p1000-run", path=P1000_RUN),
        InputRef(name="family-freeze", path=blockers.FAMILY_FREEZE),
        InputRef(name="families", path=blockers.FAMILIES),
        InputRef(name="downstream-recipe-campaign",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_recipe_campaign.py"),
        InputRef(name="downstream-blockers",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_blockers.py"),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard", path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]


def write_outputs(body: dict) -> None:
    doc = envelope(kind="downstream-recipe-campaign", authority=PRODUCTION_AUTHORITY,
                   inputs=_inputs_list(), body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


def _baseline_doc(summary: dict) -> dict:
    body = dict(summary,
                source="24.17 pre-campaign planes",
                captured_by="forensics/tools/downstream_recipe_campaign.py --capture-baseline",
                captured_note=("the 24.16 blocker summary of the pre-campaign planes, captured once "
                               "before the planes were re-measured and committed as the record's "
                               "`before`"))
    doc = envelope(kind="downstream-recipe-campaign-baseline", authority=PRODUCTION_AUTHORITY,
                   inputs=[InputRef(name="shared-blockers", path=SHARED_BLOCKERS)],
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    return doc


def cmd_capture_baseline() -> int:
    """Capture the pre-campaign 24.16 blocker summary as the committed `before` input.

    Run once, before the planes are re-measured. It reads the committed planes through 24.16's own
    derivation and freezes the summary; the record then reads it rather than a plane that no longer
    exists.
    """
    missing = [rel(p) for p in (SHARED_BLOCKERS, BUILD_LINK_ATLAS, P1000_RUN, blockers.FAMILY_FREEZE,
                                blockers.FAMILIES) if not p.is_file()]
    if missing:
        print(f"[downstream-recipe-campaign] {', '.join(missing)} is absent; cannot capture a "
              f"baseline")
        return 1
    inputs = load_inputs()
    analysis = blockers.derive_blockers(inputs)
    if not analysis.get("partition"):
        print("[downstream-recipe-campaign] the derived 24.16 partition is empty; cannot capture a "
              "baseline")
        return 1
    write_json(BASELINE, _baseline_doc(_summarise(analysis)))
    print(f"[downstream-recipe-campaign] captured the pre-campaign baseline "
          f"({len(analysis['partition'])} families) -> {rel(BASELINE)}")
    return 0


def cmd_measure() -> int:
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-recipe-campaign] {', '.join(missing)} is absent; run the earlier "
              f"subphase(s) first")
        return 1
    inputs = load_inputs()
    body = derive_campaign(inputs)
    findings = campaign_findings(inputs, body)
    control = campaign_sensitivity_control(inputs, body)
    if findings or not control["honest"]:
        print("[downstream-recipe-campaign] the derived record fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body)
    c = body["counts"]
    print(f"[downstream-recipe-campaign] attempted={c['attempted']} admitted={c['admitted']} "
          f"built={c['built']} linked={c['linked']} authority_linked={c['authority_linked']} "
          f"yield={c['yield']['admitted_per_attempted']}")
    for metric in ("recipe_backed_families", "measurable_families", "linked", "drop_in_pass",
                   "no_admitted_recipe", "resolved_none"):
        m = body["movement"][metric]
        print(f"  {metric:<26} before={m['before']:<5} after={m['after']:<5} delta={m['delta']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check() -> int:
    if not OUT.is_file():
        print(f"[downstream-recipe-campaign] {rel(OUT)} is absent")
        return 1
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-recipe-campaign] {', '.join(missing)} is absent")
        return 1
    inputs = load_inputs()
    body = _load_json(OUT)
    findings = campaign_findings(inputs, body)
    control = campaign_sensitivity_control(inputs, body)
    if findings:
        print(f"[downstream-recipe-campaign] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    print(f"[downstream-recipe-campaign] findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard admits this metadata-only generator and the pure functions behave."""
    failures: list[str] = []

    admission = phase24_guard.evaluate(env={}, dockerenv=False,
                                       manifest=phase24_guard.load_manifest(),
                                       entry_point="downstream_recipe_campaign.py")
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append(
            "the guard did not admit downstream_recipe_campaign.py as metadata-only on a host")

    if set(BLOCKER_CLASSES) != set(blockers.CLASS_RULE):
        failures.append("the blocker vocabulary this record partitions against is not the schema's")

    missing = _missing_inputs()
    if missing:
        failures.append(f"{', '.join(missing)} is absent")
    elif not OUT.is_file():
        failures.append(f"{rel(OUT)} is absent; run --measure")
    else:
        inputs = load_inputs()
        body = _load_json(OUT)
        findings = campaign_findings(inputs, body)
        if findings:
            failures.append(f"the committed record has findings: {findings[:3]}")
        control = campaign_sensitivity_control(inputs, body)
        if not control["honest"]:
            failures.append(f"the sensitivity control is not honest: {control}")
        if len(body.get("attempts") or []) < 40:
            failures.append(f"the record accounts for only {len(body.get('attempts') or [])} "
                            f"attempts, below the campaign's 40-family floor")
        # Every admitted recipe must be in the shared catalogue the build/link tool imports.
        if {r["family"] for r in ADMITTED} != {r["family"] for r in body.get("admitted_recipes") or []}:
            failures.append("the module catalogue is not exactly the record's admitted recipes")

    if failures:
        print("[downstream-recipe-campaign] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-recipe-campaign] self-test ok: the guard admits this metadata-only generator "
          "on a host, the vocabulary matches the schema, the committed record reproduces with zero "
          "findings, every admitted recipe really built against both subjects, the record accounts "
          "for at least 40 attempts, and every seeded mutation (a rejected family marked admitted, a "
          "dropped admitted recipe, a movement figure disagreeing with the planes, a non-admitted "
          "family stripped of its reason and a typed count) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive the record from the committed planes and write it")
    ap.add_argument("--capture-baseline", action="store_true",
                    help="capture the pre-campaign 24.16 summary as the committed before input")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed record without regenerating")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool reads committed evidence and writes one
    # record, so it executes nothing itself, but it is a Phase-24 entry point and a host invocation is
    # refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    if args.capture_baseline:
        return cmd_capture_baseline()
    return cmd_measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
